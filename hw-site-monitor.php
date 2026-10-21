<?php
/**
 * Plugin Name:       HW Site Monitor
 * Plugin URI:        https://github.com/Waldoweb/hw-site-monitor
 * Description:       Read-only report for the Hostetler Web dashboard: WordPress, PHP, plugin and theme versions, pending updates, and Independent Analytics traffic and conversions. Answers only requests signed by the dashboard, and reading the report changes nothing on the site.
 * Version:           1.1.1
 * Author:            Hostetler Web
 * Author URI:        https://hostetlerweb.com
 * Update URI:        https://github.com/Waldoweb/hw-site-monitor
 * License:           GPL-2.0-or-later
 * Requires PHP:      7.4
 * Requires at least: 5.6
 * Text Domain:       hw-site-monitor
 */

defined( 'ABSPATH' ) || exit;

define( 'HW_MONITOR_VERSION', '1.1.1' );

// Updates come from GitHub releases through Plugin Update Checker. Pushing a vX.Y.Z
// tag builds the release zip (.github/workflows/release.yml); sites check every 6
// hours and install it automatically.
if ( is_readable( __DIR__ . '/vendor/plugin-update-checker/plugin-update-checker.php' ) ) {
	require_once __DIR__ . '/vendor/plugin-update-checker/plugin-update-checker.php';
	\YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
		'https://github.com/Waldoweb/hw-site-monitor/',
		__FILE__,
		'hw-site-monitor',
		6
	)->getVcsApi()->enableReleaseAssets( '/\.zip($|[?&#])/i' );

	add_filter(
		'auto_update_plugin',
		function ( $update, $item ) {
			return ( isset( $item->plugin ) && plugin_basename( __FILE__ ) === $item->plugin ) ? true : $update;
		},
		10,
		2
	);
}

require_once __DIR__ . '/public-keys.php';

/*
 * How a request is checked (see verify_request below):
 * - Headers X-HW-Timestamp (unix seconds) and X-HW-Signature (base64 Ed25519 signature).
 * - Signed message: "hw-monitor-v1\nGET\n{host}\n{route}\n{timestamp}", where host is this
 *   site's own host (from home_url, without "www.") and route is "/hw-monitor/v1/report".
 *   A traffic request (1.1+) adds a sixth line with its query, "from=…&to=…" (plus "&tops=1"),
 *   so a captured request can't be replayed for a different date range.
 * - The timestamp must be within 5 minutes, and the signature must match one of the dashboard's
 *   public keys in public-keys.php. There's no secret on the site: the private key exists only
 *   in the dashboard's Convex environment.
 * Answering a request writes nothing to the database, not even a nonce. (The updater, like in every
 * in-house plugin, keeps its own update-check state.)
 */

add_action(
	'rest_api_init',
	function () {
		register_rest_route(
			'hw-monitor/v1',
			'/report',
			array(
				'methods'             => 'GET',
				'callback'            => 'hw_monitor_report',
				'permission_callback' => 'hw_monitor_verify_request',
			)
		);
	}
);

function hw_monitor_site_host() {
	$host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
	return preg_replace( '/^www\./', '', $host );
}

function hw_monitor_public_keys() {
	$keys = HW_MONITOR_PUBLIC_KEYS;
	// Optional extra key for testing against a development dashboard. Set in wp-config.php.
	if ( defined( 'HW_MONITOR_EXTRA_PUBLIC_KEY' ) && HW_MONITOR_EXTRA_PUBLIC_KEY ) {
		$keys[] = HW_MONITOR_EXTRA_PUBLIC_KEY;
	}
	return $keys;
}

/**
 * @param WP_REST_Request $request
 * @return true|WP_Error
 */
function hw_monitor_verify_request( $request ) {
	$deny = new WP_Error( 'hw_monitor_forbidden', 'Signature required.', array( 'status' => 401 ) );

	$ts  = $request->get_header( 'x_hw_timestamp' );
	$sig = $request->get_header( 'x_hw_signature' );
	if ( ! $ts || ! $sig || ! ctype_digit( (string) $ts ) ) {
		return $deny;
	}
	if ( abs( time() - (int) $ts ) > 300 ) {
		return new WP_Error( 'hw_monitor_clock', 'Timestamp out of range. Check the server clock.', array( 'status' => 401 ) );
	}

	$signature = base64_decode( strtr( (string) $sig, '-_', '+/' ), true );
	if ( false === $signature || strlen( $signature ) !== 64 ) {
		return $deny;
	}

	$lines = array( 'hw-monitor-v1', 'GET', hw_monitor_site_host(), $request->get_route(), (string) $ts );
	$query = hw_monitor_signed_query( $request );
	if ( '' !== $query ) {
		$lines[] = $query;
	}
	$message = implode( "\n", $lines );

	foreach ( hw_monitor_public_keys() as $key_b64 ) {
		$key = base64_decode( (string) $key_b64, true );
		if ( false === $key || strlen( $key ) !== 32 ) {
			continue;
		}
		try {
			// libsodium, or WordPress's bundled sodium_compat on hosts without it
			if ( sodium_crypto_sign_verify_detached( $signature, $message, $key ) ) {
				return true;
			}
		} catch ( Exception $e ) {
			continue;
		}
	}
	return $deny;
}

/** The traffic part of a request in the fixed order it's signed: "from=…&to=…[&tops=1]", or "". */
function hw_monitor_signed_query( $request ) {
	$from = (string) $request->get_param( 'from' );
	$to   = (string) $request->get_param( 'to' );
	if ( '' === $from && '' === $to ) {
		return '';
	}
	return 'from=' . $from . '&to=' . $to . ( $request->get_param( 'tops' ) ? '&tops=1' : '' );
}

/** Everything here is read from WordPress; nothing is changed. */
function hw_monitor_report( $request = null ) {
	if ( ! function_exists( 'get_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	if ( ! function_exists( 'get_core_updates' ) ) {
		require_once ABSPATH . 'wp-admin/includes/update.php';
	}
	global $wp_version, $wpdb;

	// Update info as WordPress last saw it (its own twice-daily check). We don't trigger a check.
	$plugin_updates = get_site_transient( 'update_plugins' );
	$theme_updates  = get_site_transient( 'update_themes' );
	$core_updates   = get_site_transient( 'update_core' );
	$auto_plugins   = (array) get_site_option( 'auto_update_plugins', array() );
	$auto_themes    = (array) get_site_option( 'auto_update_themes', array() );

	$core_latest = null;
	if ( $core_updates && ! empty( $core_updates->updates ) ) {
		foreach ( $core_updates->updates as $u ) {
			if ( isset( $u->response ) && 'upgrade' === $u->response ) {
				$core_latest = $u->current;
				break;
			}
		}
	}

	$plugins = array();
	foreach ( get_plugins() as $file => $data ) {
		$update    = isset( $plugin_updates->response[ $file ] ) ? $plugin_updates->response[ $file ] : null;
		$plugins[] = array(
			'file'        => $file,
			'slug'        => dirname( $file ) === '.' ? basename( $file, '.php' ) : dirname( $file ),
			'name'        => wp_strip_all_tags( $data['Name'] ),
			'version'     => $data['Version'],
			'latest'      => $update && isset( $update->new_version ) ? $update->new_version : null,
			'active'      => is_plugin_active( $file ),
			'auto_update' => in_array( $file, $auto_plugins, true ),
		);
	}

	$active_theme = wp_get_theme();
	$themes       = array();
	foreach ( wp_get_themes() as $stylesheet => $theme ) {
		$update   = isset( $theme_updates->response[ $stylesheet ] ) ? $theme_updates->response[ $stylesheet ] : null;
		$role     = $stylesheet === $active_theme->get_stylesheet() ? 'active' : ( $stylesheet === $active_theme->get_template() ? 'parent' : 'inactive' );
		$themes[] = array(
			'slug'        => $stylesheet,
			'name'        => wp_strip_all_tags( $theme->get( 'Name' ) ),
			'version'     => $theme->get( 'Version' ),
			'latest'      => $update && isset( $update['new_version'] ) ? $update['new_version'] : null,
			'role'        => $role,
			'auto_update' => in_array( $stylesheet, $auto_themes, true ),
		);
	}

	$response = rest_ensure_response(
		array(
			'monitor'   => HW_MONITOR_VERSION,
			'site'      => array(
				'host'      => hw_monitor_site_host(),
				'home'      => home_url(),
				'multisite' => is_multisite(),
				'timezone'  => wp_timezone_string(),
			),
			'core'      => array(
				'version' => $wp_version,
				'latest'  => $core_latest,
			),
			'php'       => PHP_VERSION,
			'mysql'     => $wpdb->db_version(),
			'theme'     => $active_theme->get( 'Name' ),
			'plugins'   => $plugins,
			'themes'    => $themes,
			'ia'        => hw_monitor_ia_status(),
			'checked'   => array(
				'plugins' => $plugin_updates && isset( $plugin_updates->last_checked ) ? (int) $plugin_updates->last_checked : null,
				'themes'  => $theme_updates && isset( $theme_updates->last_checked ) ? (int) $theme_updates->last_checked : null,
				'core'    => $core_updates && isset( $core_updates->last_checked ) ? (int) $core_updates->last_checked : null,
			),
		)
	);
	if ( $request instanceof WP_REST_Request && '' !== hw_monitor_signed_query( $request ) ) {
		$data            = $response->get_data();
		$data['traffic'] = hw_monitor_ia_traffic( (string) $request->get_param( 'from' ), (string) $request->get_param( 'to' ), (bool) $request->get_param( 'tops' ) );
		$response->set_data( $data );
	}
	$response->header( 'Cache-Control', 'no-store, private' );
	// RunCloud's nginx page cache ignores Cache-Control (proxy_ignore_headers) and would replay a
	// signed report to anyone. It does honour X-Accel-Expires, where 0 means "never cache this".
	$response->header( 'X-Accel-Expires', '0' );
	return $response;
}

/*
 * Independent Analytics has no API, so traffic comes from its own tables. Everything below only
 * reads them, with a handful of summary queries (IA indexes them by date). IA stores times in UTC;
 * days here are the site's own calendar days (Settings → General → Timezone).
 *
 * Only layouts we've checked are read: every column used is confirmed first, so an IA update that
 * changes its tables gets "unsupported" instead of wrong numbers. Checked against IA Pro 2.16.1
 * (database version 53).
 */

/** Columns each IA table must have. Core tables are required; the rest only add a section. */
function hw_monitor_ia_columns() {
	return array(
		'core'     => array(
			'sessions'       => array( 'session_id', 'visitor_id', 'referrer_id', 'campaign_id', 'created_at' ),
			'views'          => array( 'id', 'resource_id', 'viewed_at' ),
			'resources'      => array( 'id', 'cached_title', 'cached_url' ),
			'referrers'      => array( 'id', 'domain', 'referrer_type_id' ),
			'referrer_types' => array( 'id', 'referrer_type' ),
		),
		'optional' => array(
			'campaigns'        => array( 'campaign_id', 'utm_source_id', 'utm_medium_id', 'utm_campaign_id' ),
			'utm_sources'      => array( 'id', 'utm_source' ),
			'utm_mediums'      => array( 'id', 'utm_medium' ),
			'utm_campaigns'    => array( 'id', 'utm_campaign' ),
			'form_submissions' => array( 'form_id', 'created_at' ),
			'forms'            => array( 'form_id', 'cached_form_title' ),
			'orders'           => array( 'is_included_in_analytics', 'total', 'total_refunded', 'created_at' ),
			'clicks'           => array( 'click_id', 'created_at' ),
		),
	);
}

/** Is IA installed, which version, and can its tables be read? Cached for the request. */
function hw_monitor_ia_status() {
	static $status = null;
	if ( null !== $status ) {
		return $status;
	}
	global $wpdb;
	if ( ! function_exists( 'get_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	$version = null;
	foreach ( get_plugins() as $file => $data ) {
		if ( 0 === strpos( $file, 'independent-analytics' ) ) {
			$version = $data['Version'];
			break;
		}
	}
	if ( ! $version ) {
		$status = array( 'installed' => false );
		return $status;
	}

	$prefix = $wpdb->prefix . 'independent_analytics_';
	$rows   = $wpdb->get_results(
		$wpdb->prepare(
			'SELECT TABLE_NAME AS t, COLUMN_NAME AS c FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE %s',
			$wpdb->esc_like( $prefix ) . '%'
		),
		ARRAY_A
	);
	$have = array();
	foreach ( (array) $rows as $r ) {
		$have[ substr( $r['t'], strlen( $prefix ) ) ][ $r['c'] ] = true;
	}
	$spec    = hw_monitor_ia_columns();
	$missing = array();
	foreach ( $spec['core'] as $table => $cols ) {
		foreach ( $cols as $col ) {
			if ( empty( $have[ $table ][ $col ] ) ) {
				$missing[] = $table . '.' . $col;
			}
		}
	}
	$sections = array();
	foreach ( $spec['optional'] as $table => $cols ) {
		$ok = true;
		foreach ( $cols as $col ) {
			$ok = $ok && ! empty( $have[ $table ][ $col ] );
		}
		$sections[ $table ] = $ok;
	}

	$status = array(
		'installed'  => true,
		'version'    => $version,
		'db_version' => (string) get_option( 'iawp_db_version' ),
		'supported'  => empty( $missing ),
		'missing'    => $missing,
		'campaigns'  => $sections['campaigns'] && $sections['utm_sources'] && $sections['utm_mediums'] && $sections['utm_campaigns'],
		'forms'      => $sections['form_submissions'] && $sections['forms'],
		'orders'     => $sections['orders'],
		'clicks'     => $sections['clicks'],
	);
	return $status;
}

/** "Y-m-d" local day → UTC "Y-m-d H:i:s" at its midnight. */
function hw_monitor_utc_midnight( $day, $tz ) {
	$d = new DateTimeImmutable( $day . ' 00:00:00', $tz );
	return $d->setTimezone( new DateTimeZone( 'UTC' ) )->format( 'Y-m-d H:i:s' );
}

/** UTC hour "Y-m-d H" → local day "Y-m-d". */
function hw_monitor_local_day( $utc_hour, $tz ) {
	$d = new DateTimeImmutable( $utc_hour . ':00:00', new DateTimeZone( 'UTC' ) );
	return $d->setTimezone( $tz )->format( 'Y-m-d' );
}

/**
 * Daily totals for local days $from..$to (at most 31), plus conversions, and top pages,
 * referrers, channels and campaigns when $tops.
 */
function hw_monitor_ia_traffic( $from, $to, $tops ) {
	global $wpdb;
	$ia = hw_monitor_ia_status();
	if ( empty( $ia['installed'] ) ) {
		return array( 'available' => false, 'reason' => 'Independent Analytics is not installed' );
	}
	if ( empty( $ia['supported'] ) ) {
		return array( 'available' => false, 'reason' => 'Unsupported Independent Analytics version', 'missing' => $ia['missing'] );
	}
	$valid = '/^\d{4}-\d{2}-\d{2}$/';
	if ( ! preg_match( $valid, $from ) || ! preg_match( $valid, $to ) || $to < $from ) {
		return array( 'available' => false, 'reason' => 'from and to must be dates (YYYY-MM-DD), from ≤ to' );
	}
	$tz = wp_timezone();
	try {
		$start = new DateTimeImmutable( $from, $tz );
		$end   = new DateTimeImmutable( $to, $tz );
	} catch ( Exception $e ) {
		return array( 'available' => false, 'reason' => 'Invalid date' );
	}
	if ( $start->diff( $end )->days > 30 ) {
		return array( 'available' => false, 'reason' => 'At most 31 days per request' );
	}

	$p        = $wpdb->prefix . 'independent_analytics_';
	$range_lo = hw_monitor_utc_midnight( $from, $tz );
	$range_hi = hw_monitor_utc_midnight( $end->modify( '+1 day' )->format( 'Y-m-d' ), $tz );

	// One small indexed range query per day: sessions, distinct visitors, page views.
	$days = array();
	for ( $d = $start; $d <= $end; $d = $d->modify( '+1 day' ) ) {
		$day  = $d->format( 'Y-m-d' );
		$lo   = hw_monitor_utc_midnight( $day, $tz );
		$hi   = hw_monitor_utc_midnight( $d->modify( '+1 day' )->format( 'Y-m-d' ), $tz );
		$sess = $wpdb->get_row( $wpdb->prepare( "SELECT COUNT(*) AS sessions, COUNT(DISTINCT visitor_id) AS visitors FROM `{$p}sessions` WHERE created_at >= %s AND created_at < %s", $lo, $hi ), ARRAY_A );
		$view = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM `{$p}views` WHERE viewed_at >= %s AND viewed_at < %s", $lo, $hi ) );
		$days[] = array(
			'day'      => $day,
			'visitors' => (int) $sess['visitors'],
			'sessions' => (int) $sess['sessions'],
			'views'    => $view,
		);
	}

	// Conversions, counted per UTC hour in SQL and placed on local days here.
	$by_hour = function ( $sql ) use ( $wpdb ) {
		return (array) $wpdb->get_results( $sql, ARRAY_A );
	};
	$forms = array();
	if ( $ia['forms'] ) {
		foreach ( $by_hour( $wpdb->prepare( "SELECT COALESCE(f.cached_form_title, CONCAT('Form ', fs.form_id)) AS form, DATE_FORMAT(fs.created_at, '%%Y-%%m-%%d %%H') AS h, COUNT(*) AS n FROM `{$p}form_submissions` fs LEFT JOIN `{$p}forms` f ON f.form_id = fs.form_id WHERE fs.created_at >= %s AND fs.created_at < %s GROUP BY form, h", $range_lo, $range_hi ) ) as $r ) {
			$k = hw_monitor_local_day( $r['h'], $tz ) . "\0" . $r['form'];
			$forms[ $k ] = ( isset( $forms[ $k ] ) ? $forms[ $k ] : 0 ) + (int) $r['n'];
		}
	}
	$orders = array();
	if ( $ia['orders'] ) {
		foreach ( $by_hour( $wpdb->prepare( "SELECT DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H') AS h, COUNT(*) AS n, COALESCE(SUM(total), 0) AS total, COALESCE(SUM(total_refunded), 0) AS refunded FROM `{$p}orders` WHERE is_included_in_analytics = 1 AND created_at >= %s AND created_at < %s GROUP BY h", $range_lo, $range_hi ) ) as $r ) {
			$k = hw_monitor_local_day( $r['h'], $tz );
			if ( ! isset( $orders[ $k ] ) ) {
				$orders[ $k ] = array( 'day' => $k, 'orders' => 0, 'revenue_cents' => 0, 'refunded_cents' => 0 );
			}
			$orders[ $k ]['orders']         += (int) $r['n'];
			$orders[ $k ]['revenue_cents']  += (int) $r['total'];
			$orders[ $k ]['refunded_cents'] += (int) $r['refunded'];
		}
	}
	$clicks = array();
	if ( $ia['clicks'] ) {
		foreach ( $by_hour( $wpdb->prepare( "SELECT DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H') AS h, COUNT(*) AS n FROM `{$p}clicks` WHERE created_at >= %s AND created_at < %s GROUP BY h", $range_lo, $range_hi ) ) as $r ) {
			$k = hw_monitor_local_day( $r['h'], $tz );
			$clicks[ $k ] = ( isset( $clicks[ $k ] ) ? $clicks[ $k ] : 0 ) + (int) $r['n'];
		}
	}

	$out = array(
		'available' => true,
		'timezone'  => wp_timezone_string(),
		'from'      => $from,
		'to'        => $to,
		'first_day' => null,
		'days'      => $days,
		'forms'     => array(),
		'orders'    => array_values( $orders ),
		'clicks'    => array(),
	);
	foreach ( $forms as $k => $n ) {
		list( $day, $form ) = explode( "\0", $k, 2 );
		$out['forms'][]     = array( 'day' => $day, 'form' => $form, 'submissions' => $n );
	}
	foreach ( $clicks as $day => $n ) {
		$out['clicks'][] = array( 'day' => $day, 'clicks' => $n );
	}
	$first = $wpdb->get_var( "SELECT MIN(created_at) FROM `{$p}sessions`" );
	if ( $first ) {
		$out['first_day'] = ( new DateTimeImmutable( $first, new DateTimeZone( 'UTC' ) ) )->setTimezone( $tz )->format( 'Y-m-d' );
	}

	if ( $tops ) {
		$totals        = $wpdb->get_row( $wpdb->prepare( "SELECT COUNT(*) AS sessions, COUNT(DISTINCT visitor_id) AS visitors FROM `{$p}sessions` WHERE created_at >= %s AND created_at < %s", $range_lo, $range_hi ), ARRAY_A );
		$out['totals'] = array(
			'visitors' => (int) $totals['visitors'],
			'sessions' => (int) $totals['sessions'],
			'views'    => array_sum( wp_list_pluck( $days, 'views' ) ),
		);
		$out['pages']    = array_map(
			function ( $r ) {
				return array( 'title' => (string) $r['title'], 'url' => (string) $r['url'], 'views' => (int) $r['views'] );
			},
			(array) $wpdb->get_results( $wpdb->prepare( "SELECT r.cached_title AS title, r.cached_url AS url, COUNT(*) AS views FROM `{$p}views` v JOIN `{$p}resources` r ON r.id = v.resource_id WHERE v.viewed_at >= %s AND v.viewed_at < %s GROUP BY v.resource_id, r.cached_title, r.cached_url ORDER BY views DESC LIMIT 25", $range_lo, $range_hi ), ARRAY_A )
		);
		$out['channels'] = array_map(
			function ( $r ) {
				return array( 'channel' => (string) $r['channel'], 'sessions' => (int) $r['sessions'] );
			},
			(array) $wpdb->get_results( $wpdb->prepare( "SELECT COALESCE(t.referrer_type, 'Direct') AS channel, COUNT(*) AS sessions FROM `{$p}sessions` s LEFT JOIN `{$p}referrers` r ON r.id = s.referrer_id LEFT JOIN `{$p}referrer_types` t ON t.id = r.referrer_type_id WHERE s.created_at >= %s AND s.created_at < %s GROUP BY channel ORDER BY sessions DESC", $range_lo, $range_hi ), ARRAY_A )
		);
		$out['referrers'] = array_map(
			function ( $r ) {
				return array( 'domain' => (string) $r['domain'], 'channel' => (string) $r['channel'], 'sessions' => (int) $r['sessions'] );
			},
			(array) $wpdb->get_results( $wpdb->prepare( "SELECT r.domain AS domain, COALESCE(t.referrer_type, '') AS channel, COUNT(*) AS sessions FROM `{$p}sessions` s JOIN `{$p}referrers` r ON r.id = s.referrer_id LEFT JOIN `{$p}referrer_types` t ON t.id = r.referrer_type_id WHERE s.created_at >= %s AND s.created_at < %s AND r.domain <> '' GROUP BY r.domain, channel ORDER BY sessions DESC LIMIT 15", $range_lo, $range_hi ), ARRAY_A )
		);
		$out['campaigns'] = array();
		if ( $ia['campaigns'] ) {
			$out['campaigns'] = array_map(
				function ( $r ) {
					return array( 'source' => (string) $r['source'], 'medium' => (string) $r['medium'], 'campaign' => (string) $r['campaign'], 'sessions' => (int) $r['sessions'] );
				},
				(array) $wpdb->get_results( $wpdb->prepare( "SELECT COALESCE(us.utm_source, '') AS source, COALESCE(um.utm_medium, '') AS medium, COALESCE(uc.utm_campaign, '') AS campaign, COUNT(*) AS sessions FROM `{$p}sessions` s JOIN `{$p}campaigns` c ON c.campaign_id = s.campaign_id LEFT JOIN `{$p}utm_sources` us ON us.id = c.utm_source_id LEFT JOIN `{$p}utm_mediums` um ON um.id = c.utm_medium_id LEFT JOIN `{$p}utm_campaigns` uc ON uc.id = c.utm_campaign_id WHERE s.created_at >= %s AND s.created_at < %s GROUP BY source, medium, campaign ORDER BY sessions DESC LIMIT 15", $range_lo, $range_hi ), ARRAY_A )
			);
		}
	}
	return $out;
}
