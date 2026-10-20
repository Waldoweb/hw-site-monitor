<?php
/**
 * Plugin Name:       HW Site Monitor
 * Plugin URI:        https://github.com/Waldoweb/hw-site-monitor
 * Description:       Read-only report for the Hostetler Web dashboard: WordPress, PHP, plugin and theme versions and pending updates. Answers only requests signed by the dashboard, and reading the report changes nothing on the site.
 * Version:           1.0.0
 * Author:            Hostetler Web
 * Author URI:        https://hostetlerweb.com
 * Update URI:        https://github.com/Waldoweb/hw-site-monitor
 * License:           GPL-2.0-or-later
 * Requires PHP:      7.4
 * Requires at least: 5.6
 * Text Domain:       hw-site-monitor
 */

defined( 'ABSPATH' ) || exit;

define( 'HW_MONITOR_VERSION', '1.0.0' );

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

	$message = implode( "\n", array( 'hw-monitor-v1', 'GET', hw_monitor_site_host(), $request->get_route(), (string) $ts ) );

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

/** Everything here is read from WordPress; nothing is changed. */
function hw_monitor_report() {
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
			'ia'        => hw_monitor_ia_discovery(),
			'checked'   => array(
				'plugins' => $plugin_updates && isset( $plugin_updates->last_checked ) ? (int) $plugin_updates->last_checked : null,
				'themes'  => $theme_updates && isset( $theme_updates->last_checked ) ? (int) $theme_updates->last_checked : null,
				'core'    => $core_updates && isset( $core_updates->last_checked ) ? (int) $core_updates->last_checked : null,
			),
		)
	);
	$response->header( 'Cache-Control', 'no-store, private' );
	return $response;
}

/**
 * Independent Analytics has no API, so traffic will come from its database tables.
 * Version 1.0 only reports which IA tables exist and their columns, so the dashboard can be
 * built against the real structure. Daily visitor totals and conversions come in 1.1.
 */
function hw_monitor_ia_discovery() {
	global $wpdb;
	if ( ! function_exists( 'is_plugin_active' ) ) {
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
		return array( 'installed' => false );
	}
	$like   = $wpdb->esc_like( $wpdb->prefix . 'independent_analytics' ) . '%';
	$tables = $wpdb->get_col( $wpdb->prepare( 'SHOW TABLES LIKE %s', $like ) );
	$schema = array();
	foreach ( array_slice( (array) $tables, 0, 20 ) as $table ) {
		$columns = $wpdb->get_col( 'SHOW COLUMNS FROM `' . esc_sql( $table ) . '`' );
		$schema[ substr( $table, strlen( $wpdb->prefix ) ) ] = $columns;
	}
	return array(
		'installed' => true,
		'version'   => $version,
		'tables'    => $schema,
	);
}
