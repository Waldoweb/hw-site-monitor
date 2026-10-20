<?php
/**
 * The dashboard's public signing keys (Ed25519, base64). Public keys are safe to publish;
 * the matching private key lives only in the dashboard's Convex environment.
 * Written by the dashboard repo's scripts/connector-keys.mjs. During a key change, list both the new and the old key.
 */

defined( 'ABSPATH' ) || exit;

const HW_MONITOR_PUBLIC_KEYS = array(
	'DHa3FZupR6mpY8ExjqtcU6RlYUaIXJTQx40YBKZxJxM=', // 2026-10-20
);
