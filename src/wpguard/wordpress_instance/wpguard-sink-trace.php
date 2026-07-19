<?php
/**
 * WPGuard: Dynamic sink tracer.
 *
 * A must-use plugin that records — for each HTTP request — every time
 * attacker-reachable data hits a dangerous WordPress-level sink, together with
 * the PHP call stack that led there. It is the runtime "data-flow" oracle:
 * a generalization of the MySQL general_log (which only sees SQL) to SQL +
 * option writes + user/role creation + meta writes + outbound HTTP (SSRF) +
 * mail, each annotated with the backtrace so you can see the whole path from
 * entry point to sink.
 *
 * DISABLED BY DEFAULT — zero overhead unless the flag file exists. The
 * wpguard_sink_trace MCP tool creates/removes the flag and reads/clears the log.
 *
 *   Flag file : /var/log/wpguard/sink-trace.on
 *   Log file  : /var/log/wpguard/sink-trace.jsonl   (one JSON object per line)
 *
 * NOT for production. Intended only for the WPGuard security sandbox.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPGUARD_SINK_DIR', '/var/log/wpguard' );
define( 'WPGUARD_SINK_FLAG', WPGUARD_SINK_DIR . '/sink-trace.on' );
define( 'WPGUARD_SINK_LOG', WPGUARD_SINK_DIR . '/sink-trace.jsonl' );

// Fast path: if tracing is off, do nothing at all.
if ( ! @file_exists( WPGUARD_SINK_FLAG ) ) {
	return;
}

// Skip WP-Cron requests by default: publishing a post (and many other actions)
// spawns wp-cron.php in the background, whose action-scheduler / ping / transient
// churn would otherwise flood the log and drown out the PoC request. Delete the
// flag file's sibling `.cron` marker to include cron. Correlate real requests via
// the per-record `reqid` regardless.
if ( ( defined( 'DOING_CRON' ) && DOING_CRON )
	|| ( isset( $_SERVER['REQUEST_URI'] ) && false !== strpos( $_SERVER['REQUEST_URI'], 'wp-cron.php' ) ) ) {
	if ( ! @file_exists( WPGUARD_SINK_FLAG . '.cron' ) ) {
		return;
	}
}

/**
 * A short, stable id for the current request so multiple sink hits from one
 * PoC request can be correlated/filtered together.
 */
function wpguard_sink_reqid() {
	static $id = null;
	if ( null === $id ) {
		$seed = ( $_SERVER['REQUEST_TIME_FLOAT'] ?? microtime( true ) ) . '|'
			. ( $_SERVER['REMOTE_PORT'] ?? '' ) . '|'
			. ( $_SERVER['REQUEST_URI'] ?? 'cli' );
		$id   = substr( md5( $seed ), 0, 10 );
	}
	return $id;
}

/**
 * Build a compact backtrace: the plugin/theme/core frames that led to the sink,
 * as "file:line function()" strings. WP-core internal frames are kept but the
 * tracer's own frames are dropped. This is the "walk the whole process" view.
 */
function wpguard_sink_backtrace() {
	$frames = debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS );
	$out    = array();
	foreach ( $frames as $f ) {
		$file = $f['file'] ?? '';
		// Skip the tracer's own frames.
		if ( $file && false !== strpos( $file, 'wpguard-sink-trace.php' ) ) {
			continue;
		}
		$fn = ( isset( $f['class'] ) ? $f['class'] . $f['type'] : '' ) . ( $f['function'] ?? '' );
		// Make paths relative to wp-content for readability.
		$rel = $file;
		if ( $file && false !== ( $p = strpos( $file, '/wp-content/' ) ) ) {
			$rel = substr( $file, $p + 1 );
		} elseif ( $file && false !== ( $p = strpos( $file, '/wp-includes/' ) ) ) {
			$rel = substr( $file, $p + 1 );
		} elseif ( $file && false !== ( $p = strpos( $file, '/wp-admin/' ) ) ) {
			$rel = substr( $file, $p + 1 );
		}
		$out[] = $rel . ( isset( $f['line'] ) ? ':' . $f['line'] : '' ) . ' ' . $fn . '()';
		if ( count( $out ) >= 25 ) {
			break;
		}
	}
	return $out;
}

/**
 * Truncate a value for logging (avoid dumping megabytes / binary).
 */
function wpguard_sink_trunc( $val, $len = 400 ) {
	if ( is_array( $val ) || is_object( $val ) ) {
		$val = wp_json_encode( $val );
	}
	$val = (string) $val;
	if ( strlen( $val ) > $len ) {
		$val = substr( $val, 0, $len ) . '…[' . strlen( $val ) . ' bytes]';
	}
	return $val;
}

/**
 * Append one sink record as a JSON line.
 *
 * @param string $type    Sink category (sql, option, user, meta, http, mail).
 * @param string $sink    Specific sink (e.g. wpdb::query, update_option).
 * @param array  $detail  Sink-specific fields (already truncated).
 */
function wpguard_sink_record( $type, $sink, array $detail ) {
	static $current_user_cache = null;
	if ( null === $current_user_cache && function_exists( 'wp_get_current_user' ) ) {
		$u                  = wp_get_current_user();
		$current_user_cache = ( $u && $u->ID ) ? ( $u->ID . ':' . $u->user_login ) : '0:unauth';
	}

	$rec = array(
		'reqid'     => wpguard_sink_reqid(),
		'ts'        => gmdate( 'H:i:s' ),
		'type'      => $type,
		'sink'      => $sink,
		'detail'    => $detail,
		'method'    => $_SERVER['REQUEST_METHOD'] ?? 'CLI',
		'uri'       => wpguard_sink_trunc( $_SERVER['REQUEST_URI'] ?? '', 200 ),
		'action'    => wpguard_sink_trunc( $_REQUEST['action'] ?? '', 80 ),
		'user'      => $current_user_cache ?? '0:unauth',
		'backtrace' => wpguard_sink_backtrace(),
	);

	$line = wp_json_encode( $rec );
	if ( false === $line ) {
		$line = wp_json_encode( array( 'reqid' => $rec['reqid'], 'type' => $type, 'sink' => $sink, 'error' => 'json_encode_failed' ) );
	}
	// LOCK_EX so concurrent requests don't interleave partial lines.
	@file_put_contents( WPGUARD_SINK_LOG, $line . "\n", FILE_APPEND | LOCK_EX );
}

// ============================================================================
// SQL — the query filter fires for EVERY $wpdb query (read and write).
// This is the biggest signal: the exact SQL emitted + the call path to it.
// ============================================================================
add_filter(
	'query',
	function ( $query ) {
		// Skip the tracer's own noise and trivial autoload/option bootstrap reads
		// to keep the log focused; keep everything else including SELECTs so
		// second-order and read-side injections are visible.
		wpguard_sink_record( 'sql', 'wpdb::query', array( 'sql' => wpguard_sink_trunc( $query, 1000 ) ) );
		return $query;
	},
	0
);

// ============================================================================
// OPTIONS — settings writes (arbitrary options update is high value).
// ============================================================================
foreach ( array( 'added_option', 'updated_option', 'deleted_option' ) as $opt_hook ) {
	add_action(
		$opt_hook,
		function ( $option, $a = null, $b = null ) use ( $opt_hook ) {
			// updated_option passes (option, old, new); added_option (option, value); deleted_option (option).
			$value = ( 'updated_option' === $opt_hook ) ? $b : $a;
			wpguard_sink_record(
				'option',
				$opt_hook,
				array( 'option' => wpguard_sink_trunc( $option, 120 ), 'value' => wpguard_sink_trunc( $value ) )
			);
		},
		10,
		3
	);
}

// ============================================================================
// USERS / ROLES — account creation and role changes (privilege escalation).
// ============================================================================
add_action(
	'user_register',
	function ( $user_id ) {
		$u = get_userdata( $user_id );
		wpguard_sink_record(
			'user',
			'user_register',
			array(
				'user_id' => (int) $user_id,
				'login'   => $u ? wpguard_sink_trunc( $u->user_login, 80 ) : '',
				'roles'   => $u ? implode( ',', (array) $u->roles ) : '',
			)
		);
	},
	10,
	1
);
add_action(
	'set_user_role',
	function ( $user_id, $role, $old_roles ) {
		wpguard_sink_record(
			'user',
			'set_user_role',
			array(
				'user_id'   => (int) $user_id,
				'new_role'  => wpguard_sink_trunc( $role, 80 ),
				'old_roles' => wpguard_sink_trunc( $old_roles ),
			)
		);
	},
	10,
	3
);
add_action(
	'add_user_role',
	function ( $user_id, $role ) {
		wpguard_sink_record( 'user', 'add_user_role', array( 'user_id' => (int) $user_id, 'role' => wpguard_sink_trunc( $role, 80 ) ) );
	},
	10,
	2
);

// ============================================================================
// META — post/user/term meta writes (capability-relevant meta, e.g. wp_capabilities).
// ============================================================================
foreach ( array( 'user', 'post', 'term' ) as $meta_type ) {
	foreach ( array( 'added', 'updated' ) as $meta_op ) {
		add_action(
			"{$meta_op}_{$meta_type}_meta",
			function ( $mid, $object_id, $meta_key, $meta_value = null ) use ( $meta_type, $meta_op ) {
				// Only log security-relevant meta keys to keep noise down, plus any
				// key an attacker could influence (skip pure-core transient/edit-lock churn).
				$key = (string) $meta_key;
				$noisy = array( '_edit_lock', '_edit_last', '_wp_page_template', 'session_tokens', '_wp_old_slug' );
				if ( in_array( $key, $noisy, true ) ) {
					return;
				}
				wpguard_sink_record(
					'meta',
					"{$meta_op}_{$meta_type}_meta",
					array(
						'object_id' => (int) $object_id,
						'meta_key'  => wpguard_sink_trunc( $meta_key, 120 ),
						'value'     => wpguard_sink_trunc( $meta_value ),
					)
				);
			},
			10,
			4
		);
	}
}

// ============================================================================
// HTTP EGRESS — every wp_remote_* call (SSRF / webhook exfil).
// ============================================================================
add_action(
	'http_api_debug',
	function ( $response, $context, $class, $args, $url ) {
		wpguard_sink_record(
			'http',
			'wp_remote',
			array(
				'url'    => wpguard_sink_trunc( $url, 300 ),
				'method' => wpguard_sink_trunc( $args['method'] ?? 'GET', 10 ),
			)
		);
	},
	10,
	5
);

// ============================================================================
// MAIL — outbound mail (spam abuse, OTP-to-attacker, injection).
// ============================================================================
add_filter(
	'wp_mail',
	function ( $atts ) {
		wpguard_sink_record(
			'mail',
			'wp_mail',
			array(
				'to'      => wpguard_sink_trunc( $atts['to'] ?? '', 200 ),
				'subject' => wpguard_sink_trunc( $atts['subject'] ?? '', 200 ),
			)
		);
		return $atts;
	},
	0
);
