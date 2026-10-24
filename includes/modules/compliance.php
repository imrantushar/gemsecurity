<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Compliance layer over the activity log:
 *  - Tamper-evident hash chain (each row's hash chains from the previous one,
 *    so any edit or out-of-band deletion is detectable).
 *  - SIEM / syslog forwarding of security events.
 *  - Framework-tagged summary reports.
 */
class Compliance {

	const CHAIN_OPTION = 'gemsecurity_log_chain';

	public static function init() {
		$self = new self();
		if ( Helper::get_setting( 'log_hash_chain_enabled', false ) ) {
			add_action( 'gemsecurity/event_logged', [ $self, 'chain' ], 10, 5 );
		}
		if ( Helper::get_setting( 'siem_enabled', false ) ) {
			add_action( 'gemsecurity/event_logged', [ $self, 'forward' ], 20, 5 );
		}
	}

	private static function severity_rank( $sev ) {
		$map = [ 'info' => 0, 'notice' => 1, 'warning' => 2, 'critical' => 3 ];
		return isset( $map[ $sev ] ) ? $map[ $sev ] : 0;
	}

	private static function payload( $id, $event_type, $severity, $message ) {
		return $id . '|' . $event_type . '|' . $severity . '|' . $message;
	}

	/* ---------------- Hash chain ---------------- */

	/**
	 * @param string   $event_type
	 * @param string   $message
	 * @param string   $severity
	 * @param array    $args
	 * @param int|false $row_id
	 */
	public function chain( $event_type, $message, $severity, $args, $row_id ) {
		if ( ! $row_id ) {
			return;
		}
		global $wpdb;
		$table = $wpdb->prefix . 'gemsecurity_logs';
		$chain = get_option( self::CHAIN_OPTION, [ 'last' => '', 'count' => 0 ] );
		$prev  = ! empty( $chain['last'] ) ? $chain['last'] : 'genesis';
		$hash  = hash_hmac( 'sha256', $prev . '|' . self::payload( $row_id, $event_type, $severity, $message ), wp_salt( 'auth' ) );

		$wpdb->update( $table, [ 'hash' => $hash ], [ 'id' => $row_id ], [ '%s' ], [ '%d' ] ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		update_option( self::CHAIN_OPTION, [ 'last' => $hash, 'count' => (int) $chain['count'] + 1 ], false );
	}

	/**
	 * Verify the hash chain over the retained rows.
	 *
	 * @return array{ok:bool,checked:int,tampered_at:?int}
	 */
	public static function verify() {
		global $wpdb;
		$table = $wpdb->prefix . 'gemsecurity_logs';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows  = $wpdb->get_results( "SELECT id, event_type, severity, message, hash FROM {$table} WHERE hash IS NOT NULL ORDER BY id ASC", ARRAY_A );

		$prev    = null;
		$checked = 0;
		foreach ( (array) $rows as $r ) {
			if ( null === $prev ) {
				$prev = $r['hash']; // anchor (earliest retained row).
				continue;
			}
			$expected = hash_hmac( 'sha256', $prev . '|' . self::payload( $r['id'], $r['event_type'], $r['severity'], $r['message'] ), wp_salt( 'auth' ) );
			$checked++;
			if ( ! hash_equals( $expected, (string) $r['hash'] ) ) {
				return [ 'ok' => false, 'checked' => $checked, 'tampered_at' => (int) $r['id'] ];
			}
			$prev = $r['hash'];
		}
		return [ 'ok' => true, 'checked' => $checked, 'tampered_at' => null ];
	}

	/* ---------------- SIEM / syslog ---------------- */

	public function forward( $event_type, $message, $severity, $args, $row_id ) {
		if ( self::severity_rank( $severity ) < self::severity_rank( Helper::get_setting( 'siem_min_severity', 'warning' ) ) ) {
			return;
		}
		$entry = [
			'ts'       => gmdate( 'c' ),
			'event'    => $event_type,
			'severity' => $severity,
			'message'  => $message,
			'ip'       => isset( $args['ip_address'] ) ? $args['ip_address'] : '',
			'user_id'  => isset( $args['user_id'] ) ? $args['user_id'] : 0,
			'site'     => home_url(),
		];

		$endpoint = trim( (string) Helper::get_setting( 'siem_endpoint', '' ) );
		if ( '' !== $endpoint ) {
			wp_remote_post( $endpoint, [
				'timeout'  => 2,
				'blocking' => false,
				'headers'  => [ 'Content-Type' => 'application/json' ],
				'body'     => wp_json_encode( $entry ),
			] );
		}

		if ( Helper::get_setting( 'siem_syslog', false ) && function_exists( 'syslog' ) ) {
			$levels = [ 'info' => LOG_INFO, 'notice' => LOG_NOTICE, 'warning' => LOG_WARNING, 'critical' => LOG_CRIT ];
			openlog( 'gemsecurity', LOG_PID, LOG_USER );
			syslog( isset( $levels[ $severity ] ) ? $levels[ $severity ] : LOG_INFO, wp_json_encode( $entry ) );
			closelog();
		}
	}

	/* ---------------- Reports ---------------- */

	/**
	 * Summary report over the last N days.
	 *
	 * @param int    $days
	 * @param string $framework
	 * @return array
	 */
	public static function report( $days = 30, $framework = 'general' ) {
		global $wpdb;
		$table = $wpdb->prefix . 'gemsecurity_logs';
		$since = gmdate( 'Y-m-d H:i:s', time() - max( 1, (int) $days ) * DAY_IN_SECONDS );

		// Our own gemsecurity_logs table; built from $wpdb->prefix.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$by_sev = $wpdb->get_results( $wpdb->prepare( "SELECT severity, COUNT(*) c FROM {$table} WHERE created_at >= %s GROUP BY severity", $since ), ARRAY_A );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$top    = $wpdb->get_results( $wpdb->prepare( "SELECT event_type, COUNT(*) c FROM {$table} WHERE created_at >= %s GROUP BY event_type ORDER BY c DESC LIMIT 15", $since ), ARRAY_A );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$total  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE created_at >= %s", $since ) );

		return [
			'framework'   => $framework,
			'period_days' => (int) $days,
			'generated'   => gmdate( 'Y-m-d H:i:s' ),
			'site'        => home_url(),
			'total'       => $total,
			'by_severity' => $by_sev ?: [],
			'top_events'  => $top ?: [],
			'integrity'   => self::verify(),
		];
	}
}
