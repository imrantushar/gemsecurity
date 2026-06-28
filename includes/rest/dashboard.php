<?php
namespace GemSecurity\Rest;

use GemSecurity\Helper;
use GemSecurity\Modules\Scanner;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Dashboard overview controller.
 */
class Dashboard {

	/**
	 * GET /dashboard
	 */
	public static function get() {
		global $wpdb;
		$table = $wpdb->prefix . 'gemsecurity_logs';

		$since_24h = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
		$since_7d  = gmdate( 'Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS );

		$counts = [
			'logins_24h'        => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type IN ('admin_login','user_login') AND created_at >= %s", $since_24h ) ),
			'failed_logins_24h' => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'login_failed' AND created_at >= %s", $since_24h ) ),
			'lockouts_7d'       => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'login_lockout' AND created_at >= %s", $since_7d ) ),
			'blocks_7d'         => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type IN ('firewall_block','author_enumeration_blocked') AND created_at >= %s", $since_7d ) ),
			'rogue_admins_7d'   => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type IN ('rogue_admin_deleted','rogue_admin_demoted') AND created_at >= %s", $since_7d ) ),
			'critical_7d'       => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE severity = 'critical' AND created_at >= %s", $since_7d ) ),
		];

		// Activity sparkline: events per day for the last 7 days.
		$trend = [];
		for ( $i = 6; $i >= 0; $i-- ) {
			$day   = gmdate( 'Y-m-d', time() - $i * DAY_IN_SECONDS );
			$start = $day . ' 00:00:00';
			$end   = $day . ' 23:59:59';
			$trend[] = [
				'date'  => $day,
				'count' => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE created_at BETWEEN %s AND %s", $start, $end ) ),
			];
		}

		$recent = $wpdb->get_results( "SELECT id, event_type, severity, message, ip_address, user_id, created_at FROM {$table} ORDER BY id DESC LIMIT 8", ARRAY_A );

		return rest_ensure_response( [
			'success'        => true,
			'counts'         => $counts,
			'trend'          => $trend,
			'recent'         => $recent ? $recent : [],
			'security_score' => self::security_score(),
			'protections'    => self::protections_status(),
			'last_scan'      => Scanner::get_last_result(),
		] );
	}

	/**
	 * A simple weighted security score out of 100 based on which protections
	 * are enabled.
	 *
	 * @return array { score, grade }
	 */
	private static function security_score() {
		$checks = [
			'firewall_enabled'              => 15,
			'login_attempts_enabled'        => 15,
			'admin_whitelist_enabled'       => 15,
			'disable_file_editing'          => 10,
			'block_author_enumeration'      => 10,
			'disable_user_rest'             => 10,
			'hide_wp_version'               => 5,
			'xmlrpc_disabled'               => 5,
			'admin_login_alert_enabled'     => 5,
			'admin_session_timeout_enabled' => 5,
			'scanner_auto_scan'             => 5,
		];

		$score = 0;
		$total = array_sum( $checks );
		foreach ( $checks as $key => $weight ) {
			if ( Helper::get_setting( $key, false ) ) {
				$score += $weight;
			}
		}

		$percent = (int) round( ( $score / $total ) * 100 );
		$grade   = 'F';
		if ( $percent >= 90 ) {
			$grade = 'A';
		} elseif ( $percent >= 75 ) {
			$grade = 'B';
		} elseif ( $percent >= 60 ) {
			$grade = 'C';
		} elseif ( $percent >= 40 ) {
			$grade = 'D';
		}

		return [ 'score' => $percent, 'grade' => $grade ];
	}

	/**
	 * Status of individual protections for the dashboard checklist.
	 *
	 * @return array
	 */
	private static function protections_status() {
		$items = [
			'firewall_enabled'              => __( 'Firewall', 'gemsecurity' ),
			'login_attempts_enabled'        => __( 'Brute-force protection', 'gemsecurity' ),
			'admin_whitelist_enabled'       => __( 'Admin whitelist guard', 'gemsecurity' ),
			'admin_login_alert_enabled'     => __( 'Admin login alerts', 'gemsecurity' ),
			'admin_session_timeout_enabled' => __( 'Admin session timeout', 'gemsecurity' ),
			'disable_file_editing'          => __( 'File editor disabled', 'gemsecurity' ),
			'block_author_enumeration'      => __( 'Author enumeration blocked', 'gemsecurity' ),
			'disable_user_rest'             => __( 'REST user enumeration blocked', 'gemsecurity' ),
			'xmlrpc_disabled'               => __( 'XML-RPC disabled', 'gemsecurity' ),
			'hide_wp_version'               => __( 'WordPress version hidden', 'gemsecurity' ),
			'scanner_auto_scan'             => __( 'Daily malware scan', 'gemsecurity' ),
		];

		$out = [];
		foreach ( $items as $key => $label ) {
			$out[] = [
				'key'     => $key,
				'label'   => $label,
				'enabled' => (bool) Helper::get_setting( $key, false ),
			];
		}
		return $out;
	}
}
