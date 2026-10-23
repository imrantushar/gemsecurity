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
			'blocks_7d'         => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type IN ('firewall_block','author_enumeration_blocked','waf_block','waf_bad_bot','waf_rate_limited','waf_404_flood') AND created_at >= %s", $since_7d ) ),
			'bots_blocked_24h'  => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'waf_bad_bot' AND created_at >= %s", $since_24h ) ),
			'rogue_admins_7d'   => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type IN ('rogue_admin_deleted','rogue_admin_demoted') AND created_at >= %s", $since_7d ) ),
			'critical_7d'       => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE severity = 'critical' AND created_at >= %s", $since_7d ) ),
			'banned_ips'        => \GemSecurity\Security\BanList::count_active(),
			'vulnerabilities'   => is_array( $vuln = \GemSecurity\Security\Vulnerability::get_last_result() ) ? (int) $vuln['count'] : 0,
			'hidden_admins'     => is_array( $ha = \GemSecurity\Modules\HiddenAdmin::get_last_result() ) ? count( $ha['hidden_ids'] ) : 0,
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

		$assessment = \GemSecurity\Security\SecurityScore::assess();

		return rest_ensure_response( [
			'success'        => true,
			'counts'         => $counts,
			'trend'          => $trend,
			'recent'         => $recent ? $recent : [],
			'security_score' => [ 'score' => $assessment['score'], 'grade' => $assessment['grade'] ],
			'posture'        => [
				'posture_percent' => $assessment['posture_percent'],
				'checks'          => $assessment['checks'],
				'threats'         => $assessment['threats'],
				'summary'         => $assessment['summary'],
			],
			'last_scan'      => Scanner::get_last_result(),
		] );
	}

	/**
	 * GET /score — score + full posture breakdown, nothing else.
	 *
	 * Backs the "boost your score" banner that appears on every module page:
	 * the UI filters the checks client-side by the current page's slug, so
	 * one assessment per page load is enough.
	 */
	public static function score() {
		$assessment = \GemSecurity\Security\SecurityScore::assess();
		return rest_ensure_response( [
			'success' => true,
			'score'   => $assessment['score'],
			'grade'   => $assessment['grade'],
			'posture_percent' => $assessment['posture_percent'],
			'checks'  => $assessment['checks'],
			'threats' => $assessment['threats'],
			'summary' => $assessment['summary'],
		] );
	}
}
