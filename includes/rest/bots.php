<?php
namespace GemSecurity\Rest;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Bot blocking statistics controller.
 */
class Bots {

	/**
	 * GET /bots/stats
	 *
	 * Returns per-day counts and top triggered patterns for the last 7 days.
	 */
	public static function stats() {
		global $wpdb;
		$table    = $wpdb->prefix . 'gemsecurity_logs';
		$since_7d = gmdate( 'Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS );

		// Total counts.
		$total_7d  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'waf_bad_bot' AND created_at >= %s", $since_7d ) );
		$since_24h = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
		$total_24h = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_type = 'waf_bad_bot' AND created_at >= %s", $since_24h ) );

		// Per-day sparkline.
		$per_day = [];
		for ( $i = 6; $i >= 0; $i-- ) {
			$day      = gmdate( 'Y-m-d', time() - $i * DAY_IN_SECONDS );
			$per_day[] = [
				'date'  => $day,
				'count' => (int) $wpdb->get_var( $wpdb->prepare(
					"SELECT COUNT(*) FROM {$table} WHERE event_type = 'waf_bad_bot' AND created_at BETWEEN %s AND %s",
					$day . ' 00:00:00',
					$day . ' 23:59:59'
				) ),
			];
		}

		// Top matched patterns — parse context JSON in PHP.
		$rows = $wpdb->get_col( $wpdb->prepare(
			"SELECT context FROM {$table} WHERE event_type = 'waf_bad_bot' AND context IS NOT NULL AND created_at >= %s LIMIT 2000",
			$since_7d
		) );

		$pattern_counts = [];
		$ua_counts      = [];
		foreach ( $rows as $raw ) {
			$ctx = json_decode( $raw, true );
			if ( ! is_array( $ctx ) ) {
				continue;
			}
			if ( ! empty( $ctx['matched'] ) ) {
				$key = (string) $ctx['matched'];
				$pattern_counts[ $key ] = ( $pattern_counts[ $key ] ?? 0 ) + 1;
			}
			if ( ! empty( $ctx['ua'] ) ) {
				$ua = (string) $ctx['ua'];
				$ua_counts[ $ua ] = ( $ua_counts[ $ua ] ?? 0 ) + 1;
			}
		}

		arsort( $pattern_counts );
		arsort( $ua_counts );

		$top_patterns = [];
		foreach ( array_slice( $pattern_counts, 0, 10, true ) as $pattern => $count ) {
			$top_patterns[] = [ 'pattern' => $pattern, 'count' => $count ];
		}

		$top_uas = [];
		foreach ( array_slice( $ua_counts, 0, 10, true ) as $ua => $count ) {
			$top_uas[] = [ 'ua' => $ua, 'count' => $count ];
		}

		return rest_ensure_response( [
			'success'      => true,
			'total_7d'     => $total_7d,
			'total_24h'    => $total_24h,
			'per_day'      => $per_day,
			'top_patterns' => $top_patterns,
			'top_uas'      => $top_uas,
		] );
	}
}
