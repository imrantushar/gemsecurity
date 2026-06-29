<?php
namespace GemBackup\Helpers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Health monitor: alerts if no successful backup has occurred within N days.
 */
class Health_Monitor {

	public static function init() {
		add_action( 'gembackup_health_tick', [ __CLASS__, 'check' ] );
	}

	public static function summary() {
		global $wpdb;
		$last = $wpdb->get_var( "SELECT completed_at FROM {$wpdb->gembackup_backups} WHERE status='completed' ORDER BY completed_at DESC LIMIT 1" );
		$alert_days = (int) ( get_option( GEMBACKUP_SETTINGS_NAME )['health_alert_days'] ?? 7 );
		$disk = @disk_free_space( GEMBACKUP_BACKUP_DIR_PATH );

		$days_since = $last ? (int) floor( ( time() - strtotime( $last ) ) / DAY_IN_SECONDS ) : null;

		return [
			'last_successful_backup' => $last,
			'days_since'             => $days_since,
			'alert_threshold_days'   => $alert_days,
			'status'                 => self::derive_status( $days_since, $alert_days ),
			'disk_free'              => $disk,
		];
	}

	private static function derive_status( $days_since, $threshold ) {
		if ( $days_since === null ) return 'unknown';
		if ( $days_since >= $threshold ) return 'unhealthy';
		if ( $days_since >= ceil( $threshold / 2 ) ) return 'warning';
		return 'healthy';
	}

	public static function check() {
		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		$summary  = self::summary();
		if ( $summary['status'] === 'unhealthy' && ! empty( $settings['notify_email'] ) ) {
			$subject = sprintf( '[%s] GemBackup health alert', wp_parse_url( home_url(), PHP_URL_HOST ) );
			$body = sprintf(
				"No successful backup in %d days (threshold: %d).\nLast: %s\nCheck the GemBackup dashboard for details.",
				$summary['days_since'] ?? -1,
				$summary['alert_threshold_days'],
				$summary['last_successful_backup'] ?: 'never'
			);
			wp_mail( $settings['notify_email'], $subject, $body );
		}

		// Prune old logs.
		global $wpdb;
		$days = max( 1, (int) ( $settings['logs_retention_days'] ?? 30 ) );
		$wpdb->query( $wpdb->prepare(
			"DELETE FROM {$wpdb->gembackup_logs} WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
			$days
		) );
	}
}
