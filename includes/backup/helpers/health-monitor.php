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
		if ( 'unhealthy' === $summary['status'] && ! empty( $settings['notify_on_failure'] ) ) {
			\GemSecurity\Mailer::send(
				\GemSecurity\Mailer::recipient(),
				'⚠️',
				__( 'No recent backup', 'gemsecurity' ),
				[
					[
						'type' => 'notice',
						'tone' => 'warning',
						'text' => __( 'This site has gone without a successful backup for longer than the configured threshold. If a scheduled backup is failing quietly, there is no restore point to fall back on.', 'gemsecurity' ),
					],
					[
						'type'    => 'table',
						'heading' => __( 'Details', 'gemsecurity' ),
						'rows'    => [
							[ __( 'Days since last success', 'gemsecurity' ), (string) ( $summary['days_since'] ?? -1 ) ],
							[ __( 'Threshold', 'gemsecurity' ), (string) $summary['alert_threshold_days'] ],
							[ __( 'Last successful backup', 'gemsecurity' ), $summary['last_successful_backup'] ?: __( 'never', 'gemsecurity' ) ],
						],
					],
					[
						'type'  => 'button',
						'url'   => admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG . '-backup' ),
						'label' => __( 'Open Backup', 'gemsecurity' ),
					],
				]
			);
		}

		// Prune old logs.
		global $wpdb;
		$days = max( 1, (int) ( $settings['backup_logs_retention_days'] ?? 30 ) );
		$wpdb->query( $wpdb->prepare(
			"DELETE FROM {$wpdb->gembackup_logs} WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
			$days
		) );
	}
}
