<?php
namespace GemBackup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Installer {

	public static function activate() {
		self::create_backup_directory();
		self::create_tables();
		self::set_default_options();
		self::schedule_heartbeat();
		flush_rewrite_rules();
	}

	public static function deactivate() {
		$schedules = [
			'gembackup_daily_event',
			'gembackup_weekly_event',
			'gembackup_monthly_event',
			'gembackup_job_tick',
			'gembackup_health_tick',
		];
		foreach ( $schedules as $hook ) {
			$timestamp = wp_next_scheduled( $hook );
			if ( $timestamp ) {
				wp_unschedule_event( $timestamp, $hook );
			}
		}
		flush_rewrite_rules();
	}

	public static function maybe_upgrade() {
		$current = get_option( 'gembackup_db_version', '0' );
		if ( version_compare( $current, GEMBACKUP_DB_VERSION, '<' ) ) {
			self::create_tables();
		}
		self::schedule_heartbeat();
	}

	private static function schedule_heartbeat() {
		if ( ! wp_next_scheduled( 'gembackup_job_tick' ) ) {
			wp_schedule_event( time() + 60, 'gembackup_minute', 'gembackup_job_tick' );
		}
		if ( ! wp_next_scheduled( 'gembackup_health_tick' ) ) {
			wp_schedule_event( time() + 300, 'hourly', 'gembackup_health_tick' );
		}
	}

	private static function create_backup_directory() {
		$dir = GEMBACKUP_BACKUP_DIR_PATH;

		if ( ! file_exists( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		$htaccess = $dir . '.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( $htaccess, "deny from all\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		$index = $dir . 'index.php';
		if ( ! file_exists( $index ) ) {
			file_put_contents( $index, "<?php // Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
	}

	private static function create_tables() {
		global $wpdb;
		$charset_collate = $wpdb->get_charset_collate();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$backups_table = $wpdb->prefix . 'gemsecurity_backups';
		dbDelta( "CREATE TABLE IF NOT EXISTS {$backups_table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			backup_name VARCHAR(255) NOT NULL,
			backup_type VARCHAR(50) NOT NULL,
			storage_driver VARCHAR(50) NOT NULL DEFAULT 'local',
			file_path TEXT DEFAULT NULL,
			remote_path TEXT DEFAULT NULL,
			file_size BIGINT(20) UNSIGNED DEFAULT 0,
			status VARCHAR(20) NOT NULL DEFAULT 'pending',
			progress TINYINT(3) UNSIGNED DEFAULT 0,
			state LONGTEXT DEFAULT NULL,
			manifest_hash VARCHAR(64) DEFAULT NULL,
			label VARCHAR(64) DEFAULT NULL,
			encrypted TINYINT(1) NOT NULL DEFAULT 0,
			schedule_id BIGINT(20) UNSIGNED DEFAULT NULL,
			origin VARCHAR(50) NOT NULL DEFAULT 'manual',
			started_at DATETIME DEFAULT NULL,
			completed_at DATETIME DEFAULT NULL,
			error_message TEXT DEFAULT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY backup_type (backup_type),
			KEY status (status),
			KEY created_at (created_at),
			KEY schedule_id (schedule_id)
		) {$charset_collate};" );

		$schedules_table = $wpdb->prefix . 'gemsecurity_backup_schedules';
		dbDelta( "CREATE TABLE IF NOT EXISTS {$schedules_table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			schedule_name VARCHAR(255) NOT NULL,
			backup_type VARCHAR(50) NOT NULL,
			storage_drivers TEXT NOT NULL,
			frequency VARCHAR(50) NOT NULL DEFAULT 'daily',
			run_time VARCHAR(10) NOT NULL DEFAULT '02:00',
			next_run DATETIME DEFAULT NULL,
			last_run DATETIME DEFAULT NULL,
			retention TINYINT UNSIGNED DEFAULT 10,
			label VARCHAR(64) DEFAULT NULL,
			encrypted TINYINT(1) NOT NULL DEFAULT 0,
			incremental TINYINT(1) NOT NULL DEFAULT 0,
			status VARCHAR(20) NOT NULL DEFAULT 'active',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY frequency (frequency),
			KEY status (status),
			KEY next_run (next_run)
		) {$charset_collate};" );

		$logs_table = $wpdb->prefix . 'gemsecurity_backup_logs';
		dbDelta( "CREATE TABLE IF NOT EXISTS {$logs_table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			backup_id BIGINT(20) UNSIGNED DEFAULT NULL,
			level VARCHAR(20) NOT NULL DEFAULT 'info',
			message TEXT NOT NULL,
			context LONGTEXT DEFAULT NULL,
			user_id BIGINT(20) UNSIGNED DEFAULT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY backup_id (backup_id),
			KEY level (level),
			KEY created_at (created_at)
		) {$charset_collate};" );

		$jobs_table = $wpdb->prefix . 'gemsecurity_backup_jobs';
		dbDelta( "CREATE TABLE IF NOT EXISTS {$jobs_table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			job_type VARCHAR(50) NOT NULL,
			backup_id BIGINT(20) UNSIGNED DEFAULT NULL,
			payload LONGTEXT DEFAULT NULL,
			state LONGTEXT DEFAULT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'queued',
			attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
			locked_until DATETIME DEFAULT NULL,
			run_after DATETIME DEFAULT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT NULL,
			PRIMARY KEY (id),
			KEY status (status),
			KEY backup_id (backup_id),
			KEY run_after (run_after)
		) {$charset_collate};" );

		update_option( 'gembackup_db_version', GEMBACKUP_DB_VERSION );
	}

	private static function set_default_options() {
		$defaults = [
			'backup_retention'        => 10,
			'logs_retention_days'     => 30,

			'active_storage'          => 'local',
			'enabled_drivers'         => [ 'local' ],
			'local_path'              => GEMBACKUP_BACKUP_DIR_PATH,

			'encryption_enabled'      => false,
			'encryption_passphrase'   => '',

			'exclude_paths'           => "wp-content/cache\nwp-content/uploads/cache\nwp-content/upgrade",
			'exclude_tables_smart'    => true,
			'exclude_tables_extra'    => '',

			'notify_on_failure'       => false,
			'notify_email'            => '',

			'restore_safety_snapshot' => true,

			'health_alert_days'       => 7,
			'webhook_url'             => '',

			'schedule_enabled'        => false,
			'schedule_frequency'      => 'daily',
			'schedule_backup_type'    => 'full',
			'schedule_storage_driver' => 'local',
			'schedule_time'           => '02:00',
		];

		$existing = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		update_option( GEMBACKUP_SETTINGS_NAME, array_merge( $defaults, $existing ) );
	}
}
