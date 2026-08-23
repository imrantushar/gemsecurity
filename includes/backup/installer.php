<?php
namespace GemBackup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Installer {

	/**
	 * Bump whenever the .htaccess/web.config content in create_backup_directory()
	 * changes, so maybe_upgrade() re-lays the files for sites that already have
	 * the (older, weaker) versions on disk — not just fresh installs.
	 */
	const PROTECTION_VERSION = '2';

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
		// Idempotent and cheap to call every load (short-circuits once the
		// stored protection version is current) — re-lays the directory's
		// .htaccess/web.config for sites that installed before a fix, not just
		// new installs.
		self::create_backup_directory();
		self::schedule_heartbeat();
	}

	public static function schedule_heartbeat() {
		// wp_schedule_event() calls wp_get_schedules() internally, which fires
		// the `cron_schedules` filter. maybe_upgrade() runs at plugins_loaded,
		// so resolving schedules here forces every other plugin's interval
		// callback (SureCart, Bit Flows, GemBooking, …) to translate its label
		// before `init`, tripping WP 6.7+'s `_load_textdomain_just_in_time`
		// notice. Defer to `init` so schedules resolve after translations load.
		if ( ! did_action( 'init' ) ) {
			add_action( 'init', [ __CLASS__, 'schedule_heartbeat' ] );
			return;
		}
		if ( ! wp_next_scheduled( 'gembackup_job_tick' ) ) {
			wp_schedule_event( time() + 60, 'gembackup_minute', 'gembackup_job_tick' );
		}
		if ( ! wp_next_scheduled( 'gembackup_health_tick' ) ) {
			wp_schedule_event( time() + 300, 'hourly', 'gembackup_health_tick' );
		}
	}

	/**
	 * Create the backup directory and lay down its access-control files.
	 *
	 * Neither .htaccess nor web.config protects anything on nginx — nginx
	 * doesn't read per-directory config files at all, so a request for a file
	 * under this directory is served directly as a static file before
	 * WordPress/PHP ever runs. See Backup::maybe_nginx_notice() for the
	 * admin-facing warning that covers that case; this function only handles
	 * what's actually possible to do with dropped-in files (Apache/LiteSpeed
	 * via .htaccess, IIS via web.config).
	 */
	private static function create_backup_directory() {
		$dir = GEMBACKUP_BACKUP_DIR_PATH;

		if ( ! file_exists( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		// Cheap short-circuit: this runs on every request via maybe_upgrade(),
		// but only touches disk when the on-disk files are from an older,
		// weaker version.
		if ( get_option( 'gembackup_dir_protection_version', '0' ) === self::PROTECTION_VERSION ) {
			return;
		}

		// Apache 2.4+ / LiteSpeed read `Require all denied`; Apache 2.2 (and
		// any host without mod_authz_core) falls back to `Deny from all`.
		// `Options -Indexes` stops a directory listing on hosts that inherited
		// +Indexes from a parent config.
		file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions
			$dir . '.htaccess',
			"<IfModule mod_authz_core.c>\n" .
			"\tRequire all denied\n" .
			"</IfModule>\n" .
			"<IfModule !mod_authz_core.c>\n" .
			"\tDeny from all\n" .
			"</IfModule>\n" .
			"Options -Indexes\n"
		);

		// IIS equivalent of the block above. Requires the URL-authorization
		// module (bundled on most Windows/IIS WordPress hosting); harmless if
		// the module isn't present — IIS ignores directives it can't process
		// rather than erroring.
		file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions
			$dir . 'web.config',
			"<configuration>\n" .
			"\t<system.web>\n" .
			"\t\t<authorization>\n" .
			"\t\t\t<deny users=\"*\" />\n" .
			"\t\t</authorization>\n" .
			"\t</system.web>\n" .
			"</configuration>\n"
		);

		if ( ! file_exists( $dir . 'index.php' ) ) {
			file_put_contents( $dir . 'index.php', "<?php // Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		update_option( 'gembackup_dir_protection_version', self::PROTECTION_VERSION, false );
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
			'backup_retention'          => 10,
			// Named apart from the security log's own retention setting: both
			// stores had a `logs_retention_days` key, so the Settings field
			// looked like it covered this one and never did.
			'backup_logs_retention_days' => 30,

			'active_storage'            => 'local',
			'enabled_drivers'           => [ 'local' ],
			'local_path'                => GEMBACKUP_BACKUP_DIR_PATH,

			'encryption_enabled'        => false,
			'encryption_passphrase'     => '',

			'exclude_paths'             => "wp-content/cache\nwp-content/uploads/cache\nwp-content/upgrade",
			'exclude_tables_smart'      => true,
			'exclude_tables_extra'      => '',

			// Recipient and webhook are the plugin-wide ones (Settings →
			// Notifications); this only decides whether backup events are sent.
			'notify_on_failure'         => false,

			'restore_safety_snapshot'   => true,

			'health_alert_days'         => 7,

			// Schedules live in the gembackup_schedules table, not in settings.
			// The old schedule_* keys here were written on install and read by
			// nothing.
		];

		$existing = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		update_option( GEMBACKUP_SETTINGS_NAME, array_merge( $defaults, $existing ) );
	}
}
