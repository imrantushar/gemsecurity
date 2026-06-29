<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Backup subsystem bootstrap.
 *
 * Re-homes the GemBackup engine inside GemSecurity: the engine code lives in
 * includes/backup/ under its original `GemBackup\` namespace and is loaded
 * through GemSecurity's autoloader. The standalone GemBackup plugin's own
 * admin UI is intentionally not loaded — GemSecurity provides the backup UI.
 */
class Backup {

	const BACKUP_DIR = 'gemsecurity-backups';

	/**
	 * Runtime bootstrap (called from GemSecurity::dispatch_hooks).
	 */
	public static function init() {
		if ( self::standalone_active() ) {
			add_action( 'admin_notices', [ __CLASS__, 'standalone_conflict_notice' ] );
			return;
		}

		self::prepare();

		\GemBackup\Installer::maybe_upgrade();
		\GemBackup\Database::init();
		\GemBackup\Api::init();
		\GemBackup\Scheduler::init();
		\GemBackup\Jobs\Job_Processor::init();
		\GemBackup\Helpers\Health_Monitor::init();
		\GemBackup\Storage\Oauth_Handler::init();

		add_action( 'init', [ __CLASS__, 'handle_secure_download' ] );

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			\GemBackup\Cli\Backup_Command::register();
		}
	}

	/**
	 * Create the backup tables / defaults on plugin activation.
	 */
	public static function activate() {
		if ( self::standalone_active() ) {
			return;
		}
		self::prepare();
		\GemBackup\Installer::activate();
	}

	/**
	 * Clear backup scheduled events on deactivation.
	 */
	public static function deactivate() {
		foreach ( [
			'gembackup_daily_event',
			'gembackup_weekly_event',
			'gembackup_monthly_event',
			'gembackup_job_tick',
			'gembackup_health_tick',
		] as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
	}

	/**
	 * Define the engine constants and register its autoload path. Idempotent.
	 */
	private static function prepare() {
		$base = GEMSECURITY_INCLUDES_DIR_PATH . 'backup/';

		if ( ! defined( 'GEMBACKUP_VERSION' ) ) {
			define( 'GEMBACKUP_VERSION', '1.0.0' );
		}
		if ( ! defined( 'GEMBACKUP_DB_VERSION' ) ) {
			define( 'GEMBACKUP_DB_VERSION', '1.1' );
		}
		if ( ! defined( 'GEMBACKUP_SETTINGS_NAME' ) ) {
			define( 'GEMBACKUP_SETTINGS_NAME', 'gemsecurity_backup_settings' );
		}
		if ( ! defined( 'GEMBACKUP_PLUGIN_SLUG' ) ) {
			define( 'GEMBACKUP_PLUGIN_SLUG', 'gembackup' );
		}
		if ( ! defined( 'GEMBACKUP_INCLUDES_DIR_PATH' ) ) {
			define( 'GEMBACKUP_INCLUDES_DIR_PATH', $base );
		}
		if ( ! defined( 'GEMBACKUP_ROOT_DIR_PATH' ) ) {
			define( 'GEMBACKUP_ROOT_DIR_PATH', $base );
		}
		if ( ! defined( 'GEMBACKUP_BACKUP_DIR_PATH' ) ) {
			define( 'GEMBACKUP_BACKUP_DIR_PATH', trailingslashit( WP_CONTENT_DIR ) . self::BACKUP_DIR . '/' );
		}

		Autoload::get_instance()->add_namespace_directory( 'GemBackup', GEMBACKUP_INCLUDES_DIR_PATH );
	}

	/**
	 * Is the standalone GemBackup plugin (retired) still active?
	 *
	 * @return bool
	 */
	private static function standalone_active() {
		// The standalone plugin defines a global `GemBackup` class. The engine
		// we re-home uses the `GemBackup\` namespace, which does not match.
		return class_exists( 'GemBackup', false );
	}

	public static function standalone_conflict_notice() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p>';
		echo esc_html__( 'GemSecurity now includes backups. Please deactivate the standalone GemBackup plugin to avoid conflicts.', 'gemsecurity' );
		echo '</p></div>';
	}

	/**
	 * Serve a backup file behind a one-time token (moved from the standalone
	 * plugin's main file).
	 */
	public static function handle_secure_download() {
		if ( empty( $_GET['gembackup_download'] ) ) {
			return;
		}
		$token     = sanitize_text_field( wp_unslash( $_GET['gembackup_download'] ) );
		$backup_id = get_transient( 'gembackup_dl_' . $token );
		if ( ! $backup_id || ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Invalid or expired download link.', 'gemsecurity' ), 'Forbidden', 403 );
		}
		delete_transient( 'gembackup_dl_' . $token );

		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->gembackup_backups} WHERE id=%d", (int) $backup_id ), ARRAY_A );
		if ( ! $row || empty( $row['file_path'] ) || ! file_exists( $row['file_path'] ) ) {
			wp_die( esc_html__( 'Backup file not found.', 'gemsecurity' ), 'Not found', 404 );
		}

		nocache_headers();
		header( 'Content-Type: application/octet-stream' );
		header( 'Content-Disposition: attachment; filename="' . basename( $row['file_path'] ) . '"' );
		header( 'Content-Length: ' . filesize( $row['file_path'] ) );
		readfile( $row['file_path'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}
}
