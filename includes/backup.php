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

	/** Storage drivers available on the free tier. Everything else is Pro. */
	const FREE_DRIVERS = [ 'local' ];

	/** Whether Pro is active. */
	public static function is_pro() {
		return Helper::is_pro_active();
	}

	/**
	 * Are all the given storage drivers allowed on the current tier?
	 *
	 * @param array|string $drivers
	 * @return bool
	 */
	public static function drivers_allowed( $drivers ) {
		if ( self::is_pro() ) {
			return true;
		}
		foreach ( (array) $drivers as $d ) {
			if ( ! in_array( $d, self::FREE_DRIVERS, true ) ) {
				return false;
			}
		}
		return true;
	}

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
		add_action( 'admin_init', [ __CLASS__, 'maybe_dismiss_nginx_notice' ] );
		add_action( 'admin_notices', [ __CLASS__, 'maybe_nginx_notice' ] );

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
	 * Whether the request is being served by nginx. The .htaccess / web.config
	 * files GemBackup lays down (Installer::create_backup_directory()) protect
	 * the local backup directory on Apache/LiteSpeed and IIS — nginx doesn't
	 * read per-directory config files at all, so those files do nothing there
	 * and a request for a backup archive is served as a static file before
	 * WordPress ever runs. There's no file this plugin can drop that fixes
	 * that; the admin has to add a rule to their own server block.
	 *
	 * Only warns on a positive "nginx" signature, not merely an unrecognised
	 * one, so hosts we can't identify aren't nagged over a guess.
	 *
	 * @return bool
	 */
	private static function server_is_nginx() {
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( (string) $_SERVER['SERVER_SOFTWARE'] ) : '';
		return false !== strpos( $software, 'nginx' );
	}

	/**
	 * One-time warning on nginx that the local backup directory isn't
	 * protected the way it is on Apache/IIS, with a snippet to close it.
	 */
	public static function maybe_nginx_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( get_option( 'gembackup_nginx_notice_dismissed', false ) ) {
			return;
		}
		if ( ! self::server_is_nginx() ) {
			return;
		}

		$dir_name    = trim( str_replace( trailingslashit( WP_CONTENT_DIR ), '', GEMBACKUP_BACKUP_DIR_PATH ), '/' );
		$dismiss_url = wp_nonce_url(
			add_query_arg( 'gembackup_dismiss_nginx_notice', '1' ),
			'gembackup_dismiss_nginx_notice'
		);

		echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'GemSecurity: local backups are not protected from direct download on nginx.', 'gemsecurity' ) . '</strong></p>';
		echo '<p>' . sprintf(
			/* translators: %s: backup directory path, relative to wp-content */
			esc_html__( 'The .htaccess file GemSecurity uses to block direct access to wp-content/%s only works on Apache/LiteSpeed — nginx does not read it. Add this to your nginx server block to close the gap:', 'gemsecurity' ),
			esc_html( $dir_name )
		) . '</p>';
		echo '<pre style="background:#f0f0f1;padding:10px;overflow:auto;">location ^~ /wp-content/' . esc_html( $dir_name ) . "/ {\n\tdeny all;\n\treturn 404;\n}</pre>";
		echo '<p><a href="' . esc_url( $dismiss_url ) . '">' . esc_html__( "I've handled this / stop showing this notice", 'gemsecurity' ) . '</a></p>';
		echo '</div>';
	}

	/**
	 * Persist the nginx-notice dismissal.
	 */
	public static function maybe_dismiss_nginx_notice() {
		if ( ! isset( $_GET['gembackup_dismiss_nginx_notice'] ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) || ! check_admin_referer( 'gembackup_dismiss_nginx_notice' ) ) {
			return;
		}
		update_option( 'gembackup_nginx_notice_dismissed', true, false );
		wp_safe_redirect( remove_query_arg( [ 'gembackup_dismiss_nginx_notice', '_wpnonce' ] ) );
		exit;
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
