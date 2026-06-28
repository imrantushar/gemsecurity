<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Installer {

	const CRON_PRUNE_LOGS = 'gemsecurity_prune_logs';
	const CRON_DAILY_SCAN = 'gemsecurity_daily_scan';

	public static function activate() {
		self::create_tables();
		self::set_default_options();
		self::schedule_events();
		self::snapshot_admin_whitelist();
		flush_rewrite_rules();
	}

	public static function deactivate() {
		self::clear_events();
		flush_rewrite_rules();
	}

	/**
	 * Run dbDelta when the stored schema version is behind the code version.
	 * Hooked on init so already-active installs self-heal without re-activation.
	 */
	public static function maybe_upgrade() {
		if ( get_option( 'gemsecurity_db_version' ) !== GEMSECURITY_DB_VERSION ) {
			self::create_tables();
			self::set_default_options();
			self::schedule_events();
		}
	}

	private static function create_tables() {
		global $wpdb;
		$charset_collate = $wpdb->get_charset_collate();

		$logs_table = $wpdb->prefix . 'gemsecurity_logs';
		$sql = "CREATE TABLE {$logs_table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			event_type VARCHAR(50) NOT NULL,
			severity VARCHAR(20) NOT NULL DEFAULT 'info',
			message TEXT NOT NULL,
			ip_address VARCHAR(45) DEFAULT NULL,
			user_id BIGINT(20) UNSIGNED DEFAULT NULL,
			context LONGTEXT DEFAULT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY event_type (event_type),
			KEY severity (severity),
			KEY user_id (user_id),
			KEY created_at (created_at)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		update_option( 'gemsecurity_db_version', GEMSECURITY_DB_VERSION );
	}

	/**
	 * Default settings. Existing values always win on merge.
	 */
	public static function default_settings() {
		return [
			// General / firewall.
			'firewall_enabled'             => true,
			'ip_blocklist'                 => [],
			'xmlrpc_disabled'              => false,
			'disable_file_editing'         => true,
			'block_author_enumeration'     => true,
			'disable_user_rest'            => true,
			'hide_wp_version'              => true,
			'disable_application_passwords' => false,

			// Login security.
			'login_attempts_enabled'       => true,
			'login_attempts_limit'         => 5,
			'login_lockout_duration'       => 30, // minutes.
			'admin_login_alert_enabled'    => false,
			'admin_login_alert_email'      => get_option( 'admin_email' ),
			'admin_session_timeout_enabled' => false,
			'admin_session_timeout_hours'  => 24,

			// Admin whitelist guard.
			'admin_whitelist_enabled'      => false,
			'admin_whitelist'              => [], // array of email addresses.
			'rogue_admin_action'           => 'demote', // delete | demote (applies to promotions of existing users).
			'notify_on_rogue_admin'        => true,

			// Scanner.
			'scanner_auto_scan'            => false,

			// Logs / audit.
			'logs_retention_days'          => 30,
			'audit_log_enabled'            => true,
			'audit_content'                => true,
			'audit_plugins_themes'         => true,
			'audit_users'                  => true,
			'audit_settings'               => true,

			// Security headers (master off; safe individual defaults).
			'security_headers_enabled'     => false,
			'header_x_frame_options'       => 'SAMEORIGIN',
			'header_x_content_type_options' => true,
			'header_referrer_policy'       => 'strict-origin-when-cross-origin',
			'header_permissions_policy'    => 'geolocation=(), camera=(), microphone=()',
			'header_hsts_enabled'          => false,
			'header_hsts_max_age'          => 15552000,
			'header_hsts_subdomains'       => false,
			'header_hsts_preload'          => false,
			'header_csp_enabled'           => false,
			'header_csp_value'             => "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
			'header_csp_report_only'       => true,

			// CAPTCHA.
			'captcha_enabled'              => false,
			'captcha_provider'             => 'recaptcha_v2',
			'captcha_site_key'             => '',
			'captcha_secret_key'           => '',
			'captcha_on_login'             => true,
			'captcha_on_register'          => true,
			'captcha_on_lostpassword'      => false,
			'captcha_v3_threshold'         => 0.5,

			// Two-factor.
			'two_factor_enabled'           => false,
			'two_factor_enforced_roles'    => [],

			// Social / OAuth login.
			'social_login_enabled'         => false,
			'social_allow_registration'    => true,
			'social_link_by_email'         => true,
			'social_default_role'          => 'subscriber',
			'social_google_enabled'        => false,
			'social_google_client_id'      => '',
			'social_google_client_secret'  => '',
			'social_facebook_enabled'      => false,
			'social_facebook_client_id'    => '',
			'social_facebook_client_secret' => '',
			'social_github_enabled'        => false,
			'social_github_client_id'      => '',
			'social_github_client_secret'  => '',
			'social_twitter_enabled'       => false,
			'social_twitter_client_id'     => '',
			'social_twitter_client_secret' => '',

			// Geolocation (all off by default — a wrong rule can lock everyone out).
			'geo_enabled'                  => false,
			'geo_whitelist_login_enabled'  => false,
			'geo_block_site_enabled'       => false,
			'geo_block_unknown'            => false,
			'geo_whitelist_block_admins'   => false,
			'geo_allowed_countries'        => [],
			'geo_user_lock_enabled'        => false,
			'geo_user_lock_action'         => 'verify',
		];
	}

	private static function set_default_options() {
		$existing = get_option( GEMSECURITY_SETTINGS_NAME, [] );
		if ( ! is_array( $existing ) ) {
			$existing = [];
		}
		$merged = array_merge( self::default_settings(), $existing );
		update_option( GEMSECURITY_SETTINGS_NAME, $merged );
	}

	/**
	 * On first enable of the whitelist guard, seed it with all current
	 * administrators so existing legitimate admins are never auto-removed.
	 */
	public static function snapshot_admin_whitelist() {
		$settings = get_option( GEMSECURITY_SETTINGS_NAME, [] );
		if ( ! is_array( $settings ) ) {
			$settings = [];
		}

		if ( ! empty( $settings['admin_whitelist'] ) ) {
			return;
		}

		$admins = get_users( [ 'role' => 'administrator', 'fields' => [ 'user_email' ] ] );
		$emails = array_values( array_filter( array_map( static function ( $u ) {
			return strtolower( trim( $u->user_email ) );
		}, $admins ) ) );

		$settings['admin_whitelist'] = array_values( array_unique( $emails ) );
		update_option( GEMSECURITY_SETTINGS_NAME, $settings );
	}

	private static function schedule_events() {
		if ( ! wp_next_scheduled( self::CRON_PRUNE_LOGS ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_PRUNE_LOGS );
		}
		if ( ! wp_next_scheduled( self::CRON_DAILY_SCAN ) ) {
			wp_schedule_event( time() + 2 * HOUR_IN_SECONDS, 'daily', self::CRON_DAILY_SCAN );
		}
	}

	private static function clear_events() {
		wp_clear_scheduled_hook( self::CRON_PRUNE_LOGS );
		wp_clear_scheduled_hook( self::CRON_DAILY_SCAN );
	}
}
