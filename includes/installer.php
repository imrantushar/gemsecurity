<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Installer {

	public static function activate() {
		self::create_tables();
		self::set_default_options();
		flush_rewrite_rules();
	}

	public static function deactivate() {
		flush_rewrite_rules();
	}

	private static function create_tables() {
		global $wpdb;
		$charset_collate = $wpdb->get_charset_collate();

		$logs_table = $wpdb->prefix . 'gemsecurity_logs';
		$sql = "CREATE TABLE IF NOT EXISTS {$logs_table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			event_type VARCHAR(50) NOT NULL,
			severity VARCHAR(20) NOT NULL DEFAULT 'info',
			message TEXT NOT NULL,
			ip_address VARCHAR(45) DEFAULT NULL,
			user_id BIGINT(20) UNSIGNED DEFAULT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY event_type (event_type),
			KEY severity (severity),
			KEY created_at (created_at)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		update_option( 'gemsecurity_db_version', GEMSECURITY_DB_VERSION );
	}

	private static function set_default_options() {
		$defaults = [
			'firewall_enabled'        => true,
			'login_attempts_limit'    => 5,
			'login_lockout_duration'  => 30,
			'scanner_auto_scan'       => false,
			'logs_retention_days'     => 30,
		];

		$existing = get_option( GEMSECURITY_SETTINGS_NAME, [] );
		$merged   = array_merge( $defaults, $existing );
		update_option( GEMSECURITY_SETTINGS_NAME, $merged );
	}
}
