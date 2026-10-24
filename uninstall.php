<?php
/**
 * GemSecurity uninstall — remove all plugin data when the plugin is deleted.
 *
 * The variables here live in uninstall.php's own file scope, which WP
 * loads once at delete time. They are not globals in the WPCS sense and
 * do not leak outside this request.
 */
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// Options.
$options = [
	'gemsecurity_settings',
	'gemsecurity_meta',
	'gemsecurity_state',
	'gemsecurity_active_modules',
	'gemsecurity_last_scan',
	'gemsecurity_hidden_admin_scan',
	'gemsecurity_hidden_admin_state',
	'gemsecurity_daily_report_snapshot',
	'gemsecurity_safe_files',
	// Pre-2.2 standalone keys. Still deleted so an uninstall after an upgrade
	// from before the OptionStore consolidation leaves nothing behind.
	'gemsecurity_db_version',
	'gemsecurity_first_install_time',
	'gemsecurity_pro_first_install_time',
	'gemsecurity_2fa_sealed',
	'gemsecurity_vuln_scan',
	'gemsecurity_quarantine',
	'gemsecurity_watchdog_alert',
	'gemsecurity_pro_file_baseline',
];
foreach ( $options as $option ) {
	delete_option( $option );
}

// Custom tables. Backup data (tables, archives, schedules) belongs to the
// GemBackup plugin and is deliberately left alone — it may be the site's
// only restore point, including any GemBackup has not imported yet.
$tables = [
	'gemsecurity_logs',
	'gemsecurity_bans',
];
foreach ( $tables as $table ) {
	$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . $table ); // phpcs:ignore WordPress.DB
}

// User meta created by the plugin.
$meta_keys = [
	'_gemsecurity_login_time',
	'_gemsec_2fa_enabled',
	'_gemsec_2fa_method',
	'_gemsec_2fa_secret',
	'_gemsec_2fa_secret_pending',
	'_gemsec_2fa_backup_codes',
	'_gemsec_oauth_avatar',
	'_gemsec_oauth_registered_via',
	'_gemsec_geo_allowed_countries',
	'_gemsec_pw_set',
	'_gemsec_last_activity',
];
foreach ( $meta_keys as $key ) {
	$wpdb->delete( $wpdb->usermeta, [ 'meta_key' => $key ] ); // phpcs:ignore WordPress.DB
}
// OAuth provider id meta (one per provider).
$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE '\_gemsec\_oauth\_%\_id'" ); // phpcs:ignore WordPress.DB

// Scheduled events.
$hooks = [
	'gemsecurity_password_rotation',
	'gemsecurity_prune_logs',
	'gemsecurity_daily_scan',
	'gemsecurity_weekly_digest',
	'gemsecurity_admin_guard_sweep',
	'gemsecurity_daily_report',
];
foreach ( $hooks as $hook ) {
	wp_clear_scheduled_hook( $hook );
}

// Extended-protection mu-plugin.
$mu = ( defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins' ) . '/gemsecurity-extended-protection.php';
if ( file_exists( $mu ) ) {
	unlink( $mu ); // phpcs:ignore
}
