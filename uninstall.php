<?php
/**
 * GemSecurity uninstall — remove all plugin data when the plugin is deleted.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// Options.
$options = [
	'gemsecurity_settings',
	'gemsecurity_db_version',
	'gemsecurity_last_scan',
	'gemsecurity_vuln_scan',
	'gemsecurity_hidden_admin_scan',
	'gemsecurity_hidden_admin_state',
	// Backup subsystem.
	'gemsecurity_backup_settings',
	'gembackup_db_version',
];
foreach ( $options as $option ) {
	delete_option( $option );
}

// Custom tables (security + backup).
$tables = [
	'gemsecurity_logs',
	'gemsecurity_bans',
	'gemsecurity_backups',
	'gemsecurity_backup_jobs',
	'gemsecurity_backup_schedules',
	'gemsecurity_backup_logs',
];
foreach ( $tables as $table ) {
	$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . $table ); // phpcs:ignore WordPress.DB
}

// Backup storage directory.
$backup_dir = trailingslashit( WP_CONTENT_DIR ) . 'gemsecurity-backups';
if ( is_dir( $backup_dir ) ) {
	$files = glob( $backup_dir . '/*' );
	if ( is_array( $files ) ) {
		foreach ( $files as $f ) {
			if ( is_file( $f ) ) {
				unlink( $f ); // phpcs:ignore
			}
		}
	}
	@rmdir( $backup_dir ); // phpcs:ignore
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

// Scheduled events (security + backup).
$hooks = [
	'gemsecurity_prune_logs',
	'gemsecurity_daily_scan',
	'gemsecurity_weekly_digest',
	'gembackup_daily_event',
	'gembackup_weekly_event',
	'gembackup_monthly_event',
	'gembackup_job_tick',
	'gembackup_health_tick',
];
foreach ( $hooks as $hook ) {
	wp_clear_scheduled_hook( $hook );
}

// Extended-protection mu-plugin.
$mu = ( defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins' ) . '/gemsecurity-extended-protection.php';
if ( file_exists( $mu ) ) {
	unlink( $mu ); // phpcs:ignore
}
