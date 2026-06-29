<?php
namespace GemBackup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Helper {

	public static function get_time() {
		return time() + ( get_option( 'gmt_offset' ) * HOUR_IN_SECONDS );
	}

	/**
	 * Get a single plugin setting with optional fallback.
	 *
	 * @param string $key
	 * @param mixed  $default
	 * @return mixed
	 */
	public static function get_setting( $key, $default = null ) {
		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		return isset( $settings[ $key ] ) ? $settings[ $key ] : $default;
	}

	/**
	 * Admin menu definition — filterable.
	 */
	public static function get_admin_menu_list() {
		$menu = [];

		$menu[ GEMBACKUP_PLUGIN_SLUG ] = [
			'parent_slug' => GEMBACKUP_PLUGIN_SLUG,
			'title'       => __( 'Dashboard', 'gembackup' ),
			'capability'  => 'manage_options',
		];

		$menu[ GEMBACKUP_PLUGIN_SLUG . '-backups' ] = [
			'parent_slug' => GEMBACKUP_PLUGIN_SLUG,
			'title'       => __( 'Backups', 'gembackup' ),
			'capability'  => 'manage_options',
		];

		$menu[ GEMBACKUP_PLUGIN_SLUG . '-schedule' ] = [
			'parent_slug' => GEMBACKUP_PLUGIN_SLUG,
			'title'       => __( 'Schedule', 'gembackup' ),
			'capability'  => 'manage_options',
		];

		$menu[ GEMBACKUP_PLUGIN_SLUG . '-storage' ] = [
			'parent_slug' => GEMBACKUP_PLUGIN_SLUG,
			'title'       => __( 'Storage', 'gembackup' ),
			'capability'  => 'manage_options',
		];

		$menu[ GEMBACKUP_PLUGIN_SLUG . '-logs' ] = [
			'parent_slug' => GEMBACKUP_PLUGIN_SLUG,
			'title'       => __( 'Logs', 'gembackup' ),
			'capability'  => 'manage_options',
		];

		$menu[ GEMBACKUP_PLUGIN_SLUG . '-settings' ] = [
			'parent_slug' => GEMBACKUP_PLUGIN_SLUG,
			'title'       => __( 'Settings', 'gembackup' ),
			'capability'  => 'manage_options',
		];

		return apply_filters( 'gembackup/admin_menu_list', $menu );
	}

	/**
	 * Returns true for both the top-level page and all subpages.
	 *
	 * @param string $hook
	 * @return bool
	 */
	public static function plugin_page_hook_suffix( $hook ) {
		if ( 'toplevel_page_' . GEMBACKUP_PLUGIN_SLUG === $hook ) {
			return true;
		}
		if ( strpos( $hook, '_page_' . GEMBACKUP_PLUGIN_SLUG ) !== false ) {
			return true;
		}
		return false;
	}

	/**
	 * Human-readable backup type labels.
	 *
	 * @return array
	 */
	public static function get_backup_types() {
		return apply_filters( 'gembackup/backup_types', [
			'full'     => __( 'Full Site (DB + Files)', 'gembackup' ),
			'database' => __( 'Database Only', 'gembackup' ),
			'files'    => __( 'Files (wp-content)', 'gembackup' ),
			'media'    => __( 'Media Library Only', 'gembackup' ),
		] );
	}

	/**
	 * Registered storage driver labels.
	 *
	 * @return array
	 */
	public static function get_storage_drivers() {
		return apply_filters( 'gembackup/storage_drivers', [
			'local'     => __( 'Local Server', 'gembackup' ),
			'gdrive'    => __( 'Google Drive', 'gembackup' ),
			'dropbox'   => __( 'Dropbox', 'gembackup' ),
			'onedrive'  => __( 'OneDrive', 'gembackup' ),
			's3'        => __( 'Amazon S3', 'gembackup' ),
			'r2'        => __( 'Cloudflare R2', 'gembackup' ),
			'backblaze' => __( 'Backblaze B2', 'gembackup' ),
			'ftp'       => __( 'FTP / SFTP', 'gembackup' ),
		] );
	}

	/**
	 * Available schedule frequency options.
	 *
	 * @return array
	 */
	public static function get_schedule_frequencies() {
		return apply_filters( 'gembackup/schedule_frequencies', [
			'daily'   => __( 'Daily', 'gembackup' ),
			'weekly'  => __( 'Weekly', 'gembackup' ),
			'monthly' => __( 'Monthly', 'gembackup' ),
		] );
	}

	/**
	 * Format bytes into a human-readable size string.
	 *
	 * @param int $bytes
	 * @param int $precision
	 * @return string
	 */
	public static function format_file_size( $bytes, $precision = 2 ) {
		$units = [ 'B', 'KB', 'MB', 'GB', 'TB' ];
		$bytes = max( $bytes, 0 );
		$pow   = floor( ( $bytes ? log( $bytes ) : 0 ) / log( 1024 ) );
		$pow   = min( $pow, count( $units ) - 1 );
		$bytes /= pow( 1024, $pow );
		return round( $bytes, $precision ) . ' ' . $units[ $pow ];
	}
}
