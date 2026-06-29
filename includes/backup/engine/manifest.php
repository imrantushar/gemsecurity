<?php
namespace GemBackup\Engine;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Manifest {

	public static function build( $backup_id, $type, $extras = [] ) {
		global $wpdb;
		$site_url = get_site_url();
		$home_url = get_home_url();

		return array_merge( [
			'gembackup_version' => GEMBACKUP_VERSION,
			'backup_id'         => (int) $backup_id,
			'backup_type'       => $type,
			'created_at'        => current_time( 'mysql' ),
			'wp_version'        => get_bloginfo( 'version' ),
			'php_version'       => PHP_VERSION,
			'mysql_version'     => $wpdb->db_version(),
			'site_url'          => $site_url,
			'home_url'          => $home_url,
			'table_prefix'      => $wpdb->prefix,
			'charset'           => $wpdb->get_charset_collate(),
			'multisite'         => is_multisite(),
			'abspath'           => ABSPATH,
			'wp_content_dir'    => WP_CONTENT_DIR,
			'active_theme'      => get_stylesheet(),
			'active_plugins'    => array_values( get_option( 'active_plugins', [] ) ),
			'files'             => [],
			'sql_files'         => [],
			'integrity'         => [],
		], $extras );
	}

	public static function write( $path, array $manifest ) {
		return file_put_contents( $path, wp_json_encode( $manifest, JSON_PRETTY_PRINT ) ); // phpcs:ignore
	}

	public static function read( $path ) {
		if ( ! file_exists( $path ) ) {
			return new \WP_Error( 'gembackup_manifest_missing', 'manifest.json not found' );
		}
		$json = file_get_contents( $path ); // phpcs:ignore
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) ) {
			return new \WP_Error( 'gembackup_manifest_invalid', 'manifest.json is invalid JSON' );
		}
		return $data;
	}

	public static function hash_file( $path ) {
		return hash_file( 'sha256', $path );
	}
}
