<?php
namespace GemBackup\Api;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use GemBackup\Engine\Backup_Runner;
use GemBackup\Helper;
use GemBackup\Helpers\Health_Monitor;

class System_Controller extends Rest_Controller {

	protected $rest_base = 'system';

	public function register_routes() {
		register_rest_route( $this->namespace, '/' . $this->rest_base, [
			'methods'             => 'GET',
			'callback'            => [ $this, 'get_system' ],
			'permission_callback' => [ $this, 'permissions_check' ],
		] );

		register_rest_route( $this->namespace, '/' . $this->rest_base . '/overview', [
			'methods'             => 'GET',
			'callback'            => [ $this, 'get_overview' ],
			'permission_callback' => [ $this, 'permissions_check' ],
		] );
	}

	public function get_system( $request ) {
		global $wpdb;
		$upload = wp_upload_dir();

		return $this->ok( [
			'php_version'      => PHP_VERSION,
			'wp_version'       => get_bloginfo( 'version' ),
			'mysql_version'    => $wpdb->db_version(),
			'plugin_version'   => GEMBACKUP_VERSION,
			'memory_limit'     => ini_get( 'memory_limit' ),
			'max_execution'    => (int) ini_get( 'max_execution_time' ),
			'disk_free'        => @disk_free_space( ABSPATH ),
			'backup_dir'       => GEMBACKUP_BACKUP_DIR_PATH,
			'backup_dir_writable' => is_writable( GEMBACKUP_BACKUP_DIR_PATH ),
			'wp_cron_enabled'  => ! ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ),
			'upload_dir'       => $upload['basedir'],
			'is_multisite'     => is_multisite(),
			'health'           => Health_Monitor::summary(),
		] );
	}

	public function get_overview( $request ) {
		global $wpdb;
		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->gembackup_backups}" );
		$completed = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->gembackup_backups} WHERE status='completed'" );
		$failed = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->gembackup_backups} WHERE status='failed' AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)" );
		$total_size = (int) $wpdb->get_var( "SELECT COALESCE(SUM(file_size),0) FROM {$wpdb->gembackup_backups} WHERE status='completed'" );
		$last = $wpdb->get_row( "SELECT id, backup_name, backup_type, completed_at, file_size, storage_driver FROM {$wpdb->gembackup_backups} WHERE status='completed' ORDER BY completed_at DESC LIMIT 1", ARRAY_A );

		return $this->ok( [
			'total_backups'     => $total,
			'completed_backups' => $completed,
			'failed_30d'        => $failed,
			'total_size'        => $total_size,
			'last_backup'       => $last,
		] );
	}
}
