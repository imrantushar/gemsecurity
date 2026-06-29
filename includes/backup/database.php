<?php
namespace GemBackup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Database {

	public static function init() {
		$self = new self();
		add_action( 'init', [ $self, 'register_tables' ], 5 );
	}

	/**
	 * Register custom table names on the global $wpdb object so they
	 * can be referenced as $wpdb->gembackup_backups etc. anywhere.
	 */
	public function register_tables() {
		global $wpdb;
		// Single-brand table names; the $wpdb->gembackup_* aliases are kept so
		// the relocated engine's queries work unchanged.
		$wpdb->gembackup_backups   = $wpdb->prefix . 'gemsecurity_backups';
		$wpdb->gembackup_schedules = $wpdb->prefix . 'gemsecurity_backup_schedules';
		$wpdb->gembackup_logs      = $wpdb->prefix . 'gemsecurity_backup_logs';
		$wpdb->gembackup_jobs      = $wpdb->prefix . 'gemsecurity_backup_jobs';
	}
}
