<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Database {

	public static function init() {
		$self = new self();
		add_action( 'init', [ $self, 'register_tables' ], 5 );
		add_action( 'init', [ Installer::class, 'maybe_upgrade' ], 6 );

		// Cron callbacks.
		add_action( Installer::CRON_PRUNE_LOGS, [ Logger::class, 'prune' ] );
		add_action( Installer::CRON_PRUNE_LOGS, [ Security\BanList::class, 'prune' ] );
		add_action( Installer::CRON_DAILY_SCAN, [ $self, 'maybe_run_daily_scan' ] );
	}

	/**
	 * Register custom table names on the $wpdb object so they
	 * can be referenced as $wpdb->gemsecurity_logs anywhere.
	 */
	public function register_tables() {
		global $wpdb;
		$wpdb->gemsecurity_logs = $wpdb->prefix . 'gemsecurity_logs';
		$wpdb->gemsecurity_bans = $wpdb->prefix . 'gemsecurity_bans';
	}

	/**
	 * Daily cron: run the integrity scan only when auto-scan is enabled.
	 */
	public function maybe_run_daily_scan() {
		if ( Helper::get_setting( 'scanner_auto_scan', false ) ) {
			Modules\Scanner::run_and_store();
		}
		if ( Helper::get_setting( 'vuln_scan_enabled', true ) ) {
			\GemSecurity\Security\Vulnerability::run_and_store();
		}
	}
}
