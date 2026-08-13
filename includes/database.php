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

		// Re-scan shortly after any plugin/theme/core update — the moment a fresh
		// infection is most likely to have arrived (e.g. a nulled or trojaned
		// package). Deferred to a single cron event so the update request stays
		// fast, and only when automatic scanning is enabled.
		add_action( 'upgrader_process_complete', [ $self, 'schedule_post_update_scan' ], 10, 2 );
		add_action( Installer::CRON_POST_UPDATE_SCAN, [ $self, 'run_post_update_scan' ] );
	}

	/**
	 * Queue a one-off integrity scan after a plugin/theme/core update.
	 *
	 * @param mixed $upgrader
	 * @param array $extra Context from upgrader_process_complete.
	 */
	public function schedule_post_update_scan( $upgrader, $extra ) {
		$action = isset( $extra['action'] ) ? $extra['action'] : '';
		$type   = isset( $extra['type'] ) ? $extra['type'] : '';
		if ( ! in_array( $action, [ 'update', 'install' ], true ) ) {
			return;
		}
		if ( ! in_array( $type, [ 'plugin', 'theme', 'core' ], true ) ) {
			return;
		}
		if ( ! wp_next_scheduled( Installer::CRON_POST_UPDATE_SCAN ) ) {
			wp_schedule_single_event( time() + 2 * MINUTE_IN_SECONDS, Installer::CRON_POST_UPDATE_SCAN );
		}
	}

	/**
	 * Cron: run the integrity scan after an update, when auto-scan is enabled.
	 */
	public function run_post_update_scan() {
		if ( Helper::get_setting( 'scanner_auto_scan', false ) ) {
			Modules\Scanner::run_and_store();
		}
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
		if ( Modules\HiddenAdmin::enabled() ) {
			Modules\HiddenAdmin::scan_and_store();
		}
	}
}
