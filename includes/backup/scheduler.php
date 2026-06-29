<?php
namespace GemBackup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use GemBackup\Engine\Backup_Runner;

class Scheduler {

	public static function init() {
		$self = new self();
		add_filter( 'cron_schedules', [ $self, 'add_cron_intervals' ] );

		add_action( 'gembackup_daily_event',   [ $self, 'run_scheduled_backups' ] );
		add_action( 'gembackup_weekly_event',  [ $self, 'run_scheduled_backups' ] );
		add_action( 'gembackup_monthly_event', [ $self, 'run_scheduled_backups' ] );

		// Listener for the cron-driven action.
		add_action( 'gembackup/run_backup', [ $self, 'enqueue_backup' ], 10, 3 );
	}

	public function add_cron_intervals( $schedules ) {
		$schedules['gembackup_minute'] = [
			'interval' => MINUTE_IN_SECONDS,
			'display'  => __( 'Every minute (GemBackup)', 'gembackup' ),
		];
		$schedules['gembackup_weekly'] = [
			'interval' => WEEK_IN_SECONDS,
			'display'  => __( 'Once Weekly (GemBackup)', 'gembackup' ),
		];
		$schedules['gembackup_monthly'] = [
			'interval' => 30 * DAY_IN_SECONDS,
			'display'  => __( 'Once Monthly (GemBackup)', 'gembackup' ),
		];
		return $schedules;
	}

	public static function schedule( $frequency = 'daily', $time = '02:00' ) {
		self::unschedule_all();

		$hook_map = [
			'daily'   => [ 'hook' => 'gembackup_daily_event',   'recurrence' => 'daily' ],
			'weekly'  => [ 'hook' => 'gembackup_weekly_event',  'recurrence' => 'gembackup_weekly' ],
			'monthly' => [ 'hook' => 'gembackup_monthly_event', 'recurrence' => 'gembackup_monthly' ],
		];

		if ( ! isset( $hook_map[ $frequency ] ) ) {
			return;
		}

		$entry = $hook_map[ $frequency ];
		list( $hour, $minute ) = explode( ':', $time );
		$now       = Helper::get_time();
		$first_run = mktime( (int) $hour, (int) $minute, 0 );
		if ( $first_run <= $now ) {
			$first_run = strtotime( '+1 day', $first_run );
		}

		wp_schedule_event( $first_run, $entry['recurrence'], $entry['hook'] );
	}

	public static function unschedule_all() {
		$hooks = [ 'gembackup_daily_event', 'gembackup_weekly_event', 'gembackup_monthly_event' ];
		foreach ( $hooks as $hook ) {
			$timestamp = wp_next_scheduled( $hook );
			if ( $timestamp ) {
				wp_unschedule_event( $timestamp, $hook );
			}
		}
	}

	/**
	 * Cron-driven dispatcher — finds all due active schedules and enqueues a backup for each.
	 */
	public function run_scheduled_backups() {
		global $wpdb;
		$now = current_time( 'mysql' );
		$rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT * FROM {$wpdb->gembackup_schedules} WHERE status = 'active' AND (next_run IS NULL OR next_run <= %s)",
			$now
		), ARRAY_A );

		foreach ( $rows as $row ) {
			$drivers = json_decode( $row['storage_drivers'], true );
			if ( ! is_array( $drivers ) || empty( $drivers ) ) {
				$drivers = [ 'local' ];
			}
			do_action( 'gembackup/run_backup', $row['backup_type'], $drivers, [
				'origin'      => 'scheduled',
				'schedule_id' => (int) $row['id'],
				'label'       => $row['label'],
				'encrypted'   => (bool) $row['encrypted'],
			] );

			$wpdb->update( $wpdb->gembackup_schedules, [
				'last_run' => $now,
				'next_run' => self::calc_next_run( $row['frequency'], $row['run_time'] ),
			], [ 'id' => $row['id'] ] );
		}
	}

	private static function calc_next_run( $frequency, $time = '02:00' ) {
		list( $h, $m ) = explode( ':', $time );
		$base = mktime( (int) $h, (int) $m, 0, (int) gmdate( 'n' ), (int) gmdate( 'j' ) + 1, (int) gmdate( 'Y' ) );
		switch ( $frequency ) {
			case 'weekly':
				$base = strtotime( '+1 week', $base ); break;
			case 'monthly':
				$base = strtotime( '+1 month', $base ); break;
		}
		return gmdate( 'Y-m-d H:i:s', $base );
	}

	/**
	 * Public entry — anything that wants to start a backup can fire `gembackup/run_backup`.
	 *
	 * @param string $backup_type
	 * @param array  $drivers
	 * @param array  $opts
	 */
	public function enqueue_backup( $backup_type = 'full', $drivers = [ 'local' ], $opts = [] ) {
		// Pre-update backups (the gemsecurity Lockdown integration) fire this
		// action with no arguments — default to a full backup to local.
		if ( empty( $backup_type ) ) {
			$backup_type = 'full';
		}
		if ( empty( $drivers ) ) {
			$drivers = [ 'local' ];
		} elseif ( ! is_array( $drivers ) ) {
			$drivers = [ $drivers ];
		}
		Backup_Runner::start( $backup_type, $drivers, $opts );
	}
}
