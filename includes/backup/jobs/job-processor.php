<?php
namespace GemBackup\Jobs;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use GemBackup\Engine\Backup_Runner;
use GemBackup\Engine\Restore_Runner;
use GemBackup\Engine\Logger;

class Job_Processor {

	public static function init() {
		add_action( 'gembackup_job_tick', [ __CLASS__, 'tick' ] );
	}

	public static function tick() {
		$start = microtime( true );
		$deadline = $start + 25; // stop processing after 25s to avoid timeouts

		while ( microtime( true ) < $deadline ) {
			$job = Job_Queue::next();
			if ( ! $job ) {
				return;
			}

			Job_Queue::lock( (int) $job['id'] );

			try {
				$result = self::process( $job );
				if ( $result === 'continue' ) {
					Job_Queue::unlock( (int) $job['id'], $job['state'] ? json_decode( $job['state'], true ) : null );
					Job_Queue::reschedule( (int) $job['id'], 2 );
					return; // yield this tick
				} elseif ( $result === 'done' ) {
					Job_Queue::complete( (int) $job['id'] );
				}
			} catch ( \Throwable $e ) {
				Logger::error( 'Job failure: ' . $e->getMessage(), $job['backup_id'] ? (int) $job['backup_id'] : null, [ 'job_id' => $job['id'] ] );
				Job_Queue::fail( (int) $job['id'], $e->getMessage() );
				if ( $job['backup_id'] ) {
					// A restore failure must not corrupt the source backup row's
					// status — it stays a valid, completed backup. Only mark the
					// restore-status slot. Backup-job failures flip the row.
					if ( 'restore' === $job['job_type'] ) {
						Restore_Runner::mark_failed( (int) $job['backup_id'], $e->getMessage() );
					} else {
						global $wpdb;
						$wpdb->update( $wpdb->gembackup_backups, [
							'status'        => 'failed',
							'error_message' => $e->getMessage(),
						], [ 'id' => (int) $job['backup_id'] ] );
						// Alert on failure — a silent backup failure is the worst
						// outcome for a backup plugin.
						Backup_Runner::notify_failed( (int) $job['backup_id'], $e->getMessage() );
					}
				}
			}
		}

		// Still work to do — schedule another tick.
		wp_schedule_single_event( time() + 2, 'gembackup_job_tick' );
	}

	private static function process( $job ) {
		switch ( $job['job_type'] ) {
			case 'backup':
				return Backup_Runner::tick( $job );
			case 'restore':
				return Restore_Runner::tick( $job );
		}
		return 'done';
	}
}
