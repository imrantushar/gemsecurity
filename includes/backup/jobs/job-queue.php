<?php
namespace GemBackup\Jobs;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Job_Queue {

	public static function enqueue( $type, array $payload, $backup_id = null, $run_after = null ) {
		global $wpdb;
		$wpdb->insert( $wpdb->gembackup_jobs, [
			'job_type'   => $type,
			'backup_id'  => $backup_id,
			'payload'    => wp_json_encode( $payload ),
			'state'      => null,
			'status'     => 'queued',
			'attempts'   => 0,
			'run_after'  => $run_after ?: current_time( 'mysql' ),
			'updated_at' => current_time( 'mysql' ),
		] );
		$id = (int) $wpdb->insert_id;

		// Spawn an async tick immediately so the job starts without waiting for cron.
		wp_schedule_single_event( time() + 1, 'gembackup_job_tick' );

		return $id;
	}

	public static function next() {
		global $wpdb;
		$now = current_time( 'mysql' );
		return $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$wpdb->gembackup_jobs} WHERE status IN ('queued','running') AND (locked_until IS NULL OR locked_until < %s) AND (run_after IS NULL OR run_after <= %s) ORDER BY id ASC LIMIT 1",
			$now,
			$now
		), ARRAY_A );
	}

	public static function lock( $job_id, $seconds = 120 ) {
		global $wpdb;
		$until = gmdate( 'Y-m-d H:i:s', time() + $seconds );
		$wpdb->update( $wpdb->gembackup_jobs, [
			'locked_until' => $until,
			'status'       => 'running',
			'updated_at'   => current_time( 'mysql' ),
		], [ 'id' => $job_id ] );
	}

	public static function unlock( $job_id, $state = null ) {
		global $wpdb;
		$wpdb->update( $wpdb->gembackup_jobs, [
			'locked_until' => null,
			'state'        => $state !== null ? wp_json_encode( $state ) : null,
			'updated_at'   => current_time( 'mysql' ),
		], [ 'id' => $job_id ] );
	}

	public static function complete( $job_id, $state = null ) {
		global $wpdb;
		$wpdb->update( $wpdb->gembackup_jobs, [
			'locked_until' => null,
			'state'        => $state !== null ? wp_json_encode( $state ) : null,
			'status'       => 'completed',
			'updated_at'   => current_time( 'mysql' ),
		], [ 'id' => $job_id ] );
	}

	public static function fail( $job_id, $message ) {
		global $wpdb;
		$wpdb->update( $wpdb->gembackup_jobs, [
			'locked_until' => null,
			'status'       => 'failed',
			'state'        => wp_json_encode( [ 'error' => $message ] ),
			'updated_at'   => current_time( 'mysql' ),
		], [ 'id' => $job_id ] );
	}

	public static function reschedule( $job_id, $seconds = 5 ) {
		wp_schedule_single_event( time() + $seconds, 'gembackup_job_tick' );
	}
}
