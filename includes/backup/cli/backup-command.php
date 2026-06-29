<?php
namespace GemBackup\Cli;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use GemBackup\Engine\Backup_Runner;
use GemBackup\Engine\Restore_Runner;
use GemBackup\Storage\Driver_Factory;

class Backup_Command {

	public static function register() {
		\WP_CLI::add_command( 'gembackup', __CLASS__ );
	}

	/**
	 * Run a backup synchronously.
	 *
	 * ## OPTIONS
	 *
	 * [--type=<type>]
	 * : full | database | files | media
	 *
	 * [--to=<drivers>]
	 * : Comma-separated storage drivers (e.g. local,s3)
	 *
	 * [--label=<label>]
	 * : Optional label
	 *
	 * ## EXAMPLES
	 *
	 *     wp gembackup run --type=full --to=local,s3
	 */
	public function run( $args, $assoc ) {
		$type    = $assoc['type'] ?? 'full';
		$drivers = array_filter( array_map( 'trim', explode( ',', $assoc['to'] ?? 'local' ) ) );
		$label   = $assoc['label'] ?? null;

		$backup_id = Backup_Runner::start( $type, $drivers, [ 'origin' => 'cli', 'label' => $label ] );
		if ( is_wp_error( $backup_id ) ) {
			\WP_CLI::error( $backup_id->get_error_message() );
		}

		\WP_CLI::log( "Backup #{$backup_id} queued. Processing…" );
		$this->drain_jobs( $backup_id );
		\WP_CLI::success( "Backup #{$backup_id} complete." );
	}

	/**
	 * Restore from a backup id.
	 *
	 * ## OPTIONS
	 *
	 * <id>
	 * : Backup ID
	 *
	 * [--parts=<parts>]
	 * : Comma-separated parts (database,files). Default: database,files
	 *
	 * [--search=<from>]
	 * : Source string for serialized search-replace
	 *
	 * [--replace=<to>]
	 * : Target string for serialized search-replace
	 */
	public function restore( $args, $assoc ) {
		$backup_id = (int) ( $args[0] ?? 0 );
		if ( ! $backup_id ) {
			\WP_CLI::error( 'Backup ID required.' );
		}

		$parts = array_filter( array_map( 'trim', explode( ',', $assoc['parts'] ?? 'database,files' ) ) );
		$opts  = [ 'parts' => $parts, 'search' => [] ];
		if ( ! empty( $assoc['search'] ) && isset( $assoc['replace'] ) ) {
			$opts['search'][] = [ 'from' => $assoc['search'], 'to' => $assoc['replace'] ];
		}

		$job = Restore_Runner::start( $backup_id, $opts );
		if ( is_wp_error( $job ) ) {
			\WP_CLI::error( $job->get_error_message() );
		}
		\WP_CLI::log( "Restore queued. Processing…" );
		$this->drain_jobs( $backup_id );
		\WP_CLI::success( 'Restore complete.' );
	}

	/**
	 * List backups.
	 */
	public function list( $args, $assoc ) {
		global $wpdb;
		$rows = $wpdb->get_results( "SELECT id, backup_name, backup_type, status, file_size, created_at FROM {$wpdb->gembackup_backups} ORDER BY created_at DESC LIMIT 50", ARRAY_A );
		\WP_CLI\Utils\format_items( 'table', $rows, [ 'id', 'backup_name', 'backup_type', 'status', 'file_size', 'created_at' ] );
	}

	/**
	 * Delete a backup.
	 *
	 * ## OPTIONS
	 * <id>
	 * : Backup id
	 */
	public function delete( $args ) {
		global $wpdb;
		$id = (int) $args[0];
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->gembackup_backups} WHERE id=%d", $id ), ARRAY_A );
		if ( ! $row ) \WP_CLI::error( 'Not found.' );
		if ( $row['file_path'] && file_exists( $row['file_path'] ) ) @unlink( $row['file_path'] );
		$wpdb->delete( $wpdb->gembackup_backups, [ 'id' => $id ] );
		\WP_CLI::success( "Deleted #{$id}" );
	}

	/**
	 * Verify a backup's integrity hash.
	 *
	 * ## OPTIONS
	 * <id>
	 * : Backup id
	 */
	public function verify( $args ) {
		global $wpdb;
		$id = (int) $args[0];
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->gembackup_backups} WHERE id=%d", $id ), ARRAY_A );
		if ( ! $row ) \WP_CLI::error( 'Not found.' );
		if ( ! $row['file_path'] || ! file_exists( $row['file_path'] ) ) \WP_CLI::error( 'Backup file not available locally.' );
		$actual = hash_file( 'sha256', $row['file_path'] );
		if ( $row['manifest_hash'] && $row['manifest_hash'] !== $actual ) {
			\WP_CLI::error( "Integrity check FAILED. Expected {$row['manifest_hash']} got {$actual}" );
		}
		\WP_CLI::success( "OK ({$actual})" );
	}

	/**
	 * Test a driver connection.
	 *
	 * ## OPTIONS
	 * <driver>
	 * : Driver key (local, s3, r2, gdrive, …)
	 */
	public function test_driver( $args ) {
		$driver = Driver_Factory::make( $args[0] );
		if ( is_wp_error( $driver ) ) \WP_CLI::error( $driver->get_error_message() );
		$result = $driver->test_connection();
		if ( is_wp_error( $result ) ) \WP_CLI::error( $result->get_error_message() );
		\WP_CLI::success( "{$args[0]} connection OK" );
	}

	private function drain_jobs( $backup_id, $max_seconds = 600 ) {
		global $wpdb;
		$deadline = microtime( true ) + $max_seconds;
		while ( microtime( true ) < $deadline ) {
			$status = $wpdb->get_var( $wpdb->prepare( "SELECT status FROM {$wpdb->gembackup_backups} WHERE id=%d", $backup_id ) );
			if ( in_array( $status, [ 'completed', 'failed' ], true ) ) {
				return;
			}
			\GemBackup\Jobs\Job_Processor::tick();
			usleep( 200000 );
		}
	}
}
