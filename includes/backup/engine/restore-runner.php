<?php
namespace GemBackup\Engine;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use GemBackup\Jobs\Job_Queue;
use GemBackup\Storage\Driver_Factory;
use GemBackup\Helpers\Search_Replace;

/**
 * Restore Runner — chunked restore from a completed backup row.
 *
 * Phases:
 *   1. fetch       -> ensure backup archive is on disk (download from driver if needed)
 *   2. decrypt     -> if encrypted, decrypt to a temp .zip
 *   3. extract     -> unzip to a staging directory
 *   4. database    -> import the .sql in chunks
 *   5. files       -> copy extracted files over the live wp-content (chunked)
 *   6. search      -> serialized search-replace
 *   7. cleanup
 */
class Restore_Runner {

	/**
	 * Option holding the latest restore's live progress/status so the admin UI
	 * can poll it. Only one restore runs at a time, so a single slot is enough.
	 */
	const STATUS_OPTION = 'gembackup_restore_status';

	public static function start( $backup_id, array $opts = [] ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->gembackup_backups} WHERE id=%d", $backup_id ), ARRAY_A );
		if ( ! $row ) {
			return new \WP_Error( 'gembackup_not_found', 'Backup not found' );
		}

		// Create a pre-restore rollback point so a bad restore is recoverable.
		// The restore job waits for it to finish before touching the live site
		// (see phase_snapshot_wait). Skipped on request or if disabled.
		$snapshot_id = self::maybe_create_snapshot( $backup_id, $opts );

		Logger::info( 'Restore queued', $backup_id );

		self::set_status( $backup_id, [
			'status'      => 'running',
			'phase'       => $snapshot_id ? 'snapshot' : 'queued',
			'progress'    => 0,
			'message'     => '',
			'backup_name' => $row['backup_name'],
			'snapshot_id' => $snapshot_id,
			'started_at'  => current_time( 'mysql' ),
			'completed_at'=> null,
		] );

		return Job_Queue::enqueue( 'restore', [
			'backup_id'   => $backup_id,
			'opts'        => $opts,
			'snapshot_id' => $snapshot_id,
		], $backup_id );
	}

	/**
	 * Queue a rollback-point backup that captures whatever the restore is about
	 * to overwrite (DB and/or files), to local storage. Returns its backup id,
	 * or null when no snapshot was created.
	 *
	 * @param int   $backup_id Backup being restored (for the label).
	 * @param array $opts      Restore options.
	 * @return int|null
	 */
	private static function maybe_create_snapshot( $backup_id, array $opts ) {
		if ( ! empty( $opts['skip_snapshot'] ) ) {
			return null;
		}
		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		// Default ON — only disabled when the setting is explicitly false.
		if ( isset( $settings['restore_safety_snapshot'] ) && empty( $settings['restore_safety_snapshot'] ) ) {
			return null;
		}

		$parts     = $opts['parts'] ?? [ 'database', 'files' ];
		$has_db    = in_array( 'database', $parts, true );
		$has_files = in_array( 'files', $parts, true );
		$snap_type = ( $has_db && $has_files ) ? 'full' : ( $has_files ? 'files' : 'database' );

		$snap = Backup_Runner::start( $snap_type, [ 'local' ], [
			'origin' => 'pre_restore',
			'label'  => 'rollback',
			'name'   => sprintf( 'Rollback point before restore #%d', (int) $backup_id ),
		] );

		return is_wp_error( $snap ) ? null : (int) $snap;
	}

	public static function tick( $job ) {
		$payload   = json_decode( $job['payload'], true );
		$backup_id = (int) $job['backup_id'];
		$state     = $job['state'] ? json_decode( $job['state'], true ) : self::init_state( $payload, $backup_id );

		switch ( $state['phase'] ) {
			case 'snapshot_wait': $state = self::phase_snapshot_wait( $state, $backup_id ); break;
			case 'fetch':    $state = self::phase_fetch( $state, $backup_id ); break;
			case 'decrypt':  $state = self::phase_decrypt( $state, $backup_id ); break;
			case 'extract':  $state = self::phase_extract( $state, $backup_id ); break;
			case 'database': $state = self::phase_database( $state, $backup_id ); break;
			case 'files':    $state = self::phase_files( $state, $backup_id ); break;
			case 'search':   $state = self::phase_search( $state, $backup_id ); break;
			case 'cleanup':  $state = self::phase_cleanup( $state, $backup_id ); break;
		}

		global $wpdb;
		$wpdb->update( $wpdb->gembackup_jobs, [ 'state' => wp_json_encode( $state ) ], [ 'id' => (int) $job['id'] ] );

		if ( $state['phase'] === 'complete' ) {
			self::set_status( $backup_id, [
				'status'       => 'completed',
				'phase'        => 'complete',
				'progress'     => 100,
				'completed_at' => current_time( 'mysql' ),
			] );
			Logger::success( 'Restore complete', $backup_id );
			return 'done';
		}

		self::set_status( $backup_id, [
			'status'   => 'running',
			'phase'    => $state['phase'],
			'progress' => (int) ( $state['progress'] ?? 0 ),
		] );
		return 'continue';
	}

	/**
	 * Mark the active restore as failed. Called by the job processor when a
	 * restore job throws — restore failures must NOT flip the source backup
	 * row's own status, only this restore-status slot.
	 */
	public static function mark_failed( $backup_id, $message ) {
		self::set_status( $backup_id, [
			'status'  => 'failed',
			'message' => $message,
		] );
	}

	/**
	 * Merge a patch into the single restore-status option slot.
	 */
	private static function set_status( $backup_id, array $patch ) {
		$current = get_option( self::STATUS_OPTION, [] );
		if ( ! is_array( $current ) ) {
			$current = [];
		}
		$patch['backup_id']  = (int) $backup_id;
		$patch['updated_at'] = current_time( 'mysql' );
		update_option( self::STATUS_OPTION, array_merge( $current, $patch ), false );
	}

	private static function init_state( $payload, $backup_id ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->gembackup_backups} WHERE id=%d", $backup_id ), ARRAY_A );
		$tmp = GEMBACKUP_BACKUP_DIR_PATH . 'restore-' . wp_generate_uuid4();
		wp_mkdir_p( $tmp );

		$snapshot_id = $payload['snapshot_id'] ?? null;

		return [
			'phase'       => $snapshot_id ? 'snapshot_wait' : 'fetch',
			'snapshot_id' => $snapshot_id,
			'tmp_dir'     => $tmp,
			'archive'     => $row['file_path'],
			'remote'      => $row['remote_path'],
			'driver'      => $row['storage_driver'],
			'encrypted'   => (bool) $row['encrypted'],
			'parts'       => $payload['opts']['parts'] ?? [ 'database', 'files' ],
			'search'      => $payload['opts']['search'] ?? [],
			'sql_pos'     => 0,
			'sql_path'    => '',
			'extracted'   => '',
			'progress'    => 0,
		];
	}

	/**
	 * Hold the restore until the pre-restore rollback snapshot finishes. The job
	 * processor prefers the lower-id snapshot backup job, so by the time this
	 * runs the snapshot is normally already done — this gates on its outcome.
	 */
	private static function phase_snapshot_wait( $state, $backup_id ) {
		global $wpdb;
		$snap_id = (int) ( $state['snapshot_id'] ?? 0 );
		if ( ! $snap_id ) {
			$state['phase'] = 'fetch';
			return $state;
		}

		$snap = $wpdb->get_row( $wpdb->prepare( "SELECT status FROM {$wpdb->gembackup_backups} WHERE id=%d", $snap_id ), ARRAY_A );
		if ( ! $snap ) {
			// Snapshot row vanished — proceed rather than block the restore.
			$state['phase'] = 'fetch';
			return $state;
		}

		if ( 'completed' === $snap['status'] ) {
			Logger::info( "Rollback point #{$snap_id} created", $backup_id );
			$state['phase']    = 'fetch';
			$state['progress'] = 5;
			return $state;
		}

		if ( 'failed' === $snap['status'] ) {
			throw new \RuntimeException( 'Could not create a pre-restore rollback point; restore aborted to protect your site.' );
		}

		// Still running — hold here; the processor will keep ticking the snapshot.
		return $state;
	}

	private static function phase_fetch( $state, $backup_id ) {
		if ( $state['archive'] && file_exists( $state['archive'] ) ) {
			$state['phase'] = $state['encrypted'] ? 'decrypt' : 'extract';
			return $state;
		}

		// A local backup with no remote copy can't be re-fetched — the file is
		// simply gone. Fail clearly instead of asking the local driver to
		// "download" a path it can't resolve.
		if ( 'local' === $state['driver'] || empty( $state['remote'] ) ) {
			throw new \RuntimeException( 'Backup archive is missing and cannot be restored.' );
		}

		// Download via driver.
		$driver = Driver_Factory::make( $state['driver'] );
		if ( is_wp_error( $driver ) ) {
			throw new \RuntimeException( 'Driver unavailable: ' . $driver->get_error_message() );
		}
		$local = trailingslashit( $state['tmp_dir'] ) . basename( $state['remote'] );
		if ( method_exists( $driver, 'download' ) ) {
			$res = $driver->download( $state['remote'], $local );
			if ( is_wp_error( $res ) ) {
				throw new \RuntimeException( 'Download failed: ' . $res->get_error_message() );
			}
		} else {
			throw new \RuntimeException( 'Driver does not support download yet' );
		}
		$state['archive'] = $local;
		$state['phase']   = $state['encrypted'] ? 'decrypt' : 'extract';
		$state['progress'] = 10;
		return $state;
	}

	private static function phase_decrypt( $state, $backup_id ) {
		$decrypted = trailingslashit( $state['tmp_dir'] ) . 'decrypted.zip';
		$pass = Encryption::get_passphrase();
		$res = Encryption::decrypt_file( $state['archive'], $decrypted, $pass );
		if ( is_wp_error( $res ) ) {
			throw new \RuntimeException( $res->get_error_message() );
		}
		$state['archive'] = $decrypted;
		$state['phase']   = 'extract';
		$state['progress'] = 20;
		return $state;
	}

	private static function phase_extract( $state, $backup_id ) {
		$dest = trailingslashit( $state['tmp_dir'] ) . 'extracted';
		$res  = File_Archiver::extract( $state['archive'], $dest );
		if ( is_wp_error( $res ) ) {
			throw new \RuntimeException( $res->get_error_message() );
		}
		$state['extracted'] = $dest;
		$state['sql_path']  = $dest . '/gembackup-database.sql';
		$state['progress']  = 35;
		$state['phase']     = in_array( 'database', $state['parts'], true ) && file_exists( $state['sql_path'] ) ? 'database' : 'files';
		return $state;
	}

	private static function phase_database( $state, $backup_id ) {
		global $wpdb;
		$fp = fopen( $state['sql_path'], 'rb' );
		if ( ! $fp ) {
			throw new \RuntimeException( 'Cannot read SQL file' );
		}
		fseek( $fp, $state['sql_pos'] );

		$deadline = microtime( true ) + 10;
		$buffer = '';
		while ( microtime( true ) < $deadline && ! feof( $fp ) ) {
			$line = fgets( $fp );
			if ( $line === false ) break;
			$buffer .= $line;
			if ( substr( rtrim( $line ), -1 ) === ';' ) {
				$sql = trim( $buffer );
				$buffer = '';
				if ( $sql === '' || strpos( $sql, '--' ) === 0 ) continue;
				$wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			}
		}
		$size = max( 1, (int) filesize( $state['sql_path'] ) );
		$state['sql_pos']  = ftell( $fp );
		$state['progress'] = (int) min( 70, 35 + ( ( $state['sql_pos'] / $size ) * 35 ) );
		$reached_eof       = feof( $fp );
		fclose( $fp );

		// Done once the whole SQL file is consumed. (Previously this tested
		// feof(fopen(...)) on a brand-new handle, which is ALWAYS false — so the
		// database phase never finished and the restore hung at ~70%.)
		if ( $reached_eof || $state['sql_pos'] >= $size ) {
			$state['phase'] = in_array( 'files', $state['parts'], true ) ? 'files' : 'search';
		}
		return $state;
	}

	private static function phase_files( $state, $backup_id ) {
		// Copy extracted wp-content over the live one (simple synchronous for now).
		$source = $state['extracted'] . '/wp-content';
		if ( is_dir( $source ) ) {
			self::copy_tree( $source, WP_CONTENT_DIR );
		}
		$state['progress'] = 90;
		$state['phase'] = ! empty( $state['search'] ) ? 'search' : 'cleanup';
		return $state;
	}

	private static function phase_search( $state, $backup_id ) {
		$replaced = 0;
		foreach ( $state['search'] as $pair ) {
			if ( ! empty( $pair['from'] ) && isset( $pair['to'] ) ) {
				$replaced += Search_Replace::replace_all_tables( $pair['from'], $pair['to'] );
			}
		}
		Logger::info( "Search-replace touched {$replaced} rows", $backup_id );
		$state['progress'] = 95;
		$state['phase']    = 'cleanup';
		return $state;
	}

	private static function phase_cleanup( $state, $backup_id ) {
		// Remove temp dir.
		self::rmdir_recursive( $state['tmp_dir'] );
		$state['phase'] = 'complete';
		$state['progress'] = 100;
		return $state;
	}

	private static function copy_tree( $src, $dst ) {
		if ( ! is_dir( $dst ) ) wp_mkdir_p( $dst );
		$it = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $src, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::SELF_FIRST
		);
		foreach ( $it as $file ) {
			$target = $dst . '/' . substr( $file->getPathname(), strlen( $src ) + 1 );
			if ( $file->isDir() ) {
				wp_mkdir_p( $target );
			} else {
				@copy( $file->getPathname(), $target );
			}
		}
	}

	private static function rmdir_recursive( $dir ) {
		if ( ! is_dir( $dir ) ) return;
		$items = @scandir( $dir );
		if ( ! $items ) return;
		foreach ( $items as $item ) {
			if ( $item === '.' || $item === '..' ) continue;
			$path = $dir . '/' . $item;
			if ( is_dir( $path ) ) {
				self::rmdir_recursive( $path );
			} else {
				@unlink( $path );
			}
		}
		@rmdir( $dir );
	}
}
