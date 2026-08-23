<?php
namespace GemBackup\Engine;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use GemBackup\Helper;
use GemBackup\Jobs\Job_Queue;
use GemBackup\Storage\Driver_Factory;

/**
 * Backup Runner — orchestrates a chunked backup job.
 *
 * Backup state machine (state.phase):
 *   1. init        -> set up temp dir, paths
 *   2. database    -> dump SQL (chunked across ticks)
 *   3. archive     -> build file list + zip files (chunked)
 *   4. finalize    -> add manifest + sql into zip, compute hash
 *   5. encrypt     -> optional, encrypt the zip
 *   6. upload      -> push to each driver (one per tick)
 *   7. cleanup     -> delete temp files, mark backup completed
 */
class Backup_Runner {

	/**
	 * Create a backup row + queue the worker job.
	 */
	public static function start( $type, array $drivers, array $opts = [] ) {
		global $wpdb;

		if ( ! in_array( $type, [ 'full', 'database', 'files', 'media' ], true ) ) {
			return new \WP_Error( 'gembackup_invalid_type', 'Invalid backup type: ' . $type );
		}
		$drivers = array_values( array_filter( $drivers ) );
		if ( empty( $drivers ) ) {
			$drivers = [ 'local' ];
		}

		$timestamp = current_time( 'mysql' );
		$name = $opts['name'] ?? sprintf( '%s backup — %s', ucfirst( $type ), wp_date( 'Y-m-d H:i' ) );

		$wpdb->insert( $wpdb->gembackup_backups, [
			'backup_name'    => $name,
			'backup_type'    => $type,
			'storage_driver' => $drivers[0],
			'status'         => 'pending',
			'origin'         => $opts['origin'] ?? 'manual',
			'label'          => $opts['label'] ?? null,
			'schedule_id'    => $opts['schedule_id'] ?? null,
			'encrypted'      => ! empty( $opts['encrypted'] ) ? 1 : 0,
			'created_at'     => $timestamp,
		] );
		$backup_id = (int) $wpdb->insert_id;

		Logger::info( "Backup queued ({$type}) → " . implode( ', ', $drivers ), $backup_id );

		$job_id = Job_Queue::enqueue( 'backup', [
			'backup_id' => $backup_id,
			'type'      => $type,
			'drivers'   => $drivers,
			'opts'      => $opts,
		], $backup_id );

		return $backup_id;
	}

	public static function tick( $job ) {
		global $wpdb;
		$payload = json_decode( $job['payload'], true );
		$state   = $job['state'] ? json_decode( $job['state'], true ) : self::init_state( $payload );
		$backup_id = (int) $job['backup_id'];

		// Mark backup as running on first tick.
		$wpdb->update( $wpdb->gembackup_backups, [
			'status'     => 'running',
			'started_at' => $wpdb->get_var( $wpdb->prepare( "SELECT started_at FROM {$wpdb->gembackup_backups} WHERE id=%d", $backup_id ) ) ?: current_time( 'mysql' ),
		], [ 'id' => $backup_id ] );

		switch ( $state['phase'] ) {
			case 'init':
				$state = self::phase_init( $state, $backup_id );
				break;
			case 'database':
				$state = self::phase_database( $state, $backup_id );
				break;
			case 'archive':
				$state = self::phase_archive( $state, $backup_id );
				break;
			case 'finalize':
				$state = self::phase_finalize( $state, $backup_id );
				break;
			case 'encrypt':
				$state = self::phase_encrypt( $state, $backup_id );
				break;
			case 'upload':
				$state = self::phase_upload( $state, $backup_id );
				break;
			case 'cleanup':
				$state = self::phase_cleanup( $state, $backup_id );
				break;
		}

		// Persist state + progress.
		$wpdb->update( $wpdb->gembackup_backups, [
			'state'    => wp_json_encode( $state ),
			'progress' => (int) ( $state['progress'] ?? 0 ),
		], [ 'id' => $backup_id ] );

		// Persist state on the job too so the processor can resume.
		global $wpdb;
		$wpdb->update( $wpdb->gembackup_jobs, [ 'state' => wp_json_encode( $state ) ], [ 'id' => (int) $job['id'] ] );
		$job['state'] = wp_json_encode( $state );

		if ( $state['phase'] === 'complete' ) {
			$wpdb->update( $wpdb->gembackup_backups, [
				'status'       => 'completed',
				'progress'     => 100,
				'completed_at' => current_time( 'mysql' ),
			], [ 'id' => $backup_id ] );
			Logger::success( 'Backup completed', $backup_id );
			self::prune_old_backups();
			self::notify_complete( $backup_id );
			return 'done';
		}

		return 'continue';
	}

	private static function init_state( $payload ) {
		$tmp_dir = trailingslashit( GEMBACKUP_BACKUP_DIR_PATH ) . 'tmp-' . wp_generate_uuid4();
		wp_mkdir_p( $tmp_dir );

		return [
			'phase'      => 'init',
			'progress'   => 0,
			'tmp_dir'    => $tmp_dir,
			'type'       => $payload['type'],
			'drivers'    => $payload['drivers'],
			'opts'       => $payload['opts'],
			'sql_path'   => '',
			'zip_path'   => '',
			'final_path' => '',
			'manifest'   => null,
			'db_state'   => null,
			'arc_state'  => null,
			'uploaded'   => [],
		];
	}

	private static function phase_init( $state, $backup_id ) {
		$slug = sanitize_title( str_replace( [ ' ', ':' ], '-', $state['type'] . '-' . current_time( 'Y-m-d-His' ) ) );
		$state['sql_path']   = trailingslashit( $state['tmp_dir'] ) . 'database.sql';
		$state['zip_path']   = trailingslashit( $state['tmp_dir'] ) . "gembackup-{$backup_id}-{$slug}.zip";
		$state['final_path'] = $state['zip_path'];

		$state['manifest'] = Manifest::build( $backup_id, $state['type'] );

		// Skip DB phase for files/media-only.
		$state['phase'] = in_array( $state['type'], [ 'files', 'media' ], true ) ? 'archive' : 'database';
		$state['db_state'] = $state['phase'] === 'database' ? Database_Dumper::init_state() : null;
		$state['progress'] = 2;

		Logger::info( 'Backup started', $backup_id );
		return $state;
	}

	private static function phase_database( $state, $backup_id ) {
		$state['db_state'] = Database_Dumper::tick( $state['sql_path'], $state['db_state'] );
		$state['progress'] = (int) ( 5 + ( Database_Dumper::progress( $state['db_state'] ) * 0.30 ) );

		if ( ! empty( $state['db_state']['completed'] ) ) {
			$state['manifest']['sql_files'][] = 'gembackup-database.sql';
			$state['manifest']['integrity']['gembackup-database.sql'] = Manifest::hash_file( $state['sql_path'] );

			if ( $state['type'] === 'database' ) {
				$state['phase'] = 'finalize';
			} else {
				$state['phase']     = 'archive';
				$state['arc_state'] = File_Archiver::init_state( $state['type'] );
				if ( is_wp_error( $state['arc_state'] ) ) {
					throw new \RuntimeException( $state['arc_state']->get_error_message() );
				}
			}
		}
		return $state;
	}

	private static function phase_archive( $state, $backup_id ) {
		if ( $state['arc_state'] === null ) {
			$state['arc_state'] = File_Archiver::init_state( $state['type'] );
			if ( is_wp_error( $state['arc_state'] ) ) {
				throw new \RuntimeException( $state['arc_state']->get_error_message() );
			}
		}
		$state['arc_state'] = File_Archiver::tick( $state['zip_path'], $state['arc_state'] );
		if ( is_wp_error( $state['arc_state'] ) ) {
			throw new \RuntimeException( $state['arc_state']->get_error_message() );
		}
		$state['progress'] = (int) ( 40 + ( File_Archiver::progress( $state['arc_state'] ) * 0.40 ) );

		if ( ! empty( $state['arc_state']['completed'] ) ) {
			$state['phase'] = 'finalize';
		}
		return $state;
	}

	private static function phase_finalize( $state, $backup_id ) {
		// Write manifest to disk first.
		$manifest_path = trailingslashit( $state['tmp_dir'] ) . 'manifest.json';
		Manifest::write( $manifest_path, $state['manifest'] );

		// If only DB → bundle sql + manifest into a zip.
		if ( $state['type'] === 'database' ) {
			$zip = new \ZipArchive();
			if ( $zip->open( $state['zip_path'], \ZipArchive::CREATE ) === true ) {
				$zip->addFile( $state['sql_path'], 'gembackup-database.sql' );
				$zip->addFile( $manifest_path, 'manifest.json' );
				$zip->close();
			}
		} else {
			File_Archiver::add_sql_to_zip( $state['zip_path'], $state['sql_path'], $manifest_path );
		}

		$state['manifest']['integrity']['archive'] = Manifest::hash_file( $state['zip_path'] );
		$state['progress'] = 85;
		$state['phase'] = ! empty( $state['opts']['encrypted'] ) && Encryption::is_enabled() ? 'encrypt' : 'upload';
		return $state;
	}

	private static function phase_encrypt( $state, $backup_id ) {
		$encrypted_path = $state['zip_path'] . '.enc';
		$pass = Encryption::get_passphrase();
		$res  = Encryption::encrypt_file( $state['zip_path'], $encrypted_path, $pass );
		if ( is_wp_error( $res ) ) {
			throw new \RuntimeException( $res->get_error_message() );
		}
		@unlink( $state['zip_path'] );
		$state['final_path'] = $encrypted_path;
		$state['progress']   = 90;
		$state['phase']      = 'upload';
		Logger::info( 'Backup file encrypted', $backup_id );
		return $state;
	}

	private static function phase_upload( $state, $backup_id ) {
		global $wpdb;
		$drivers   = $state['drivers'];
		$uploaded  = $state['uploaded'];
		$remaining = array_values( array_diff( $drivers, array_keys( $uploaded ) ) );

		if ( empty( $remaining ) ) {
			$state['phase']    = 'cleanup';
			$state['progress'] = 95;
			return $state;
		}

		$driver_key = $remaining[0];
		Logger::info( "Uploading to {$driver_key}", $backup_id );

		// Local driver = move file into the backup dir, no remote upload needed.
		if ( $driver_key === 'local' ) {
			$dest = GEMBACKUP_BACKUP_DIR_PATH . basename( $state['final_path'] );
			if ( $state['final_path'] !== $dest && ! @rename( $state['final_path'], $dest ) ) {
				@copy( $state['final_path'], $dest );
			}
			$state['final_path']     = $dest;
			$state['uploaded'][ $driver_key ] = $dest;

			$wpdb->update( $wpdb->gembackup_backups, [
				'file_path'      => $dest,
				'file_size'      => filesize( $dest ),
				'manifest_hash'  => $state['manifest']['integrity']['archive'] ?? null,
			], [ 'id' => $backup_id ] );
		} else {
			$driver = Driver_Factory::make( $driver_key );
			if ( is_wp_error( $driver ) ) {
				Logger::warning( "Skipping {$driver_key}: " . $driver->get_error_message(), $backup_id );
				$state['uploaded'][ $driver_key ] = false;
				return $state;
			}
			$remote_name = basename( $state['final_path'] );
			$result = $driver->upload( $state['final_path'], $remote_name );
			if ( is_wp_error( $result ) ) {
				Logger::warning( "Upload to {$driver_key} failed: " . $result->get_error_message(), $backup_id );
				$state['uploaded'][ $driver_key ] = false;
			} else {
				$state['uploaded'][ $driver_key ] = $remote_name;
				Logger::success( "Uploaded to {$driver_key}", $backup_id );
				$wpdb->update( $wpdb->gembackup_backups, [
					'remote_path' => $remote_name,
					'file_size'   => filesize( $state['final_path'] ),
				], [ 'id' => $backup_id ] );
			}
		}

		$state['progress'] = (int) ( 90 + ( ( count( $state['uploaded'] ) / max( 1, count( $drivers ) ) ) * 5 ) );
		return $state;
	}

	private static function phase_cleanup( $state, $backup_id ) {
		// Remove temp dir but keep final file at local destination if local was a driver.
		$tmp = $state['tmp_dir'];
		if ( $tmp && file_exists( $tmp ) ) {
			self::rmdir_recursive( $tmp );
		}

		do_action( 'gembackup/after_backup', $backup_id, $state );

		$state['phase']    = 'complete';
		$state['progress'] = 100;
		return $state;
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

	private static function prune_old_backups() {
		global $wpdb;
		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		$keep = max( 1, (int) ( $settings['backup_retention'] ?? 10 ) );

		$ids = $wpdb->get_col( $wpdb->prepare(
			"SELECT id FROM {$wpdb->gembackup_backups} WHERE status='completed' ORDER BY created_at DESC LIMIT 1000 OFFSET %d",
			$keep
		) );
		foreach ( $ids as $id ) {
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->gembackup_backups} WHERE id=%d", $id ), ARRAY_A );
			if ( ! $row ) continue;
			if ( $row['file_path'] && file_exists( $row['file_path'] ) ) {
				@unlink( $row['file_path'] );
			}
			if ( $row['remote_path'] ) {
				$drv = Driver_Factory::make( $row['storage_driver'] );
				if ( $drv && ! is_wp_error( $drv ) ) {
					$drv->delete( $row['remote_path'] );
				}
			}
			$wpdb->delete( $wpdb->gembackup_backups, [ 'id' => $id ] );
			Logger::info( "Pruned old backup #{$id}" );
		}
	}

	private static function notify_complete( $backup_id ) {
		self::dispatch_notification( $backup_id, 'completed' );
	}

	/**
	 * Notify on a failed backup. A silent backup failure is the worst outcome
	 * for a backup plugin, so this path matters as much as the success path.
	 *
	 * @param int    $backup_id
	 * @param string $error
	 */
	public static function notify_failed( $backup_id, $error = '' ) {
		self::dispatch_notification( $backup_id, 'failed', $error );
	}

	private static function dispatch_notification( $backup_id, $event, $error = '' ) {
		global $wpdb;
		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->gembackup_backups} WHERE id=%d", $backup_id ), ARRAY_A );
		if ( ! $row ) {
			return;
		}

		$host    = wp_parse_url( home_url(), PHP_URL_HOST );
		$is_fail = ( 'failed' === $event );
		$error   = $error ?: ( $row['error_message'] ?? '' );

		// Email. Backup notices go to the site's one security address and
		// through the shared mailer, so they look like — and land with — every
		// other notification the plugin sends. Success notices are opt-in via
		// the same toggle as failures.
		if ( ! empty( $settings['notify_on_failure'] ) ) {
			if ( $is_fail ) {
				\GemSecurity\Mailer::send(
					\GemSecurity\Mailer::recipient(),
					'⚠️',
					sprintf(
						/* translators: %s: backup name. */
						__( 'Backup failed: %s', 'gemsecurity' ),
						$row['backup_name']
					),
					[
						[
							'type' => 'notice',
							'tone' => 'critical',
							'text' => __( 'A scheduled backup did not complete. Until it does, this site has no fresh restore point.', 'gemsecurity' ),
						],
						[
							'type'    => 'table',
							'heading' => __( 'Details', 'gemsecurity' ),
							'rows'    => [
								[ __( 'Backup', 'gemsecurity' ), sprintf( '#%d (%s)', $backup_id, $row['backup_type'] ) ],
								[ __( 'Error', 'gemsecurity' ), $error ?: __( 'Unknown error', 'gemsecurity' ) ],
								[ __( 'Destination', 'gemsecurity' ), $row['storage_driver'] ],
								[ __( 'When', 'gemsecurity' ), current_time( 'mysql' ) ],
							],
						],
						[
							'type'  => 'button',
							'url'   => admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG . '-backup' ),
							'label' => __( 'Open Backup', 'gemsecurity' ),
						],
					]
				);
			} else {
				\GemSecurity\Mailer::send(
					\GemSecurity\Mailer::recipient(),
					'✅',
					sprintf(
						/* translators: %s: backup name. */
						__( 'Backup completed: %s', 'gemsecurity' ),
						$row['backup_name']
					),
					[
						[
							'type'    => 'table',
							'heading' => __( 'Details', 'gemsecurity' ),
							'rows'    => [
								[ __( 'Backup', 'gemsecurity' ), sprintf( '#%d (%s)', $backup_id, $row['backup_type'] ) ],
								[ __( 'Size', 'gemsecurity' ), size_format( (int) $row['file_size'] ) ],
								[ __( 'Destination', 'gemsecurity' ), $row['storage_driver'] ],
							],
						],
					]
				);
			}
		}

		// Webhook — fire for both completed and failed events. This is the same
		// generic webhook the rest of the plugin posts alerts to; backup used
		// to carry a second URL setting of its own that had no UI at all.
		$webhook = trim( (string) \GemSecurity\Helper::get_setting( 'alert_webhook_url', '' ) );
		if ( '' !== $webhook ) {
			wp_remote_post( $webhook, [
				'timeout' => 5,
				'headers' => [ 'Content-Type' => 'application/json' ],
				'body'    => wp_json_encode( [
					'event'     => $is_fail ? 'backup.failed' : 'backup.completed',
					'backup_id' => $backup_id,
					'type'      => $row['backup_type'],
					'status'    => $row['status'],
					'size'      => (int) $row['file_size'],
					'error'     => $is_fail ? ( $error ?: 'Unknown error' ) : null,
					'site'      => home_url(),
				] ),
			] );
		}
	}
}
