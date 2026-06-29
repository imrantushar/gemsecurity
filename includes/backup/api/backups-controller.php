<?php
namespace GemBackup\Api;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use GemBackup\Engine\Backup_Runner;
use GemBackup\Engine\Restore_Runner;

class Backups_Controller extends Rest_Controller {

	protected $rest_base = 'backups';

	public function register_routes() {
		register_rest_route( $this->namespace, '/' . $this->rest_base, [
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'list_backups' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'create_backup' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
		] );

		register_rest_route( $this->namespace, '/' . $this->rest_base . '/(?P<id>\d+)', [
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'get_backup' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
			[
				'methods'             => 'DELETE',
				'callback'            => [ $this, 'delete_backup' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
		] );

		register_rest_route( $this->namespace, '/' . $this->rest_base . '/(?P<id>\d+)/restore', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'restore_backup' ],
			'permission_callback' => [ $this, 'permissions_check' ],
		] );

		register_rest_route( $this->namespace, '/' . $this->rest_base . '/(?P<id>\d+)/cancel', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'cancel_backup' ],
			'permission_callback' => [ $this, 'permissions_check' ],
		] );

		register_rest_route( $this->namespace, '/' . $this->rest_base . '/(?P<id>\d+)/download', [
			'methods'             => 'GET',
			'callback'            => [ $this, 'download_backup' ],
			'permission_callback' => [ $this, 'permissions_check' ],
		] );

		// Upload an external backup archive (.zip/.enc) so it can be restored.
		register_rest_route( $this->namespace, '/' . $this->rest_base . '/upload', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'upload_backup' ],
			'permission_callback' => [ $this, 'permissions_check' ],
		] );

		// Live status of the most recent restore (for progress polling).
		register_rest_route( $this->namespace, '/' . $this->rest_base . '/restore-status', [
			'methods'             => 'GET',
			'callback'            => [ $this, 'restore_status' ],
			'permission_callback' => [ $this, 'permissions_check' ],
		] );
	}

	public function list_backups( $request ) {
		global $wpdb;
		$status = $request->get_param( 'status' );
		$search = $request->get_param( 'search' );
		$limit  = max( 1, min( 200, (int) ( $request->get_param( 'limit' ) ?: 50 ) ) );
		$offset = max( 0, (int) ( $request->get_param( 'offset' ) ?: 0 ) );

		$where = [ '1=1' ];
		$args  = [];

		if ( $status && in_array( $status, [ 'pending', 'running', 'completed', 'failed' ], true ) ) {
			$where[] = 'status = %s';
			$args[]  = $status;
		}
		if ( $search ) {
			$where[] = 'backup_name LIKE %s';
			$args[]  = '%' . $wpdb->esc_like( $search ) . '%';
		}

		$where_sql = implode( ' AND ', $where );
		$sql = "SELECT * FROM {$wpdb->gembackup_backups} WHERE {$where_sql} ORDER BY created_at DESC LIMIT %d OFFSET %d";
		$args[] = $limit;
		$args[] = $offset;
		$rows = $wpdb->get_results( $wpdb->prepare( $sql, $args ), ARRAY_A );

		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->gembackup_backups} WHERE {$where_sql}" );

		return $this->ok( [
			'items' => array_map( [ $this, 'format_backup' ], $rows ),
			'total' => $total,
		] );
	}

	public function get_backup( $request ) {
		global $wpdb;
		$id = (int) $request['id'];
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->gembackup_backups} WHERE id=%d", $id ), ARRAY_A );
		if ( ! $row ) {
			return $this->fail( 'gembackup_not_found', __( 'Backup not found.', 'gembackup' ), 404 );
		}
		return $this->ok( $this->format_backup( $row ) );
	}

	public function create_backup( $request ) {
		$params = $request->get_json_params();
		$type   = sanitize_key( $params['type'] ?? 'full' );
		$drivers = $params['drivers'] ?? [ 'local' ];
		if ( ! is_array( $drivers ) ) {
			$drivers = [ $drivers ];
		}
		$drivers = array_map( 'sanitize_key', $drivers );

		$opts = [
			'origin'    => 'manual',
			'label'     => isset( $params['label'] ) ? sanitize_text_field( $params['label'] ) : null,
			'name'      => isset( $params['name'] ) ? sanitize_text_field( $params['name'] ) : null,
			'encrypted' => ! empty( $params['encrypted'] ),
		];

		$backup_id = Backup_Runner::start( $type, $drivers, $opts );
		if ( is_wp_error( $backup_id ) ) {
			return $backup_id;
		}

		return $this->ok( [ 'id' => $backup_id ] );
	}

	public function delete_backup( $request ) {
		global $wpdb;
		$id = (int) $request['id'];
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->gembackup_backups} WHERE id=%d", $id ), ARRAY_A );
		if ( ! $row ) {
			return $this->fail( 'gembackup_not_found', __( 'Backup not found.', 'gembackup' ), 404 );
		}

		// Delete local file if exists.
		if ( $row['file_path'] && file_exists( $row['file_path'] ) ) {
			@unlink( $row['file_path'] );
		}

		// Delete remote file via driver.
		if ( $row['remote_path'] ) {
			$driver = \GemBackup\Storage\Driver_Factory::make( $row['storage_driver'] );
			if ( $driver && ! is_wp_error( $driver ) ) {
				$driver->delete( $row['remote_path'] );
			}
		}

		$wpdb->delete( $wpdb->gembackup_backups, [ 'id' => $id ] );
		return $this->ok( [ 'deleted' => true ] );
	}

	public function cancel_backup( $request ) {
		global $wpdb;
		$id = (int) $request['id'];
		$wpdb->update( $wpdb->gembackup_backups, [ 'status' => 'failed', 'error_message' => 'Cancelled by user' ], [ 'id' => $id ] );
		$wpdb->update( $wpdb->gembackup_jobs, [ 'status' => 'failed' ], [ 'backup_id' => $id, 'status' => 'queued' ] );
		return $this->ok( [ 'cancelled' => true ] );
	}

	public function restore_backup( $request ) {
		$id = (int) $request['id'];
		$params = $request->get_json_params();
		$opts = [
			'parts'         => $params['parts'] ?? [ 'database', 'files' ],
			'search'        => $params['search_replace'] ?? [],
			'skip_snapshot' => ! empty( $params['skip_snapshot'] ),
		];
		$result = Restore_Runner::start( $id, $opts );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		return $this->ok( [ 'job_id' => $result ] );
	}

	public function download_backup( $request ) {
		global $wpdb;
		$id = (int) $request['id'];
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->gembackup_backups} WHERE id=%d", $id ), ARRAY_A );
		if ( ! $row || ! $row['file_path'] || ! file_exists( $row['file_path'] ) ) {
			return $this->fail( 'gembackup_not_available', __( 'Backup file not available locally.', 'gembackup' ), 404 );
		}

		$token = wp_generate_password( 32, false );
		set_transient( 'gembackup_dl_' . $token, $id, 5 * MINUTE_IN_SECONDS );

		return $this->ok( [
			'url' => add_query_arg( [ 'gembackup_download' => $token ], admin_url( 'admin-ajax.php' ) ),
			'expires_in' => 300,
		] );
	}

	/**
	 * Accept an uploaded backup archive, register it as a completed backup row
	 * so it can be restored through the normal restore flow.
	 */
	public function upload_backup( $request ) {
		$files = $request->get_file_params();
		if ( empty( $files['file'] ) || empty( $files['file']['tmp_name'] ) ) {
			return $this->fail( 'gembackup_no_file', __( 'No file was uploaded.', 'gembackup' ), 400 );
		}

		$file = $files['file'];
		if ( ! empty( $file['error'] ) ) {
			return $this->fail( 'gembackup_upload_error', __( 'The file failed to upload. It may exceed the server upload limit.', 'gembackup' ), 400 );
		}

		$orig_name = $file['name'];
		$ext       = strtolower( pathinfo( $orig_name, PATHINFO_EXTENSION ) );
		$encrypted = ( 'enc' === $ext );
		if ( ! in_array( $ext, [ 'zip', 'enc' ], true ) ) {
			return $this->fail( 'gembackup_bad_type', __( 'Only .zip or .enc backup archives can be restored.', 'gembackup' ), 400 );
		}

		$dir = GEMBACKUP_BACKUP_DIR_PATH;
		wp_mkdir_p( $dir );
		$safe = sanitize_file_name( 'uploaded-' . current_time( 'Y-m-d-His' ) . '-' . $orig_name );
		$dest = trailingslashit( $dir ) . $safe;

		if ( ! @move_uploaded_file( $file['tmp_name'], $dest ) && ! @copy( $file['tmp_name'], $dest ) ) {
			return $this->fail( 'gembackup_move_failed', __( 'Could not store the uploaded file.', 'gembackup' ), 500 );
		}

		// Detect backup type from the embedded manifest where possible.
		$type = 'full';
		if ( ! $encrypted && class_exists( '\ZipArchive' ) ) {
			$zip = new \ZipArchive();
			if ( true === $zip->open( $dest ) ) {
				$json = $zip->getFromName( 'manifest.json' );
				$zip->close();
				if ( $json ) {
					$manifest = json_decode( $json, true );
					if ( is_array( $manifest ) && ! empty( $manifest['backup_type'] ) ) {
						$type = sanitize_key( $manifest['backup_type'] );
					}
				}
			}
		}
		if ( ! in_array( $type, [ 'full', 'database', 'files', 'media' ], true ) ) {
			$type = 'full';
		}

		global $wpdb;
		$now = current_time( 'mysql' );
		$wpdb->insert( $wpdb->gembackup_backups, [
			'backup_name'    => sprintf( /* translators: %s: original file name */ __( 'Uploaded — %s', 'gembackup' ), $orig_name ),
			'backup_type'    => $type,
			'storage_driver' => 'local',
			'file_path'      => $dest,
			'file_size'      => filesize( $dest ),
			'status'         => 'completed',
			'progress'       => 100,
			'origin'         => 'upload',
			'encrypted'      => $encrypted ? 1 : 0,
			'created_at'     => $now,
			'completed_at'   => $now,
		] );
		$backup_id = (int) $wpdb->insert_id;

		\GemBackup\Engine\Logger::info( 'Backup archive uploaded for restore: ' . $orig_name, $backup_id );

		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->gembackup_backups} WHERE id=%d", $backup_id ), ARRAY_A );
		return $this->ok( [ 'id' => $backup_id, 'backup' => $this->format_backup( $row ) ] );
	}

	/**
	 * Live status of the most recent restore so the UI can poll progress.
	 */
	public function restore_status() {
		$status = get_option( Restore_Runner::STATUS_OPTION, null );
		return $this->ok( [ 'restore' => is_array( $status ) ? $status : null ] );
	}

	private function format_backup( $row ) {
		return [
			'id'             => (int) $row['id'],
			'backup_name'    => $row['backup_name'],
			'backup_type'    => $row['backup_type'],
			'storage_driver' => $row['storage_driver'],
			'file_size'      => (int) $row['file_size'],
			'status'         => $row['status'],
			'progress'       => (int) $row['progress'],
			'state'          => $row['state'] ? json_decode( $row['state'], true ) : null,
			'origin'         => $row['origin'],
			'label'          => $row['label'],
			'encrypted'      => (bool) $row['encrypted'],
			'created_at'     => $row['created_at'],
			'started_at'     => $row['started_at'],
			'completed_at'   => $row['completed_at'],
			'error_message'  => $row['error_message'],
		];
	}
}
