<?php
namespace GemBackup\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Local extends AbstractDriver {

	private $base_path;

	public function __construct() {
		$this->base_path = trailingslashit( $this->setting( 'local_path', GEMBACKUP_BACKUP_DIR_PATH ) );
	}

	public function upload( $local_path, $remote_name ) {
		if ( ! file_exists( $local_path ) ) {
			return new \WP_Error( 'gembackup_local_upload', __( 'Source file does not exist.', 'gembackup' ) );
		}

		$destination = $this->base_path . basename( $remote_name );

		if ( ! copy( $local_path, $destination ) ) {
			return new \WP_Error( 'gembackup_local_upload', __( 'Failed to copy file to local backup directory.', 'gembackup' ) );
		}

		return true;
	}

	public function delete( $remote_name ) {
		$file = $this->base_path . basename( $remote_name );

		if ( file_exists( $file ) && ! unlink( $file ) ) {
			return new \WP_Error( 'gembackup_local_delete', __( 'Failed to delete backup file.', 'gembackup' ) );
		}

		return true;
	}

	public function list_files() {
		$files  = [];
		$items  = glob( $this->base_path . '*.{zip,sql,gz,tar}', GLOB_BRACE );

		if ( ! $items ) {
			return $files;
		}

		foreach ( $items as $item ) {
			$files[] = [
				'name'     => basename( $item ),
				'path'     => $item,
				'size'     => filesize( $item ),
				'modified' => filemtime( $item ),
			];
		}

		// Sort newest first.
		usort( $files, fn( $a, $b ) => $b['modified'] - $a['modified'] );

		return $files;
	}

	public function test_connection() {
		if ( ! is_writable( $this->base_path ) ) {
			return new \WP_Error( 'gembackup_local_test', sprintf(
				/* translators: %s: directory path */
				__( 'Backup directory is not writable: %s', 'gembackup' ),
				$this->base_path
			) );
		}
		return true;
	}

	public function download( $remote_name, $local_path ) {
		$src = $this->base_path . basename( $remote_name );
		if ( ! file_exists( $src ) ) {
			return new \WP_Error( 'gembackup_local_download', 'Local backup file not found' );
		}
		if ( $src === $local_path ) return true;
		return copy( $src, $local_path ) ? true : new \WP_Error( 'gembackup_local_download', 'Copy failed' );
	}
}
