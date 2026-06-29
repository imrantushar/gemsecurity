<?php
namespace GemBackup\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * FTP / SFTP storage driver.
 *
 * Uses PHP's built-in ftp_* functions for FTP.
 * SFTP requires the ssh2 PHP extension.
 */
class Ftp extends AbstractDriver {

	private $host;
	private $port;
	private $username;
	private $password;
	private $folder;
	private $use_sftp;

	public function __construct() {
		$this->host     = $this->setting( 'ftp_host', '' );
		$this->port     = (int) $this->setting( 'ftp_port', 21 );
		$this->username = $this->setting( 'ftp_username', '' );
		$this->password = $this->setting( 'ftp_password', '' );
		$this->folder   = $this->setting( 'ftp_folder', '/gembackup' );
		$this->use_sftp = (bool) $this->setting( 'ftp_use_sftp', false );
	}

	public function upload( $local_path, $remote_name ) {
		if ( ! file_exists( $local_path ) ) {
			return new \WP_Error( 'gembackup_ftp_upload', __( 'Source file does not exist.', 'gembackup' ) );
		}

		return $this->use_sftp
			? $this->sftp_upload( $local_path, $remote_name )
			: $this->ftp_upload( $local_path, $remote_name );
	}

	public function delete( $remote_name ) {
		return $this->use_sftp
			? $this->sftp_delete( $remote_name )
			: $this->ftp_delete( $remote_name );
	}

	public function download( $remote_name, $local_path ) {
		return $this->use_sftp
			? $this->sftp_download( $remote_name, $local_path )
			: $this->ftp_download( $remote_name, $local_path );
	}

	public function list_files() {
		return $this->use_sftp
			? $this->sftp_list()
			: $this->ftp_list();
	}

	public function test_connection() {
		return $this->use_sftp
			? $this->sftp_test()
			: $this->ftp_test();
	}

	// -----------------------------------------------------------------------
	// FTP Methods
	// -----------------------------------------------------------------------

	private function ftp_connect() {
		if ( ! function_exists( 'ftp_connect' ) ) {
			return new \WP_Error( 'gembackup_ftp', __( 'The PHP FTP extension is not available.', 'gembackup' ) );
		}

		$conn = ftp_connect( $this->host, $this->port, 15 );
		if ( ! $conn ) {
			return new \WP_Error( 'gembackup_ftp', __( 'Could not connect to FTP server.', 'gembackup' ) );
		}

		if ( ! ftp_login( $conn, $this->username, $this->password ) ) {
			ftp_close( $conn );
			return new \WP_Error( 'gembackup_ftp', __( 'FTP login failed. Check your username and password.', 'gembackup' ) );
		}

		ftp_pasv( $conn, true );
		return $conn;
	}

	private function ftp_upload( $local_path, $remote_name ) {
		$conn = $this->ftp_connect();
		if ( is_wp_error( $conn ) ) {
			return $conn;
		}

		$remote_path = trailingslashit( $this->folder ) . basename( $remote_name );

		if ( ! ftp_put( $conn, $remote_path, $local_path, FTP_BINARY ) ) {
			ftp_close( $conn );
			return new \WP_Error( 'gembackup_ftp_upload', __( 'FTP upload failed.', 'gembackup' ) );
		}

		ftp_close( $conn );
		return true;
	}

	private function ftp_delete( $remote_name ) {
		$conn = $this->ftp_connect();
		if ( is_wp_error( $conn ) ) {
			return $conn;
		}

		$remote_path = trailingslashit( $this->folder ) . basename( $remote_name );
		$result      = ftp_delete( $conn, $remote_path );
		ftp_close( $conn );

		if ( ! $result ) {
			return new \WP_Error( 'gembackup_ftp_delete', __( 'FTP delete failed.', 'gembackup' ) );
		}

		return true;
	}

	private function ftp_download( $remote_name, $local_path ) {
		$conn = $this->ftp_connect();
		if ( is_wp_error( $conn ) ) {
			return $conn;
		}

		$remote_path = trailingslashit( $this->folder ) . basename( $remote_name );
		$ok          = ftp_get( $conn, $local_path, $remote_path, FTP_BINARY );
		ftp_close( $conn );

		if ( ! $ok ) {
			return new \WP_Error( 'gembackup_ftp_download', __( 'FTP download failed.', 'gembackup' ) );
		}

		return true;
	}

	private function ftp_list() {
		$conn = $this->ftp_connect();
		if ( is_wp_error( $conn ) ) {
			return $conn;
		}

		$items = ftp_nlist( $conn, $this->folder );
		ftp_close( $conn );

		$files = [];
		foreach ( $items ?: [] as $item ) {
			$files[] = [
				'name' => basename( $item ),
				'path' => $item,
				'size' => 0, // ftp_nlist doesn't return size; use ftp_rawlist for that.
			];
		}

		return $files;
	}

	private function ftp_test() {
		$conn = $this->ftp_connect();
		if ( is_wp_error( $conn ) ) {
			return $conn;
		}
		ftp_close( $conn );
		return true;
	}

	// -----------------------------------------------------------------------
	// SFTP Methods (requires ssh2 PHP extension)
	// -----------------------------------------------------------------------

	private function sftp_connect() {
		if ( ! function_exists( 'ssh2_connect' ) ) {
			return new \WP_Error( 'gembackup_sftp', __( 'The PHP ssh2 extension is not available. Install it to use SFTP.', 'gembackup' ) );
		}

		$conn = ssh2_connect( $this->host, $this->port );
		if ( ! $conn ) {
			return new \WP_Error( 'gembackup_sftp', __( 'Could not connect to SFTP server.', 'gembackup' ) );
		}

		if ( ! ssh2_auth_password( $conn, $this->username, $this->password ) ) {
			return new \WP_Error( 'gembackup_sftp', __( 'SFTP authentication failed. Check your username and password.', 'gembackup' ) );
		}

		$sftp = ssh2_sftp( $conn );
		if ( ! $sftp ) {
			return new \WP_Error( 'gembackup_sftp', __( 'Could not initialise SFTP subsystem.', 'gembackup' ) );
		}

		return [ 'conn' => $conn, 'sftp' => $sftp ];
	}

	private function sftp_upload( $local_path, $remote_name ) {
		$connection = $this->sftp_connect();
		if ( is_wp_error( $connection ) ) {
			return $connection;
		}

		$remote_path = trailingslashit( $this->folder ) . basename( $remote_name );
		$stream_path = 'ssh2.sftp://' . intval( $connection['sftp'] ) . $remote_path;

		$local_stream  = fopen( $local_path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$remote_stream = fopen( $stream_path, 'wb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $local_stream || ! $remote_stream ) {
			return new \WP_Error( 'gembackup_sftp_upload', __( 'SFTP upload failed: could not open file streams.', 'gembackup' ) );
		}

		$result = stream_copy_to_stream( $local_stream, $remote_stream );
		fclose( $local_stream );  // phpcs:ignore WordPress.WP.AlternativeFunctions
		fclose( $remote_stream ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( false === $result ) {
			return new \WP_Error( 'gembackup_sftp_upload', __( 'SFTP upload failed.', 'gembackup' ) );
		}

		return true;
	}

	private function sftp_delete( $remote_name ) {
		$connection = $this->sftp_connect();
		if ( is_wp_error( $connection ) ) {
			return $connection;
		}

		$remote_path = trailingslashit( $this->folder ) . basename( $remote_name );
		if ( ! ssh2_sftp_unlink( $connection['sftp'], $remote_path ) ) {
			return new \WP_Error( 'gembackup_sftp_delete', __( 'SFTP delete failed.', 'gembackup' ) );
		}

		return true;
	}

	private function sftp_download( $remote_name, $local_path ) {
		$connection = $this->sftp_connect();
		if ( is_wp_error( $connection ) ) {
			return $connection;
		}

		$remote_path   = trailingslashit( $this->folder ) . basename( $remote_name );
		$stream_path   = 'ssh2.sftp://' . intval( $connection['sftp'] ) . $remote_path;
		$remote_stream = @fopen( $stream_path, 'rb' );  // phpcs:ignore WordPress.WP.AlternativeFunctions
		$local_stream  = @fopen( $local_path, 'wb' );   // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $remote_stream || ! $local_stream ) {
			if ( $remote_stream ) { fclose( $remote_stream ); } // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( $local_stream ) { fclose( $local_stream ); }   // phpcs:ignore WordPress.WP.AlternativeFunctions
			return new \WP_Error( 'gembackup_sftp_download', __( 'SFTP download failed: could not open file streams.', 'gembackup' ) );
		}

		$result = stream_copy_to_stream( $remote_stream, $local_stream );
		fclose( $remote_stream ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		fclose( $local_stream );  // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( false === $result ) {
			return new \WP_Error( 'gembackup_sftp_download', __( 'SFTP download failed.', 'gembackup' ) );
		}

		return true;
	}

	private function sftp_list() {
		$connection = $this->sftp_connect();
		if ( is_wp_error( $connection ) ) {
			return $connection;
		}

		$handle = opendir( 'ssh2.sftp://' . intval( $connection['sftp'] ) . $this->folder ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$files  = [];

		if ( $handle ) {
			while ( false !== ( $entry = readdir( $handle ) ) ) { // phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$files[] = [ 'name' => $entry ];
			}
			closedir( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		return $files;
	}

	private function sftp_test() {
		$connection = $this->sftp_connect();
		if ( is_wp_error( $connection ) ) {
			return $connection;
		}
		return true;
	}
}
