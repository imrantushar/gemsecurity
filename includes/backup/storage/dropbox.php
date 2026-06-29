<?php
namespace GemBackup\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Dropbox storage driver.
 *
 * Uses the Dropbox API v2 with a long-lived access token stored in options.
 */
class Dropbox extends AbstractDriver {

	private $access_token;
	private $folder;

	const UPLOAD_ENDPOINT   = 'https://content.dropboxapi.com/2/files/upload';
	const DOWNLOAD_ENDPOINT = 'https://content.dropboxapi.com/2/files/download';
	const DELETE_ENDPOINT   = 'https://api.dropboxapi.com/2/files/delete_v2';
	const LIST_ENDPOINT     = 'https://api.dropboxapi.com/2/files/list_folder';

	public function __construct() {
		$this->access_token = get_option( 'gembackup_dropbox_access_token', '' );
		$this->folder       = trailingslashit( $this->setting( 'dropbox_folder', '/gembackup' ) );
	}

	public function upload( $local_path, $remote_name ) {
		if ( empty( $this->access_token ) ) {
			return new \WP_Error( 'gembackup_dropbox_auth', __( 'Dropbox is not authenticated. Please connect your account in Storage settings.', 'gembackup' ) );
		}

		if ( ! file_exists( $local_path ) ) {
			return new \WP_Error( 'gembackup_dropbox_upload', __( 'Source file does not exist.', 'gembackup' ) );
		}

		$remote_path  = rtrim( $this->folder, '/' ) . '/' . basename( $remote_name );
		$api_arg      = wp_json_encode( [
			'path'       => $remote_path,
			'mode'       => 'overwrite',
			'autorename' => false,
			'mute'       => true,
		] );

		$response = wp_remote_post(
			self::UPLOAD_ENDPOINT,
			[
				'headers' => [
					'Authorization'   => 'Bearer ' . $this->access_token,
					'Content-Type'    => 'application/octet-stream',
					'Dropbox-API-Arg' => $api_arg,
				],
				'body'    => file_get_contents( $local_path ), // phpcs:ignore WordPress.WP.AlternativeFunctions
				'timeout' => 120,
			]
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== (int) $code ) {
			return new \WP_Error( 'gembackup_dropbox_upload', __( 'Dropbox upload failed.', 'gembackup' ), wp_remote_retrieve_body( $response ) );
		}

		return true;
	}

	public function delete( $remote_name ) {
		if ( empty( $this->access_token ) ) {
			return new \WP_Error( 'gembackup_dropbox_auth', __( 'Dropbox is not authenticated.', 'gembackup' ) );
		}

		$remote_path = rtrim( $this->folder, '/' ) . '/' . basename( $remote_name );
		$response    = wp_remote_post(
			self::DELETE_ENDPOINT,
			[
				'headers' => [
					'Authorization' => 'Bearer ' . $this->access_token,
					'Content-Type'  => 'application/json',
				],
				'body'    => wp_json_encode( [ 'path' => $remote_path ] ),
				'timeout' => 30,
			]
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== (int) $code ) {
			return new \WP_Error( 'gembackup_dropbox_delete', __( 'Dropbox delete failed.', 'gembackup' ), wp_remote_retrieve_body( $response ) );
		}

		return true;
	}

	public function download( $remote_name, $local_path ) {
		if ( empty( $this->access_token ) ) {
			return new \WP_Error( 'gembackup_dropbox_auth', __( 'Dropbox is not authenticated.', 'gembackup' ) );
		}

		$remote_path = rtrim( $this->folder, '/' ) . '/' . basename( $remote_name );

		// Stream straight to disk; the path argument rides in the header.
		$response = wp_remote_post(
			self::DOWNLOAD_ENDPOINT,
			[
				'headers'  => [
					'Authorization'   => 'Bearer ' . $this->access_token,
					'Dropbox-API-Arg' => wp_json_encode( [ 'path' => $remote_path ] ),
				],
				'timeout'  => 300,
				'stream'   => true,
				'filename' => $local_path,
			]
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			@unlink( $local_path );
			return new \WP_Error( 'gembackup_dropbox_download', __( 'Dropbox download failed.', 'gembackup' ) );
		}

		return true;
	}

	public function list_files() {
		if ( empty( $this->access_token ) ) {
			return new \WP_Error( 'gembackup_dropbox_auth', __( 'Dropbox is not authenticated.', 'gembackup' ) );
		}

		$folder   = rtrim( $this->folder, '/' ) ?: '';
		$response = wp_remote_post(
			self::LIST_ENDPOINT,
			[
				'headers' => [
					'Authorization' => 'Bearer ' . $this->access_token,
					'Content-Type'  => 'application/json',
				],
				'body'    => wp_json_encode( [ 'path' => $folder ] ),
				'timeout' => 30,
			]
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$data  = json_decode( wp_remote_retrieve_body( $response ), true );
		$files = [];

		foreach ( $data['entries'] ?? [] as $entry ) {
			if ( 'file' !== $entry['.tag'] ) {
				continue;
			}
			$files[] = [
				'name'     => $entry['name'],
				'size'     => $entry['size'] ?? 0,
				'modified' => strtotime( $entry['server_modified'] ?? '' ),
			];
		}

		return $files;
	}

	public function test_connection() {
		if ( empty( $this->access_token ) ) {
			return new \WP_Error( 'gembackup_dropbox_test', __( 'Dropbox account is not connected. Please authenticate.', 'gembackup' ) );
		}

		$response = wp_remote_post(
			'https://api.dropboxapi.com/2/users/get_current_account',
			[
				'headers' => [ 'Authorization' => 'Bearer ' . $this->access_token ],
				'timeout' => 15,
			]
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== (int) $code ) {
			return new \WP_Error( 'gembackup_dropbox_test', __( 'Dropbox connection test failed. Check your access token.', 'gembackup' ) );
		}

		return true;
	}
}
