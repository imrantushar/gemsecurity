<?php
namespace GemBackup\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Google Drive storage driver.
 *
 * Requires OAuth2 credentials (Client ID + Secret) configured in Settings → Storage.
 * The actual Google API calls are made via wp_remote_post/get using the stored access token.
 */
class Gdrive extends AbstractDriver {

	private $client_id;
	private $client_secret;
	private $folder_id;
	private $access_token;

	public function __construct() {
		$this->client_id     = $this->setting( 'gdrive_client_id', '' );
		$this->client_secret = $this->setting( 'gdrive_client_secret', '' );
		$this->folder_id     = $this->setting( 'gdrive_folder_id', '' );
		$this->access_token  = get_option( 'gembackup_gdrive_access_token', '' );
	}

	public function upload( $local_path, $remote_name ) {
		if ( empty( $this->access_token ) ) {
			return new \WP_Error( 'gembackup_gdrive_auth', __( 'Google Drive is not authenticated. Please connect your account in Storage settings.', 'gembackup' ) );
		}

		if ( ! file_exists( $local_path ) ) {
			return new \WP_Error( 'gembackup_gdrive_upload', __( 'Source file does not exist.', 'gembackup' ) );
		}

		// Metadata request.
		$metadata = wp_json_encode( [
			'name'    => basename( $remote_name ),
			'parents' => $this->folder_id ? [ $this->folder_id ] : [],
		] );

		$file_content = file_get_contents( $local_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$mime_type    = 'application/zip';
		$boundary     = wp_generate_uuid4();

		$body  = "--{$boundary}\r\n";
		$body .= "Content-Type: application/json; charset=UTF-8\r\n\r\n";
		$body .= $metadata . "\r\n";
		$body .= "--{$boundary}\r\n";
		$body .= "Content-Type: {$mime_type}\r\n\r\n";
		$body .= $file_content . "\r\n";
		$body .= "--{$boundary}--";

		$response = wp_remote_post(
			'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart',
			[
				'headers' => [
					'Authorization' => 'Bearer ' . $this->access_token,
					'Content-Type'  => "multipart/related; boundary={$boundary}",
				],
				'body'    => $body,
				'timeout' => 120,
			]
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== (int) $code ) {
			return new \WP_Error( 'gembackup_gdrive_upload', __( 'Google Drive upload failed.', 'gembackup' ), wp_remote_retrieve_body( $response ) );
		}

		return true;
	}

	/**
	 * Resolve a Drive file ID from its name within the configured folder.
	 *
	 * @param string $remote_name
	 * @return string|\WP_Error
	 */
	private function find_file_id( $remote_name ) {
		if ( empty( $this->access_token ) ) {
			return new \WP_Error( 'gembackup_gdrive_auth', __( 'Google Drive is not authenticated.', 'gembackup' ) );
		}

		$name  = str_replace( "'", "\\'", basename( $remote_name ) );
		$query = "name = '{$name}' and trashed = false";
		if ( $this->folder_id ) {
			$query = "'{$this->folder_id}' in parents and " . $query;
		}

		$response = wp_remote_get(
			add_query_arg( [
				'q'        => rawurlencode( $query ),
				'fields'   => 'files(id,name)',
				'pageSize' => 1,
			], 'https://www.googleapis.com/drive/v3/files' ),
			[
				'headers' => [ 'Authorization' => 'Bearer ' . $this->access_token ],
				'timeout' => 30,
			]
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		$id   = $data['files'][0]['id'] ?? '';
		if ( ! $id ) {
			return new \WP_Error( 'gembackup_gdrive_notfound', __( 'File not found on Google Drive.', 'gembackup' ) );
		}

		return $id;
	}

	public function delete( $remote_name ) {
		$id = $this->find_file_id( $remote_name );
		if ( is_wp_error( $id ) ) {
			return $id;
		}

		$response = wp_remote_request(
			'https://www.googleapis.com/drive/v3/files/' . rawurlencode( $id ),
			[
				'method'  => 'DELETE',
				'headers' => [ 'Authorization' => 'Bearer ' . $this->access_token ],
				'timeout' => 30,
			]
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 204 !== $code && 200 !== $code ) {
			return new \WP_Error( 'gembackup_gdrive_delete', __( 'Google Drive delete failed.', 'gembackup' ), wp_remote_retrieve_body( $response ) );
		}

		return true;
	}

	public function download( $remote_name, $local_path ) {
		$id = $this->find_file_id( $remote_name );
		if ( is_wp_error( $id ) ) {
			return $id;
		}

		// Stream straight to disk so large archives never load into memory.
		$response = wp_remote_get(
			'https://www.googleapis.com/drive/v3/files/' . rawurlencode( $id ) . '?alt=media',
			[
				'headers'  => [ 'Authorization' => 'Bearer ' . $this->access_token ],
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
			return new \WP_Error( 'gembackup_gdrive_download', __( 'Google Drive download failed.', 'gembackup' ) );
		}

		return true;
	}

	public function list_files() {
		if ( empty( $this->access_token ) ) {
			return new \WP_Error( 'gembackup_gdrive_auth', __( 'Google Drive is not authenticated.', 'gembackup' ) );
		}

		$query = "mimeType != 'application/vnd.google-apps.folder' and trashed = false";
		if ( $this->folder_id ) {
			$query = "'{$this->folder_id}' in parents and " . $query;
		}

		$response = wp_remote_get(
			add_query_arg( [
				'q'      => $query,
				'fields' => 'files(id,name,size,modifiedTime)',
			], 'https://www.googleapis.com/drive/v3/files' ),
			[
				'headers' => [ 'Authorization' => 'Bearer ' . $this->access_token ],
				'timeout' => 30,
			]
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$data  = json_decode( wp_remote_retrieve_body( $response ), true );
		$files = [];

		foreach ( $data['files'] ?? [] as $file ) {
			$files[] = [
				'name'     => $file['name'],
				'id'       => $file['id'],
				'size'     => $file['size'] ?? 0,
				'modified' => strtotime( $file['modifiedTime'] ?? '' ),
			];
		}

		return $files;
	}

	public function test_connection() {
		if ( empty( $this->client_id ) || empty( $this->client_secret ) ) {
			return new \WP_Error( 'gembackup_gdrive_test', __( 'Google Drive Client ID and Secret are required.', 'gembackup' ) );
		}
		if ( empty( $this->access_token ) ) {
			return new \WP_Error( 'gembackup_gdrive_test', __( 'Google Drive account is not connected. Please authenticate.', 'gembackup' ) );
		}
		return true;
	}
}
