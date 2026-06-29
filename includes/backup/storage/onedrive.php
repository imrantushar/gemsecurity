<?php
namespace GemBackup\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Microsoft OneDrive driver via Microsoft Graph API.
 */
class Onedrive extends AbstractDriver {

	private $client_id;
	private $client_secret;
	private $refresh_token;
	private $folder;
	private $access_token;

	public function __construct() {
		$this->client_id     = (string) $this->setting( 'onedrive_client_id', '' );
		$this->client_secret = (string) $this->setting( 'onedrive_client_secret', '' );
		$this->refresh_token = (string) $this->setting( 'onedrive_refresh_token', '' );
		$this->folder        = (string) $this->setting( 'onedrive_folder', 'gembackup' );
		$this->access_token  = get_transient( 'gembackup_onedrive_token' );
	}

	private function token() {
		if ( $this->access_token ) return $this->access_token;
		if ( ! $this->refresh_token ) return new \WP_Error( 'gembackup_od_token', 'OneDrive not authenticated' );

		$response = wp_remote_post( 'https://login.microsoftonline.com/common/oauth2/v2.0/token', [
			'body'    => [
				'client_id'     => $this->client_id,
				'client_secret' => $this->client_secret,
				'refresh_token' => $this->refresh_token,
				'grant_type'    => 'refresh_token',
				'scope'         => 'offline_access Files.ReadWrite',
			],
			'timeout' => 20,
		] );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['access_token'] ) ) return new \WP_Error( 'gembackup_od_refresh', 'Token refresh failed' );
		set_transient( 'gembackup_onedrive_token', $body['access_token'], (int) ( $body['expires_in'] ?? 3600 ) - 60 );
		$this->access_token = $body['access_token'];
		return $this->access_token;
	}

	public function upload( $local_path, $remote_name ) {
		$token = $this->token();
		if ( is_wp_error( $token ) ) return $token;

		// Use Graph upload session for files of any size.
		$path = '/me/drive/root:/' . trim( $this->folder, '/' ) . '/' . basename( $remote_name ) . ':/createUploadSession';
		$response = wp_remote_post( 'https://graph.microsoft.com/v1.0' . $path, [
			'headers' => [ 'Authorization' => 'Bearer ' . $token, 'Content-Type' => 'application/json' ],
			'body'    => wp_json_encode( [ 'item' => (object) [ '@microsoft.graph.conflictBehavior' => 'replace' ] ] ),
			'timeout' => 30,
		] );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['uploadUrl'] ) ) return new \WP_Error( 'gembackup_od_session', 'OneDrive upload session failed' );

		$size = filesize( $local_path );
		$fp   = fopen( $local_path, 'rb' );
		$chunk_size = 5 * 1024 * 1024; // 5 MB
		$offset = 0;

		while ( ! feof( $fp ) ) {
			$chunk = fread( $fp, $chunk_size );
			$len = strlen( $chunk );
			$response = wp_remote_request( $body['uploadUrl'], [
				'method'  => 'PUT',
				'headers' => [
					'Content-Length' => $len,
					'Content-Range'  => sprintf( 'bytes %d-%d/%d', $offset, $offset + $len - 1, $size ),
				],
				'body'    => $chunk,
				'timeout' => 120,
			] );
			$offset += $len;
			$code = wp_remote_retrieve_response_code( $response );
			if ( $code >= 400 ) {
				fclose( $fp );
				return new \WP_Error( 'gembackup_od_upload', 'OneDrive upload failed (HTTP ' . $code . ')' );
			}
		}
		fclose( $fp );
		return true;
	}

	public function delete( $remote_name ) {
		$token = $this->token();
		if ( is_wp_error( $token ) ) return $token;
		$path = '/me/drive/root:/' . trim( $this->folder, '/' ) . '/' . basename( $remote_name );
		wp_remote_request( 'https://graph.microsoft.com/v1.0' . $path, [
			'method'  => 'DELETE',
			'headers' => [ 'Authorization' => 'Bearer ' . $token ],
			'timeout' => 20,
		] );
		return true;
	}

	public function list_files() {
		$token = $this->token();
		if ( is_wp_error( $token ) ) return $token;
		$path = '/me/drive/root:/' . trim( $this->folder, '/' ) . ':/children';
		$response = wp_remote_get( 'https://graph.microsoft.com/v1.0' . $path, [
			'headers' => [ 'Authorization' => 'Bearer ' . $token ],
			'timeout' => 30,
		] );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		$out = [];
		foreach ( ( $body['value'] ?? [] ) as $f ) {
			$out[] = [ 'name' => $f['name'], 'size' => (int) ( $f['size'] ?? 0 ), 'modified' => strtotime( $f['lastModifiedDateTime'] ?? '' ) ];
		}
		return $out;
	}

	public function test_connection() {
		$token = $this->token();
		if ( is_wp_error( $token ) ) return $token;
		$response = wp_remote_get( 'https://graph.microsoft.com/v1.0/me/drive', [
			'headers' => [ 'Authorization' => 'Bearer ' . $token ],
			'timeout' => 15,
		] );
		return wp_remote_retrieve_response_code( $response ) === 200 ? true : new \WP_Error( 'gembackup_od_test', 'OneDrive test failed' );
	}

	public function download( $remote_name, $local_path ) {
		$token = $this->token();
		if ( is_wp_error( $token ) ) return $token;
		$path = '/me/drive/root:/' . trim( $this->folder, '/' ) . '/' . basename( $remote_name ) . ':/content';
		$response = wp_remote_get( 'https://graph.microsoft.com/v1.0' . $path, [
			'headers' => [ 'Authorization' => 'Bearer ' . $token ],
			'timeout' => 120,
		] );
		if ( wp_remote_retrieve_response_code( $response ) !== 200 ) {
			return new \WP_Error( 'gembackup_od_download', 'OneDrive download failed' );
		}
		return file_put_contents( $local_path, wp_remote_retrieve_body( $response ) ) !== false; // phpcs:ignore
	}
}
