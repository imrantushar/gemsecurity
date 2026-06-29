<?php
namespace GemBackup\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Backblaze B2 driver — uses the native B2 API.
 */
class Backblaze extends AbstractDriver {

	private $key_id;
	private $application_key;
	private $bucket;
	private $folder;

	public function __construct() {
		$this->key_id          = (string) $this->setting( 'backblaze_key_id', '' );
		$this->application_key = (string) $this->setting( 'backblaze_application_key', '' );
		$this->bucket          = (string) $this->setting( 'backblaze_bucket', '' );
		$this->folder          = trim( (string) $this->setting( 'backblaze_folder', 'gembackup' ), '/' );
	}

	private function authorize() {
		$cached = get_transient( 'gembackup_b2_auth' );
		if ( $cached ) return $cached;

		$auth = base64_encode( $this->key_id . ':' . $this->application_key );
		$response = wp_remote_get( 'https://api.backblazeb2.com/b2api/v3/b2_authorize_account', [
			'headers' => [ 'Authorization' => 'Basic ' . $auth ],
			'timeout' => 20,
		] );
		if ( is_wp_error( $response ) ) return $response;
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $body ) || empty( $body['apiInfo']['storageApi']['apiUrl'] ) ) {
			return new \WP_Error( 'gembackup_b2_auth', 'Backblaze auth failed' );
		}

		$result = [
			'token'   => $body['authorizationToken'],
			'api'     => $body['apiInfo']['storageApi']['apiUrl'],
			'bucket_id' => $this->lookup_bucket_id( $body['apiInfo']['storageApi']['apiUrl'], $body['authorizationToken'], $body['accountId'] ?? null ),
		];
		set_transient( 'gembackup_b2_auth', $result, 60 * MINUTE_IN_SECONDS );
		return $result;
	}

	private function lookup_bucket_id( $api_url, $token, $account_id ) {
		$response = wp_remote_post( $api_url . '/b2api/v3/b2_list_buckets', [
			'headers' => [ 'Authorization' => $token, 'Content-Type' => 'application/json' ],
			'body'    => wp_json_encode( [ 'accountId' => $account_id, 'bucketName' => $this->bucket ] ),
			'timeout' => 20,
		] );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		return $body['buckets'][0]['bucketId'] ?? null;
	}

	public function upload( $local_path, $remote_name ) {
		$auth = $this->authorize();
		if ( is_wp_error( $auth ) ) return $auth;
		if ( empty( $auth['bucket_id'] ) ) return new \WP_Error( 'gembackup_b2_bucket', 'Bucket not found' );

		// 1) Get upload URL
		$response = wp_remote_post( $auth['api'] . '/b2api/v3/b2_get_upload_url', [
			'headers' => [ 'Authorization' => $auth['token'], 'Content-Type' => 'application/json' ],
			'body'    => wp_json_encode( [ 'bucketId' => $auth['bucket_id'] ] ),
			'timeout' => 20,
		] );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['uploadUrl'] ) ) return new \WP_Error( 'gembackup_b2_url', 'Cannot fetch upload URL' );

		$contents = file_get_contents( $local_path ); // phpcs:ignore
		$sha1     = sha1_file( $local_path );
		$key      = $this->folder ? $this->folder . '/' . basename( $remote_name ) : basename( $remote_name );

		$response = wp_remote_request( $body['uploadUrl'], [
			'method'  => 'POST',
			'headers' => [
				'Authorization'     => $body['authorizationToken'],
				'X-Bz-File-Name'    => rawurlencode( $key ),
				'Content-Type'      => 'application/zip',
				'X-Bz-Content-Sha1' => $sha1,
			],
			'body'    => $contents,
			'timeout' => 120,
		] );
		$code = wp_remote_retrieve_response_code( $response );
		return ( $code === 200 ) ? true : new \WP_Error( 'gembackup_b2_upload', 'Backblaze upload failed (HTTP ' . $code . ')' );
	}

	public function delete( $remote_name ) {
		$auth = $this->authorize();
		if ( is_wp_error( $auth ) ) return $auth;
		$key = $this->folder ? $this->folder . '/' . basename( $remote_name ) : basename( $remote_name );
		// Need file id — list_file_names first.
		$response = wp_remote_post( $auth['api'] . '/b2api/v3/b2_list_file_names', [
			'headers' => [ 'Authorization' => $auth['token'], 'Content-Type' => 'application/json' ],
			'body'    => wp_json_encode( [ 'bucketId' => $auth['bucket_id'], 'prefix' => $key, 'maxFileCount' => 1 ] ),
			'timeout' => 20,
		] );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['files'][0]['fileId'] ) ) return true;

		wp_remote_post( $auth['api'] . '/b2api/v3/b2_delete_file_version', [
			'headers' => [ 'Authorization' => $auth['token'], 'Content-Type' => 'application/json' ],
			'body'    => wp_json_encode( [ 'fileId' => $body['files'][0]['fileId'], 'fileName' => $key ] ),
			'timeout' => 20,
		] );
		return true;
	}

	public function list_files() {
		$auth = $this->authorize();
		if ( is_wp_error( $auth ) ) return $auth;
		$response = wp_remote_post( $auth['api'] . '/b2api/v3/b2_list_file_names', [
			'headers' => [ 'Authorization' => $auth['token'], 'Content-Type' => 'application/json' ],
			'body'    => wp_json_encode( [ 'bucketId' => $auth['bucket_id'], 'prefix' => $this->folder, 'maxFileCount' => 1000 ] ),
			'timeout' => 30,
		] );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		$out = [];
		foreach ( ( $body['files'] ?? [] ) as $f ) {
			$out[] = [ 'name' => $f['fileName'], 'size' => (int) $f['contentLength'], 'modified' => (int) ( $f['uploadTimestamp'] / 1000 ) ];
		}
		return $out;
	}

	public function test_connection() {
		if ( empty( $this->key_id ) || empty( $this->application_key ) || empty( $this->bucket ) ) {
			return new \WP_Error( 'gembackup_b2_creds', 'Missing Backblaze credentials' );
		}
		$auth = $this->authorize();
		if ( is_wp_error( $auth ) ) return $auth;
		if ( empty( $auth['bucket_id'] ) ) return new \WP_Error( 'gembackup_b2_bucket', 'Bucket not accessible' );
		return true;
	}

	public function download( $remote_name, $local_path ) {
		$auth = $this->authorize();
		if ( is_wp_error( $auth ) ) return $auth;
		$key = $this->folder ? $this->folder . '/' . basename( $remote_name ) : basename( $remote_name );
		$response = wp_remote_get( $auth['api'] . '/file/' . rawurlencode( $this->bucket ) . '/' . $key, [
			'headers' => [ 'Authorization' => $auth['token'] ],
			'timeout' => 120,
		] );
		if ( is_wp_error( $response ) ) return $response;
		if ( wp_remote_retrieve_response_code( $response ) !== 200 ) {
			return new \WP_Error( 'gembackup_b2_download', 'Backblaze download failed' );
		}
		return file_put_contents( $local_path, wp_remote_retrieve_body( $response ) ) !== false; // phpcs:ignore
	}
}
