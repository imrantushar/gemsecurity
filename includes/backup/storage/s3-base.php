<?php
namespace GemBackup\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shared AWS Signature V4 helper used by S3, R2, and other S3-compatible drivers.
 */
abstract class S3_Base extends AbstractDriver {

	protected $access_key;
	protected $secret_key;
	protected $bucket;
	protected $region;
	protected $folder;
	protected $service = 's3';

	abstract protected function get_endpoint();

	protected function full_object_key( $name ) {
		$name = ltrim( $name, '/' );
		return $this->folder ? trim( $this->folder, '/' ) . '/' . $name : $name;
	}

	public function upload( $local_path, $remote_name ) {
		if ( ! file_exists( $local_path ) ) {
			return new \WP_Error( 'gembackup_s3_missing', 'Local file does not exist' );
		}

		$payload = file_get_contents( $local_path ); // phpcs:ignore
		$key     = $this->full_object_key( $remote_name );

		$response = $this->signed_request( 'PUT', '/' . $key, $payload, [
			'Content-Type' => 'application/zip',
		] );
		if ( is_wp_error( $response ) ) return $response;

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code >= 200 && $code < 300 ) return true;
		return new \WP_Error( 'gembackup_s3_upload', 'Upload failed (HTTP ' . $code . ')' );
	}

	public function download( $remote_name, $local_path ) {
		$key = $this->full_object_key( $remote_name );
		$response = $this->signed_request( 'GET', '/' . $key, '', [] );
		if ( is_wp_error( $response ) ) return $response;
		$code = wp_remote_retrieve_response_code( $response );
		if ( $code !== 200 ) {
			return new \WP_Error( 'gembackup_s3_download', 'Download failed (HTTP ' . $code . ')' );
		}
		return file_put_contents( $local_path, wp_remote_retrieve_body( $response ) ) !== false; // phpcs:ignore
	}

	public function delete( $remote_name ) {
		$key = $this->full_object_key( $remote_name );
		$response = $this->signed_request( 'DELETE', '/' . $key, '', [] );
		if ( is_wp_error( $response ) ) return $response;
		$code = wp_remote_retrieve_response_code( $response );
		return ( $code >= 200 && $code < 300 ) ? true : new \WP_Error( 'gembackup_s3_delete', 'Delete failed' );
	}

	public function list_files() {
		$response = $this->signed_request( 'GET', '/', '', [], [ 'prefix' => $this->folder ?: '' ] );
		if ( is_wp_error( $response ) ) return $response;
		$body = wp_remote_retrieve_body( $response );
		$xml  = @simplexml_load_string( $body );
		if ( ! $xml ) return [];
		$out = [];
		foreach ( $xml->Contents as $entry ) {
			$out[] = [
				'name'     => (string) $entry->Key,
				'size'     => (int) $entry->Size,
				'modified' => strtotime( (string) $entry->LastModified ),
			];
		}
		return $out;
	}

	public function test_connection() {
		if ( empty( $this->access_key ) || empty( $this->secret_key ) || empty( $this->bucket ) ) {
			return new \WP_Error( 'gembackup_s3_creds', 'Missing credentials or bucket' );
		}
		$response = $this->signed_request( 'GET', '/', '', [], [ 'max-keys' => 1 ] );
		if ( is_wp_error( $response ) ) return $response;
		$code = wp_remote_retrieve_response_code( $response );
		if ( $code === 200 ) return true;
		return new \WP_Error( 'gembackup_s3_test', 'Connection failed (HTTP ' . $code . ')' );
	}

	protected function signed_request( $method, $uri, $payload, $headers = [], $query = [] ) {
		$host    = wp_parse_url( $this->get_endpoint(), PHP_URL_HOST );
		$datetime = gmdate( 'Ymd\THis\Z' );
		$date     = gmdate( 'Ymd' );
		$payload_hash = hash( 'sha256', $payload );

		$headers['host']                 = $host;
		$headers['x-amz-date']           = $datetime;
		$headers['x-amz-content-sha256'] = $payload_hash;

		ksort( $headers );
		$canonical_headers = '';
		$signed_headers_arr = [];
		foreach ( $headers as $k => $v ) {
			$lk = strtolower( $k );
			$canonical_headers .= $lk . ':' . trim( $v ) . "\n";
			$signed_headers_arr[] = $lk;
		}
		$signed_headers = implode( ';', $signed_headers_arr );

		ksort( $query );
		$canonical_query = http_build_query( $query, '', '&', PHP_QUERY_RFC3986 );

		$canonical_request = implode( "\n", [
			$method,
			$uri,
			$canonical_query,
			$canonical_headers,
			$signed_headers,
			$payload_hash,
		] );

		$scope = "{$date}/{$this->region}/{$this->service}/aws4_request";
		$string_to_sign = implode( "\n", [
			'AWS4-HMAC-SHA256',
			$datetime,
			$scope,
			hash( 'sha256', $canonical_request ),
		] );

		$signing_key = hash_hmac( 'sha256', 'aws4_request',
			hash_hmac( 'sha256', $this->service,
				hash_hmac( 'sha256', $this->region,
					hash_hmac( 'sha256', $date, 'AWS4' . $this->secret_key, true ),
					true ),
				true ),
			true );
		$signature = hash_hmac( 'sha256', $string_to_sign, $signing_key );

		$auth = sprintf(
			'AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s',
			$this->access_key, $scope, $signed_headers, $signature
		);

		$url = $this->get_endpoint() . $uri . ( $canonical_query ? '?' . $canonical_query : '' );

		return wp_remote_request( $url, [
			'method'  => $method,
			'headers' => array_merge( $headers, [ 'Authorization' => $auth ] ),
			'body'    => $payload,
			'timeout' => 60,
		] );
	}
}
