<?php
namespace GemBackup\Api;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use GemBackup\Helper;
use GemBackup\Storage\Driver_Factory;

class Storage_Controller extends Rest_Controller {

	protected $rest_base = 'storage';

	public function register_routes() {
		register_rest_route( $this->namespace, '/' . $this->rest_base, [
			'methods'             => 'GET',
			'callback'            => [ $this, 'list_drivers' ],
			'permission_callback' => [ $this, 'permissions_check' ],
		] );

		register_rest_route( $this->namespace, '/' . $this->rest_base . '/(?P<driver>[a-z0-9_-]+)', [
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'get_driver' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
			[
				'methods'             => 'PUT',
				'callback'            => [ $this, 'update_driver' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
		] );

		register_rest_route( $this->namespace, '/' . $this->rest_base . '/(?P<driver>[a-z0-9_-]+)/test', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'test_driver' ],
			'permission_callback' => [ $this, 'permissions_check' ],
		] );

		register_rest_route( $this->namespace, '/' . $this->rest_base . '/active', [
			'methods'             => 'PUT',
			'callback'            => [ $this, 'set_active' ],
			'permission_callback' => [ $this, 'permissions_check' ],
		] );
	}

	public function list_drivers() {
		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		$drivers  = Helper::get_storage_drivers();
		$out      = [];
		foreach ( $drivers as $key => $label ) {
			$out[ $key ] = $this->driver_payload( $key, $settings );
		}
		return $this->ok( [
			'active'  => $settings['active_storage'] ?? 'local',
			'drivers' => $out,
		] );
	}

	public function get_driver( $request ) {
		$key = sanitize_key( $request['driver'] );
		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		return $this->ok( $this->driver_payload( $key, $settings ) );
	}

	public function update_driver( $request ) {
		$key   = sanitize_key( $request['driver'] );
		$body  = $request->get_json_params();
		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );

		$prefix = $key . '_';
		foreach ( $body as $field => $value ) {
			$opt_key = $prefix . sanitize_key( $field );
			if ( is_array( $value ) ) {
				$settings[ $opt_key ] = $value;
			} elseif ( is_bool( $value ) ) {
				$settings[ $opt_key ] = (bool) $value;
			} else {
				$settings[ $opt_key ] = sanitize_text_field( (string) $value );
			}
		}

		update_option( GEMBACKUP_SETTINGS_NAME, $settings );
		return $this->ok( $this->driver_payload( $key, $settings ) );
	}

	public function test_driver( $request ) {
		$key = sanitize_key( $request['driver'] );
		$driver = Driver_Factory::make( $key );
		if ( is_wp_error( $driver ) ) {
			return $driver;
		}
		$result = $driver->test_connection();
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		return $this->ok( [ 'connected' => true ] );
	}

	public function set_active( $request ) {
		$params = $request->get_json_params();
		$driver = sanitize_key( $params['driver'] ?? 'local' );
		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		$settings['active_storage'] = $driver;
		update_option( GEMBACKUP_SETTINGS_NAME, $settings );
		return $this->ok( [ 'active' => $driver ] );
	}

	private function driver_payload( $key, $settings ) {
		$prefix = $key . '_';
		$payload = [
			'key'             => $key,
			'label'           => Helper::get_storage_drivers()[ $key ] ?? $key,
			'enabled'         => in_array( $key, (array) ( $settings['enabled_drivers'] ?? [ 'local' ] ), true ),
			'connection_mode' => $settings[ $prefix . 'connection_mode' ] ?? ( in_array( $key, [ 'gdrive', 'dropbox', 'onedrive' ], true ) ? 'oauth' : 'manual' ),
			'connected'       => $this->is_connected( $key, $settings ),
			'fields'          => [],
		];

		foreach ( $settings as $opt_key => $value ) {
			if ( strpos( $opt_key, $prefix ) === 0 ) {
				$field = substr( $opt_key, strlen( $prefix ) );
				if ( in_array( $field, [ 'secret_key', 'app_secret', 'client_secret', 'application_key', 'password', 'refresh_token', 'access_token' ], true ) && $value ) {
					$payload['fields'][ $field ] = '••••••••';
				} else {
					$payload['fields'][ $field ] = $value;
				}
			}
		}

		return $payload;
	}

	private function is_connected( $key, $settings ) {
		switch ( $key ) {
			case 'local':
				return is_writable( $settings['local_path'] ?? GEMBACKUP_BACKUP_DIR_PATH );
			case 'gdrive':
			case 'dropbox':
			case 'onedrive':
				return ! empty( get_option( 'gembackup_' . $key . '_access_token' ) ) || ! empty( $settings[ $key . '_refresh_token' ] );
			case 's3':
			case 'r2':
				return ! empty( $settings[ $key . '_access_key' ] ) && ! empty( $settings[ $key . '_secret_key' ] ) && ! empty( $settings[ $key . '_bucket' ] );
			case 'backblaze':
				return ! empty( $settings[ 'backblaze_key_id' ] ) && ! empty( $settings[ 'backblaze_application_key' ] ) && ! empty( $settings[ 'backblaze_bucket' ] );
			case 'ftp':
				return ! empty( $settings[ 'ftp_host' ] ) && ! empty( $settings[ 'ftp_username' ] );
		}
		return false;
	}
}
