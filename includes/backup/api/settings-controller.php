<?php
namespace GemBackup\Api;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Settings_Controller extends Rest_Controller {

	protected $rest_base = 'settings';

	public function register_routes() {
		register_rest_route( $this->namespace, '/' . $this->rest_base, [
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'get_settings' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
			[
				'methods'             => 'PUT',
				'callback'            => [ $this, 'update_settings' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
		] );
	}

	public function get_settings() {
		return $this->ok( get_option( GEMBACKUP_SETTINGS_NAME, [] ) );
	}

	public function update_settings( $request ) {
		$current = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		$incoming = $request->get_json_params();
		if ( ! is_array( $incoming ) ) {
			return $this->fail( 'gembackup_invalid_payload', __( 'Invalid payload.', 'gembackup' ) );
		}

		$merged = array_merge( $current, $incoming );

		// Sanitize known keys.
		$merged['backup_retention']    = max( 1, (int) ( $merged['backup_retention'] ?? 10 ) );
		$merged['logs_retention_days'] = max( 1, (int) ( $merged['logs_retention_days'] ?? 30 ) );
		$merged['notify_email']        = sanitize_email( $merged['notify_email'] ?? '' );
		$merged['webhook_url']         = esc_url_raw( $merged['webhook_url'] ?? '' );

		update_option( GEMBACKUP_SETTINGS_NAME, $merged );
		do_action( 'gembackup/settings_updated', $merged );

		return $this->ok( $merged );
	}
}
