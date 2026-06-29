<?php
namespace GemBackup\Api;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use GemBackup\Api;

abstract class Rest_Controller {

	protected $namespace = Api::NAMESPACE;
	protected $rest_base = '';

	abstract public function register_routes();

	public function permissions_check( $request ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new \WP_Error( 'gembackup_forbidden', __( 'You do not have permission to manage backups.', 'gembackup' ), [ 'status' => 403 ] );
		}
		return true;
	}

	protected function ok( $data ) {
		return rest_ensure_response( $data );
	}

	protected function fail( $code, $message, $status = 400 ) {
		return new \WP_Error( $code, $message, [ 'status' => $status ] );
	}
}
