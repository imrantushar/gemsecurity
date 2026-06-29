<?php
namespace GemBackup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Api {

	const NAMESPACE = 'gembackup/v1';

	public static function init() {
		$self = new self();
		add_action( 'rest_api_init', [ $self, 'register_routes' ] );
	}

	public function register_routes() {
		( new Api\System_Controller() )->register_routes();
		( new Api\Settings_Controller() )->register_routes();
		( new Api\Backups_Controller() )->register_routes();
		( new Api\Schedules_Controller() )->register_routes();
		( new Api\Storage_Controller() )->register_routes();
		( new Api\Logs_Controller() )->register_routes();
	}
}
