<?php
namespace GemSecurity\Rest;

use GemSecurity\Admin\Setup as SetupScreen;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Setup wizard REST controller.
 *
 * POST /setup { status: completed|skipped } → records how the wizard ended.
 * Settings and modules are saved through their own endpoints beforehand.
 */
class Setup {

	/**
	 * @param \WP_REST_Request $request
	 */
	public static function save( $request ) {
		$status = 'skipped' === $request->get_param( 'status' ) ? 'skipped' : 'completed';
		update_option( SetupScreen::STATUS_OPTION, $status, false );
		delete_transient( SetupScreen::PENDING_TRANSIENT );

		return rest_ensure_response( [
			'success' => true,
			'status'  => $status,
		] );
	}
}
