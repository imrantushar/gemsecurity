<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\Registry;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Module activation REST controller.
 *
 * GET  /modules        → the module list with resolved active/visible flags.
 * POST /modules        → toggle a single module { id, active }.
 */
class Modules {

	/**
	 * GET /modules
	 */
	public static function get() {
		return rest_ensure_response( [
			'success' => true,
			'modules' => Registry::for_js(),
			'is_pro'  => \GemSecurity\Helper::is_pro_active(),
		] );
	}

	/**
	 * POST /modules
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function save( $request ) {
		$id     = sanitize_key( (string) $request->get_param( 'id' ) );
		$active = rest_sanitize_boolean( $request->get_param( 'active' ) );

		if ( '' === $id ) {
			return new \WP_Error(
				'gemsecurity_missing_id',
				__( 'A module id is required.', 'gemsecurity' ),
				[ 'status' => 400 ]
			);
		}

		// Turning a module off is another way of switching protection off.
		if ( ! $active && \GemSecurity\Security\SiteGuard::locked_for_current_user() ) {
			return new \WP_Error(
				'gemsecurity_locked',
				__( 'GemSecurity is locked. Unlock it on the Firewall page (password and emailed code) to turn a module off.', 'gemsecurity' ),
				[ 'status' => 403 ]
			);
		}

		$result = Registry::set_active( $id, $active );
		if ( is_wp_error( $result ) ) {
			$result->add_data( [ 'status' => 400 ] );
			return $result;
		}

		return rest_ensure_response( [
			'success' => true,
			'modules' => Registry::for_js(),
		] );
	}
}
