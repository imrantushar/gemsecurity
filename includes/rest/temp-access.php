<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\TempAccess as TempAccessModule;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Temporary access REST controller.
 *
 * Every route is gated on {@see TempAccessModule::can_manage()}, so a user who
 * is holding a grant can never manage (or extend) it.
 */
class TempAccess {

	public static function permission() {
		return TempAccessModule::can_manage();
	}

	public static function get() {
		$items  = TempAccessModule::items();
		$counts = [ 'active' => 0, 'expired' => 0, 'revoked' => 0 ];
		foreach ( $items as $item ) {
			$counts[ $item['status'] ]++;
		}

		return rest_ensure_response( [
			'success'   => true,
			'items'     => $items,
			'counts'    => $counts,
			'roles'     => TempAccessModule::assignable_roles(),
			'presets'   => array_keys( TempAccessModule::PRESETS ),
			'max_days'  => (int) floor( TempAccessModule::MAX_SECONDS / DAY_IN_SECONDS ),
			'server_ts' => time(),
		] );
	}

	/** @param \WP_REST_Request $request */
	public static function users( $request ) {
		return rest_ensure_response( [
			'success' => true,
			'users'   => TempAccessModule::search_users( (string) $request->get_param( 'search' ) ),
		] );
	}

	/** @param \WP_REST_Request $request */
	public static function create( $request ) {
		$result = TempAccessModule::grant( [
			'user_id'          => absint( $request->get_param( 'user_id' ) ),
			'role'             => (string) $request->get_param( 'role' ),
			'duration'         => (string) $request->get_param( 'duration' ),
			'expires_at'       => (int) $request->get_param( 'expires_at' ),
			'confirm_elevated' => (bool) $request->get_param( 'confirm_elevated' ),
		] );
		return self::respond( $result );
	}

	/** @param \WP_REST_Request $request */
	public static function extend( $request ) {
		$result = TempAccessModule::extend(
			absint( $request->get_param( 'user_id' ) ),
			(string) $request->get_param( 'duration' ),
			(int) $request->get_param( 'expires_at' )
		);
		return self::respond( $result );
	}

	/** @param \WP_REST_Request $request */
	public static function revoke( $request ) {
		return self::respond( TempAccessModule::revoke( absint( $request->get_param( 'user_id' ) ) ) );
	}

	private static function respond( $result ) {
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		return rest_ensure_response( array_merge( [ 'success' => true ], is_array( $result ) ? $result : [] ) );
	}
}
