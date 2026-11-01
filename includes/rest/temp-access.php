<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\TempAccess as TempAccessModule;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Temporary access REST controller.
 *
 * GET  /temp-access             → accounts, counts and the options the form needs.
 * POST /temp-access             → create an account { email, role, duration, expires_at, send_email, confirm_elevated }.
 * POST /temp-access/extend      → { user_id, duration, expires_at }.
 * POST /temp-access/regenerate  → { user_id, send_email }.
 * POST /temp-access/revoke      → { user_id }.
 *
 * Every route is gated by {@see TempAccessModule::can_manage()} and, being
 * cookie-authenticated, by the REST nonce. Raw links are returned only by the
 * call that created them and are never stored.
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
			'https'     => is_ssl() || 0 === strpos( wp_login_url(), 'https://' ),
			'server_ts' => time(),
		] );
	}

	/** @param \WP_REST_Request $request */
	public static function create( $request ) {
		$result = TempAccessModule::create( [
			'email'            => (string) $request->get_param( 'email' ),
			'role'             => (string) $request->get_param( 'role' ),
			'duration'         => (string) $request->get_param( 'duration' ),
			'expires_at'       => (int) $request->get_param( 'expires_at' ),
			'send_email'       => (bool) $request->get_param( 'send_email' ),
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
	public static function regenerate( $request ) {
		return self::respond( TempAccessModule::regenerate( absint( $request->get_param( 'user_id' ) ), (bool) $request->get_param( 'send_email' ) ) );
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
