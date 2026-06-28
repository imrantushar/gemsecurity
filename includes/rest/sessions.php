<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\Sessions as SessionsModule;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Session listing + revocation.
 */
class Sessions {

	/**
	 * GET /sessions — the current user's active sessions.
	 */
	public static function get() {
		return rest_ensure_response( [
			'success'  => true,
			'sessions' => SessionsModule::list_for( get_current_user_id() ),
		] );
	}

	/**
	 * POST /sessions/revoke-others — end every session except this one.
	 */
	public static function revoke_others() {
		$token = wp_get_session_token();
		\WP_Session_Tokens::get_instance( get_current_user_id() )->destroy_others( $token );
		return rest_ensure_response( [ 'success' => true, 'sessions' => SessionsModule::list_for( get_current_user_id() ) ] );
	}

	/**
	 * POST /sessions/force-logout — destroy all sessions for another user.
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function force_logout( $request ) {
		$user_id = (int) $request->get_param( 'user_id' );
		$user    = $user_id ? get_user_by( 'id', $user_id ) : null;
		if ( ! $user ) {
			return new \WP_Error( 'bad_user', __( 'Unknown user.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		\WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		Logger::log( 'sessions_revoked', sprintf( 'All sessions revoked for "%s".', $user->user_login ), Logger::SEVERITY_NOTICE, [ 'context' => [ 'target_user_id' => $user_id ] ] );
		return rest_ensure_response( [ 'success' => true ] );
	}
}
