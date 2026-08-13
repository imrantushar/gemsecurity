<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\LoginExtras;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Magic-link recovery REST controller (Pro).
 */
class MagicLink {

	/**
	 * POST /magic-link — email a one-time login link to a user.
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function issue( $request ) {
		$user_id = absint( $request->get_param( 'user_id' ) );
		if ( ! $user_id ) {
			// Allow a username or email string.
			$who = sanitize_text_field( (string) $request->get_param( 'user' ) );
			if ( '' !== $who ) {
				$u = is_email( $who ) ? get_user_by( 'email', $who ) : get_user_by( 'login', $who );
				$user_id = $u ? $u->ID : 0;
			}
		}
		if ( ! $user_id ) {
			return new \WP_Error( 'gemsec_missing_user', __( 'Enter a valid username or email.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		$result = LoginExtras::issue_magic_link( $user_id );
		if ( is_wp_error( $result ) ) {
			$result->add_data( [ 'status' => 400 ] );
			return $result;
		}
		return rest_ensure_response( [ 'success' => true ] );
	}
}
