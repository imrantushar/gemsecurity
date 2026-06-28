<?php
namespace GemSecurity\Rest;

use GemSecurity\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Administrator listing for the whitelist management UI.
 */
class Admins {

	/**
	 * GET /admins
	 */
	public static function get() {
		$whitelist = array_map( 'strtolower', (array) Helper::get_setting( 'admin_whitelist', [] ) );

		$admins = get_users( [ 'role' => 'administrator', 'orderby' => 'display_name' ] );
		$out    = [];

		foreach ( $admins as $user ) {
			$email = strtolower( $user->user_email );
			$out[] = [
				'id'           => (int) $user->ID,
				'login'        => $user->user_login,
				'display_name' => $user->display_name,
				'email'        => $user->user_email,
				'whitelisted'  => in_array( $email, $whitelist, true ),
				'registered'   => $user->user_registered,
				'is_current'   => (int) $user->ID === get_current_user_id(),
			];
		}

		return rest_ensure_response( [
			'success'   => true,
			'admins'    => $out,
			'whitelist' => (array) Helper::get_setting( 'admin_whitelist', [] ),
		] );
	}
}
