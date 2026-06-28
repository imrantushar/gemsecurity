<?php
namespace GemSecurity\Rest;

use GemSecurity\Security\BanList;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Banned-IP management.
 */
class Bans {

	/**
	 * GET /bans
	 */
	public static function get() {
		return rest_ensure_response( [
			'success' => true,
			'bans'    => BanList::all(),
			'active'  => BanList::count_active(),
		] );
	}

	/**
	 * POST /bans — add a manual ban.
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function add( $request ) {
		$ip = trim( (string) $request->get_param( 'ip' ) );
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return new \WP_Error( 'bad_ip', __( 'Enter a valid IP address.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		$reason   = sanitize_text_field( (string) $request->get_param( 'reason' ) ) ?: __( 'Manually banned', 'gemsecurity' );
		$minutes  = (int) $request->get_param( 'duration' ); // 0 = permanent
		BanList::ban( $ip, $reason, $minutes > 0 ? $minutes * MINUTE_IN_SECONDS : 0 );

		return rest_ensure_response( [ 'success' => true, 'bans' => BanList::all() ] );
	}

	/**
	 * DELETE /bans — remove a ban.
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function remove( $request ) {
		$ip = trim( (string) $request->get_param( 'ip' ) );
		BanList::unban( $ip );
		return rest_ensure_response( [ 'success' => true, 'bans' => BanList::all() ] );
	}
}
