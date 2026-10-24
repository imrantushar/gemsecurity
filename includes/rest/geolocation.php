<?php
namespace GemSecurity\Rest;

use GemSecurity\Security\Geo;
use GemSecurity\Modules\Geolocation as GeoModule;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Geolocation admin endpoints.
 */
class Geolocation {

	/**
	 * GET /geo/test — country detected for the current request (sanity check).
	 */
	public static function test() {
		return rest_ensure_response( [
			'success' => true,
			'country' => Geo::current_country(),
			'ip'      => \GemSecurity\Helper::get_ip_address(),
		] );
	}

	/**
	 * GET /geo/users — users that have a per-user country list assigned.
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function users( $request ) {
		$search = sanitize_text_field( (string) $request->get_param( 'search' ) );

		// Users-with-geolocation list page needs this meta_key, which is
		// indexed and queried only on the admin page.
		$args = [
			'meta_key' => GeoModule::USER_META, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
			'number'   => 100,
			'orderby'  => 'display_name',
		];
		if ( $search ) {
			$args['search']         = '*' . $search . '*';
			$args['search_columns'] = [ 'user_login', 'user_email', 'display_name' ];
			unset( $args['meta_key'] ); // When searching, look across all users.
		}

		$users = get_users( $args );
		$out   = [];
		foreach ( $users as $u ) {
			$countries = get_user_meta( $u->ID, GeoModule::USER_META, true );
			$out[] = [
				'id'           => (int) $u->ID,
				'login'        => $u->user_login,
				'display_name' => $u->display_name,
				'email'        => $u->user_email,
				'countries'    => is_array( $countries ) ? array_values( array_map( 'strtoupper', $countries ) ) : [],
			];
		}

		return rest_ensure_response( [ 'success' => true, 'users' => $out ] );
	}

	/**
	 * POST /geo/user — set a user's allowed countries.
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function set_user( $request ) {
		$user_id = (int) $request->get_param( 'user_id' );
		if ( ! $user_id || ! get_user_by( 'id', $user_id ) ) {
			return new \WP_Error( 'bad_user', __( 'Unknown user.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		$raw  = (array) $request->get_param( 'countries' );
		$list = [];
		foreach ( $raw as $code ) {
			$code = strtoupper( substr( trim( (string) $code ), 0, 2 ) );
			if ( Geo::is_valid_code( $code ) && ! in_array( $code, $list, true ) ) {
				$list[] = $code;
			}
		}

		if ( empty( $list ) ) {
			delete_user_meta( $user_id, GeoModule::USER_META );
		} else {
			update_user_meta( $user_id, GeoModule::USER_META, $list );
		}

		return rest_ensure_response( [ 'success' => true, 'user_id' => $user_id, 'countries' => $list ] );
	}
}
