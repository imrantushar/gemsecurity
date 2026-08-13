<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\ApiHardening;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Application-password governance REST controller.
 *
 * GET  /app-passwords          → every application password across all users.
 * POST /app-passwords/revoke   → revoke one { user_id, uuid } or all { all: true }.
 */
class AppPasswords {

	/**
	 * GET /app-passwords
	 */
	public static function get() {
		if ( ! ApiHardening::app_passwords_supported() ) {
			return rest_ensure_response( [ 'success' => true, 'supported' => false, 'items' => [] ] );
		}

		$out      = [];
		$user_ids = get_users( [ 'meta_key' => '_application_passwords', 'fields' => 'ID' ] ); // phpcs:ignore WordPress.DB.SlowDBQuery
		foreach ( $user_ids as $uid ) {
			$user  = get_userdata( $uid );
			$items = \WP_Application_Passwords::get_user_application_passwords( $uid );
			foreach ( $items as $item ) {
				$out[] = [
					'user_id'    => (int) $uid,
					'user_login' => $user ? $user->user_login : (string) $uid,
					'uuid'       => $item['uuid'],
					'name'       => isset( $item['name'] ) ? $item['name'] : '',
					'created'    => ! empty( $item['created'] ) ? gmdate( 'Y-m-d H:i', (int) $item['created'] ) : '',
					'last_used'  => ! empty( $item['last_used'] ) ? gmdate( 'Y-m-d H:i', (int) $item['last_used'] ) : '',
					'last_ip'    => isset( $item['last_ip'] ) ? $item['last_ip'] : '',
				];
			}
		}

		return rest_ensure_response( [
			'success'   => true,
			'supported' => true,
			'items'     => $out,
		] );
	}

	/**
	 * POST /app-passwords/revoke
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function revoke( $request ) {
		if ( ! ApiHardening::app_passwords_supported() ) {
			return new \WP_Error( 'gemsecurity_unsupported', __( 'Application passwords are not available.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		$all = rest_sanitize_boolean( $request->get_param( 'all' ) );
		if ( $all ) {
			$user_ids = get_users( [ 'meta_key' => '_application_passwords', 'fields' => 'ID' ] ); // phpcs:ignore WordPress.DB.SlowDBQuery
			$n = 0;
			foreach ( $user_ids as $uid ) {
				$n += (int) \WP_Application_Passwords::delete_all_application_passwords( $uid );
			}
			return rest_ensure_response( [ 'success' => true, 'revoked' => $n ] );
		}

		$uid  = absint( $request->get_param( 'user_id' ) );
		$uuid = sanitize_text_field( (string) $request->get_param( 'uuid' ) );
		if ( ! $uid || '' === $uuid ) {
			return new \WP_Error( 'gemsecurity_missing_params', __( 'A user and password id are required.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		$result = \WP_Application_Passwords::delete_application_password( $uid, $uuid );
		if ( is_wp_error( $result ) ) {
			$result->add_data( [ 'status' => 400 ] );
			return $result;
		}

		return rest_ensure_response( [ 'success' => true, 'revoked' => 1 ] );
	}
}
