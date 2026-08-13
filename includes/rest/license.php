<?php
namespace GemSecurity\Rest;

use GemSecurity\StoreLicense;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Backs the wp-admin Settings > License screen.
 *
 * GemSecurity (free) is registered `is_free: true` with the StoreEngine
 * SDK, so there is no license key to activate — SE_License_SDK_Client::
 * license() throws a RuntimeException for free products, and the SDK's own
 * REST routes for that live under a separate `storeengine-sdk/v1` namespace
 * we don't enable here. This only proxies the SDK's usage-tracking opt-in
 * (SE_License_SDK_Insights), which has no such gate, through our existing
 * `gemsecurity/v1` namespace so the settings tab can use the same nonce and
 * `apiFetch` helper every other tab already uses.
 *
 * GET  /license/insights   → current opt-in status + package metadata.
 * POST /license/insights   → toggle opt-in { opt_in }.
 */
class License {

	/**
	 * GET /license/insights
	 */
	public static function get() {
		return rest_ensure_response( self::status() );
	}

	/**
	 * POST /license/insights
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function set( $request ) {
		$client = StoreLicense::get_client();

		if ( $client ) {
			if ( rest_sanitize_boolean( $request->get_param( 'opt_in' ) ) ) {
				$client->insights()->optIn();
			} else {
				$client->insights()->optOut();
			}
		}

		return rest_ensure_response( self::status() );
	}

	private static function status() {
		$client = StoreLicense::get_client();

		return [
			'success'      => true,
			'allowed'      => $client ? $client->insights()->is_tracking_allowed() : false,
			'version'      => defined( 'GEMSECURITY_VERSION' ) ? GEMSECURITY_VERSION : '',
			'package_name' => $client ? $client->getPackageName() : 'GemSecurity',
			'purchase_url' => $client ? $client->get_purchase_url() : null,
			'device_id'    => $client ? $client->get_device_id() : '',
		];
	}
}
