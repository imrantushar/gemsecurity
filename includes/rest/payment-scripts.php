<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\PaymentIntegrity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Payment-page script integrity REST controller.
 */
class PaymentScripts {

	/**
	 * POST /payment-scripts — public collector (browsers post here).
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function ingest( $request ) {
		$body    = $request->get_json_params();
		$scripts = isset( $body['scripts'] ) && is_array( $body['scripts'] ) ? $body['scripts'] : [];
		$page    = isset( $body['page'] ) ? (string) $body['page'] : '';
		if ( ! empty( $scripts ) ) {
			PaymentIntegrity::ingest( $scripts, $page );
		}
		return new \WP_REST_Response( null, 204 );
	}

	/**
	 * GET /payment-scripts — baseline + latest inventory + recent alerts (admin).
	 */
	public static function get() {
		$baseline = get_option( PaymentIntegrity::BASELINE_OPTION, null );
		$seen     = get_option( PaymentIntegrity::SEEN_OPTION, null );
		$alerts   = get_option( PaymentIntegrity::ALERTS_OPTION, [] );
		$base_arr = is_array( $baseline ) ? $baseline : [];

		$inventory = [];
		if ( is_array( $seen ) && ! empty( $seen['scripts'] ) ) {
			foreach ( $seen['scripts'] as $src ) {
				$inventory[] = [ 'src' => $src, 'authorised' => in_array( $src, $base_arr, true ) ];
			}
		}

		return rest_ensure_response( [
			'success'        => true,
			'has_baseline'   => is_array( $baseline ),
			'last_seen'      => is_array( $seen ) ? ( $seen['time'] ?? '' ) : '',
			'inventory'      => $inventory,
			'alerts'         => is_array( $alerts ) ? $alerts : [],
		] );
	}

	/**
	 * POST /payment-scripts/authorize — set the baseline to the current inventory.
	 */
	public static function authorize() {
		$scripts = PaymentIntegrity::authorise_current();
		return rest_ensure_response( [ 'success' => true, 'count' => count( $scripts ) ] );
	}
}
