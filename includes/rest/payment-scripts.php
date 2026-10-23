<?php
namespace GemSecurity\Rest;

use GemSecurity\Helper;
use GemSecurity\Modules\PaymentIntegrity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Payment-page script integrity REST controller.
 */
class PaymentScripts {

	/** Per-IP submission cap for the public /payment-scripts collector. */
	const RATE_LIMIT_MAX    = 30;
	const RATE_LIMIT_WINDOW = 5 * MINUTE_IN_SECONDS;

	/**
	 * POST /payment-scripts — public collector (browsers post here).
	 *
	 * Unauthenticated by design (the checkout-page collector script has no
	 * user session to authenticate with, so a capability check isn't
	 * possible). Lighter-weight defenses instead:
	 *
	 * - A signed token printed into the payment page by the collector, valid
	 *   for an hour. Blind POSTs (no page fetched) are dropped; the
	 *   inventory is still treated as untrusted — see authorize().
	 * - Same-origin check: a real browser sendBeacon()/fetch() call from the
	 *   collector always carries an Origin (or at least Referer) header
	 *   matching this site — that's enforced by the browser, not something
	 *   page JS can override. This doesn't stop a determined attacker
	 *   deliberately crafting headers, but it blocks the far more common
	 *   case of a scanner or script hitting a discovered REST route directly
	 *   with no headers at all.
	 * - Per-IP rate limit, so a remote caller that does pass the origin
	 *   check still can't flood this endpoint or seed the "seen inventory"
	 *   freely.
	 *
	 * Always responds 204 regardless of outcome — this is a fire-and-forget
	 * beacon (sendBeacon/fetch(keepalive) callers don't inspect the
	 * response), and silently dropping rather than returning 4xx avoids
	 * giving a prober a signal to distinguish "rejected" from "accepted".
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function ingest( $request ) {
		$body = $request->get_json_params();
		$token = is_array( $body ) && isset( $body['token'] ) ? (string) $body['token'] : '';
		if ( PaymentIntegrity::valid_token( $token ) && self::is_same_origin( $request ) && ! self::is_rate_limited() ) {
			$scripts = isset( $body['scripts'] ) && is_array( $body['scripts'] ) ? $body['scripts'] : [];
			$page    = isset( $body['page'] ) ? (string) $body['page'] : '';
			if ( ! empty( $scripts ) ) {
				PaymentIntegrity::ingest( $scripts, $page );
			}
		}
		return new \WP_REST_Response( null, 204 );
	}

	/**
	 * @param \WP_REST_Request $request
	 * @return bool
	 */
	private static function is_same_origin( $request ) {
		$site_host = wp_parse_url( home_url(), PHP_URL_HOST );

		$origin = $request->get_header( 'origin' );
		if ( $origin ) {
			return wp_parse_url( $origin, PHP_URL_HOST ) === $site_host;
		}

		$referer = $request->get_header( 'referer' );
		if ( $referer ) {
			return wp_parse_url( $referer, PHP_URL_HOST ) === $site_host;
		}

		// Neither header present — not what a real browser beacon looks like.
		return false;
	}

	/** @return bool */
	private static function is_rate_limited() {
		$key   = 'gemsec_payscr_rl_' . md5( Helper::get_ip_address() );
		$count = (int) get_transient( $key ) + 1;
		set_transient( $key, $count, self::RATE_LIMIT_WINDOW );
		return $count > self::RATE_LIMIT_MAX;
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
			'success'      => true,
			'has_baseline' => is_array( $baseline ),
			'last_seen'    => is_array( $seen ) ? ( $seen['time'] ?? '' ) : '',
			// The page the current inventory was captured from — surfaced so
			// the admin UI can show it next to the Authorise action instead
			// of trusting the inventory blindly (see PaymentIntegrity.js).
			'seen_page'    => is_array( $seen ) ? ( $seen['page'] ?? '' ) : '',
			'inventory'    => $inventory,
			'seen_hash'    => PaymentIntegrity::inventory_hash( is_array( $seen ) && ! empty( $seen['scripts'] ) ? $seen['scripts'] : [] ),
			'alerts'       => is_array( $alerts ) ? $alerts : [],
		] );
	}

	/**
	 * POST /payment-scripts/authorize — set the baseline to the inventory the
	 * admin reviewed (seen_hash from GET), refusing if it changed since.
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function authorize( $request ) {
		$scripts = PaymentIntegrity::authorise_current( (string) $request->get_param( 'seen_hash' ) );
		if ( false === $scripts ) {
			return new \WP_Error(
				'gemsecurity_inventory_changed',
				__( 'The script list changed since you loaded this page. Review the new list, then authorise again.', 'gemsecurity' ),
				[ 'status' => 409 ]
			);
		}
		return rest_ensure_response( [ 'success' => true, 'count' => count( $scripts ) ] );
	}
}
