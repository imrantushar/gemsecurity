<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Client-side / payment-page script integrity (PCI-DSS 4.0 §6.4.3 + §11.6.1).
 *
 * On checkout pages a tiny inline collector reports the set of scripts the
 * browser actually loaded. We compare that against an admin-authorised baseline
 * and flag any new/unexpected script — the signal of a Magecart-style skimmer
 * injected into the payment page.
 */
class PaymentIntegrity {

	const BASELINE_OPTION = 'gemsecurity_payment_baseline';
	const ALERTS_OPTION   = 'gemsecurity_payment_alerts';
	const SEEN_OPTION     = 'gemsecurity_payment_seen';

	/** Most entries one report may carry; a checkout page has a few dozen. */
	const MAX_SCRIPTS = 100;
	/** How long the token printed into a payment page stays valid. */
	const TOKEN_TTL   = HOUR_IN_SECONDS;

	public static function init() {
		if ( ! Helper::get_setting( 'payment_integrity_enabled', false ) ) {
			return;
		}
		$self = new self();
		add_action( 'wp_footer', [ $self, 'inject_collector' ], 99 );
	}

	/** Is the current front-end request a payment/checkout page? */
	public static function is_payment_page() {
		$is = false;
		if ( function_exists( 'is_checkout' ) && is_checkout() ) {
			$is = true;
		}
		$ids = array_filter( array_map( 'absint', (array) Helper::get_setting( 'payment_page_ids', [] ) ) );
		if ( ! $is && $ids && is_page( $ids ) ) {
			$is = true;
		}
		/**
		 * Filter whether the current request is a monitored payment page.
		 *
		 * @param bool $is
		 */
		return (bool) apply_filters( 'gemsecurity/is_payment_page', $is );
	}

	/** Print the client-side script collector on payment pages. */
	public function inject_collector() {
		if ( is_admin() || ! self::is_payment_page() ) {
			return;
		}
		$endpoint = esc_url_raw( rest_url( 'gemsecurity/v1/payment-scripts' ) );
		// A signed, short-lived token ties a report to a page this site
		// actually served, so blind POSTs to the public route are dropped.
		$token = Helper::sign_payload( [ 'k' => 'payment_collector' ] );
		$js = "(function(){try{var s=[].slice.call(document.scripts).map(function(x){return x.src?x.src:('inline:'+((x.textContent||'').length));});"
			. "var b=JSON.stringify({scripts:s,page:location.pathname,token:" . wp_json_encode( $token ) . "});"
			. "if(navigator.sendBeacon){navigator.sendBeacon(" . wp_json_encode( $endpoint ) . ",new Blob([b],{type:'application/json'}));}"
			. "else{fetch(" . wp_json_encode( $endpoint ) . ",{method:'POST',body:b,headers:{'Content-Type':'application/json'},keepalive:true});}}catch(e){}})();";
		echo "<script>{$js}</script>\n"; // phpcs:ignore WordPress.Security.EscapeOutput -- static, self-built JS.
	}

	/* ------------------------------------------------------------------ */
	/* Report handling (called from the REST controller)                   */
	/* ------------------------------------------------------------------ */

	/**
	 * Ingest a browser report of loaded scripts.
	 *
	 * @param array  $scripts
	 * @param string $page
	 */
	/**
	 * Whether a token came from inject_collector() and is still fresh.
	 *
	 * @param string $token
	 * @return bool
	 */
	public static function valid_token( $token ) {
		$data = Helper::verify_signed_payload( (string) $token, self::TOKEN_TTL );
		return is_array( $data ) && isset( $data['k'] ) && 'payment_collector' === $data['k'];
	}

	/**
	 * Fingerprint of an inventory, so Authorise can prove the admin approved
	 * exactly the list they were shown.
	 *
	 * @param array $scripts
	 * @return string
	 */
	public static function inventory_hash( array $scripts ) {
		return hash( 'sha256', wp_json_encode( array_values( $scripts ) ) );
	}

	public static function ingest( array $scripts, $page ) {
		// Only what a browser can report: script URLs, or "inline:<length>".
		$scripts = array_slice( array_values( array_unique( array_filter( array_map( static function ( $s ) {
			$s = substr( sanitize_text_field( (string) $s ), 0, 300 );
			if ( preg_match( '#^inline:\d{1,9}$#', $s ) ) {
				return $s;
			}
			// Format check only — no DNS lookup (that is what wp_http_validate_url does).
			$parts = wp_parse_url( $s );
			return isset( $parts['scheme'], $parts['host'] ) && in_array( strtolower( $parts['scheme'] ), [ 'http', 'https' ], true ) ? $s : '';
		}, array_slice( $scripts, 0, self::MAX_SCRIPTS * 2 ) ) ) ) ), 0, self::MAX_SCRIPTS );
		if ( empty( $scripts ) ) {
			return;
		}

		// Record the latest inventory so the admin can authorise it.
		update_option( self::SEEN_OPTION, [ 'scripts' => $scripts, 'page' => sanitize_text_field( $page ), 'time' => gmdate( 'Y-m-d H:i:s' ) ], false );

		$baseline = get_option( self::BASELINE_OPTION, null );
		if ( ! is_array( $baseline ) ) {
			return; // No baseline yet → nothing is "unauthorised" until the admin sets one.
		}

		$unauthorised = array_values( array_diff( $scripts, $baseline ) );
		if ( empty( $unauthorised ) ) {
			return;
		}

		// Raise each unauthorised script once a day, so a stream of reports
		// (real or forged) cannot flood the log and alert emails.
		$unauthorised = array_values( array_filter( $unauthorised, static function ( $src ) {
			$key = 'gemsec_payscr_seen_' . md5( $src );
			if ( get_transient( $key ) ) {
				return false;
			}
			set_transient( $key, 1, DAY_IN_SECONDS );
			return true;
		} ) );
		if ( empty( $unauthorised ) ) {
			return;
		}

		$alerts = get_option( self::ALERTS_OPTION, [] );
		$alerts = is_array( $alerts ) ? $alerts : [];
		foreach ( $unauthorised as $src ) {
			array_unshift( $alerts, [ 'src' => $src, 'page' => sanitize_text_field( $page ), 'time' => gmdate( 'Y-m-d H:i:s' ) ] );
		}
		update_option( self::ALERTS_OPTION, array_slice( $alerts, 0, 50 ), false );

		Logger::log(
			'payment_script_unauthorised',
			sprintf(
				/* translators: 1: count, 2: page */
				_n( '%1$d unauthorised script on the payment page %2$s.', '%1$d unauthorised scripts on the payment page %2$s.', count( $unauthorised ), 'gemsecurity' ),
				count( $unauthorised ),
				$page
			),
			Logger::SEVERITY_CRITICAL,
			[ 'user_id' => 0, 'context' => [ 'scripts' => $unauthorised ] ]
		);
	}

	/**
	 * Authorise the last-seen inventory as the new baseline — only if it is
	 * still the exact list the admin reviewed. The inventory comes from a
	 * public beacon, so a report landing between "view" and "Authorise"
	 * must not slip a script into the baseline unseen.
	 *
	 * @param string $expected_hash inventory_hash() of the list shown to the admin.
	 * @return array|false Authorised scripts, or false if the inventory changed.
	 */
	public static function authorise_current( $expected_hash ) {
		$seen = get_option( self::SEEN_OPTION, null );
		$scripts = is_array( $seen ) && ! empty( $seen['scripts'] ) ? $seen['scripts'] : [];
		if ( ! hash_equals( self::inventory_hash( $scripts ), (string) $expected_hash ) ) {
			return false;
		}
		update_option( self::BASELINE_OPTION, $scripts, false );
		update_option( self::ALERTS_OPTION, [], false );
		return $scripts;
	}
}
