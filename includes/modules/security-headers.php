<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Security response headers.
 *
 * Emits a configurable set of hardening headers on front-end, admin and login
 * responses. Each header is individually toggleable; CSP defaults to off (and
 * report-only when first enabled) because it can break sites.
 */
class SecurityHeaders {

	public static function init() {
		if ( ! Helper::get_setting( 'security_headers_enabled', false ) ) {
			return;
		}
		$self = new self();
		add_action( 'send_headers', [ $self, 'send' ], 99 );
		add_action( 'admin_init', [ $self, 'send' ], 99 );
		add_action( 'login_init', [ $self, 'send' ], 99 );
	}

	public function send() {
		if ( headers_sent() ) {
			return;
		}

		foreach ( $this->build_headers() as $name => $value ) {
			if ( '' !== $value ) {
				header( "{$name}: {$value}" );
			}
		}
	}

	/**
	 * @return array<string,string>
	 */
	public function build_headers() {
		$headers = [];

		$xfo = Helper::get_setting( 'header_x_frame_options', 'SAMEORIGIN' );
		if ( in_array( $xfo, [ 'SAMEORIGIN', 'DENY' ], true ) ) {
			$headers['X-Frame-Options'] = $xfo;
		}

		if ( Helper::get_setting( 'header_x_content_type_options', true ) ) {
			$headers['X-Content-Type-Options'] = 'nosniff';
		}

		$ref = Helper::get_setting( 'header_referrer_policy', 'strict-origin-when-cross-origin' );
		if ( $ref && 'off' !== $ref ) {
			$headers['Referrer-Policy'] = $ref;
		}

		$perm = Helper::get_setting( 'header_permissions_policy', 'geolocation=(), camera=(), microphone=()' );
		if ( $perm && 'off' !== $perm ) {
			$headers['Permissions-Policy'] = $perm;
		}

		// HSTS only over HTTPS.
		if ( Helper::get_setting( 'header_hsts_enabled', false ) && is_ssl() ) {
			$max = max( 0, (int) Helper::get_setting( 'header_hsts_max_age', 15552000 ) );
			$hsts = "max-age={$max}";
			if ( Helper::get_setting( 'header_hsts_subdomains', false ) ) {
				$hsts .= '; includeSubDomains';
			}
			if ( Helper::get_setting( 'header_hsts_preload', false ) ) {
				$hsts .= '; preload';
			}
			$headers['Strict-Transport-Security'] = $hsts;
		}

		// Content-Security-Policy.
		if ( Helper::get_setting( 'header_csp_enabled', false ) ) {
			$csp = trim( (string) Helper::get_setting( 'header_csp_value', "default-src 'self'" ) );
			if ( '' !== $csp ) {
				$key = Helper::get_setting( 'header_csp_report_only', true )
					? 'Content-Security-Policy-Report-Only'
					: 'Content-Security-Policy';
				$headers[ $key ] = $csp;
			}
		}

		/**
		 * Filter the security headers before they are sent.
		 *
		 * @param array<string,string> $headers
		 */
		return apply_filters( 'gemsecurity/security_headers', $headers );
	}
}
