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

	/** Option holding the recent CSP violation ring buffer. */
	const CSP_LOG_OPTION = 'gemsecurity_csp_reports';

	public static function init() {
		$self = new self();

		// security.txt (RFC 9116) is independent of the headers master switch.
		if ( Helper::get_setting( 'securitytxt_enabled', false ) ) {
			add_action( 'init', [ $self, 'add_securitytxt_rewrite' ] );
			add_action( 'template_redirect', [ $self, 'maybe_serve_securitytxt' ], 0 );
		}

		if ( ! Helper::get_setting( 'security_headers_enabled', false ) ) {
			return;
		}
		add_action( 'send_headers', [ $self, 'send' ], 99 );
		add_action( 'admin_init', [ $self, 'send' ], 99 );
		add_action( 'login_init', [ $self, 'send' ], 99 );
		// REST requests are answered during parse_request, before core ever
		// fires send_headers — without this, every /wp-json/ response goes out
		// with none of the headers above.
		add_filter( 'rest_post_dispatch', [ $self, 'add_to_rest_response' ], 99 );
	}

	/**
	 * @param mixed $result
	 * @return mixed
	 */
	public function add_to_rest_response( $result ) {
		if ( $result instanceof \WP_HTTP_Response ) {
			$existing = array_change_key_case( $result->get_headers(), CASE_LOWER );
			foreach ( $this->build_headers() as $name => $value ) {
				// Never override a header the endpoint set deliberately.
				if ( '' !== $value && ! isset( $existing[ strtolower( $name ) ] ) ) {
					$result->header( $name, $value );
				}
			}
		}
		return $result;
	}

	/* ------------------------------------------------------------------ */
	/* security.txt (RFC 9116)                                             */
	/* ------------------------------------------------------------------ */

	public function add_securitytxt_rewrite() {
		add_rewrite_rule( '^\.well-known/security\.txt$', 'index.php?gemsec_securitytxt=1', 'top' );
		add_rewrite_tag( '%gemsec_securitytxt%', '1' );
	}

	public function maybe_serve_securitytxt() {
		// Match both the rewrite var and a direct request, so it works even
		// before rewrite rules are flushed.
		$req = isset( $_SERVER['REQUEST_URI'] ) ? wp_parse_url( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), PHP_URL_PATH ) : '';
		if ( '1' !== get_query_var( 'gemsec_securitytxt' ) && '/.well-known/security.txt' !== $req ) {
			return;
		}

		$contact = trim( (string) Helper::get_setting( 'securitytxt_contact', '' ) );
		if ( '' === $contact ) {
			// The site's public contact for security reports — deliberately the
			// WordPress admin address and not the internal alert recipient,
			// which is where *our* notifications go, not where researchers write.
			$contact = 'mailto:' . get_option( 'admin_email' );
		} elseif ( false === strpos( $contact, ':' ) ) {
			// Bare email or URL → normalise to a mailto:/https: URI.
			$contact = is_email( $contact ) ? 'mailto:' . $contact : $contact;
		}

		$expires = trim( (string) Helper::get_setting( 'securitytxt_expires', '' ) );
		if ( '' === $expires ) {
			$expires = gmdate( 'Y-m-d\TH:i:s\Z', time() + YEAR_IN_SECONDS );
		}

		$lines   = [ 'Contact: ' . $contact, 'Expires: ' . $expires ];
		$policy  = trim( (string) Helper::get_setting( 'securitytxt_policy', '' ) );
		if ( '' !== $policy ) {
			$lines[] = 'Policy: ' . $policy;
		}
		$lines[] = 'Preferred-Languages: en';

		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo esc_html( implode( "\n", $lines ) ) . "\n";
		exit;
	}

	/* ------------------------------------------------------------------ */
	/* CSP violation reporting                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Store a CSP violation report (capped ring buffer of 50).
	 *
	 * @param array $report Parsed csp-report body.
	 */
	public static function record_csp_report( $report ) {
		$log = get_option( self::CSP_LOG_OPTION, [] );
		if ( ! is_array( $log ) ) {
			$log = [];
		}
		array_unshift( $log, [
			'blocked'   => isset( $report['blocked-uri'] ) ? substr( (string) $report['blocked-uri'], 0, 300 ) : '',
			'directive' => isset( $report['violated-directive'] ) ? substr( (string) $report['violated-directive'], 0, 100 ) : '',
			'document'  => isset( $report['document-uri'] ) ? substr( (string) $report['document-uri'], 0, 300 ) : '',
			'time'      => gmdate( 'Y-m-d H:i:s' ),
		] );
		update_option( self::CSP_LOG_OPTION, array_slice( $log, 0, 50 ), false );
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
				// Route violations to our own collector when reporting is on.
				if ( Helper::get_setting( 'header_csp_report', false ) ) {
					$endpoint = rest_url( 'gemsecurity/v1/csp-report' );
					if ( false === strpos( $csp, 'report-uri' ) ) {
						$csp = rtrim( $csp, '; ' ) . '; report-uri ' . esc_url_raw( $endpoint );
					}
				}
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
