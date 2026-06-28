<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Firewall & hardening module.
 *
 * IP blocklist plus a curated set of WordPress hardening switches. Each switch
 * is driven by its own setting so site owners can opt in individually.
 */
class Firewall {

	public static function init() {
		$self = new self();

		// IP blocklist runs very early.
		add_action( 'init', [ $self, 'enforce_ip_blocklist' ], 0 );

		// Hardening switches.
		add_action( 'init', [ $self, 'apply_hardening' ], 1 );

		if ( Helper::get_setting( 'xmlrpc_disabled', false ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array' );
			// xmlrpc_call only fires inside individual WP method handlers;
			// system.* IXR built-ins bypass it entirely. Killing the request
			// at plugins_loaded (XMLRPC_REQUEST is defined before wp-load.php
			// runs) blocks everything before IXR_Server dispatches any method.
			if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
				status_header( 403 );
				nocache_headers();
				wp_die(
					esc_html__( 'XML-RPC services are disabled on this site.', 'gemsecurity' ),
					esc_html__( 'Disabled', 'gemsecurity' ),
					[ 'response' => 403 ]
				);
			}
		}

		if ( Helper::get_setting( 'hide_wp_version', true ) ) {
			add_filter( 'the_generator', '__return_empty_string' );
			remove_action( 'wp_head', 'wp_generator' );
		}

		if ( Helper::get_setting( 'disable_user_rest', true ) ) {
			add_filter( 'rest_endpoints', [ $self, 'maybe_remove_users_endpoint' ] );
		}

		if ( Helper::get_setting( 'disable_application_passwords', false ) ) {
			// Priority 20: WordPress core registers __return_true at priority 10
			// on `init`; running after it ensures our false wins.
			add_filter( 'wp_is_application_passwords_available', '__return_false', 20 );
		}
	}

	/* --------------------------------------------------------------------- */
	/* IP blocklist                                                           */
	/* --------------------------------------------------------------------- */

	public function enforce_ip_blocklist() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}
		if ( ! Helper::get_setting( 'firewall_enabled', true ) ) {
			return;
		}

		$blocklist = (array) Helper::get_setting( 'ip_blocklist', [] );
		if ( empty( $blocklist ) ) {
			return;
		}

		// Never lock out an already-authenticated administrator.
		if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
			return;
		}

		$ip = Helper::get_ip_address();
		if ( '0.0.0.0' === $ip ) {
			return;
		}

		foreach ( $blocklist as $entry ) {
			if ( self::ip_matches( $ip, trim( (string) $entry ) ) ) {
				Logger::log(
					'firewall_block',
					sprintf( 'Blocked request from blocklisted IP %s.', $ip ),
					Logger::SEVERITY_WARNING,
					[ 'user_id' => 0, 'ip_address' => $ip ]
				);
				status_header( 403 );
				nocache_headers();
				wp_die(
					esc_html__( 'Your access to this site has been blocked.', 'gemsecurity' ),
					esc_html__( 'Access denied', 'gemsecurity' ),
					[ 'response' => 403 ]
				);
			}
		}
	}

	/**
	 * Match an IP against an exact address or CIDR range (IPv4 + IPv6).
	 *
	 * @param string $ip
	 * @param string $entry
	 * @return bool
	 */
	public static function ip_matches( $ip, $entry ) {
		if ( '' === $entry ) {
			return false;
		}
		if ( false === strpos( $entry, '/' ) ) {
			return $ip === $entry;
		}

		list( $subnet, $bits ) = explode( '/', $entry, 2 );
		$bits = (int) $bits;

		$ip_bin     = @inet_pton( $ip );
		$subnet_bin = @inet_pton( $subnet );
		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$bytes = intdiv( $bits, 8 );
		$rem   = $bits % 8;

		if ( $bytes > 0 && 0 !== substr_compare( $ip_bin, $subnet_bin, 0, $bytes ) ) {
			return false;
		}
		if ( 0 === $rem ) {
			return true;
		}

		$mask = chr( 0xff << ( 8 - $rem ) & 0xff );
		return ( $ip_bin[ $bytes ] & $mask ) === ( $subnet_bin[ $bytes ] & $mask );
	}

	/* --------------------------------------------------------------------- */
	/* Hardening                                                              */
	/* --------------------------------------------------------------------- */

	public function apply_hardening() {
		// Disable the theme / plugin file editors.
		if ( Helper::get_setting( 'disable_file_editing', true ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}

		// Block ?author=N enumeration for anonymous visitors.
		if ( Helper::get_setting( 'block_author_enumeration', true ) && ! is_admin() && ! is_user_logged_in() ) {
			$author = isset( $_GET['author'] ) ? sanitize_text_field( wp_unslash( $_GET['author'] ) ) : '';
			if ( '' !== $author && preg_match( '/^\d+$/', $author ) ) {
				Logger::log(
					'author_enumeration_blocked',
					sprintf( 'Blocked author enumeration attempt (?author=%s).', $author ),
					Logger::SEVERITY_NOTICE,
					[ 'user_id' => 0 ]
				);
				wp_safe_redirect( home_url(), 301 );
				exit;
			}
		}
	}

	/**
	 * Remove the /wp/v2/users endpoints for unauthenticated requests so the
	 * REST API cannot be used to enumerate usernames.
	 *
	 * @param array $endpoints
	 * @return array
	 */
	public function maybe_remove_users_endpoint( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		foreach ( [ '/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)' ] as $route ) {
			if ( isset( $endpoints[ $route ] ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}
}
