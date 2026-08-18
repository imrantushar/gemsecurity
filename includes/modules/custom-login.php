<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Custom login URL — serve the login form from a secret slug and 404 the
 * default wp-login.php for logged-out visitors. Stops the bulk of automated
 * login attacks.
 *
 * Recovery if locked out: remove the `custom_login_*` keys from the
 * `gemsecurity_settings` option (e.g. via wp-cli or the database).
 */
class CustomLogin {

	private $slug = '';
	private $serving = false;

	public static function init() {
		$slug = sanitize_title( (string) Helper::get_setting( 'custom_login_slug', '' ) );
		if ( ! Helper::get_setting( 'custom_login_enabled', false ) || '' === $slug ) {
			return;
		}
		$self       = new self();
		$self->slug = $slug;

		// Rewrite generated login URLs to the custom slug.
		add_filter( 'site_url', [ $self, 'filter_site_url' ], 10, 2 );
		add_filter( 'network_site_url', [ $self, 'filter_site_url' ], 10, 2 );
		add_filter( 'wp_redirect', [ $self, 'filter_redirect' ], 10, 1 );
		add_filter( 'login_url', [ $self, 'login_url' ], 10, 1 );
		add_filter( 'lostpassword_url', [ $self, 'login_url' ], 10, 1 );

		// Serve the slug once WordPress is fully loaded (pluggable functions
		// available); 404 the default wp-login.php from inside its own bootstrap.
		add_action( 'wp_loaded', [ $self, 'serve_slug' ], 1 );
		add_action( 'login_init', [ $self, 'block_default_login' ], 0 );
	}

	private function new_login_url( $scheme = null ) {
		return home_url( '/' . $this->slug . '/', $scheme );
	}

	/* ------------------------------------------------------------------ */

	/**
	 * If the secret slug is requested, render the login page.
	 */
	public function serve_slug() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) || is_admin() ) {
			return;
		}

		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$path = trim( (string) wp_parse_url( $uri, PHP_URL_PATH ), '/' );
		$home = trim( (string) wp_parse_url( home_url(), PHP_URL_PATH ), '/' );
		$rel  = $home ? trim( preg_replace( '#^' . preg_quote( $home, '#' ) . '#', '', $path ), '/' ) : $path;

		if ( $rel !== $this->slug ) {
			return;
		}

		if ( is_user_logged_in() && empty( $_REQUEST['action'] ) ) {
			wp_safe_redirect( admin_url() );
			exit;
		}

		$this->serving = true;
		global $pagenow, $error, $interim_login, $action, $user_login;
		$pagenow = 'wp-login.php';
		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Fires inside wp-login.php. If we did not get here via the secret slug and
	 * the visitor is logged out, hide the default login behind a 404.
	 */
	public function block_default_login() {
		if ( $this->serving || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		$action = isset( $_REQUEST['action'] ) ? $_REQUEST['action'] : '';
		if ( 'postpass' === $action || 'logout' === $action ) {
			return; // Don't break password-protected posts or logout links.
		}

		// Social sign-in returns to wp-login.php with the provider's code. That
		// URL is registered with Google and friends and cannot be moved to the
		// secret slug, so 404ing it here would break every social login the
		// moment a custom login URL is switched on. Both parameters are
		// dispatched immediately afterwards on login_init.
		if ( isset( $_GET['gemsec_oauth'] ) || isset( $_GET['gemsec_oauth_cb'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		// The second-factor form posts back here while the visitor is still
		// logged out, so denying it would break every 2FA sign-in the moment a
		// custom login URL is switched on. The token in the request is what
		// authorises it, and it is verified immediately afterwards.
		if ( 'gemsec_2fa' === $action ) {
			return;
		}
		if ( ! is_user_logged_in() ) {
			$this->deny();
		} else {
			// Logged-in users who land on wp-login.php directly should go to admin,
			// not be served the login form (which would expose the default URL).
			wp_safe_redirect( admin_url() );
			exit;
		}
	}

	private function deny() {
		status_header( 404 );
		nocache_headers();
		wp_die(
			esc_html__( 'This page does not exist.', 'gemsecurity' ),
			'404',
			[ 'response' => 404 ]
		);
	}

	/* ------------------------------------------------------------------ */
	/* URL rewriting                                                       */
	/* ------------------------------------------------------------------ */

	public function filter_site_url( $url, $path ) {
		return $this->maybe_rewrite( $url );
	}

	public function filter_redirect( $location ) {
		return $this->maybe_rewrite( $location );
	}

	public function login_url( $url ) {
		return $this->maybe_rewrite( $url );
	}

	private function maybe_rewrite( $url ) {
		if ( false === strpos( $url, 'wp-login.php' ) ) {
			return $url;
		}
		$query = wp_parse_url( $url, PHP_URL_QUERY );
		$base  = $this->new_login_url();
		return $query ? $base . '?' . $query : $base;
	}
}
