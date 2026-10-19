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
 * The slug is only a secret for as long as nothing hands it out. WordPress
 * redirects a logged-out visitor from wp-admin to the login page, and because
 * this class rewrites login URLs, that redirect pointed straight at the secret
 * address — so anyone could type /wp-admin and be told where the login lives.
 * Logged-out wp-admin requests are therefore refused with a 404 rather than
 * redirected; see {@see block_admin_when_logged_out()}.
 *
 * Recovery if locked out: add
 * `define( 'GEMSECURITY_DISABLE_CUSTOM_LOGIN', true );` to wp-config.php,
 * which turns the whole module off and puts wp-login.php back. Removing the
 * `custom_login_*` keys from the `gemsecurity_settings` option works too.
 */
class CustomLogin {

	private $slug = '';
	private $serving = false;

	public static function init() {
		// Recovery hatch. Being locked out of your own site by a security
		// plugin is the worst thing it can do to you, and telling somebody to
		// go and edit an option in the database is not a recovery plan — plenty
		// of people who can edit wp-config.php cannot comfortably do that.
		if ( defined( 'GEMSECURITY_DISABLE_CUSTOM_LOGIN' ) && GEMSECURITY_DISABLE_CUSTOM_LOGIN ) {
			return;
		}

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
		add_filter( 'register_url', [ $self, 'login_url' ], 10, 1 );
		add_filter( 'logout_url', [ $self, 'logout_url' ], 10, 1 );

		// Serve the slug once WordPress is fully loaded (pluggable functions
		// available); 404 the default wp-login.php from inside its own bootstrap.
		add_action( 'wp_loaded', [ $self, 'serve_slug' ], 1 );
		add_action( 'login_init', [ $self, 'block_default_login' ], 0 );

		// wp_loaded fires from wp-settings.php, which wp-admin/admin.php has
		// already run by the time it calls auth_redirect() — so this lands
		// before the redirect that would leak the slug.
		add_action( 'wp_loaded', [ $self, 'block_admin_when_logged_out' ], 1 );
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

	/**
	 * Send logged-out wp-admin requests to the front page instead of the login.
	 *
	 * auth_redirect() sends anonymous visitors to the login URL, and this class
	 * rewrites that URL to the secret slug — which turned /wp-admin into a
	 * public "where is the login page?" oracle and made the whole feature
	 * pointless.
	 *
	 * The redirect goes to the home page rather than to a 404. Both reveal
	 * nothing about the slug, but the two failure modes are not equivalent: if
	 * this ever misjudges a real administrator — an expired cookie, a session
	 * that has not been recognised yet — a 404 reads as "my site is broken and
	 * I am locked out", while the home page leaves them one click from their
	 * own login. A security feature should degrade towards the owner keeping
	 * access, not towards losing it.
	 *
	 * Endpoints inside wp-admin that are legitimately public are left alone:
	 * admin-ajax.php and admin-post.php both serve logged-out callers by
	 * design, and blocking them would break front-end forms, payment callbacks
	 * and anything else that posts to them.
	 *
	 * @return void
	 */
	public function block_admin_when_logged_out() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}
		if ( ! is_admin() || is_user_logged_in() ) {
			return;
		}
		if ( ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return;
		}

		$script = basename( (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '', PHP_URL_PATH ) );
		if ( in_array( $script, [ 'admin-ajax.php', 'admin-post.php' ], true ) ) {
			return;
		}

		wp_safe_redirect( home_url( '/' ) );
		exit;
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

	/**
	 * Login / lost-password / registration links.
	 *
	 * Plugins and themes print these on public pages — in menus, "log in to
	 * continue" buttons, and the settings objects their scripts read — so
	 * for a logged-out visitor every page would hand out the secret address.
	 * There they point at the public login page chosen in settings (or the
	 * homepage) instead. The real login screen itself, and signed-in users,
	 * still get the secret address. Login forms embedded on public pages
	 * keep posting to it (that goes through site_url()), or they would stop
	 * working.
	 *
	 * @param string $url
	 * @return string
	 */
	public function login_url( $url ) {
		if ( $this->hide_from_visitor() ) {
			return $this->public_login_url();
		}
		return $this->maybe_rewrite( $url );
	}

	/**
	 * A visitor who is not signed in has nothing to log out of; the link
	 * would only reveal the secret address.
	 *
	 * @param string $url
	 * @return string
	 */
	public function logout_url( $url ) {
		if ( $this->hide_from_visitor() ) {
			return home_url( '/' );
		}
		return $this->maybe_rewrite( $url );
	}

	/** Logged-out request for anything other than the login screen itself. */
	private function hide_from_visitor() {
		if ( $this->serving || ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return false;
		}
		if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) {
			return false;
		}
		// Too early to know who is asking: leave it alone.
		if ( ! function_exists( 'is_user_logged_in' ) || ! did_action( 'plugins_loaded' ) ) {
			return false;
		}
		return ! is_user_logged_in();
	}

	/** Where public login links go: the chosen page, else the homepage. */
	private function public_login_url() {
		$page_id = (int) Helper::get_setting( 'custom_login_public_page', 0 );
		$url     = $page_id && 'publish' === get_post_status( $page_id ) ? get_permalink( $page_id ) : '';
		/**
		 * Filter where public login links point while the login URL is secret.
		 *
		 * @param string $url
		 */
		return (string) apply_filters( 'gemsecurity/custom_login_public_url', $url ? $url : home_url( '/' ) );
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
