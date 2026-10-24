<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Social / OAuth login — Google, Facebook, GitHub and Twitter (X).
 *
 * OAuth 2.0 Authorization Code flow with a single, fixed redirect URI; the
 * provider is carried in the signed `state` value. Twitter uses PKCE.
 *
 * User meta: _gemsec_oauth_{provider}_id, _gemsec_oauth_avatar.
 */
class SocialLogin {

	/** What the provider said the last time a token exchange failed. */
	private static $last_token_error = '';

	const STATE_PREFIX = 'gemsec_oauth_state_';

	/** Guards the one-time inline stylesheet on front-end forms. */
	private static $style_printed = false;

	public static function providers_meta() {
		return [
			'google' => [
				'label'     => 'Google',
				'authorize' => 'https://accounts.google.com/o/oauth2/v2/auth',
				'token'     => 'https://oauth2.googleapis.com/token',
				'userinfo'  => 'https://openidconnect.googleapis.com/v1/userinfo',
				'scope'     => 'openid email profile',
				'pkce'      => false,
				'color'     => '#ea4335',
			],
			'facebook' => [
				'label'     => 'Facebook',
				'authorize' => 'https://www.facebook.com/v19.0/dialog/oauth',
				'token'     => 'https://graph.facebook.com/v19.0/oauth/access_token',
				'userinfo'  => 'https://graph.facebook.com/me?fields=id,name,email,picture.type(large)',
				'scope'     => 'email public_profile',
				'pkce'      => false,
				'color'     => '#1877f2',
			],
			'github' => [
				'label'     => 'GitHub',
				'authorize' => 'https://github.com/login/oauth/authorize',
				'token'     => 'https://github.com/login/oauth/access_token',
				'userinfo'  => 'https://api.github.com/user',
				'scope'     => 'read:user user:email',
				'pkce'      => false,
				'color'     => '#24292f',
			],
			'twitter' => [
				'label'     => 'Twitter',
				// X retired the twitter.com/api.twitter.com OAuth2 domains —
				// twitter.com/i/oauth2/authorize now 404s ("Page doesn't
				// exist"), and api.twitter.com/2/... along with it. x.com /
				// api.x.com are the only endpoints that still work, and are
				// what X's own docs point at. Credentials::test_social()
				// already used api.x.com for its token check; these three
				// were the only ones still on the dead domain, which broke
				// the *real* sign-in flow (start_flow()'s redirect, and the
				// callback's token exchange + profile fetch) even though the
				// credential test could still look fine.
				'authorize' => 'https://x.com/i/oauth2/authorize',
				'token'     => 'https://api.x.com/2/oauth2/token',
				'userinfo'  => 'https://api.x.com/2/users/me?user.fields=profile_image_url',
				'scope'     => 'users.read tweet.read',
				'pkce'      => true,
				'color'     => '#1da1f2',
			],
		];
	}

	public static function init() {
		if ( ! Helper::get_setting( 'social_login_enabled', false ) ) {
			return;
		}
		$self = new self();

		// Default WordPress login form (wp-login.php). The buttons are echoed
		// inside the form via `login_form` (which fires *before* the submit
		// button) and then relocated directly after the "Log In" button by the
		// inline script in styles().
		add_action( 'login_init', [ $self, 'maybe_dispatch' ], 1 );
		add_action( 'login_form', [ $self, 'render_buttons' ] );
		add_action( 'login_enqueue_scripts', [ $self, 'styles' ] );

		// Front-end login forms. These fire on the theme/plugin-rendered sign-in
		// pages where the core `login_form` action never runs, so the buttons
		// would otherwise only appear on wp-login.php.
		add_action( 'storeengine/templates/shortcode/after_login', [ $self, 'render_frontend' ] );
		add_action( 'academy/templates/shortcode/after_login', [ $self, 'render_frontend' ] );
		// Core wp_login_form() (and WooCommerce, which nests it) — append below the fields.
		add_filter( 'login_form_bottom', [ $self, 'append_to_form' ], 10, 1 );
	}

	/** The single fixed redirect URI registered with each provider. */
	public static function redirect_uri() {
		return site_url( 'wp-login.php?gemsec_oauth_cb=1' );
	}

	public static function enabled_providers() {
		$out = [];
		foreach ( self::providers_meta() as $key => $meta ) {
			if (
				Helper::get_setting( "social_{$key}_enabled", false ) &&
				Helper::get_setting( "social_{$key}_client_id", '' ) &&
				Helper::get_setting( "social_{$key}_client_secret", '' )
			) {
				$out[ $key ] = $meta;
			}
		}
		return $out;
	}

	/* ------------------------------------------------------------------ */
	/* Dispatch                                                            */
	/* ------------------------------------------------------------------ */

	public function maybe_dispatch() {
		// OAuth kick-off and the provider's own redirect-back; there is no WP
		// nonce either side because the state value in start_flow() travels
		// through the provider instead. Verified in handle_callback().
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['gemsec_oauth'] ) ) {
			$this->start_flow( sanitize_key( wp_unslash( $_GET['gemsec_oauth'] ) ) );
		}
		if ( isset( $_GET['gemsec_oauth_cb'] ) ) {
			$this->handle_callback();
		}
		// phpcs:enable
	}

	private function start_flow( $provider ) {
		$providers = self::enabled_providers();
		if ( ! isset( $providers[ $provider ] ) ) {
			$this->bail( __( 'This sign-in method is not available.', 'gemsecurity' ) );
		}
		$meta  = $providers[ $provider ];
		$state = wp_generate_password( 32, false );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$data = [
			'provider'    => $provider,
			'redirect_to' => isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : admin_url(),
			'time'        => time(),
			// Carries the role a caller (e.g. Academy's per-page registration
			// forms via buttons_html()'s $role param) wants a *new* account
			// created with, through the redirect round-trip to the provider
			// and back. Re-validated against the site's actual roles in
			// create_user() rather than trusted as-is, since this travels
			// through a public query string. Empty when the caller didn't
			// specify one, or when it came from a form that isn't asking for
			// a specific role — see buttons_html()'s default.
			'role'        => isset( $_GET['gemsec_role'] ) ? sanitize_key( wp_unslash( $_GET['gemsec_role'] ) ) : '',
		];
		// phpcs:enable

		$params = [
			'client_id'     => Helper::get_setting( "social_{$provider}_client_id", '' ),
			'redirect_uri'  => self::redirect_uri(),
			'response_type' => 'code',
			'scope'         => $meta['scope'],
			'state'         => $state,
		];

		if ( ! empty( $meta['pkce'] ) ) {
			$verifier        = wp_generate_password( 64, false );
			$data['verifier'] = $verifier;
			$params['code_challenge']        = rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' );
			$params['code_challenge_method'] = 'S256';
		}

		set_transient( self::STATE_PREFIX . $state, $data, 10 * MINUTE_IN_SECONDS );
		// Belt and braces. A transient can be gone by the time the provider
		// sends the visitor back — an object cache that is per-process rather
		// than shared, a second app server, a cache flush mid-flow — and the
		// only symptom is a sign-in that cannot be verified. The same payload
		// travels in a signed, http-only cookie so the callback can still
		// verify itself when the server-side copy has vanished.
		self::set_state_cookie( $state, $data );

		// The authorize URL is the provider's own OAuth endpoint (Google,
		// Facebook, GitHub, Twitter) — not a user-supplied redirect — so
		// wp_safe_redirect's host allowlist is not applicable here.
		wp_redirect( $meta['authorize'] . '?' . http_build_query( $params ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}

	/* ------------------------------------------------------------------ */
	/* State handling                                                      */
	/* ------------------------------------------------------------------ */

	/** Name of the fallback cookie. */
	private static function cookie_name() {
		return 'gemsec_oauth_state';
	}

	/**
	 * @param string $state
	 * @param array  $data
	 */
	private static function set_state_cookie( $state, array $data ) {
		setcookie(
			self::cookie_name(),
			Helper::sign_payload( [ 'state' => $state ] + $data ),
			[
				'expires'  => time() + 10 * MINUTE_IN_SECONDS,
				'path'     => '/',
				'secure'   => is_ssl(),
				'httponly' => true,
				// Lax still travels on the top-level GET the provider sends the
				// visitor back with; Strict would not.
				'samesite' => 'Lax',
			]
		);
	}

	/**
	 * Read and verify the fallback cookie for a given state.
	 *
	 * @param string $state
	 * @return array|false
	 */
	private static function state_from_cookie( $state ) {
		if ( empty( $_COOKIE[ self::cookie_name() ] ) ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$data = Helper::verify_signed_payload( wp_unslash( $_COOKIE[ self::cookie_name() ] ), 10 * MINUTE_IN_SECONDS );
		if ( ! is_array( $data ) || empty( $data['state'] ) || ! hash_equals( (string) $data['state'], (string) $state ) ) {
			return false;
		}

		unset( $data['state'] );
		return $data;
	}

	/** Drop the fallback cookie once the flow is finished. */
	private static function clear_state_cookie() {
		setcookie( self::cookie_name(), '', [ 'expires' => time() - 3600, 'path' => '/' ] );
	}

	private function handle_callback() {
		// The OAuth state value travels through the provider in place of a
		// WP nonce and is verified against the transient/cookie pair below.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
		$code  = isset( $_GET['code'] ) ? sanitize_text_field( wp_unslash( $_GET['code'] ) ) : '';

		// The provider refused before we ever get a code. Its own reason is far
		// more useful than anything we could infer — redirect_uri_mismatch and
		// access_denied are the two that actually happen, and one is a
		// configuration error while the other is the user changing their mind.
		if ( isset( $_GET['error'] ) ) {
			$err  = sanitize_text_field( wp_unslash( $_GET['error'] ) );
			$desc = isset( $_GET['error_description'] )
				? sanitize_text_field( wp_unslash( $_GET['error_description'] ) )
				: '';
			// phpcs:enable

			Logger::log(
				'social_login_failed',
				sprintf( 'Social sign-in refused by the provider: %s %s', $err, $desc ),
				'access_denied' === $err ? Logger::SEVERITY_NOTICE : Logger::SEVERITY_WARNING,
				[ 'user_id' => 0 ]
			);

			if ( 'access_denied' === $err ) {
				$this->bail( __( 'Sign-in was cancelled.', 'gemsecurity' ) );
			}

			$this->bail( sprintf(
				/* translators: 1: provider error code, 2: provider description. */
				__( 'The provider refused the sign-in: %1$s. %2$s', 'gemsecurity' ),
				$err,
				$desc
			) );
		}

		if ( '' === $state ) {
			Logger::log( 'social_login_failed', 'Social sign-in callback arrived without a state parameter.', Logger::SEVERITY_WARNING, [ 'user_id' => 0 ] );
			$this->bail( __( 'Sign-in could not be verified: the provider did not return a security token.', 'gemsecurity' ) );
		}

		// The signed cookie is what proves this browser started the flow, so
		// it is required even when the server-side copy exists. Accepting the
		// transient alone let an attacker start a sign-in, then hand the
		// callback URL to a victim and log them into the attacker's account.
		$cookie = self::state_from_cookie( $state );
		$data   = $cookie ? get_transient( self::STATE_PREFIX . $state ) : false;
		if ( $cookie && ! $data ) {
			// Server-side copy is gone (per-process cache, flush); the signed
			// cookie carries the same payload.
			$data = $cookie;
		}

		if ( ! $data ) {
			Logger::log(
				'social_login_failed',
				'Social sign-in state could not be found. It expired, was already used, or the browser did not return the cookie.',
				Logger::SEVERITY_WARNING,
				[ 'user_id' => 0 ]
			);
			$this->bail( __( 'Sign-in could not be verified — the attempt expired or was already used. Please try again, and make sure your browser accepts cookies for this site.', 'gemsecurity' ) );
		}

		if ( '' === $code ) {
			Logger::log( 'social_login_failed', 'Social sign-in callback arrived without an authorization code.', Logger::SEVERITY_WARNING, [ 'user_id' => 0 ] );
			$this->bail( __( 'Sign-in could not be completed: the provider did not return an authorization code.', 'gemsecurity' ) );
		}

		delete_transient( self::STATE_PREFIX . $state );
		self::clear_state_cookie();

		$provider  = $data['provider'];
		$providers = self::enabled_providers();
		if ( ! isset( $providers[ $provider ] ) ) {
			$this->bail( __( 'This sign-in method is not available.', 'gemsecurity' ) );
		}

		$token = $this->exchange_code( $provider, $code, isset( $data['verifier'] ) ? $data['verifier'] : '' );
		if ( ! $token ) {
			// self::$last_token_error holds what the provider said — usually
			// invalid_client (wrong secret) or redirect_uri_mismatch (the URI
			// registered with the provider differs from this site's). Showing
			// it turns an unactionable failure into a one-line fix.
			$detail = self::$last_token_error;
			Logger::log(
				'social_login_failed',
				sprintf( 'Token exchange with %s failed. %s', $provider, $detail ? $detail : 'No reason returned.' ),
				Logger::SEVERITY_WARNING,
				[ 'user_id' => 0 ]
			);
			$this->bail(
				$detail
					? sprintf(
						/* translators: %s: the provider's error message. */
						__( 'Could not complete sign-in with the provider: %s', 'gemsecurity' ),
						$detail
					)
					: __( 'Could not complete sign-in with the provider.', 'gemsecurity' )
			);
		}

		$profile = $this->fetch_profile( $provider, $token );
		if ( empty( $profile['id'] ) ) {
			$this->bail( __( 'Could not read your profile from the provider.', 'gemsecurity' ) );
		}

		$this->login_user(
			$provider,
			$profile,
			isset( $data['redirect_to'] ) ? $data['redirect_to'] : admin_url(),
			isset( $data['role'] ) ? $data['role'] : ''
		);
	}

	/* ------------------------------------------------------------------ */
	/* Token + profile                                                     */
	/* ------------------------------------------------------------------ */

	private function exchange_code( $provider, $code, $verifier ) {
		$meta = self::providers_meta()[ $provider ];
		$body = [
			'code'          => $code,
			'client_id'     => Helper::get_setting( "social_{$provider}_client_id", '' ),
			'redirect_uri'  => self::redirect_uri(),
			'grant_type'    => 'authorization_code',
		];
		$headers = [ 'Accept' => 'application/json' ];

		if ( 'twitter' === $provider ) {
			// Confidential client: HTTP Basic auth, code_verifier in body.
			$headers['Authorization'] = 'Basic ' . base64_encode(
				Helper::get_setting( 'social_twitter_client_id', '' ) . ':' . Helper::get_setting( 'social_twitter_client_secret', '' )
			);
			$headers['Content-Type'] = 'application/x-www-form-urlencoded';
			$body['code_verifier']   = $verifier;
		} else {
			$body['client_secret'] = Helper::get_setting( "social_{$provider}_client_secret", '' );
		}

		self::$last_token_error = '';

		$response = wp_remote_post( $meta['token'], [ 'timeout' => 15, 'headers' => $headers, 'body' => $body ] );
		if ( is_wp_error( $response ) ) {
			self::$last_token_error = $response->get_error_message();
			return '';
		}

		$parsed = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $parsed ) ) {
			// Some providers may return urlencoded; parse as fallback.
			parse_str( wp_remote_retrieve_body( $response ), $parsed );
		}

		if ( empty( $parsed['access_token'] ) ) {
			$error = isset( $parsed['error'] ) ? $parsed['error'] : '';
			if ( is_array( $error ) ) {
				$error = isset( $error['message'] ) ? $error['message'] : wp_json_encode( $error );
			}
			$desc = isset( $parsed['error_description'] ) ? $parsed['error_description'] : '';

			self::$last_token_error = trim( sanitize_text_field( (string) $error . ( $desc ? ' — ' . $desc : '' ) ) );
			return '';
		}

		return $parsed['access_token'];
	}

	/**
	 * @return array { id, email, name, avatar }
	 */
	private function fetch_profile( $provider, $token ) {
		$meta = self::providers_meta()[ $provider ];

		$args = [
			'timeout' => 15,
			'headers' => [
				'Authorization' => 'Bearer ' . $token,
				'Accept'        => 'application/json',
				'User-Agent'    => 'GemSecurity/' . GEMSECURITY_VERSION,
			],
		];
		$response = wp_remote_get( $meta['userinfo'], $args );
		if ( is_wp_error( $response ) ) {
			return [];
		}
		$d = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $d ) ) {
			return [];
		}

		switch ( $provider ) {
			case 'google':
				// email_verified gates whether login_user() may auto-link this
				// profile to an existing WP account by email match — an
				// unverified email is never trustworthy enough for that, so it's
				// dropped here rather than threading a verified flag through the
				// rest of the flow. Google sends this as a real boolean, but
				// normalise defensively since some OIDC-compatible providers
				// send "true"/"false" strings instead.
				$verified = filter_var( $d['email_verified'] ?? false, FILTER_VALIDATE_BOOLEAN );
				return [
					'id'     => $d['sub'] ?? '',
					'email'  => $verified ? ( $d['email'] ?? '' ) : '',
					'name'   => $d['name'] ?? '',
					'avatar' => $d['picture'] ?? '',
				];

			case 'facebook':
				// No per-field verified flag exists in the Graph API response —
				// Facebook only ever returns an email here once it has verified
				// it at the account level, so there's nothing more to check.
				return [
					'id'     => $d['id'] ?? '',
					'email'  => $d['email'] ?? '',
					'name'   => $d['name'] ?? '',
					'avatar' => $d['picture']['data']['url'] ?? '',
				];

			case 'github':
				// The bare /user "email" field is just the public-profile email
				// and isn't guaranteed verified — always resolve through
				// /user/emails instead, which is explicitly verified+primary
				// (see github_primary_email()).
				$email = $this->github_primary_email( $token );
				return [ 'id' => (string) ( $d['id'] ?? '' ), 'email' => $email, 'name' => $d['name'] ?: ( $d['login'] ?? '' ), 'avatar' => $d['avatar_url'] ?? '' ];

			case 'twitter':
				$u = $d['data'] ?? [];
				return [ 'id' => $u['id'] ?? '', 'email' => '', 'name' => $u['name'] ?? ( $u['username'] ?? '' ), 'avatar' => $u['profile_image_url'] ?? '' ];
		}
		return [];
	}

	private function github_primary_email( $token ) {
		$response = wp_remote_get( 'https://api.github.com/user/emails', [
			'timeout' => 15,
			'headers' => [ 'Authorization' => 'Bearer ' . $token, 'User-Agent' => 'GemSecurity', 'Accept' => 'application/json' ],
		] );
		if ( is_wp_error( $response ) ) {
			return '';
		}
		$emails = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $emails ) ) {
			return '';
		}
		foreach ( $emails as $e ) {
			if ( ! empty( $e['primary'] ) && ! empty( $e['verified'] ) ) {
				return $e['email'];
			}
		}
		return '';
	}

	/* ------------------------------------------------------------------ */
	/* User resolution                                                     */
	/* ------------------------------------------------------------------ */

	private function login_user( $provider, $profile, $redirect_to, $role = '' ) {
		$meta_key = "_gemsec_oauth_{$provider}_id";

		// 1. Already linked.
		// Linking an OAuth identity needs a lookup by this exact provider-id
		// meta pair, which is indexed on the hashed id value we store.
		// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key,WordPress.DB.SlowDBQuery.slow_db_query_meta_value
		$found = get_users( [ 'meta_key' => $meta_key, 'meta_value' => $profile['id'], 'number' => 1, 'fields' => 'ID' ] );
		$user_id = $found ? (int) $found[0] : 0;

		// 2. Link by verified email.
		if ( ! $user_id && ! empty( $profile['email'] ) && Helper::get_setting( 'social_link_by_email', true ) ) {
			$existing = get_user_by( 'email', $profile['email'] );
			if ( $existing ) {
				$user_id = $existing->ID;
				update_user_meta( $user_id, $meta_key, $profile['id'] );
			}
		}

		// 3. Register a new account.
		if ( ! $user_id ) {
			if ( ! Helper::get_setting( 'social_allow_registration', true ) ) {
				$this->bail( __( 'No account is linked to this profile and registration is disabled.', 'gemsecurity' ) );
			}
			$user_id = $this->create_user( $provider, $profile, $meta_key, $role );
			if ( is_wp_error( $user_id ) ) {
				$this->bail( $user_id->get_error_message() );
			}
		}

		if ( ! empty( $profile['avatar'] ) ) {
			update_user_meta( $user_id, '_gemsec_oauth_avatar', esc_url_raw( $profile['avatar'] ) );
		}

		$user = get_user_by( 'id', $user_id );
		Logger::log( 'social_login', sprintf( '%s signed in via %s.', $user->user_login, ucfirst( $provider ) ), Logger::SEVERITY_NOTICE, [ 'user_id' => $user_id ] );

		wp_set_current_user( $user_id );
		wp_set_auth_cookie( $user_id, true );
		// Fire wp_login so login alerts / 2FA / session stamping apply —
		// this is WP's own hook, not one of ours.
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound

		wp_safe_redirect( $redirect_to ? $redirect_to : admin_url() );
		exit;
	}

	/**
	 * Capabilities that make a role unsafe to hand out from a public URL.
	 * Checked on the role itself, so a filter cannot whitelist its way past it.
	 */
	const PRIVILEGED_CAPS = [
		'manage_options', 'edit_users', 'create_users', 'promote_users', 'delete_users',
		'activate_plugins', 'install_plugins', 'edit_plugins', 'edit_themes', 'switch_themes',
		'update_core', 'unfiltered_html', 'unfiltered_upload', 'edit_others_posts', 'manage_network',
	];

	/**
	 * Whether a role passed in the sign-in URL may be given to a new account.
	 *
	 * Allowlisted (filterable — Academy and stores add their customer roles)
	 * and never a role holding any PRIVILEGED_CAPS. Without this, anyone
	 * could open ?gemsec_oauth=google&gemsec_role=administrator and register
	 * an administrator.
	 *
	 * @param string $role
	 * @return bool
	 */
	public static function is_requestable_role( $role ) {
		if ( ! $role ) {
			return false;
		}
		$allowed = (array) apply_filters(
			'gemsecurity/social_login/allowed_roles',
			[ 'subscriber', 'customer', 'academy_student', 'storeengine_customer' ]
		);
		if ( ! in_array( $role, $allowed, true ) ) {
			return false;
		}
		$object = get_role( $role );
		if ( ! $object ) {
			return false;
		}
		foreach ( self::PRIVILEGED_CAPS as $cap ) {
			if ( ! empty( $object->capabilities[ $cap ] ) ) {
				return false;
			}
		}
		return true;
	}

	private function create_user( $provider, $profile, $meta_key, $role = '' ) {
		$email = $profile['email'];
		if ( ! $email || ! is_email( $email ) ) {
			// Twitter and locked-down accounts may not expose an email.
			$host  = wp_parse_url( home_url(), PHP_URL_HOST );
			$email = sprintf( '%s-%s@users.noreply.%s', $provider, $profile['id'], $host );
		}

		$base = sanitize_user( current( explode( '@', $email ) ), true );
		if ( ! $base ) {
			$base = $provider . '_' . substr( md5( $profile['id'] ), 0, 8 );
		}
		$username = $base;
		$i        = 1;
		while ( username_exists( $username ) ) {
			$username = $base . $i;
			$i++;
		}

		// A caller-supplied role (e.g. Academy's student/instructor
		// registration forms, via buttons_html()'s $role param) travelled
		// here through a public query string, so anyone can set it. It only
		// wins when it is on the low-privilege allowlist — see
		// is_requestable_role(). Falls back to the site-wide default.
		$requested_role = self::is_requestable_role( $role ) ? $role : '';
		$final_role      = apply_filters(
			'gemsecurity/social_login/registration_role',
			$requested_role ? $requested_role : Helper::get_setting( 'social_default_role', 'subscriber' ),
			$provider,
			$profile
		);

		$user_id = wp_insert_user( [
			'user_login'   => $username,
			'user_email'   => $email,
			'user_pass'    => wp_generate_password( 24, true, true ),
			'display_name' => $profile['name'] ?: $username,
			'role'         => $final_role,
		] );

		if ( ! is_wp_error( $user_id ) ) {
			update_user_meta( $user_id, $meta_key, $profile['id'] );
			update_user_meta( $user_id, '_gemsec_oauth_registered_via', $provider );

			if ( $requested_role ) {
				/**
				 * Fires after a new account is created via social login
				 * with a caller-supplied role that was actually honored —
				 * never for the generic login-page button, which never
				 * passes a role and so never fires this. Lets the caller
				 * (e.g. Academy's registration forms, via
				 * AcademyProSocialLogin\Hooks) complete whatever
				 * additional bookkeeping its own system normally attaches
				 * to registering a user with that role — user meta, admin
				 * notifications, its own hooks — since GemSecurity itself
				 * has no notion of what a "student" or "instructor" is
				 * beyond the plain WordPress role.
				 *
				 * @param int    $user_id
				 * @param string $role     The exact role that was honored (same as $requested_role).
				 * @param string $provider
				 * @param array  $profile
				 */
				do_action( 'gemsecurity/social_login/role_registered', $user_id, $requested_role, $provider, $profile );
			}
		}
		return $user_id;
	}

	/* ------------------------------------------------------------------ */
	/* Login-form UI                                                       */
	/* ------------------------------------------------------------------ */

	/** wp-login.php — echoed inside the core login form. */
	public function render_buttons() {
		echo $this->buttons_html(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built with escaping below.
	}

	/**
	 * Front-end login forms (StoreEngine, Academy) — echoed after the form.
	 *
	 * @param string $role Optional. A specific role new accounts created
	 *                     from this rendering should get (e.g. a caller
	 *                     invoking this directly for a role-specific
	 *                     registration page, rather than via the generic
	 *                     `academy/templates/shortcode/after_login` /
	 *                     `storeengine/templates/shortcode/after_login`
	 *                     hooks this method is also registered on, which
	 *                     always call it with no arguments). Ignored unless
	 *                     it is a low-privilege allowlisted role — see
	 *                     is_requestable_role().
	 */
	public function render_frontend( $role = '' ) {
		echo $this->buttons_html( true, $role ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built with escaping below.
	}

	/** Core wp_login_form() / WooCommerce — appended to the returned markup. */
	public function append_to_form( $html ) {
		return $html . $this->buttons_html( true );
	}

	/**
	 * Build the provider-button markup. Returns an empty string when no provider
	 * is fully configured (enabled + client id + secret).
	 *
	 * @param bool   $frontend When true, prepend the stylesheet once inline (the
	 *                         `login` style handle only exists on wp-login.php).
	 * @param string $role     Optional. See render_frontend()'s matching param —
	 *                         threaded through the button URL's `gemsec_role`
	 *                         query arg so start_flow() can pick it up.
	 */
	private function buttons_html( $frontend = false, $role = '' ) {
		$providers = self::enabled_providers();
		if ( empty( $providers ) ) {
			return '';
		}

		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only redirect target.
		if ( '' === $redirect && $frontend ) {
			// No explicit target on a front-end form — return to the current page.
			$redirect = self::current_url();
		}

		$out = '';
		if ( $frontend && ! self::$style_printed ) {
			self::$style_printed = true;
			$out .= '<style>' . self::css() . '</style>';
		}

		$out .= '<div class="gemsec-social"><div class="gemsec-social__sep"><span>' . esc_html__( 'or sign in with', 'gemsecurity' ) . '</span></div>';
		foreach ( $providers as $key => $meta ) {
			$url  = add_query_arg(
				array_filter( [ 'gemsec_oauth' => $key, 'redirect_to' => $redirect, 'gemsec_role' => $role ] ),
				site_url( 'wp-login.php' )
			);
			$out .= sprintf(
				'<a class="gemsec-social__btn" href="%s" style="--gemsec-c:%s"><span>%s</span></a>',
				esc_url( $url ),
				esc_attr( $meta['color'] ),
				/* translators: %s: social-login provider name (e.g. Google, Facebook). */
				esc_html( sprintf( __( 'Continue with %s', 'gemsecurity' ), $meta['label'] ) )
			);
		}
		$out .= '</div>';
		return $out;
	}

	/** Best-effort absolute URL of the current request. */
	private static function current_url() {
		$host = isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : wp_parse_url( home_url(), PHP_URL_HOST );
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
		return esc_url_raw( ( is_ssl() ? 'https://' : 'http://' ) . $host . $uri );
	}

	public function styles() {
		// Hide the block until the inline script below has moved it into its
		// final spot (after the "Log In" button). Without this, the `login_form`
		// action renders it above the submit button first and it visibly jumps,
		// which breaks the "or sign in with" divider layout. Scoped to the
		// wp-login page only — the front-end forms don't use this hide rule.
		wp_add_inline_style( 'login', self::css() . '.gemsec-social{opacity:0;transition:opacity .12s;}' );

		// The core `login_form` action fires before the "Log In" submit button,
		// so the provider buttons would render above it. Slide the block to sit
		// directly after the submit button, then reveal it. If JS is unavailable
		// the block is revealed anyway (graceful degradation).
		$js = "document.addEventListener('DOMContentLoaded',function(){"
			. "var s=document.querySelector('.gemsec-social');"
			. "var f=document.getElementById('loginform');"
			. "var sub=f?f.querySelector('p.submit'):null;"
			. "if(s){"
			. "if(sub){sub.parentNode.insertBefore(s,sub.nextSibling);}"
			. "s.style.opacity='1';"
			. "}"
			. "});";
		wp_add_inline_script( 'jquery', $js );
	}

	/** Shared button stylesheet (used on wp-login.php and inlined front-end). */
	private static function css() {
		return '.gemsec-social{clear:both;margin:24px 0 16px 0;display:block;width:100%;}.gemsec-social__sep{position:relative;text-align:center;margin:18px 0;color:#777;}'
			. '.gemsec-social__sep:before{content:"";position:absolute;top:50%;left:0;right:0;height:1px;background:#dcdcde;}'
			. '.gemsec-social__sep span{position:relative;background:#fff;padding:0 10px;font-size:12px;display:inline-block;}'
			. '.gemsec-social__btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;box-sizing:border-box;'
			. 'margin:8px 0;padding:10px 14px;border-radius:6px;border:1px solid var(--gemsec-c,#2271b1);color:var(--gemsec-c,#2271b1);'
			. 'background:#fff;text-decoration:none;font-weight:600;transition:all .15s;}'
			. '.gemsec-social__btn:hover{background:var(--gemsec-c,#2271b1);color:#fff;}';
	}

	private function bail( $message ) {
		wp_die(
			esc_html( $message ),
			esc_html__( 'Sign-in error', 'gemsecurity' ),
			[ 'response' => 200, 'back_link' => true ]
		);
	}
}
