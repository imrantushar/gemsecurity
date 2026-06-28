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

	const STATE_PREFIX = 'gemsec_oauth_state_';

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
				'authorize' => 'https://twitter.com/i/oauth2/authorize',
				'token'     => 'https://api.twitter.com/2/oauth2/token',
				'userinfo'  => 'https://api.twitter.com/2/users/me?user.fields=profile_image_url',
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
		add_action( 'login_init', [ $self, 'maybe_dispatch' ], 1 );
		add_action( 'login_form', [ $self, 'render_buttons' ] );
		add_action( 'login_enqueue_scripts', [ $self, 'styles' ] );
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
		if ( isset( $_GET['gemsec_oauth'] ) ) {
			$this->start_flow( sanitize_key( wp_unslash( $_GET['gemsec_oauth'] ) ) );
		}
		if ( isset( $_GET['gemsec_oauth_cb'] ) ) {
			$this->handle_callback();
		}
	}

	private function start_flow( $provider ) {
		$providers = self::enabled_providers();
		if ( ! isset( $providers[ $provider ] ) ) {
			$this->bail( __( 'This sign-in method is not available.', 'gemsecurity' ) );
		}
		$meta  = $providers[ $provider ];
		$state = wp_generate_password( 32, false );

		$data = [
			'provider'    => $provider,
			'redirect_to' => isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : admin_url(),
			'time'        => time(),
		];

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

		wp_redirect( $meta['authorize'] . '?' . http_build_query( $params ) );
		exit;
	}

	private function handle_callback() {
		$state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
		$code  = isset( $_GET['code'] ) ? sanitize_text_field( wp_unslash( $_GET['code'] ) ) : '';
		$data  = $state ? get_transient( self::STATE_PREFIX . $state ) : false;

		if ( ! $data || ! $code ) {
			$this->bail( __( 'Sign-in could not be verified. Please try again.', 'gemsecurity' ) );
		}
		delete_transient( self::STATE_PREFIX . $state );

		$provider  = $data['provider'];
		$providers = self::enabled_providers();
		if ( ! isset( $providers[ $provider ] ) ) {
			$this->bail( __( 'This sign-in method is not available.', 'gemsecurity' ) );
		}

		$token = $this->exchange_code( $provider, $code, isset( $data['verifier'] ) ? $data['verifier'] : '' );
		if ( ! $token ) {
			$this->bail( __( 'Could not complete sign-in with the provider.', 'gemsecurity' ) );
		}

		$profile = $this->fetch_profile( $provider, $token );
		if ( empty( $profile['id'] ) ) {
			$this->bail( __( 'Could not read your profile from the provider.', 'gemsecurity' ) );
		}

		$this->login_user( $provider, $profile, isset( $data['redirect_to'] ) ? $data['redirect_to'] : admin_url() );
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

		$response = wp_remote_post( $meta['token'], [ 'timeout' => 15, 'headers' => $headers, 'body' => $body ] );
		if ( is_wp_error( $response ) ) {
			return '';
		}

		$parsed = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $parsed ) ) {
			// Some providers may return urlencoded; parse as fallback.
			parse_str( wp_remote_retrieve_body( $response ), $parsed );
		}
		return ! empty( $parsed['access_token'] ) ? $parsed['access_token'] : '';
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
				return [ 'id' => $d['sub'] ?? '', 'email' => $d['email'] ?? '', 'name' => $d['name'] ?? '', 'avatar' => $d['picture'] ?? '' ];

			case 'facebook':
				return [
					'id'     => $d['id'] ?? '',
					'email'  => $d['email'] ?? '',
					'name'   => $d['name'] ?? '',
					'avatar' => $d['picture']['data']['url'] ?? '',
				];

			case 'github':
				$email = $d['email'] ?? '';
				if ( ! $email ) {
					$email = $this->github_primary_email( $token );
				}
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

	private function login_user( $provider, $profile, $redirect_to ) {
		$meta_key = "_gemsec_oauth_{$provider}_id";

		// 1. Already linked.
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
			$user_id = $this->create_user( $provider, $profile, $meta_key );
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
		// Fire wp_login so login alerts / 2FA / session stamping apply.
		do_action( 'wp_login', $user->user_login, $user );

		wp_safe_redirect( $redirect_to ? $redirect_to : admin_url() );
		exit;
	}

	private function create_user( $provider, $profile, $meta_key ) {
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

		$user_id = wp_insert_user( [
			'user_login'   => $username,
			'user_email'   => $email,
			'user_pass'    => wp_generate_password( 24, true, true ),
			'display_name' => $profile['name'] ?: $username,
			'role'         => Helper::get_setting( 'social_default_role', 'subscriber' ),
		] );

		if ( ! is_wp_error( $user_id ) ) {
			update_user_meta( $user_id, $meta_key, $profile['id'] );
			update_user_meta( $user_id, '_gemsec_oauth_registered_via', $provider );
		}
		return $user_id;
	}

	/* ------------------------------------------------------------------ */
	/* Login-form UI                                                       */
	/* ------------------------------------------------------------------ */

	public function render_buttons() {
		$providers = self::enabled_providers();
		if ( empty( $providers ) ) {
			return;
		}
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		echo '<div class="gemsec-social"><div class="gemsec-social__sep"><span>' . esc_html__( 'or sign in with', 'gemsecurity' ) . '</span></div>';
		foreach ( $providers as $key => $meta ) {
			$url = add_query_arg(
				array_filter( [ 'gemsec_oauth' => $key, 'redirect_to' => $redirect ] ),
				site_url( 'wp-login.php' )
			);
			printf(
				'<a class="gemsec-social__btn" href="%s" style="--gemsec-c:%s"><span>%s</span></a>',
				esc_url( $url ),
				esc_attr( $meta['color'] ),
				esc_html( sprintf( __( 'Continue with %s', 'gemsecurity' ), $meta['label'] ) )
			);
		}
		echo '</div>';
	}

	public function styles() {
		$css = '.gemsec-social{margin:16px 0;}.gemsec-social__sep{position:relative;text-align:center;margin:18px 0;color:#777;}'
			. '.gemsec-social__sep:before{content:"";position:absolute;top:50%;left:0;right:0;height:1px;background:#dcdcde;}'
			. '.gemsec-social__sep span{position:relative;background:#fff;padding:0 10px;font-size:12px;}'
			. '.gemsec-social__btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;box-sizing:border-box;'
			. 'margin:8px 0;padding:10px 14px;border-radius:6px;border:1px solid var(--gemsec-c,#2271b1);color:var(--gemsec-c,#2271b1);'
			. 'background:#fff;text-decoration:none;font-weight:600;transition:all .15s;}'
			. '.gemsec-social__btn:hover{background:var(--gemsec-c,#2271b1);color:#fff;}';
		wp_add_inline_style( 'login', $css );
	}

	private function bail( $message ) {
		wp_die(
			esc_html( $message ),
			esc_html__( 'Sign-in error', 'gemsecurity' ),
			[ 'response' => 200, 'back_link' => true ]
		);
	}
}
