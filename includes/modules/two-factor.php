<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Mailer;
use GemSecurity\Logger;
use GemSecurity\Security\Totp;
use GemSecurity\Security\SecretBox;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two-Factor Authentication.
 *
 * - App-based TOTP (Google Authenticator, Authy, 1Password…) and email OTP.
 * - Interactive-login challenge interstitial rendered on wp-login.php.
 * - One-time backup codes.
 * - Optional enforcement by role (falls back to email OTP so users are never
 *   locked out before they enroll).
 *
 * User meta:
 *   _gemsec_2fa_enabled       bool
 *   _gemsec_2fa_method        'totp' | 'email'
 *   _gemsec_2fa_secret        Base32 TOTP secret, sealed by SecretBox (AES-256-GCM)
 *   _gemsec_2fa_secret_pending pending secret during enrollment
 *   _gemsec_2fa_backup_codes  array of password-hashed backup codes
 */
class TwoFactor {

	const PENDING_PREFIX = 'gemsec_2fa_pending_';
	const EMAIL_OTP_PREFIX = 'gemsec_2fa_eotp_';

	public static function init() {
		if ( ! Helper::get_setting( 'two_factor_enabled', false ) ) {
			return;
		}
		$self = new self();
		// Intercept on 'authenticate', before WordPress ever sets the login
		// cookie for this attempt (wp_signon() only calls wp_set_auth_cookie()
		// once every 'authenticate' filter has returned a non-error user). An
		// earlier version of this challenge hooked 'wp_login' instead and tore
		// the just-set cookie back down with wp_clear_auth_cookie() -- but that
		// cookie is shared by every open tab on the site, not scoped to this
		// one login attempt, so clearing it could silently sign out an
		// unrelated, already-logged-in session in the same browser. Stepping
		// in before the cookie is set avoids that entirely.
		add_filter( 'authenticate', [ $self, 'maybe_challenge' ], 99, 3 );
		// Password logins that can never show the challenge (XML-RPC, REST
		// basic auth, AJAX login popups) are refused outright for 2FA users;
		// otherwise a stolen password alone would get in through them.
		add_filter( 'authenticate', [ $self, 'block_unchallengeable_login' ], 99, 3 );
		add_action( 'login_form_gemsec_2fa', [ $self, 'handle_challenge_response' ] );
		add_action( 'admin_init', [ __CLASS__, 'seal_legacy_secrets' ] );
	}

	/**
	 * One-time migration: encrypt TOTP seeds stored before SecretBox existed.
	 * Retries on later admin loads until every seed is sealed.
	 */
	public static function seal_legacy_secrets() {
		if ( \GemSecurity\OptionStore::get_meta( 'two_factor_sealed' ) || ! SecretBox::available() ) {
			return;
		}
		$left = 0;
		foreach ( [ '_gemsec_2fa_secret', '_gemsec_2fa_secret_pending' ] as $key ) {
			// Only still-plain seeds, 500 per admin load; a full batch means
			// there may be more, so the flag stays unset and it runs again.
			$ids = get_users( [
				'fields'     => 'ID',
				'number'     => 500,
				'meta_query' => [ [ 'key' => $key, 'value' => SecretBox::PREFIX, 'compare' => 'NOT LIKE' ] ], // phpcs:ignore WordPress.DB.SlowDBQuery
			] );
			if ( count( $ids ) >= 500 ) {
				$left++;
			}
			foreach ( $ids as $uid ) {
				$val = (string) get_user_meta( $uid, $key, true );
				if ( '' === $val || SecretBox::is_sealed( $val ) ) {
					continue;
				}
				$sealed = SecretBox::seal( $val );
				if ( SecretBox::is_sealed( $sealed ) && SecretBox::open( $sealed ) === $val ) {
					update_user_meta( $uid, $key, $sealed );
				} else {
					$left++;
				}
			}
		}
		if ( ! $left ) {
			\GemSecurity\OptionStore::set_meta( 'two_factor_sealed', 1 );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Login challenge                                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * Intercept a successful password check and require the second factor for
	 * interactive browser logins, before WordPress sets the login cookie.
	 *
	 * @param \WP_User|\WP_Error|null $user
	 * @param string                  $username
	 * @param string                  $password
	 * @return \WP_User|\WP_Error|null
	 */
	public function maybe_challenge( $user, $username = '', $password = '' ) {
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}
		$context = $this->login_context();
		if ( 'login' !== $context && 'form' !== $context ) {
			return $user; // 'api' is refused in block_unchallengeable_login(); cron/CLI never log in with a password.
		}
		if ( ! self::user_needs_2fa( $user ) ) {
			return $user;
		}

		$method   = self::user_method( $user );
		// We ride on WP's own login flow, which has already verified its
		// nonce before authenticate() fires and this filter runs.
		$remember = ! empty( $_POST['rememberme'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' === $redirect ) {
			// A front-end form (shop account page, member login widget) should
			// land back where it was; wp-login.php keeps going to the dashboard.
			// wp_get_referer() is false for a form that posts to its own URL
			// (the common case), so fall back to the URL being requested.
			$redirect = admin_url();
			if ( 'form' === $context ) {
				$here     = isset( $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'] ) ? ( is_ssl() ? 'https://' : 'http://' ) . sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) . esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
				$redirect = wp_validate_redirect( wp_get_referer() ? wp_get_referer() : $here, admin_url() );
			}
		}

		$token   = wp_generate_password( 32, false );
		$pending = [ 'user_id' => $user->ID, 'remember' => $remember, 'redirect' => $redirect, 'method' => $method ];

		set_transient( self::PENDING_PREFIX . $token, $pending, 5 * MINUTE_IN_SECONDS );
		// The transient can be gone by the time the code is submitted — an
		// object cache that is not shared, a second app server — and the only
		// symptom is being bounced back to the login form after entering a
		// correct code. The same payload rides along in a signed cookie.
		self::set_pending_cookie( $token, $pending );

		if ( 'email' === $method ) {
			$this->send_email_otp( $user );
		}

		Logger::log( '2fa_challenge', sprintf( 'Second factor required for "%s" (%s).', $user->user_login, $method ), Logger::SEVERITY_INFO, [ 'user_id' => $user->ID ] );

		if ( 'form' === $context ) {
			// Login forms outside wp-login.php cannot render the challenge
			// themselves (login_header() only exists there), so hand over.
			wp_safe_redirect( add_query_arg( 'gemsec_2fa_token', rawurlencode( $token ), site_url( 'wp-login.php?action=gemsec_2fa', 'login' ) ) );
			exit;
		}

		$this->render_form( $token, $method, '' );
		exit;
	}

	/**
	 * Refuse a password login that has no way to show the second-factor
	 * prompt. Application passwords stay allowed: they are per-app, revocable
	 * and are the supported way for API clients to authenticate.
	 *
	 * @param \WP_User|\WP_Error|null $user
	 * @param string                  $username
	 * @param string                  $password
	 * @return \WP_User|\WP_Error|null
	 */
	public function block_unchallengeable_login( $user, $username = '', $password = '' ) {
		if ( ! $user instanceof \WP_User || did_action( 'application_password_did_authenticate' ) ) {
			return $user;
		}
		if ( 'api' !== $this->login_context() || ! self::user_needs_2fa( $user ) ) {
			return $user;
		}
		if ( $this->challenged_elsewhere( $user ) ) {
			return $user;
		}
		Logger::log(
			'2fa_api_login_blocked',
			sprintf( 'Password login for "%s" refused: it came through %s, which cannot show the two-factor prompt.', $user->user_login, $this->api_channel() ),
			Logger::SEVERITY_WARNING,
			[ 'user_id' => $user->ID ]
		);
		return new \WP_Error(
			'gemsec_2fa_required',
			sprintf(
				/* translators: %s: login URL. */
				__( 'This account uses two-factor authentication. Please sign in at %s. Apps and integrations should use an application password.', 'gemsecurity' ),
				wp_login_url()
			)
		);
	}

	/**
	 * Whether an integration will run its own second-factor challenge for
	 * this API login (it hooks wp_login, tears the session down and asks for
	 * the code), so refusing the password here would lock its users out.
	 * Academy's REST login does exactly that.
	 *
	 * @param \WP_User $user
	 * @return bool
	 */
	private function challenged_elsewhere( $user ) {
		$route = isset( $GLOBALS['wp']->query_vars['rest_route'] ) ? '/' . trim( (string) $GLOBALS['wp']->query_vars['rest_route'], '/' ) : '';
		$routes = class_exists( '\Academy\Integration\GemSecurity' ) ? [ '/academy/v1/login' ] : [];
		/**
		 * REST routes whose login handler challenges 2FA itself.
		 *
		 * @param string[] $routes
		 */
		$routes = (array) apply_filters( 'gemsecurity/2fa_challenge_routes', $routes );
		/**
		 * Whether this API password login is challenged by an integration.
		 *
		 * @param bool     $handled
		 * @param \WP_User $user
		 * @param string   $route Current REST route ('' outside REST).
		 */
		return (bool) apply_filters( 'gemsecurity/2fa_external_challenge', '' !== $route && in_array( $route, $routes, true ), $user, $route );
	}

	/**
	 * Where this password login came from.
	 *
	 * login – wp-login.php (the challenge renders in place)
	 * form  – a browser form elsewhere (redirected to the challenge)
	 * api   – XML-RPC, REST basic auth, AJAX: no way to prompt, so refused
	 * other – cron / WP-CLI
	 *
	 * @return string
	 */
	private function login_context() {
		if ( ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return 'other';
		}
		if ( '' !== $this->api_channel() ) {
			return 'api';
		}
		return isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ? 'login' : 'form';
	}

	/** @return string Human name of the non-interactive channel, '' if none. */
	private function api_channel() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return 'XML-RPC';
		}
		// Basic-auth style plugins authenticate while resolving the current user.
		if ( doing_filter( 'determine_current_user' ) ) {
			return 'HTTP authentication';
		}
		if ( ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || wp_is_json_request() ) {
			return 'the REST API';
		}
		if ( wp_doing_ajax() ) {
			return 'an AJAX login form';
		}
		return '';
	}

	/**
	 * Handle the submitted second factor (action=gemsec_2fa on wp-login.php).
	 */
	public function handle_challenge_response() {
		// The 2FA token is a 32-char single-use value from the server-side
		// transient (and signed cookie) created in redirect_to_challenge().
		// It replaces the login nonce for the second step of the flow.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$token   = isset( $_POST['gemsec_2fa_token'] ) ? sanitize_text_field( wp_unslash( $_POST['gemsec_2fa_token'] ) ) : '';
		if ( '' === $token && isset( $_GET['gemsec_2fa_token'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$token = sanitize_text_field( wp_unslash( $_GET['gemsec_2fa_token'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}
		$pending = $token ? get_transient( self::PENDING_PREFIX . $token ) : false;

		if ( ! $pending && $token ) {
			$pending = self::pending_from_cookie( $token );
		}

		if ( ! $pending || empty( $pending['user_id'] ) ) {
			// Bouncing to the login form with no explanation is what made this
			// look like "the code did not work" when the code was never
			// checked: the challenge itself had expired or been lost.
			Logger::log(
				'2fa_challenge_lost',
				'A second-factor code was submitted but the pending challenge could not be found. It expired, was already used, or the browser did not return the cookie.',
				Logger::SEVERITY_WARNING,
				[ 'user_id' => 0 ]
			);
			login_header( __( 'Two-Factor Authentication', 'gemsecurity' ), '', new \WP_Error(
				'gemsec_2fa_expired',
				__( 'That sign-in attempt expired before the code was entered. Please sign in again.', 'gemsecurity' )
			) );
			echo '<p id="backtoblog"><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Back to sign in', 'gemsecurity' ) . '</a></p>';
			login_footer();
			exit;
		}

		$user = get_user_by( 'id', (int) $pending['user_id'] );
		if ( ! $user instanceof \WP_User ) {
			delete_transient( self::PENDING_PREFIX . $token );
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		// $token above stands in for the login nonce; the code the user types
		// is verified below against the hashed pending challenge.
		$code   = isset( $_POST['gemsec_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['gemsec_2fa_code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		$method = $pending['method'];

		// Arrived by redirect from a front-end login form: show the prompt.
		if ( ! isset( $_POST['gemsec_2fa_code'] ) && ! isset( $_POST['gemsec_2fa_resend'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$this->render_form( $token, $method, '' );
			exit;
		}

		// Allow resending an email code.
		if ( isset( $_POST['gemsec_2fa_resend'] ) && 'email' === $method ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			if ( false === $this->send_email_otp( $user ) ) {
				$this->render_form( $token, $method, __( 'Too many codes have been sent. Use the last one, or wait 15 minutes and sign in again.', 'gemsecurity' ) );
				exit;
			}
			$this->render_form( $token, $method, '', __( 'A new code has been sent to your email.', 'gemsecurity' ) );
			exit;
		}

		$ok = $this->verify_factor( $user, $method, $code );

		if ( ! $ok ) {
			// "Invalid code" is wrong — and unhelpful — when the code was never
			// compared because it had expired, or when guessing is now locked.
			$reason  = self::otp_failure();
			$message = __( 'Invalid code. Please try again.', 'gemsecurity' );
			if ( 'expired' === $reason ) {
				$message = __( 'That code has expired. Use “Resend code” to get a new one.', 'gemsecurity' );
			} elseif ( 'locked' === $reason ) {
				$message = __( 'Too many incorrect codes. Request a new one and try again.', 'gemsecurity' );
			} elseif ( 'blocked' === $reason ) {
				$message = __( 'Too many incorrect codes. Wait 15 minutes, then sign in again.', 'gemsecurity' );
			}

			Logger::log(
				'2fa_failed',
				sprintf( 'Failed second factor for "%s" (%s).', $user->user_login, $reason ? $reason : $method ),
				Logger::SEVERITY_WARNING,
				[ 'user_id' => $user->ID ]
			);
			$this->render_form( $token, $method, $message );
			exit;
		}

		// Success — complete the login.
		delete_transient( self::PENDING_PREFIX . $token );
		self::clear_pending_cookie();
		delete_transient( self::EMAIL_OTP_PREFIX . $user->ID );
		delete_user_meta( $user->ID, self::OTP_META );

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, ! empty( $pending['remember'] ) );

		Logger::log( '2fa_success', sprintf( 'Second factor verified for "%s".', $user->user_login ), Logger::SEVERITY_INFO, [ 'user_id' => $user->ID ] );

		// Fire WP's own wp_login now that both factors are verified, so other
		// modules (login alert, session stamp, device tracking, geolocation)
		// run against a login that actually completed — this is WP's hook, not
		// one of ours. Earlier, this challenge ran on 'wp_login' itself, so a
		// correct password alone made those modules fire before the second
		// factor was ever checked.
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound

		$redirect = ! empty( $pending['redirect'] ) ? $pending['redirect'] : admin_url();
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Verify a submitted second-factor code (TOTP, email OTP, or backup code)
	 * for a user. Public so other integrations (e.g. GemSecurity's Academy
	 * integration, which runs its own REST-based challenge instead of the
	 * wp-login.php interstitial) can reuse the exact same verification logic
	 * standard login 2FA uses.
	 *
	 * @param \WP_User $user
	 * @param string   $method
	 * @param string   $code
	 * @return bool
	 */
	public function verify_factor( $user, $method, $code ) {
		$code = trim( $code );
		if ( '' === $code ) {
			return false;
		}

		// Per user, not per challenge: signing in with the password again
		// must not buy a fresh set of guesses.
		if ( self::is_locked( $user ) ) {
			self::$otp_failure = 'blocked';
			return false;
		}

		$ok = false;
		// Backup code (format xxxx-xxxx) works regardless of method.
		if ( preg_match( '/[a-z0-9]{4}-?[a-z0-9]{4}/i', $code ) && $this->consume_backup_code( $user, $code ) ) {
			$ok = true;
		} elseif ( 'totp' === $method ) {
			$secret = SecretBox::open( get_user_meta( $user->ID, '_gemsec_2fa_secret', true ) );
			$ok     = '' !== $secret && Totp::verify( $secret, $code, 1 );
		} elseif ( 'email' === $method ) {
			$ok = self::verify_email_otp( $user, $code );
		}

		if ( $ok ) {
			delete_user_meta( $user->ID, self::ATTEMPTS_META );
		} else {
			self::record_failure( $user );
		}
		return $ok;
	}

	/* ------------------------------------------------------------------ */
	/* Guess and resend limits                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Wrong codes and sent emails per user, over a rolling window. Without
	 * this an authenticator code could be guessed without limit (three are
	 * valid at any moment), and each email resend reset the guess count.
	 */
	const ATTEMPTS_META = '_gemsec_2fa_attempts';
	const MAX_FAILS     = 5;
	/** Emailed codes per window: the first plus three resends. */
	const MAX_SENDS     = 4;
	const LIMIT_WINDOW  = 15 * MINUTE_IN_SECONDS;

	/**
	 * @param \WP_User $user
	 * @return array{fails:int,sends:int,start:int}
	 */
	private static function attempts( $user ) {
		$a = get_user_meta( $user->ID, self::ATTEMPTS_META, true );
		if ( ! is_array( $a ) || empty( $a['start'] ) || time() - (int) $a['start'] > self::LIMIT_WINDOW ) {
			return [ 'fails' => 0, 'sends' => 0, 'start' => time() ];
		}
		return [ 'fails' => (int) ( $a['fails'] ?? 0 ), 'sends' => (int) ( $a['sends'] ?? 0 ), 'start' => (int) $a['start'] ];
	}

	/**
	 * Whether 2FA is locked for this user after too many wrong codes.
	 *
	 * @param \WP_User $user
	 * @return bool
	 */
	public static function is_locked( $user ) {
		return self::attempts( $user )['fails'] >= self::MAX_FAILS;
	}

	/** @param \WP_User $user */
	private static function record_failure( $user ) {
		$a = self::attempts( $user );
		$a['fails']++;
		update_user_meta( $user->ID, self::ATTEMPTS_META, $a );
		if ( $a['fails'] === self::MAX_FAILS ) {
			Logger::log( '2fa_locked', sprintf( 'Two-factor locked for "%s" after %d wrong codes.', $user->user_login, self::MAX_FAILS ), Logger::SEVERITY_WARNING, [ 'user_id' => $user->ID ] );
		}
		// Count it as a failed sign-in too, so the IP lockout sees 2FA
		// guessing — WP's own hook, not one of ours.
		do_action( 'wp_login_failed', $user->user_login, new \WP_Error( 'gemsec_2fa_failed', __( 'Incorrect verification code.', 'gemsecurity' ) ) ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
	}

	/**
	 * Reserve one emailed code against the window's budget.
	 *
	 * @param \WP_User $user
	 * @return bool False when the budget is spent.
	 */
	private static function take_send( $user ) {
		$a = self::attempts( $user );
		if ( $a['sends'] >= self::MAX_SENDS ) {
			return false;
		}
		$a['sends']++;
		update_user_meta( $user->ID, self::ATTEMPTS_META, $a );
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Email OTP storage                                                   */
	/* ------------------------------------------------------------------ */

	/**
	 * Where the emailed code lives while it waits to be used.
	 *
	 * User meta, not a transient. The code is written when the challenge is
	 * issued and read on the next request, and on a host whose object cache is
	 * not shared between workers the transient is simply gone by then — so a
	 * correct code comes back as "invalid". User meta is always backed by the
	 * database, so the two requests agree.
	 *
	 * Stored hashed, with an expiry and an attempt count: a six-digit code with
	 * unlimited guesses is not a second factor.
	 */
	const OTP_META = '_gemsec_2fa_otp';

	/** Guesses allowed against one emailed code. */
	const OTP_MAX_TRIES = 5;

	/** Why the last check failed: expired | locked | mismatch (email code), blocked (user locked). */
	private static $otp_failure = '';

	/** @return string */
	public static function otp_failure() {
		return self::$otp_failure;
	}

	/**
	 * @param \WP_User $user
	 * @param string   $code
	 */
	private static function store_email_otp( $user, $code ) {
		update_user_meta(
			$user->ID,
			self::OTP_META,
			[
				'hash'    => hash_hmac( 'sha256', $code, wp_salt( 'auth' ) ),
				'expires' => time() + 10 * MINUTE_IN_SECONDS,
				'tries'   => 0,
			]
		);
	}

	/**
	 * @param \WP_User $user
	 * @param string   $code
	 * @return bool
	 */
	private static function verify_email_otp( $user, $code ) {
		self::$otp_failure = '';
		$digits = preg_replace( '/\D/', '', $code );
		$record = get_user_meta( $user->ID, self::OTP_META, true );

		// A code issued before this changed still lives in the old transient.
		if ( ! is_array( $record ) ) {
			$legacy = get_transient( self::EMAIL_OTP_PREFIX . $user->ID );
			if ( $legacy && hash_equals( (string) $legacy, $digits ) ) {
				delete_transient( self::EMAIL_OTP_PREFIX . $user->ID );
				return true;
			}
			self::$otp_failure = 'expired';
			return false;
		}

		if ( empty( $record['expires'] ) || time() > (int) $record['expires'] ) {
			delete_user_meta( $user->ID, self::OTP_META );
			self::$otp_failure = 'expired';
			return false;
		}

		if ( (int) $record['tries'] >= self::OTP_MAX_TRIES ) {
			delete_user_meta( $user->ID, self::OTP_META );
			self::$otp_failure = 'locked';
			return false;
		}

		if ( hash_equals( (string) $record['hash'], hash_hmac( 'sha256', $digits, wp_salt( 'auth' ) ) ) ) {
			delete_user_meta( $user->ID, self::OTP_META );
			return true;
		}

		$record['tries'] = (int) $record['tries'] + 1;
		update_user_meta( $user->ID, self::OTP_META, $record );
		self::$otp_failure = 'mismatch';
		return false;
	}

	/* ------------------------------------------------------------------ */
	/* Email OTP                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Send a fresh 6-digit email OTP to a user and store it for verification.
	 * Public for the same reason as verify_factor() above.
	 *
	 * @param \WP_User $user
	 * @return bool False when the user's send budget for the window is spent.
	 */
	public function send_email_otp( $user ) {
		// A spent budget keeps the code already sent valid; nothing new goes out.
		if ( ! self::take_send( $user ) ) {
			return false;
		}
		$code = str_pad( (string) random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );
		self::store_email_otp( $user, $code );

		Mailer::send(
			$user->user_email,
			'🔢',
			__( 'Your login verification code', 'gemsecurity' ),
			[
				[
					'type' => 'notice',
					'tone' => 'info',
					'text' => sprintf(
						/* translators: %s: 6-digit code. */
						__( 'Your verification code is <strong style="letter-spacing:3px;font-size:20px;">%s</strong>', 'gemsecurity' ),
						esc_html( $code )
					),
				],
				[
					'type' => 'paragraph',
					'text' => __( 'It expires in 10 minutes. If you did not try to sign in, change your password immediately.', 'gemsecurity' ),
				],
			]
		);
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Backup codes                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Generate a fresh set of one-time backup codes, store hashes, return plain.
	 *
	 * @param int $user_id
	 * @return string[]
	 */
	public static function generate_backup_codes( $user_id, $count = 10 ) {
		$plain  = [];
		$hashed = [];
		for ( $i = 0; $i < $count; $i++ ) {
			$code    = strtolower( wp_generate_password( 4, false, false ) . '-' . wp_generate_password( 4, false, false ) );
			$plain[] = $code;
			$hashed[] = wp_hash_password( str_replace( '-', '', $code ) );
		}
		update_user_meta( $user_id, '_gemsec_2fa_backup_codes', $hashed );
		return $plain;
	}

	private function consume_backup_code( $user, $code ) {
		$codes = (array) get_user_meta( $user->ID, '_gemsec_2fa_backup_codes', true );
		if ( empty( $codes ) ) {
			return false;
		}
		$normalized = strtolower( str_replace( '-', '', $code ) );
		require_once ABSPATH . WPINC . '/class-phpass.php';

		foreach ( $codes as $i => $hash ) {
			if ( wp_check_password( $normalized, $hash ) ) {
				unset( $codes[ $i ] );
				update_user_meta( $user->ID, '_gemsec_2fa_backup_codes', array_values( $codes ) );
				Logger::log( '2fa_success', sprintf( 'Backup code used for "%s".', $user->user_login ), Logger::SEVERITY_NOTICE, [ 'user_id' => $user->ID ] );
				return true;
			}
		}
		return false;
	}

	/* ------------------------------------------------------------------ */
	/* Status helpers (shared with REST)                                   */
	/* ------------------------------------------------------------------ */

	public static function user_needs_2fa( $user ) {
		if ( ! Helper::get_setting( 'two_factor_enabled', false ) ) {
			return false;
		}
		if ( get_user_meta( $user->ID, '_gemsec_2fa_enabled', true ) ) {
			return true;
		}
		return self::role_enforced( $user );
	}

	public static function role_enforced( $user ) {
		$roles = (array) Helper::get_setting( 'two_factor_enforced_roles', [] );
		if ( empty( $roles ) ) {
			return false;
		}
		// "all" means every role, including ones created later.
		if ( in_array( 'all', $roles, true ) ) {
			return true;
		}
		return (bool) array_intersect( (array) $user->roles, $roles );
	}

	/**
	 * Which factor to present to this user.
	 *
	 * @param \WP_User $user
	 * @return string 'totp' | 'email'
	 */
	public static function user_method( $user ) {
		$enabled = get_user_meta( $user->ID, '_gemsec_2fa_enabled', true );
		$method  = get_user_meta( $user->ID, '_gemsec_2fa_method', true );
		if ( $enabled && 'totp' === $method && get_user_meta( $user->ID, '_gemsec_2fa_secret', true ) ) {
			return 'totp';
		}
		if ( $enabled && 'email' === $method ) {
			return 'email';
		}
		// Enforced but not enrolled → email OTP (no lockout).
		return 'email';
	}

	/* ------------------------------------------------------------------ */
	/* Pending-challenge fallback                                          */
	/* ------------------------------------------------------------------ */

	/** Cookie holding the pending challenge, for when the transient is gone. */
	private static function cookie_name() {
		return 'gemsec_2fa_pending';
	}

	/**
	 * @param string $token
	 * @param array  $pending
	 */
	private static function set_pending_cookie( $token, array $pending ) {
		setcookie(
			self::cookie_name(),
			Helper::sign_payload( [ 'token' => $token ] + $pending ),
			[
				'expires'  => time() + 5 * MINUTE_IN_SECONDS,
				'path'     => '/',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			]
		);
	}

	/**
	 * @param string $token
	 * @return array|false
	 */
	private static function pending_from_cookie( $token ) {
		if ( empty( $_COOKIE[ self::cookie_name() ] ) ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$data = Helper::verify_signed_payload( sanitize_text_field( wp_unslash( $_COOKIE[ self::cookie_name() ] ) ), 5 * MINUTE_IN_SECONDS );
		if ( ! is_array( $data ) || empty( $data['token'] ) || ! hash_equals( (string) $data['token'], (string) $token ) ) {
			return false;
		}

		unset( $data['token'] );
		return $data;
	}

	private static function clear_pending_cookie() {
		setcookie( self::cookie_name(), '', [ 'expires' => time() - 3600, 'path' => '/' ] );
	}

	/* ------------------------------------------------------------------ */
	/* Challenge form                                                      */
	/* ------------------------------------------------------------------ */

	private function render_form( $token, $method, $error = '', $notice = '' ) {
		$is_email = 'email' === $method;
		login_header( __( 'Two-Factor Authentication', 'gemsecurity' ), '', $error ? new \WP_Error( 'gemsec_2fa', $error ) : null );
		?>
		<form name="gemsec_2fa_form" id="loginform" action="<?php echo esc_url( site_url( 'wp-login.php?action=gemsec_2fa', 'login_post' ) ); ?>" method="post">
			<?php if ( $notice ) : ?>
				<p class="message"><?php echo esc_html( $notice ); ?></p>
			<?php endif; ?>
			<p style="margin-bottom:14px;">
				<?php
				echo esc_html(
					$is_email
						? __( 'Enter the 6-digit code we just emailed you.', 'gemsecurity' )
						: __( 'Open your authenticator app and enter the current 6-digit code. You can also use a backup code.', 'gemsecurity' )
				);
				?>
			</p>
			<p>
				<label for="gemsec_2fa_code"><?php esc_html_e( 'Authentication code', 'gemsecurity' ); ?></label>
				<input type="text" name="gemsec_2fa_code" id="gemsec_2fa_code" class="input" autocomplete="one-time-code"
					inputmode="numeric" autofocus="autofocus" autocapitalize="off" />
			</p>
			<input type="hidden" name="gemsec_2fa_token" value="<?php echo esc_attr( $token ); ?>" />
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'gemsecurity' ); ?>" />
			</p>
			<?php if ( $is_email ) : ?>
				<p style="text-align:center;">
					<button type="submit" name="gemsec_2fa_resend" value="1" class="button-link"><?php esc_html_e( 'Resend code', 'gemsecurity' ); ?></button>
				</p>
			<?php endif; ?>
		</form>
		<p id="backtoblog">
			<a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( '← Back to login', 'gemsecurity' ); ?></a>
		</p>
		<?php
		login_footer();
	}
}
