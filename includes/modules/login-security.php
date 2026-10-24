<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Mailer;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Login Security module.
 *
 * - Brute-force protection: limits failed login attempts per IP and locks out
 *   for a configurable window.
 * - Administrator login email alert: emails a chosen address whenever an
 *   administrator authenticates successfully.
 * - Administrator session timeout: forces administrators to be logged out a
 *   configurable number of hours (default 24) after they signed in.
 */
class LoginSecurity {

	const LOCK_TRANSIENT_PREFIX = 'gemsec_lock_';
	const ATTEMPT_TRANSIENT_PREFIX = 'gemsec_attempts_';
	const LOGIN_TIME_META = '_gemsecurity_login_time';

	public static function init() {
		$self = new self();

		// Brute-force / login lockout.
		add_filter( 'authenticate', [ $self, 'check_lockout' ], 30, 1 );
		add_action( 'wp_login_failed', [ $self, 'on_login_failed' ], 10, 1 );
		add_action( 'wp_login', [ $self, 'on_login_success' ], 10, 2 );

		// Administrator session timeout.
		add_filter( 'auth_cookie_expiration', [ $self, 'cap_admin_cookie_expiration' ], 20, 3 );
		add_action( 'init', [ $self, 'enforce_admin_session_timeout' ], 1 );
	}

	/* --------------------------------------------------------------------- */
	/* Brute-force protection                                                 */
	/* --------------------------------------------------------------------- */

	/**
	 * Block authentication entirely while an IP is locked out.
	 *
	 * @param \WP_User|\WP_Error|null $user
	 * @return \WP_User|\WP_Error|null
	 */
	public function check_lockout( $user ) {
		if ( ! Helper::get_setting( 'login_attempts_enabled', true ) ) {
			return $user;
		}

		// Only short-circuit on an actual login attempt (credentials present).
		// authenticate fires inside WP's own nonce-verified login flow, and
		// we only check whether $_POST is empty here — no field is read.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST ) && empty( $_SERVER['PHP_AUTH_USER'] ) ) {
			return $user;
		}

		$ip = Helper::get_ip_address();
		if ( self::is_locked_out( $ip ) ) {
			$minutes = (int) Helper::get_setting( 'login_lockout_duration', 30 );
			return new \WP_Error(
				'gemsecurity_locked_out',
				sprintf(
					/* translators: %d: lockout duration in minutes. */
					__( '<strong>Access temporarily blocked.</strong> Too many failed login attempts. Please try again in %d minutes.', 'gemsecurity' ),
					$minutes
				)
			);
		}

		return $user;
	}

	/**
	 * Count a failed attempt and lock the IP out once the limit is reached.
	 *
	 * @param string $username
	 */
	public function on_login_failed( $username ) {
		if ( ! Helper::get_setting( 'login_attempts_enabled', true ) ) {
			return;
		}

		$ip    = Helper::get_ip_address();
		$limit = max( 1, (int) Helper::get_setting( 'login_attempts_limit', 5 ) );

		if ( self::is_locked_out( $ip ) ) {
			return;
		}

		$attempts = (int) get_transient( self::ATTEMPT_TRANSIENT_PREFIX . md5( $ip ) );
		$attempts++;

		// Track the attempt window for the same duration as a lockout.
		$window = max( 1, (int) Helper::get_setting( 'login_lockout_duration', 30 ) ) * MINUTE_IN_SECONDS;
		set_transient( self::ATTEMPT_TRANSIENT_PREFIX . md5( $ip ), $attempts, $window );

		Logger::log(
			'login_failed',
			sprintf( 'Failed login for "%s" (%d/%d attempts).', sanitize_user( $username ), $attempts, $limit ),
			Logger::SEVERITY_NOTICE,
			[ 'user_id' => 0, 'ip_address' => $ip, 'context' => [ 'username' => sanitize_user( $username ) ] ]
		);

		if ( $attempts >= $limit ) {
			set_transient( self::LOCK_TRANSIENT_PREFIX . md5( $ip ), time(), $window );
			delete_transient( self::ATTEMPT_TRANSIENT_PREFIX . md5( $ip ) );
			Logger::log(
				'login_lockout',
				sprintf( 'IP %s locked out after %d failed login attempts.', $ip, $limit ),
				Logger::SEVERITY_WARNING,
				[ 'user_id' => 0, 'ip_address' => $ip ]
			);
		}
	}

	/**
	 * Whether an IP is currently locked out. Public so other integrations
	 * (e.g. GemSecurity's Academy integration, which enforces this ledger on
	 * a REST login endpoint that never touches $_POST) can check the same
	 * ban ledger standard `wp-login.php` uses, without duplicating it.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_locked_out( $ip ) {
		return (bool) get_transient( self::LOCK_TRANSIENT_PREFIX . md5( $ip ) );
	}

	/* --------------------------------------------------------------------- */
	/* Successful login: clear counters, alert, stamp session                 */
	/* --------------------------------------------------------------------- */

	/**
	 * @param string   $user_login
	 * @param \WP_User $user
	 */
	public function on_login_success( $user_login, $user = null ) {
		if ( ! $user instanceof \WP_User ) {
			$user = get_user_by( 'login', $user_login );
		}
		if ( ! $user instanceof \WP_User ) {
			return;
		}

		$ip = Helper::get_ip_address();
		delete_transient( self::ATTEMPT_TRANSIENT_PREFIX . md5( $ip ) );
		delete_transient( self::LOCK_TRANSIENT_PREFIX . md5( $ip ) );

		$is_admin = self::user_is_administrator( $user );

		// Stamp the login time for session-timeout enforcement.
		if ( $is_admin ) {
			update_user_meta( $user->ID, self::LOGIN_TIME_META, time() );
		}

		Logger::log(
			$is_admin ? 'admin_login' : 'user_login',
			sprintf( '%s "%s" logged in.', $is_admin ? 'Administrator' : 'User', $user->user_login ),
			$is_admin ? Logger::SEVERITY_NOTICE : Logger::SEVERITY_INFO,
			[ 'user_id' => $user->ID, 'ip_address' => $ip ]
		);

		if ( $is_admin ) {
			$this->maybe_send_admin_alert( $user, $ip );
		}
	}

	/**
	 * Email a configured address when an administrator logs in.
	 *
	 * @param \WP_User $user
	 * @param string   $ip
	 */
	private function maybe_send_admin_alert( $user, $ip ) {
		if ( ! Helper::get_setting( 'admin_login_alert_enabled', false ) ) {
			return;
		}

		$to = Mailer::recipient();

		// Mailer::subject() supplies the site identity, so the title only needs
		// to say what happened.
		$when  = wp_date( 'F j, Y \a\t g:i a' );
		$agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : 'unknown';

		$blocks = [
			[
				'type' => 'paragraph',
				'text' => sprintf(
					/* translators: %s: username. */
					__( 'An administrator account, <strong>%s</strong>, just signed in.', 'gemsecurity' ),
					esc_html( $user->user_login )
				),
			],
			[
				'type'    => 'table',
				'heading' => __( 'Sign-in details', 'gemsecurity' ),
				'rows'    => [
					[ __( 'User', 'gemsecurity' ), esc_html( $user->user_login . ' (' . $user->user_email . ')' ) ],
					[ __( 'Time', 'gemsecurity' ), esc_html( $when ) ],
					[ __( 'IP address', 'gemsecurity' ), esc_html( $ip ) ],
					[ __( 'Browser', 'gemsecurity' ), esc_html( $agent ) ],
				],
			],
			[
				'type' => 'paragraph',
				'text' => __( 'If this was not expected, secure the account immediately and review the activity log.', 'gemsecurity' ),
			],
		];

		/**
		 * Filter the administrator login alert email payload.
		 *
		 * @param array    $payload { to, emoji, title, blocks }
		 * @param \WP_User $user
		 */
		$payload = apply_filters(
			'gemsecurity/admin_login_alert_email',
			[
				'to'     => $to,
				'emoji'  => '🔑',
				'title'  => __( 'Administrator signed in', 'gemsecurity' ),
				'blocks' => $blocks,
			],
			$user
		);

		Mailer::send( $payload['to'], $payload['emoji'], $payload['title'], $payload['blocks'] );
	}

	/* --------------------------------------------------------------------- */
	/* Administrator session timeout                                          */
	/* --------------------------------------------------------------------- */

	/**
	 * Cap the auth cookie lifetime for administrators so the browser session
	 * cannot outlive the configured timeout (even with "remember me").
	 *
	 * @param int  $length
	 * @param int  $user_id
	 * @param bool $remember
	 * @return int
	 */
	public function cap_admin_cookie_expiration( $length, $user_id, $remember ) {
		if ( ! Helper::get_setting( 'admin_session_timeout_enabled', false ) ) {
			return $length;
		}

		$user = get_user_by( 'id', $user_id );
		if ( $user && self::user_is_administrator( $user ) ) {
			$max = max( 1, (int) Helper::get_setting( 'admin_session_timeout_hours', 24 ) ) * HOUR_IN_SECONDS;
			return min( $length, $max );
		}

		return $length;
	}

	/**
	 * Authoritative server-side check: log administrators out once their
	 * session exceeds the configured window. Covers sessions established
	 * before the cookie cap took effect.
	 */
	public function enforce_admin_session_timeout() {
		if ( ! Helper::get_setting( 'admin_session_timeout_enabled', false ) || ! is_user_logged_in() ) {
			return;
		}

		$user = wp_get_current_user();
		if ( ! self::user_is_administrator( $user ) ) {
			return;
		}

		$login_time = (int) get_user_meta( $user->ID, self::LOGIN_TIME_META, true );
		if ( ! $login_time ) {
			// No stamp yet (logged in before this feature) — stamp now.
			update_user_meta( $user->ID, self::LOGIN_TIME_META, time() );
			return;
		}

		$max = max( 1, (int) Helper::get_setting( 'admin_session_timeout_hours', 24 ) ) * HOUR_IN_SECONDS;
		if ( ( time() - $login_time ) < $max ) {
			return;
		}

		$user_id = $user->ID;
		Logger::log(
			'admin_session_expired',
			sprintf( 'Administrator "%s" auto-logged out after session timeout.', $user->user_login ),
			Logger::SEVERITY_INFO,
			[ 'user_id' => $user_id ]
		);

		delete_user_meta( $user_id, self::LOGIN_TIME_META );
		wp_logout();

		if ( ! wp_doing_ajax() && ! ( defined( 'REST_REQUEST' ) && REST_REQUEST ) && ! headers_sent() ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}
	}

	/* --------------------------------------------------------------------- */
	/* Helpers                                                                */
	/* --------------------------------------------------------------------- */

	/**
	 * @param \WP_User $user
	 * @return bool
	 */
	public static function user_is_administrator( $user ) {
		if ( ! $user instanceof \WP_User ) {
			return false;
		}
		if ( is_multisite() && is_super_admin( $user->ID ) ) {
			return true;
		}
		return in_array( 'administrator', (array) $user->roles, true );
	}
}
