<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Mailer;
use GemSecurity\Logger;
use GemSecurity\Security\Totp;

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
 *   _gemsec_2fa_secret        Base32 TOTP secret
 *   _gemsec_2fa_secret_pending pending secret during enrollment
 *   _gemsec_2fa_backup_codes  array of password-hashed backup codes
 */
class TwoFactor {

	const PENDING_PREFIX = 'gemsec_2fa_pending_';
	const EMAIL_OTP_PREFIX = 'gemsec_2fa_eotp_';

	private static $passed = false;

	public static function init() {
		if ( ! Helper::get_setting( 'two_factor_enabled', false ) ) {
			return;
		}
		$self = new self();
		add_action( 'wp_login', [ $self, 'maybe_challenge' ], 10, 2 );
		add_action( 'login_form_gemsec_2fa', [ $self, 'handle_challenge_response' ] );
	}

	/* ------------------------------------------------------------------ */
	/* Login challenge                                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * After a successful password login, interrupt and require the second
	 * factor for interactive browser logins.
	 *
	 * @param string   $user_login
	 * @param \WP_User $user
	 */
	public function maybe_challenge( $user_login, $user = null ) {
		if ( self::$passed ) {
			return; // We just completed 2FA and re-fired wp_login.
		}
		if ( ! $user instanceof \WP_User ) {
			$user = get_user_by( 'login', $user_login );
		}
		if ( ! $user instanceof \WP_User || ! $this->is_interactive_login() ) {
			return;
		}
		if ( ! self::user_needs_2fa( $user ) ) {
			return;
		}

		// Tear down the session WordPress just established.
		wp_clear_auth_cookie();
		wp_destroy_current_session();

		$method   = self::user_method( $user );
		$remember = ! empty( $_POST['rememberme'] );
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : admin_url();

		$token = wp_generate_password( 32, false );
		set_transient(
			self::PENDING_PREFIX . $token,
			[ 'user_id' => $user->ID, 'remember' => $remember, 'redirect' => $redirect, 'method' => $method ],
			5 * MINUTE_IN_SECONDS
		);

		if ( 'email' === $method ) {
			$this->send_email_otp( $user );
		}

		Logger::log( '2fa_challenge', sprintf( 'Second factor required for "%s" (%s).', $user->user_login, $method ), Logger::SEVERITY_INFO, [ 'user_id' => $user->ID ] );

		$this->render_form( $token, $method, '' );
		exit;
	}

	/**
	 * Handle the submitted second factor (action=gemsec_2fa on wp-login.php).
	 */
	public function handle_challenge_response() {
		$token   = isset( $_POST['gemsec_2fa_token'] ) ? sanitize_text_field( wp_unslash( $_POST['gemsec_2fa_token'] ) ) : '';
		$pending = $token ? get_transient( self::PENDING_PREFIX . $token ) : false;

		if ( ! $pending || empty( $pending['user_id'] ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$user = get_user_by( 'id', (int) $pending['user_id'] );
		if ( ! $user instanceof \WP_User ) {
			delete_transient( self::PENDING_PREFIX . $token );
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$code   = isset( $_POST['gemsec_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['gemsec_2fa_code'] ) ) : '';
		$method = $pending['method'];

		// Allow resending an email code.
		if ( isset( $_POST['gemsec_2fa_resend'] ) && 'email' === $method ) {
			$this->send_email_otp( $user );
			$this->render_form( $token, $method, '', __( 'A new code has been sent to your email.', 'gemsecurity' ) );
			exit;
		}

		$ok = $this->verify_factor( $user, $method, $code );

		if ( ! $ok ) {
			Logger::log( '2fa_failed', sprintf( 'Failed second factor for "%s".', $user->user_login ), Logger::SEVERITY_WARNING, [ 'user_id' => $user->ID ] );
			$this->render_form( $token, $method, __( 'Invalid code. Please try again.', 'gemsecurity' ) );
			exit;
		}

		// Success — complete the login.
		delete_transient( self::PENDING_PREFIX . $token );
		delete_transient( self::EMAIL_OTP_PREFIX . $user->ID );

		self::$passed = true;
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, ! empty( $pending['remember'] ) );

		Logger::log( '2fa_success', sprintf( 'Second factor verified for "%s".', $user->user_login ), Logger::SEVERITY_INFO, [ 'user_id' => $user->ID ] );

		// Re-fire wp_login so other modules (login alert, session stamp) run.
		do_action( 'wp_login', $user->user_login, $user );

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

		// Backup code (format xxxx-xxxx) works regardless of method.
		if ( preg_match( '/[a-z0-9]{4}-?[a-z0-9]{4}/i', $code ) && $this->consume_backup_code( $user, $code ) ) {
			return true;
		}

		if ( 'totp' === $method ) {
			$secret = get_user_meta( $user->ID, '_gemsec_2fa_secret', true );
			return $secret && Totp::verify( $secret, $code, 1 );
		}

		if ( 'email' === $method ) {
			$stored = get_transient( self::EMAIL_OTP_PREFIX . $user->ID );
			return $stored && hash_equals( (string) $stored, preg_replace( '/\D/', '', $code ) );
		}

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
	 */
	public function send_email_otp( $user ) {
		$code = str_pad( (string) random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );
		set_transient( self::EMAIL_OTP_PREFIX . $user->ID, $code, 10 * MINUTE_IN_SECONDS );

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

	private function is_interactive_login() {
		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return false;
		}
		if ( wp_doing_ajax() || ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return false;
		}
		return isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'];
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
