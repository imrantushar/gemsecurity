<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;
use GemSecurity\Security\Geo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Geolocation access control.
 *
 * Two cooperating layers:
 *  - Country whitelist (global): block at login and/or block the whole site (403).
 *  - Per-user location lock: a login from a country not on the user's
 *    admin-assigned list triggers an email verification (or a hard block).
 *
 * Safety: master switch defaults off; unknown / private / localhost countries
 * are allowed unless "block unknown" is on; logged-in admins are never blocked
 * site-wide; define('GEMSEC_GEO_DISABLE', true) disables everything.
 */
class Geolocation {

	const PENDING_PREFIX = 'gemsec_geo_pending_';
	const OTP_PREFIX     = 'gemsec_geo_eotp_';
	const USER_META      = '_gemsec_geo_allowed_countries';

	private static $passed = false;

	public static function init() {
		if ( ! Helper::get_setting( 'geo_enabled', false ) || Geo::is_bypassed() ) {
			return;
		}
		$self = new self();

		if ( Helper::get_setting( 'geo_block_site_enabled', false ) ) {
			add_action( 'init', [ $self, 'enforce_site_country' ], 0 );
		}
		if ( Helper::get_setting( 'geo_whitelist_login_enabled', false ) ) {
			add_filter( 'authenticate', [ $self, 'enforce_login_country' ], 35, 1 );
		}
		if ( Helper::get_setting( 'geo_user_lock_enabled', false ) ) {
			add_action( 'wp_login', [ $self, 'maybe_verify_new_location' ], 9, 2 );
			add_action( 'login_form_gemsec_geo', [ $self, 'handle_verify' ] );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Whole-site country block                                            */
	/* ------------------------------------------------------------------ */

	public function enforce_site_country() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}
		// Never block an authenticated administrator.
		if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
			return;
		}
		// Don't fight the login challenge flow.
		if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) {
			return;
		}

		$country = Geo::current_country();
		if ( $this->country_allowed( $country, $this->global_allowed() ) ) {
			return;
		}

		Logger::log(
			'geo_site_blocked',
			sprintf( 'Blocked site access from %s (%s).', $country ?: 'unknown', Helper::get_ip_address() ),
			Logger::SEVERITY_WARNING,
			[ 'user_id' => 0, 'context' => [ 'country' => $country ] ]
		);

		status_header( 403 );
		nocache_headers();
		wp_die(
			esc_html__( 'Access from your location is not permitted.', 'gemsecurity' ),
			esc_html__( 'Access denied', 'gemsecurity' ),
			[ 'response' => 403 ]
		);
	}

	/* ------------------------------------------------------------------ */
	/* Country whitelist at login                                          */
	/* ------------------------------------------------------------------ */

	/**
	 * @param \WP_User|\WP_Error|null $user
	 * @return \WP_User|\WP_Error|null
	 */
	public function enforce_login_country( $user ) {
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}
		// Allow admins to log in even from outside the whitelist (recovery).
		if ( user_can( $user, 'manage_options' ) && ! Helper::get_setting( 'geo_whitelist_block_admins', false ) ) {
			return $user;
		}

		$country = Geo::current_country();
		if ( $this->country_allowed( $country, $this->global_allowed() ) ) {
			return $user;
		}

		Logger::log(
			'geo_login_blocked',
			sprintf( 'Blocked login for "%s" from %s.', $user->user_login, $country ?: 'unknown' ),
			Logger::SEVERITY_WARNING,
			[ 'user_id' => $user->ID, 'context' => [ 'country' => $country ] ]
		);

		return new \WP_Error(
			'gemsecurity_geo_blocked',
			__( '<strong>Login blocked.</strong> Sign-in from your location is not permitted.', 'gemsecurity' )
		);
	}

	/* ------------------------------------------------------------------ */
	/* Per-user new-location verification                                  */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string   $user_login
	 * @param \WP_User $user
	 */
	public function maybe_verify_new_location( $user_login, $user = null ) {
		if ( self::$passed ) {
			return;
		}
		if ( ! $user instanceof \WP_User ) {
			$user = get_user_by( 'login', $user_login );
		}
		if ( ! $user instanceof \WP_User || ! $this->is_interactive_login() ) {
			return;
		}

		$allowed = $this->user_countries( $user->ID );
		if ( empty( $allowed ) ) {
			return; // Per-user lock only applies once countries are assigned.
		}

		$country = Geo::current_country();
		if ( '' === $country || in_array( $country, $allowed, true ) ) {
			return; // Unknown (fail-open) or a known country → allow.
		}

		// New country.
		if ( 'block' === Helper::get_setting( 'geo_user_lock_action', 'verify' ) ) {
			Logger::log( 'geo_login_blocked', sprintf( 'Blocked "%s" from unrecognized country %s.', $user->user_login, $country ), Logger::SEVERITY_WARNING, [ 'user_id' => $user->ID, 'context' => [ 'country' => $country ] ] );
			wp_logout();
			wp_die(
				esc_html__( 'This account cannot be accessed from your current location.', 'gemsecurity' ),
				esc_html__( 'Login blocked', 'gemsecurity' ),
				[ 'response' => 403, 'back_link' => true ]
			);
		}

		// Email-verify the new location.
		wp_clear_auth_cookie();
		wp_destroy_current_session();

		$token = wp_generate_password( 32, false );
		set_transient(
			self::PENDING_PREFIX . $token,
			[
				'user_id'  => $user->ID,
				'remember' => ! empty( $_POST['rememberme'] ),
				'redirect' => isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : admin_url(),
				'country'  => $country,
			],
			10 * MINUTE_IN_SECONDS
		);
		$this->send_otp( $user );

		Logger::log( 'geo_new_location', sprintf( 'New login location for "%s" (%s) — verification required.', $user->user_login, $country ), Logger::SEVERITY_NOTICE, [ 'user_id' => $user->ID, 'context' => [ 'country' => $country ] ] );

		$this->render_form( $token, $country, '' );
		exit;
	}

	public function handle_verify() {
		$token   = isset( $_POST['gemsec_geo_token'] ) ? sanitize_text_field( wp_unslash( $_POST['gemsec_geo_token'] ) ) : '';
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

		if ( isset( $_POST['gemsec_geo_resend'] ) ) {
			$this->send_otp( $user );
			$this->render_form( $token, $pending['country'], '', __( 'A new code has been sent to your email.', 'gemsecurity' ) );
			exit;
		}

		$code   = isset( $_POST['gemsec_geo_code'] ) ? preg_replace( '/\D/', '', wp_unslash( $_POST['gemsec_geo_code'] ) ) : '';
		$stored = get_transient( self::OTP_PREFIX . $user->ID );

		if ( ! $stored || ! hash_equals( (string) $stored, $code ) ) {
			Logger::log( 'geo_verify_failed', sprintf( 'Failed location verification for "%s".', $user->user_login ), Logger::SEVERITY_WARNING, [ 'user_id' => $user->ID ] );
			$this->render_form( $token, $pending['country'], __( 'Invalid code. Please try again.', 'gemsecurity' ) );
			exit;
		}

		// Verified — remember this country for the user and complete login.
		$this->add_user_country( $user->ID, $pending['country'] );
		delete_transient( self::PENDING_PREFIX . $token );
		delete_transient( self::OTP_PREFIX . $user->ID );

		self::$passed = true;
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, ! empty( $pending['remember'] ) );

		Logger::log( 'geo_verified', sprintf( 'New location (%s) verified for "%s".', $pending['country'], $user->user_login ), Logger::SEVERITY_NOTICE, [ 'user_id' => $user->ID, 'context' => [ 'country' => $pending['country'] ] ] );

		// Re-fire wp_login so other modules (2FA, login alert, session stamp) run.
		do_action( 'wp_login', $user->user_login, $user );

		wp_safe_redirect( ! empty( $pending['redirect'] ) ? $pending['redirect'] : admin_url() );
		exit;
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	private function send_otp( $user ) {
		$code = str_pad( (string) random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );
		set_transient( self::OTP_PREFIX . $user->ID, $code, 10 * MINUTE_IN_SECONDS );

		$site = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
		wp_mail(
			$user->user_email,
			sprintf( __( '[%s] Verify your login location', 'gemsecurity' ), $site ),
			implode( "\n", [
				sprintf( __( 'A login to %s was attempted from a new location.', 'gemsecurity' ), $site ),
				sprintf( __( 'Your verification code is: %s', 'gemsecurity' ), $code ),
				'',
				__( 'It expires in 10 minutes. If this was not you, change your password immediately.', 'gemsecurity' ),
			] )
		);
	}

	/**
	 * Global allowed-country list (uppercase).
	 *
	 * @return string[]
	 */
	private function global_allowed() {
		return array_map( 'strtoupper', (array) Helper::get_setting( 'geo_allowed_countries', [] ) );
	}

	/**
	 * A user's admin-assigned allowed countries (uppercase).
	 *
	 * @param int $user_id
	 * @return string[]
	 */
	public function user_countries( $user_id ) {
		$list = get_user_meta( $user_id, self::USER_META, true );
		return is_array( $list ) ? array_map( 'strtoupper', $list ) : [];
	}

	private function add_user_country( $user_id, $country ) {
		$country = strtoupper( $country );
		if ( ! Geo::is_valid_code( $country ) ) {
			return;
		}
		$list = $this->user_countries( $user_id );
		if ( ! in_array( $country, $list, true ) ) {
			$list[] = $country;
			update_user_meta( $user_id, self::USER_META, $list );
		}
	}

	/**
	 * Is the given country acceptable against an allow-list?
	 * Unknown ('') passes unless "block unknown" is enabled.
	 *
	 * @param string   $country
	 * @param string[] $allowed
	 * @return bool
	 */
	private function country_allowed( $country, $allowed ) {
		if ( '' === $country ) {
			return ! Helper::get_setting( 'geo_block_unknown', false );
		}
		if ( empty( $allowed ) ) {
			return true; // No list configured → nothing to enforce.
		}
		return in_array( strtoupper( $country ), $allowed, true );
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

	private function render_form( $token, $country, $error = '', $notice = '' ) {
		login_header( __( 'Verify your location', 'gemsecurity' ), '', $error ? new \WP_Error( 'gemsec_geo', $error ) : null );
		?>
		<form name="gemsec_geo_form" id="loginform" action="<?php echo esc_url( site_url( 'wp-login.php?action=gemsec_geo', 'login_post' ) ); ?>" method="post">
			<?php if ( $notice ) : ?>
				<p class="message"><?php echo esc_html( $notice ); ?></p>
			<?php endif; ?>
			<p style="margin-bottom:14px;">
				<?php esc_html_e( 'We noticed a login from a new location. Enter the 6-digit code we emailed you to continue.', 'gemsecurity' ); ?>
			</p>
			<p>
				<label for="gemsec_geo_code"><?php esc_html_e( 'Verification code', 'gemsecurity' ); ?></label>
				<input type="text" name="gemsec_geo_code" id="gemsec_geo_code" class="input" autocomplete="one-time-code"
					inputmode="numeric" autofocus="autofocus" autocapitalize="off" />
			</p>
			<input type="hidden" name="gemsec_geo_token" value="<?php echo esc_attr( $token ); ?>" />
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'gemsecurity' ); ?>" />
			</p>
			<p style="text-align:center;">
				<button type="submit" name="gemsec_geo_resend" value="1" class="button-link"><?php esc_html_e( 'Resend code', 'gemsecurity' ); ?></button>
			</p>
		</form>
		<p id="backtoblog"><a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( '← Back to login', 'gemsecurity' ); ?></a></p>
		<?php
		login_footer();
	}
}
