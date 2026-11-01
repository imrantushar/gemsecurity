<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;
use GemSecurity\Mailer;
use GemSecurity\Store;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Magic login — passwordless sign-in through a one-time link sent by email.
 *
 * Flow: the visitor asks for a link (wp-login.php?action=gemsec_magic) → a
 * random token is emailed → opening the link shows a "Confirm sign-in" page →
 * confirming consumes the token and signs the user in. The confirm step is a
 * POST so mail scanners that pre-fetch links cannot burn or abuse the token.
 *
 * Only the SHA-256 of the token is stored, never the token itself.
 *
 * User meta:
 *   _gemsec_magic_hash     sha256 of the pending token (one per user; a new
 *                          request replaces the previous link)
 *   _gemsec_magic_expires  unix time the link stops working
 *   _gemsec_magic_sends    timestamps of recent requests, for rate limiting
 */
class MagicLogin {

	const ACTION       = 'gemsec_magic';
	const META_HASH    = '_gemsec_magic_hash';
	const META_EXPIRES = '_gemsec_magic_expires';
	const META_SENDS   = '_gemsec_magic_sends';

	/** Links one account can request per window. */
	const MAX_SENDS_PER_USER = 3;

	/** Requests one IP address can make per window, whoever they name. */
	const MAX_REQUESTS_PER_IP = 10;

	const LIMIT_WINDOW = 15 * MINUTE_IN_SECONDS;

	public static function init() {
		if ( ! Helper::get_setting( 'magic_login_enabled', false ) ) {
			return;
		}
		$self = new self();
		add_action( 'login_form_' . self::ACTION, [ $self, 'handle' ] );
		add_action( 'login_enqueue_scripts', [ $self, 'styles' ] );
		add_action( 'login_form', [ $self, 'render_link' ] );
		add_filter( 'login_form_bottom', [ $self, 'append_link' ] );
	}

	/* ------------------------------------------------------------------ */
	/* Policy                                                              */
	/* ------------------------------------------------------------------ */

	/** Minutes a link stays valid (5–60). */
	public static function expiry_minutes() {
		return max( 5, min( 60, (int) Helper::get_setting( 'magic_login_expiry', 10 ) ) );
	}

	/**
	 * Whether this account may sign in with a magic link.
	 *
	 * Accounts that hold any administrator-level capability are refused unless
	 * "allow administrators" is on. A non-empty role list narrows it further.
	 *
	 * @param \WP_User $user
	 * @return bool
	 */
	public static function user_allowed( $user ) {
		if ( ! $user instanceof \WP_User ) {
			return false;
		}

		// Temporary accounts sign in only through their own access link.
		if ( TempAccess::is_temp( $user->ID ) ) {
			return false;
		}

		$privileged = false;
		foreach ( SocialLogin::PRIVILEGED_CAPS as $cap ) {
			if ( $user->has_cap( $cap ) ) {
				$privileged = true;
				break;
			}
		}
		if ( $privileged && ! Helper::get_setting( 'magic_login_allow_admins', false ) ) {
			return false;
		}

		$roles = array_filter( (array) Helper::get_setting( 'magic_login_roles', [] ) );
		if ( $roles && ! array_intersect( (array) $user->roles, $roles ) ) {
			return false;
		}

		// Let account-approval / spam plugins that veto sign-in have their say.
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
		if ( is_wp_error( apply_filters( 'wp_authenticate_user', $user, '' ) ) ) {
			return false;
		}

		/**
		 * Whether a user may sign in with a magic link.
		 *
		 * @param bool     $allowed
		 * @param \WP_User $user
		 */
		return (bool) apply_filters( 'gemsecurity/magic_login/user_allowed', true, $user );
	}

	/* ------------------------------------------------------------------ */
	/* Tokens                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Create a fresh token for a user, replacing any earlier one.
	 *
	 * @param int $user_id
	 * @return string The plain token — only ever sent by email.
	 */
	private function issue_token( $user_id ) {
		$token = bin2hex( random_bytes( 32 ) );
		update_user_meta( $user_id, self::META_HASH, hash( 'sha256', $token ) );
		update_user_meta( $user_id, self::META_EXPIRES, time() + self::expiry_minutes() * MINUTE_IN_SECONDS );
		return $token;
	}

	/** Whether the token matches the user's live, unexpired link. Consumes nothing. */
	private function token_valid( $user, $token ) {
		if ( ! $user instanceof \WP_User || ! preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			return false;
		}
		$stored  = (string) get_user_meta( $user->ID, self::META_HASH, true );
		$expires = (int) get_user_meta( $user->ID, self::META_EXPIRES, true );
		return '' !== $stored && $expires >= time() && hash_equals( $stored, hash( 'sha256', $token ) );
	}

	/**
	 * Use the token up. delete_user_meta() only removes the row while it still
	 * holds this exact hash, so of two simultaneous confirmations one wins.
	 */
	private function consume_token( $user, $token ) {
		if ( ! $this->token_valid( $user, $token ) ) {
			return false;
		}
		$consumed = delete_user_meta( $user->ID, self::META_HASH, hash( 'sha256', $token ) );
		delete_user_meta( $user->ID, self::META_EXPIRES );
		return (bool) $consumed;
	}

	/** Remove stale links; run daily from the plugin's cron. */
	public static function cleanup() {
		$ids = get_users( [
			'fields'     => 'ID',
			'number'     => 500,
			'meta_query' => [ [ 'key' => self::META_EXPIRES, 'value' => time(), 'compare' => '<', 'type' => 'NUMERIC' ] ], // phpcs:ignore WordPress.DB.SlowDBQuery
		] );
		foreach ( $ids as $id ) {
			delete_user_meta( $id, self::META_HASH );
			delete_user_meta( $id, self::META_EXPIRES );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Rate limits                                                         */
	/* ------------------------------------------------------------------ */

	/** Count this request against the caller's IP. False once over the limit. */
	private function take_ip_slot() {
		// Store, not a transient: a broken object cache must not disable the limit.
		$key   = 'magic_ip_' . md5( Helper::get_ip_address() );
		$count = (int) Store::get( $key );
		if ( $count >= self::MAX_REQUESTS_PER_IP ) {
			return false;
		}
		Store::set( $key, $count + 1, self::LIMIT_WINDOW );
		return true;
	}

	/** Count an email against the account. False once its budget is spent. */
	private function take_user_slot( $user ) {
		$now   = time();
		$sends = array_filter(
			(array) get_user_meta( $user->ID, self::META_SENDS, true ),
			static function ( $t ) use ( $now ) {
				return (int) $t > $now - self::LIMIT_WINDOW;
			}
		);
		if ( count( $sends ) >= self::MAX_SENDS_PER_USER ) {
			return false;
		}
		$sends[] = $now;
		update_user_meta( $user->ID, self::META_SENDS, array_values( $sends ) );
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Request handling (wp-login.php?action=gemsec_magic)                 */
	/* ------------------------------------------------------------------ */

	public function handle() {
		nocache_headers();
		// Keep the token out of referrers.
		header( 'Referrer-Policy: no-referrer' );

		// A magic link carries its own token, which stands in for a nonce; the
		// request form below is nonce-protected.
		// phpcs:disable WordPress.Security.NonceVerification
		$key = isset( $_REQUEST['gemsec_magic_key'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['gemsec_magic_key'] ) ) : '';
		$uid = isset( $_REQUEST['gemsec_magic_uid'] ) ? absint( $_REQUEST['gemsec_magic_uid'] ) : 0;
		$redirect = isset( $_REQUEST['redirect_to'] ) ? wp_validate_redirect( esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ), '' ) : '';
		$post = isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'];
		// phpcs:enable

		if ( '' !== $key ) {
			$user = $uid ? get_user_by( 'id', $uid ) : false;
			if ( ! $user || ! $this->token_valid( $user, $key ) ) {
				Logger::log( 'magic_login_failed', 'A magic login link was opened that is invalid, expired or already used.', Logger::SEVERITY_WARNING, [ 'user_id' => $user ? $user->ID : 0 ] );
				$this->render_request_form( $redirect, '', __( 'This sign-in link is invalid, has expired, or was already used. Request a new one below.', 'gemsecurity' ) );
				exit;
			}
			if ( ! $post ) {
				$this->render_confirm( $user, $key, $redirect );
				exit;
			}
			$this->complete( $user, $key, $redirect );
			exit;
		}

		if ( $post ) {
			$this->handle_request( $redirect );
			exit;
		}

		$this->render_request_form( $redirect );
		exit;
	}

	/** Someone asked for a link. The answer never says whether the account exists. */
	private function handle_request( $redirect ) {
		$nonce = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified on the next line.
		if ( ! wp_verify_nonce( $nonce, 'gemsec_magic_request' ) ) {
			$this->render_request_form( $redirect, '', __( 'The page expired. Please try again.', 'gemsecurity' ) );
			return;
		}

		if ( ! $this->take_ip_slot() ) {
			Logger::log( 'magic_login_throttled', 'Magic login requests from one address were throttled.', Logger::SEVERITY_WARNING, [ 'user_id' => 0 ] );
			$this->render_request_form( $redirect, '', __( 'Too many requests. Please wait a few minutes and try again.', 'gemsecurity' ) );
			return;
		}

		$login = isset( $_POST['gemsec_magic_login'] ) ? sanitize_text_field( wp_unslash( $_POST['gemsec_magic_login'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified above.
		$user  = '' === $login ? false : ( is_email( $login ) ? get_user_by( 'email', $login ) : get_user_by( 'login', $login ) );

		if ( $user && self::user_allowed( $user ) && $this->take_user_slot( $user ) ) {
			$this->send_link( $user, $redirect );
		}

		$this->render_request_form(
			$redirect,
			__( 'If that account can sign in this way, a sign-in link is on its way to the email address on file. It works once and expires soon.', 'gemsecurity' ),
			'',
			false
		);
	}

	private function send_link( $user, $redirect ) {
		$token   = $this->issue_token( $user->ID );
		$minutes = self::expiry_minutes();
		$url     = add_query_arg(
			array_filter( [
				'action'           => self::ACTION,
				'gemsec_magic_uid' => $user->ID,
				'gemsec_magic_key' => $token,
				'redirect_to'      => $redirect,
			] ),
			wp_login_url()
		);

		Mailer::send(
			$user->user_email,
			'🔗',
			/* translators: %s: site name. */
			sprintf( __( 'Your sign-in link for %s', 'gemsecurity' ), Mailer::site_name() ),
			[
				[
					'type' => 'paragraph',
					'text' => sprintf(
						/* translators: %d: minutes the link is valid. */
						__( 'Use the button below to sign in. The link works once and expires in %d minutes.', 'gemsecurity' ),
						$minutes
					),
				],
				[
					'type'  => 'button',
					'url'   => $url,
					'label' => __( 'Sign in', 'gemsecurity' ),
				],
				[
					'type' => 'paragraph',
					'text' => __( 'If you did not ask for this link, ignore this email — nobody can sign in without it.', 'gemsecurity' ),
				],
			]
		);

		Logger::log( 'magic_login_sent', sprintf( 'Magic login link sent to "%s".', $user->user_login ), Logger::SEVERITY_INFO, [ 'user_id' => $user->ID ] );
	}

	/** The link was confirmed: sign in, via the second-factor prompt where required. */
	private function complete( $user, $key, $redirect ) {
		// The policy may have changed since the link was sent.
		$confirm = isset( $_POST['gemsec_magic_confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['gemsec_magic_confirm'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- checked against its SameSite cookie.
		if ( ! Helper::confirm_check( 'magic_confirm', $confirm ) ) {
			$this->render_confirm( $user, $key, $redirect );
			return;
		}

		if ( ! self::user_allowed( $user ) || is_wp_error( Helper::login_gate( $user ) ) || ! $this->consume_token( $user, $key ) ) {
			Logger::log( 'magic_login_failed', sprintf( 'Magic login for "%s" was refused.', $user->user_login ), Logger::SEVERITY_WARNING, [ 'user_id' => $user->ID ] );
			$this->render_request_form( '', '', __( 'This sign-in link is invalid, has expired, or was already used. Request a new one below.', 'gemsecurity' ) );
			return;
		}

		$remember = ! empty( $_POST['rememberme'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- the one-time token authorises this request.
		if ( '' === $redirect ) {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
			$redirect = apply_filters( 'login_redirect', admin_url(), '', $user );
		}

		if ( Helper::get_setting( 'magic_login_require_2fa', true ) && TwoFactor::user_needs_2fa( $user ) ) {
			TwoFactor::challenge_and_exit( $user, $remember, $redirect );
		}

		Logger::log( 'magic_login', sprintf( '%s signed in with a magic link.', $user->user_login ), Logger::SEVERITY_NOTICE, [ 'user_id' => $user->ID ] );

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, $remember );
		// Fire wp_login so login alerts / session stamping apply — this is WP's
		// own hook, not one of ours.
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound

		wp_safe_redirect( $redirect );
		exit;
	}

	/* ------------------------------------------------------------------ */
	/* Pages                                                               */
	/* ------------------------------------------------------------------ */

	private function form_url() {
		return add_query_arg( 'action', self::ACTION, wp_login_url() );
	}

	private function render_request_form( $redirect = '', $notice = '', $error = '', $show_form = true ) {
		login_header(
			__( 'Email me a sign-in link', 'gemsecurity' ),
			$notice ? '<p class="message">' . esc_html( $notice ) . '</p>' : '',
			$error ? new \WP_Error( 'gemsec_magic', $error ) : null
		);
		if ( $show_form ) :
			?>
			<form name="gemsec_magic_form" id="loginform" action="<?php echo esc_url( $this->form_url() ); ?>" method="post">
				<p>
					<label for="gemsec_magic_login"><?php esc_html_e( 'Username or Email Address', 'gemsecurity' ); ?></label>
					<input type="text" name="gemsec_magic_login" id="gemsec_magic_login" class="input" autocomplete="username" autofocus="autofocus" autocapitalize="off" />
				</p>
				<?php wp_nonce_field( 'gemsec_magic_request' ); ?>
				<?php if ( $redirect ) : ?>
					<input type="hidden" name="redirect_to" value="<?php echo esc_url( $redirect ); ?>" />
				<?php endif; ?>
				<p class="submit">
					<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Email me a sign-in link', 'gemsecurity' ); ?>" />
				</p>
			</form>
			<?php
		endif;
		echo '<p id="backtoblog"><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( '← Back to login', 'gemsecurity' ) . '</a></p>';
		login_footer();
	}

	/** The page a link opens on. Signing in needs this POST, not the GET itself. */
	private function render_confirm( $user, $key, $redirect ) {
		$confirm = Helper::confirm_issue( 'magic_confirm' );
		login_header( __( 'Confirm sign-in', 'gemsecurity' ) );
		?>
		<form name="gemsec_magic_confirm" id="loginform" action="<?php echo esc_url( $this->form_url() ); ?>" method="post">
			<p style="margin-bottom:14px;">
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s: user display name. */
						__( 'Sign in as %s?', 'gemsecurity' ),
						$user->display_name
					)
				);
				?>
			</p>
			<input type="hidden" name="gemsec_magic_uid" value="<?php echo esc_attr( $user->ID ); ?>" />
			<input type="hidden" name="gemsec_magic_key" value="<?php echo esc_attr( $key ); ?>" />
			<input type="hidden" name="gemsec_magic_confirm" value="<?php echo esc_attr( $confirm ); ?>" />
			<?php if ( $redirect ) : ?>
				<input type="hidden" name="redirect_to" value="<?php echo esc_url( $redirect ); ?>" />
			<?php endif; ?>
			<p class="forgetmenot">
				<input name="rememberme" type="checkbox" id="rememberme" value="forever" />
				<label for="rememberme"><?php esc_html_e( 'Remember Me', 'gemsecurity' ); ?></label>
			</p>
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Sign in', 'gemsecurity' ); ?>" />
			</p>
		</form>
		<?php
		login_footer();
	}

	/* ------------------------------------------------------------------ */
	/* Login-form UI                                                       */
	/* ------------------------------------------------------------------ */

	private function link_html() {
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only redirect target.
		$url      = add_query_arg( array_filter( [ 'action' => self::ACTION, 'redirect_to' => $redirect ] ), wp_login_url() );
		return '<p class="gemsec-magic"><a class="gemsec-magic__btn" href="' . esc_url( $url ) . '">' . esc_html__( 'Email me a sign-in link', 'gemsecurity' ) . '</a></p>';
	}

	/** wp-login.php — printed inside the form, then moved below the Log In button. */
	public function render_link() {
		echo $this->link_html(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built with escaping above.
		wp_print_inline_script_tag( 'document.addEventListener("DOMContentLoaded",function(){var f=document.getElementById("loginform"),m=document.querySelector("#loginform .gemsec-magic");if(f&&m&&f.parentNode){f.parentNode.insertBefore(m,f.nextSibling);}});' );
	}

	/** wp_login_form() / WooCommerce — appended to the returned markup. */
	public function append_link( $html ) {
		return $html . $this->link_html();
	}

	public function styles() {
		wp_add_inline_style( 'login', self::css() );
	}

	private static function css() {
		return '.gemsec-magic{clear:both;margin:16px 0 0;text-align:center;}'
			. '.gemsec-magic__btn{display:block;box-sizing:border-box;width:100%;padding:8px 14px;border:1px solid #2271b1;border-radius:3px;'
			. 'color:#2271b1;background:#fff;text-decoration:none;font-weight:600;}'
			. '.gemsec-magic__btn:hover{background:#2271b1;color:#fff;}';
	}
}
