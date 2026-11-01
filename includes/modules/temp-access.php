<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;
use GemSecurity\Mailer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Temporary access — time-limited dashboard accounts for developers and
 * support staff, without sharing anyone's password.
 *
 * Each grant is a real WordPress user with a real role, so WordPress's own
 * capability checks decide what it may do. The account has a random 64-character
 * password nobody knows; the only way in is a single-use link:
 *
 *   wp-login.php?action=gemsec_temp&gemsec_temp_uid=…&gemsec_temp_key=…
 *
 * Opening the link shows a "Continue" page; the POST from that page consumes the
 * token and signs in. The two steps keep mail scanners that pre-fetch links
 * from burning the token. Only the SHA-256 of the token is stored.
 *
 * Expiry is enforced on every request ({@see enforce()}), not only by cron, and
 * ending access (expiry or revocation) destroys the account's sessions and
 * application passwords. {@see enforce()} is booted whether or not the module
 * is switched on, so turning the module off cannot extend anyone's access.
 *
 * User meta:
 *   _gemsec_ta              1 on every temporary account
 *   _gemsec_ta_expires      unix time access ends
 *   _gemsec_ta_revoked      unix time access was revoked (absent otherwise)
 *   _gemsec_ta_ended        unix time sessions were torn down after expiry/revoke
 *   _gemsec_ta_hash         sha256 of the pending setup token
 *   _gemsec_ta_link_expires unix time the pending token stops working
 *   _gemsec_ta_created      unix time, _gemsec_ta_created_by creator's user id
 *   _gemsec_ta_last_login   unix time of the last link sign-in
 *   _gemsec_ta_logins       number of link sign-ins
 *   _gemsec_ta_history      capped list of [ time, event, detail, ip ]
 */
class TempAccess {

	const ACTION = 'gemsec_temp';
	const CRON   = 'gemsecurity_temp_access_sweep';

	const META_FLAG         = '_gemsec_ta';
	const META_EXPIRES      = '_gemsec_ta_expires';
	const META_REVOKED      = '_gemsec_ta_revoked';
	const META_ENDED        = '_gemsec_ta_ended';
	const META_HASH         = '_gemsec_ta_hash';
	const META_LINK_EXPIRES = '_gemsec_ta_link_expires';
	const META_CREATED      = '_gemsec_ta_created';
	const META_CREATED_BY   = '_gemsec_ta_created_by';
	const META_LAST_LOGIN   = '_gemsec_ta_last_login';
	const META_LOGINS       = '_gemsec_ta_logins';
	const META_HISTORY      = '_gemsec_ta_history';

	/** Accounts an administrator may create per hour. */
	const MAX_CREATES_PER_HOUR = 10;

	/** Bad link attempts one IP address may make per window. */
	const MAX_BAD_LINKS_PER_IP = 8;

	const LIMIT_WINDOW = 15 * MINUTE_IN_SECONDS;

	const HISTORY_LIMIT = 30;

	/** Longest access window that can be granted. */
	const MAX_SECONDS = 90 * DAY_IN_SECONDS;

	/** Shortest window — anything less would expire before the link arrives. */
	const MIN_SECONDS = 5 * MINUTE_IN_SECONDS;

	/**
	 * Capabilities that let a user run or reconfigure the site. Narrower than
	 * SocialLogin::PRIVILEGED_CAPS: ordinary content roles such as Editor are not
	 * "full control", so they need no extra confirmation.
	 */
	const ELEVATED_CAPS = [
		'manage_options', 'edit_users', 'create_users', 'promote_users', 'delete_users',
		'activate_plugins', 'install_plugins', 'edit_plugins', 'edit_themes', 'switch_themes',
		'update_core', 'manage_network',
	];

	/** Duration presets, in seconds. */
	const PRESETS = [
		'1h'  => HOUR_IN_SECONDS,
		'6h'  => 6 * HOUR_IN_SECONDS,
		'24h' => DAY_IN_SECONDS,
		'7d'  => 7 * DAY_IN_SECONDS,
		'30d' => 30 * DAY_IN_SECONDS,
	];

	/* ------------------------------------------------------------------ */
	/* Boot                                                                */
	/* ------------------------------------------------------------------ */

	/** Module boot: the sign-in link and the sweep schedule. */
	public static function init() {
		$self = new self();
		add_action( 'login_form_' . self::ACTION, [ $self, 'handle' ] );
		if ( ! wp_next_scheduled( self::CRON ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::CRON );
		}
	}

	/**
	 * Enforcement — booted on every request by Database::init(), independent of
	 * whether the module is active.
	 */
	public static function enforce() {
		// Every request, REST and cookie-less app-password calls included.
		add_filter( 'determine_current_user', [ __CLASS__, 'filter_current_user' ], 99 );
		// Temporary accounts have no password: the link is the only way in.
		add_filter( 'authenticate', [ __CLASS__, 'block_password_login' ], 99 );
		add_filter( 'allow_password_reset', [ __CLASS__, 'block_password_reset' ], 10, 2 );
		add_filter( 'wp_is_application_passwords_available_for_user', [ __CLASS__, 'block_app_passwords' ], 10, 2 );
		// A session cookie can never outlive the grant.
		add_filter( 'auth_cookie_expiration', [ __CLASS__, 'cap_cookie_lifetime' ], 99, 3 );
		add_action( self::CRON, [ __CLASS__, 'sweep' ] );
	}

	/* ------------------------------------------------------------------ */
	/* State                                                               */
	/* ------------------------------------------------------------------ */

	public static function is_temp( $user_id ) {
		return $user_id && (bool) get_user_meta( (int) $user_id, self::META_FLAG, true );
	}

	/** active | expired | revoked */
	public static function status( $user_id ) {
		if ( (int) get_user_meta( $user_id, self::META_REVOKED, true ) > 0 ) {
			return 'revoked';
		}
		return (int) get_user_meta( $user_id, self::META_EXPIRES, true ) > time() ? 'active' : 'expired';
	}

	/** Whether this account is a temporary one whose grant is still live. */
	public static function is_live( $user_id ) {
		return self::is_temp( $user_id ) && 'active' === self::status( $user_id );
	}

	/**
	 * Tear down an account whose grant has ended: sessions, application
	 * passwords and any pending link. Runs once per ending (guarded by
	 * META_ENDED), whoever notices first — a request, the sweep, or revoke().
	 *
	 * @return bool True when this call did the teardown.
	 */
	private static function close_out( $user_id ) {
		if ( (int) get_user_meta( $user_id, self::META_ENDED, true ) > 0 ) {
			return false;
		}
		update_user_meta( $user_id, self::META_ENDED, time() );
		delete_user_meta( $user_id, self::META_HASH );
		delete_user_meta( $user_id, self::META_LINK_EXPIRES );

		\WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		if ( class_exists( '\WP_Application_Passwords' ) ) {
			\WP_Application_Passwords::delete_all_application_passwords( $user_id );
		}
		return true;
	}

	/** Notice an expired grant: close it out and record that it expired. */
	private static function maybe_expire( $user_id ) {
		if ( 'expired' !== self::status( $user_id ) ) {
			return;
		}
		if ( self::close_out( $user_id ) ) {
			self::record( $user_id, 'expired', __( 'Access expired.', 'gemsecurity' ), Logger::SEVERITY_INFO );
		}
	}

	/** Hourly: close out grants nobody has touched since they expired. */
	public static function sweep() {
		$ids = get_users( [
			'fields'     => 'ID',
			'number'     => 200,
			'meta_query' => [ // phpcs:ignore WordPress.DB.SlowDBQuery
				'relation' => 'AND',
				[ 'key' => self::META_EXPIRES, 'value' => time(), 'compare' => '<=', 'type' => 'NUMERIC' ],
				[ 'key' => self::META_ENDED, 'compare' => 'NOT EXISTS' ],
			],
		] );
		foreach ( $ids as $id ) {
			if ( self::is_temp( $id ) ) {
				self::maybe_expire( (int) $id );
			}
		}
	}

	/* ------------------------------------------------------------------ */
	/* Enforcement filters                                                 */
	/* ------------------------------------------------------------------ */

	/** An ended grant is never "logged in", whatever cookie or credential it presents. */
	public static function filter_current_user( $user_id ) {
		if ( $user_id && self::is_temp( $user_id ) && 'active' !== self::status( $user_id ) ) {
			self::maybe_expire( (int) $user_id );
			return 0;
		}
		return $user_id;
	}

	public static function block_password_login( $user ) {
		if ( $user instanceof \WP_User && self::is_temp( $user->ID ) ) {
			return new \WP_Error( 'gemsec_temp_link_only', __( '<strong>Sign-in blocked.</strong> This temporary account can only be used through its access link.', 'gemsecurity' ) );
		}
		return $user;
	}

	public static function block_password_reset( $allow, $user_id ) {
		return self::is_temp( $user_id ) ? false : $allow;
	}

	public static function block_app_passwords( $available, $user ) {
		return ( $user instanceof \WP_User && self::is_temp( $user->ID ) ) ? false : $available;
	}

	public static function cap_cookie_lifetime( $length, $user_id, $remember ) {
		if ( self::is_temp( $user_id ) ) {
			$left = (int) get_user_meta( $user_id, self::META_EXPIRES, true ) - time();
			return max( 1, min( (int) $length, $left ) );
		}
		return $length;
	}

	/* ------------------------------------------------------------------ */
	/* Permissions                                                         */
	/* ------------------------------------------------------------------ */

	/**
	 * Who may manage temporary access. Temporary accounts never can, so a
	 * short-lived administrator cannot mint itself more time or more accounts.
	 */
	public static function can_manage() {
		$user = wp_get_current_user();
		return $user->exists()
			&& current_user_can( 'manage_options' )
			&& current_user_can( 'create_users' )
			&& ! self::is_temp( $user->ID );
	}

	/* ------------------------------------------------------------------ */
	/* Roles & durations                                                   */
	/* ------------------------------------------------------------------ */

	/** Whether a role carries any capability that can run or reconfigure the site. */
	public static function role_is_elevated( $slug ) {
		$role = get_role( $slug );
		if ( ! $role ) {
			return false;
		}
		foreach ( self::ELEVATED_CAPS as $cap ) {
			if ( ! empty( $role->capabilities[ $cap ] ) ) {
				return true;
			}
		}
		return false;
	}

	/** Roles the current user may hand out, each flagged when elevated. */
	public static function assignable_roles() {
		if ( ! function_exists( 'get_editable_roles' ) ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
		}
		$out = [];
		foreach ( get_editable_roles() as $slug => $role ) {
			$out[] = [
				'slug'     => $slug,
				'name'     => translate_user_role( $role['name'] ),
				'elevated' => self::role_is_elevated( $slug ),
			];
		}
		return $out;
	}

	/**
	 * Work out an expiry from a preset key or a custom unix time.
	 *
	 * @param string $duration  A PRESETS key, or "custom".
	 * @param int    $custom    Unix time, used when $duration is "custom".
	 * @param int    $base      Start point for presets.
	 * @return int|\WP_Error
	 */
	private static function resolve_expiry( $duration, $custom, $base ) {
		$now = time();
		if ( isset( self::PRESETS[ $duration ] ) ) {
			$expires = $base + self::PRESETS[ $duration ];
		} elseif ( 'custom' === $duration ) {
			$expires = (int) $custom;
		} else {
			return new \WP_Error( 'bad_duration', __( 'Choose how long access should last.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		/**
		 * Longest access window, in seconds from now.
		 *
		 * @param int $max
		 */
		$max = (int) apply_filters( 'gemsecurity/temp_access/max_seconds', self::MAX_SECONDS );

		if ( $expires < $now + self::MIN_SECONDS ) {
			return new \WP_Error( 'expiry_too_soon', __( 'The expiry must be at least 5 minutes from now.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		if ( $expires > $now + $max ) {
			/* translators: %d: days. */
			return new \WP_Error( 'expiry_too_far', sprintf( __( 'Temporary access can last at most %d days.', 'gemsecurity' ), (int) floor( $max / DAY_IN_SECONDS ) ), [ 'status' => 400 ] );
		}
		return $expires;
	}

	/* ------------------------------------------------------------------ */
	/* Management actions (called by the REST controller)                  */
	/* ------------------------------------------------------------------ */

	/**
	 * Create a temporary account.
	 *
	 * @param array $args email, role, duration, expires_at, send_email, confirm_elevated.
	 * @return array|\WP_Error { id, link, emailed }
	 */
	public static function create( array $args ) {
		$email = isset( $args['email'] ) ? sanitize_email( $args['email'] ) : '';
		if ( ! is_email( $email ) ) {
			return new \WP_Error( 'bad_email', __( 'Enter a valid email address.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		// An address that already belongs to someone is never touched: no
		// reuse, no role change, no "temporary" flag on a real person.
		if ( email_exists( $email ) ) {
			return new \WP_Error(
				'email_exists',
				__( 'A user with this email address already exists. Existing accounts are never changed or converted — use a different address for the temporary account.', 'gemsecurity' ),
				[ 'status' => 409 ]
			);
		}

		$slug  = isset( $args['role'] ) ? sanitize_key( $args['role'] ) : '';
		$roles = wp_list_pluck( self::assignable_roles(), 'elevated', 'slug' );
		if ( ! isset( $roles[ $slug ] ) ) {
			return new \WP_Error( 'bad_role', __( 'Choose a role to grant.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		if ( $roles[ $slug ] && empty( $args['confirm_elevated'] ) ) {
			return new \WP_Error( 'confirm_elevated', __( 'This role can change the site. Confirm that you want to grant it.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		$expires = self::resolve_expiry(
			isset( $args['duration'] ) ? sanitize_key( $args['duration'] ) : '',
			isset( $args['expires_at'] ) ? (int) $args['expires_at'] : 0,
			time()
		);
		if ( is_wp_error( $expires ) ) {
			return $expires;
		}

		$limit_key = 'gemsec_ta_create_' . get_current_user_id();
		$made      = (int) get_transient( $limit_key );
		if ( $made >= self::MAX_CREATES_PER_HOUR ) {
			return new \WP_Error( 'rate_limited', __( 'Too many temporary accounts were created in the last hour. Try again later.', 'gemsecurity' ), [ 'status' => 429 ] );
		}
		set_transient( $limit_key, $made + 1, HOUR_IN_SECONDS );

		$login = '';
		do {
			$login = 'temp-' . strtolower( wp_generate_password( 8, false ) );
		} while ( username_exists( $login ) );

		$now     = time();
		$user_id = wp_insert_user( [
			'user_login'   => $login,
			'user_email'   => $email,
			'user_pass'    => wp_generate_password( 64, true, true ),
			'role'         => $slug,
			'display_name' => __( 'Temporary access', 'gemsecurity' ),
			'nickname'     => $login,
			// Written before user_register fires so other guards can recognise the account.
			'meta_input'   => [
				self::META_FLAG       => 1,
				self::META_EXPIRES    => $expires,
				self::META_CREATED    => $now,
				self::META_CREATED_BY => get_current_user_id(),
			],
		] );
		if ( is_wp_error( $user_id ) ) {
			return new \WP_Error( 'create_failed', $user_id->get_error_message(), [ 'status' => 500 ] );
		}
		if ( is_multisite() ) {
			add_user_to_blog( get_current_blog_id(), $user_id, $slug );
		}

		self::record(
			$user_id,
			'created',
			sprintf(
				/* translators: 1: email, 2: role, 3: expiry date. */
				__( 'Temporary access created for %1$s with role "%2$s", ending %3$s.', 'gemsecurity' ),
				$email,
				$slug,
				wp_date( 'Y-m-d H:i', $expires )
			),
			$roles[ $slug ] ? Logger::SEVERITY_WARNING : Logger::SEVERITY_NOTICE
		);

		$link   = self::issue_link( $user_id );
		$mailed = false;
		if ( ! empty( $args['send_email'] ) ) {
			$mailed = self::email_invite( $user_id, $link );
		}

		if ( Helper::get_setting( 'temp_access_notify_created', true ) ) {
			self::notify_admin(
				__( 'Temporary access created', 'gemsecurity' ),
				sprintf(
					/* translators: 1: email, 2: role, 3: expiry date. */
					__( '%1$s was given temporary access with the "%2$s" role until %3$s.', 'gemsecurity' ),
					$email,
					$slug,
					wp_date( 'Y-m-d H:i', $expires )
				)
			);
		}

		return [ 'id' => $user_id, 'link' => $link, 'emailed' => $mailed ];
	}

	/**
	 * Extend or reopen access. Active grants grow from their current expiry,
	 * expired ones restart from now. Revoked grants stay revoked.
	 *
	 * @return true|\WP_Error
	 */
	public static function extend( $user_id, $duration, $custom ) {
		$err = self::require_temp( $user_id );
		if ( $err ) {
			return $err;
		}
		$status = self::status( $user_id );
		if ( 'revoked' === $status ) {
			return new \WP_Error( 'revoked', __( 'Revoked access cannot be extended. Create a new temporary account instead.', 'gemsecurity' ), [ 'status' => 409 ] );
		}

		$current = (int) get_user_meta( $user_id, self::META_EXPIRES, true );
		$base    = 'active' === $status ? $current : time();
		$expires = self::resolve_expiry( sanitize_key( $duration ), $custom, $base );
		if ( is_wp_error( $expires ) ) {
			return $expires;
		}

		update_user_meta( $user_id, self::META_EXPIRES, $expires );
		delete_user_meta( $user_id, self::META_ENDED );
		self::record(
			$user_id,
			'extended',
			/* translators: %s: date. */
			sprintf( __( 'Access extended to %s.', 'gemsecurity' ), wp_date( 'Y-m-d H:i', $expires ) ),
			Logger::SEVERITY_NOTICE
		);
		return true;
	}

	/**
	 * Replace the sign-in link. The old one stops working at once.
	 *
	 * @return array|\WP_Error { link, emailed }
	 */
	public static function regenerate( $user_id, $send_email ) {
		$err = self::require_temp( $user_id );
		if ( $err ) {
			return $err;
		}
		if ( 'active' !== self::status( $user_id ) ) {
			return new \WP_Error( 'not_active', __( 'Extend this access first — only active accounts can have a link.', 'gemsecurity' ), [ 'status' => 409 ] );
		}
		$link = self::issue_link( $user_id );
		self::record( $user_id, 'link_regenerated', __( 'A new sign-in link was generated; the previous one no longer works.', 'gemsecurity' ), Logger::SEVERITY_NOTICE );
		return [ 'link' => $link, 'emailed' => $send_email ? self::email_invite( $user_id, $link ) : false ];
	}

	/** End access immediately. @return true|\WP_Error */
	public static function revoke( $user_id ) {
		$err = self::require_temp( $user_id );
		if ( $err ) {
			return $err;
		}
		if ( 'revoked' === self::status( $user_id ) ) {
			return new \WP_Error( 'already_revoked', __( 'This access was already revoked.', 'gemsecurity' ), [ 'status' => 409 ] );
		}
		update_user_meta( $user_id, self::META_REVOKED, time() );
		delete_user_meta( $user_id, self::META_ENDED );
		self::close_out( $user_id );
		self::record( $user_id, 'revoked', __( 'Access revoked; sessions ended.', 'gemsecurity' ), Logger::SEVERITY_NOTICE );

		if ( Helper::get_setting( 'temp_access_notify_revoked', true ) ) {
			$user = get_userdata( $user_id );
			self::notify_admin(
				__( 'Temporary access revoked', 'gemsecurity' ),
				/* translators: %s: email. */
				sprintf( __( 'Temporary access for %s was revoked and its sessions were ended.', 'gemsecurity' ), $user ? $user->user_email : '' )
			);
		}
		return true;
	}

	private static function require_temp( $user_id ) {
		if ( ! self::is_temp( $user_id ) || ! get_userdata( $user_id ) ) {
			return new \WP_Error( 'not_temp', __( 'That is not a temporary access account.', 'gemsecurity' ), [ 'status' => 404 ] );
		}
		return null;
	}

	/* ------------------------------------------------------------------ */
	/* Tokens & mail                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Store a fresh token's hash (replacing any earlier one) and return the link.
	 * The raw token exists only in the returned URL.
	 */
	private static function issue_link( $user_id ) {
		$token = bin2hex( random_bytes( 32 ) );

		/**
		 * Hours a sign-in link stays usable; it never outlives the access itself.
		 *
		 * @param int $hours
		 */
		$hours   = max( 1, (int) apply_filters( 'gemsecurity/temp_access/link_hours', 48 ) );
		$expires = min( time() + $hours * HOUR_IN_SECONDS, (int) get_user_meta( $user_id, self::META_EXPIRES, true ) );

		update_user_meta( $user_id, self::META_HASH, hash( 'sha256', $token ) );
		update_user_meta( $user_id, self::META_LINK_EXPIRES, $expires );

		return add_query_arg(
			[
				'action'          => self::ACTION,
				'gemsec_temp_uid' => $user_id,
				'gemsec_temp_key' => $token,
			],
			wp_login_url()
		);
	}

	private static function token_valid( $user_id, $token ) {
		if ( ! preg_match( '/^[a-f0-9]{64}$/', $token ) || ! self::is_live( $user_id ) ) {
			return false;
		}
		$stored  = (string) get_user_meta( $user_id, self::META_HASH, true );
		$expires = (int) get_user_meta( $user_id, self::META_LINK_EXPIRES, true );
		return '' !== $stored && $expires > time() && hash_equals( $stored, hash( 'sha256', $token ) );
	}

	/**
	 * Use the token up. delete_user_meta() only removes the row while it still
	 * holds this exact hash, so of two simultaneous confirmations one wins.
	 */
	private static function consume_token( $user_id, $token ) {
		if ( ! self::token_valid( $user_id, $token ) ) {
			return false;
		}
		$consumed = delete_user_meta( $user_id, self::META_HASH, hash( 'sha256', $token ) );
		delete_user_meta( $user_id, self::META_LINK_EXPIRES );
		return (bool) $consumed;
	}

	private static function email_invite( $user_id, $link ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return false;
		}
		$expires = (int) get_user_meta( $user_id, self::META_EXPIRES, true );
		$sent    = Mailer::send(
			$user->user_email,
			'🔑',
			/* translators: %s: site name. */
			sprintf( __( 'Temporary access to %s', 'gemsecurity' ), Mailer::site_name() ),
			[
				[
					'type' => 'paragraph',
					/* translators: %s: date and time. */
					'text' => sprintf( __( 'You have been given temporary access to the dashboard. It ends on %s.', 'gemsecurity' ), wp_date( 'Y-m-d H:i T', $expires ) ),
				],
				[ 'type' => 'button', 'url' => $link, 'label' => __( 'Open the dashboard', 'gemsecurity' ) ],
				[
					'type' => 'paragraph',
					'text' => __( 'The link works once. Do not forward it — whoever opens it first gets the access.', 'gemsecurity' ),
				],
			],
			[ 'origin' => false ]
		);
		if ( $sent ) {
			self::record( $user_id, 'link_sent', __( 'Sign-in link emailed to the recipient.', 'gemsecurity' ), Logger::SEVERITY_INFO );
		}
		return (bool) $sent;
	}

	private static function notify_admin( $title, $text ) {
		Mailer::send( Mailer::recipient(), '🔑', $title, [ [ 'type' => 'paragraph', 'text' => $text ] ] );
	}

	/* ------------------------------------------------------------------ */
	/* History                                                             */
	/* ------------------------------------------------------------------ */

	/** Write to the account's own history and to the site-wide audit log. */
	private static function record( $user_id, $event, $message, $severity ) {
		$history   = (array) get_user_meta( $user_id, self::META_HISTORY, true );
		$history[] = [ time(), $event, $message, Helper::get_ip_address() ];
		update_user_meta( $user_id, self::META_HISTORY, array_slice( array_values( array_filter( $history ) ), -self::HISTORY_LIMIT ) );

		Logger::log( 'temp_access_' . $event, $message, $severity, [ 'context' => [ 'target_user_id' => (int) $user_id ] ] );
	}

	/* ------------------------------------------------------------------ */
	/* Listing                                                             */
	/* ------------------------------------------------------------------ */

	public static function items() {
		$users = get_users( [
			'number'     => 300,
			'orderby'    => 'registered',
			'order'      => 'DESC',
			'meta_key'   => self::META_FLAG, // phpcs:ignore WordPress.DB.SlowDBQuery
			'meta_value' => 1,               // phpcs:ignore WordPress.DB.SlowDBQuery
		] );

		$items = [];
		foreach ( $users as $user ) {
			self::maybe_expire( $user->ID );

			$status  = self::status( $user->ID );
			$history = array_values( array_filter( (array) get_user_meta( $user->ID, self::META_HISTORY, true ), 'is_array' ) );
			$last    = $history ? end( $history ) : null;
			$creator = get_userdata( (int) get_user_meta( $user->ID, self::META_CREATED_BY, true ) );
			$role    = $user->roles ? reset( $user->roles ) : '';

			$items[] = [
				'id'           => $user->ID,
				'email'        => $user->user_email,
				'login'        => $user->user_login,
				'role'         => $role,
				'role_name'    => $role && isset( wp_roles()->role_names[ $role ] ) ? translate_user_role( wp_roles()->role_names[ $role ] ) : $role,
				'elevated'     => $role ? self::role_is_elevated( $role ) : false,
				'status'       => $status,
				'created'      => (int) get_user_meta( $user->ID, self::META_CREATED, true ),
				'created_by'   => $creator ? $creator->display_name : '',
				'expires'      => (int) get_user_meta( $user->ID, self::META_EXPIRES, true ),
				'revoked'      => (int) get_user_meta( $user->ID, self::META_REVOKED, true ),
				'last_login'   => (int) get_user_meta( $user->ID, self::META_LAST_LOGIN, true ),
				'logins'       => (int) get_user_meta( $user->ID, self::META_LOGINS, true ),
				'link_pending' => 'active' === $status
					&& '' !== (string) get_user_meta( $user->ID, self::META_HASH, true )
					&& (int) get_user_meta( $user->ID, self::META_LINK_EXPIRES, true ) > time(),
				'last_event'   => $last ? [ 'time' => (int) $last[0], 'event' => $last[1], 'message' => $last[2] ] : null,
				'history'      => array_map(
					static function ( $h ) {
						return [ 'time' => (int) $h[0], 'event' => $h[1], 'message' => $h[2], 'ip' => isset( $h[3] ) ? $h[3] : '' ];
					},
					array_reverse( array_slice( $history, -10 ) )
				),
			];
		}

		return $items;
	}

	/* ------------------------------------------------------------------ */
	/* Sign-in link (wp-login.php?action=gemsec_temp)                      */
	/* ------------------------------------------------------------------ */

	public function handle() {
		nocache_headers();
		// Keep the token out of referrers, caches and search indexes.
		header( 'Referrer-Policy: no-referrer' );
		header( 'X-Robots-Tag: noindex, nofollow' );
		add_action( 'login_head', [ $this, 'head_meta' ] );

		// The link's own token authorises this request in place of a nonce.
		// phpcs:disable WordPress.Security.NonceVerification
		$key  = isset( $_REQUEST['gemsec_temp_key'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['gemsec_temp_key'] ) ) : '';
		$uid  = isset( $_REQUEST['gemsec_temp_uid'] ) ? absint( $_REQUEST['gemsec_temp_uid'] ) : 0;
		$post = isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'];
		// phpcs:enable

		if ( ! $this->take_ip_slot() ) {
			$this->render_error( __( 'Too many attempts. Please wait a few minutes and try again.', 'gemsecurity' ) );
			exit;
		}

		if ( '' === $key || ! $uid || ! self::is_temp( $uid ) || ! self::token_valid( $uid, $key ) ) {
			$this->fail( $uid );
			$this->render_error( __( 'This access link is invalid, has expired, or was already used. Ask the site owner for a new one.', 'gemsecurity' ) );
			exit;
		}

		if ( ! $post ) {
			$this->render_confirm( $uid, $key );
			exit;
		}

		if ( ! self::consume_token( $uid, $key ) ) {
			$this->fail( $uid );
			$this->render_error( __( 'This access link is invalid, has expired, or was already used. Ask the site owner for a new one.', 'gemsecurity' ) );
			exit;
		}

		$user = get_userdata( $uid );
		if ( ! $user || ! self::is_live( $uid ) ) {
			$this->render_error( __( 'This account cannot sign in right now.', 'gemsecurity' ) );
			exit;
		}

		$first = ! (int) get_user_meta( $uid, self::META_LAST_LOGIN, true );
		update_user_meta( $uid, self::META_LAST_LOGIN, time() );
		update_user_meta( $uid, self::META_LOGINS, 1 + (int) get_user_meta( $uid, self::META_LOGINS, true ) );
		self::record( $uid, 'login', __( 'Signed in with the access link.', 'gemsecurity' ), Logger::SEVERITY_NOTICE );

		if ( $first && Helper::get_setting( 'temp_access_notify_used', true ) ) {
			self::notify_admin(
				__( 'Temporary access used', 'gemsecurity' ),
				sprintf(
					/* translators: 1: email, 2: IP address. */
					__( '%1$s used their temporary access link for the first time, from %2$s.', 'gemsecurity' ),
					$user->user_email,
					Helper::get_ip_address()
				)
			);
		}

		wp_set_current_user( $uid );
		wp_set_auth_cookie( $uid, false );
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound

		/**
		 * Where a temporary user lands after signing in.
		 *
		 * @param string   $url
		 * @param \WP_User $user
		 */
		wp_safe_redirect( apply_filters( 'gemsecurity/temp_access/redirect', admin_url(), $user ) );
		exit;
	}

	private function fail( $uid ) {
		$message = __( 'An access link was refused: invalid, expired or already used.', 'gemsecurity' );
		if ( $uid && self::is_temp( $uid ) ) {
			self::record( $uid, 'link_failed', $message, Logger::SEVERITY_WARNING );
		} else {
			Logger::log( 'temp_access_link_failed', $message, Logger::SEVERITY_WARNING, [ 'user_id' => 0 ] );
		}
		$key   = 'gemsec_ta_bad_' . md5( Helper::get_ip_address() );
		$count = (int) get_transient( $key );
		set_transient( $key, $count + 1, self::LIMIT_WINDOW );
	}

	/** True while the caller is still under the bad-link limit. */
	private function take_ip_slot() {
		return (int) get_transient( 'gemsec_ta_bad_' . md5( Helper::get_ip_address() ) ) < self::MAX_BAD_LINKS_PER_IP;
	}

	public function head_meta() {
		echo '<meta name="referrer" content="no-referrer" />' . "\n";
	}

	private function render_error( $message ) {
		login_header( __( 'Temporary access', 'gemsecurity' ), '', new \WP_Error( 'gemsec_temp', $message ) );
		echo '<p id="backtoblog"><a href="' . esc_url( home_url( '/' ) ) . '">' . esc_html__( '← Back to site', 'gemsecurity' ) . '</a></p>';
		login_footer();
	}

	/** The page a link opens on. Signing in needs this POST, not the GET itself. */
	private function render_confirm( $uid, $key ) {
		$user = get_userdata( $uid );
		$role = $user && $user->roles ? reset( $user->roles ) : '';
		$name = $role && isset( wp_roles()->role_names[ $role ] ) ? translate_user_role( wp_roles()->role_names[ $role ] ) : '';
		login_header( __( 'Temporary access', 'gemsecurity' ) );
		?>
		<form name="gemsec_temp_confirm" id="loginform" action="<?php echo esc_url( add_query_arg( 'action', self::ACTION, wp_login_url() ) ); ?>" method="post">
			<p style="margin-bottom:14px;">
				<?php
				echo esc_html(
					sprintf(
						/* translators: 1: role name, 2: date and time. */
						__( 'You have been given temporary %1$s access until %2$s.', 'gemsecurity' ),
						$name ? $name : __( 'dashboard', 'gemsecurity' ),
						wp_date( 'Y-m-d H:i T', (int) get_user_meta( $uid, self::META_EXPIRES, true ) )
					)
				);
				?>
			</p>
			<input type="hidden" name="gemsec_temp_uid" value="<?php echo esc_attr( $uid ); ?>" />
			<input type="hidden" name="gemsec_temp_key" value="<?php echo esc_attr( $key ); ?>" />
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Continue to the dashboard', 'gemsecurity' ); ?>" />
			</p>
		</form>
		<?php
		login_footer();
	}
}
