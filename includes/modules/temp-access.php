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
 * Temporary access — give an existing user a role for a limited time, then
 * return them to the role they had.
 *
 * Nothing here creates an account or signs anyone in. The person receiving
 * access already has a WordPress user (added through Users → Add New, so
 * WordPress's own password, e-mail and login protections apply) and signs in
 * the normal way. An administrator picks that user, a role and a duration;
 * the user's previous roles are stored and put back when the time is up.
 *
 * Expiry is enforced on every request ({@see enforce()}), not only by cron.
 * Ending a grant restores the previous roles, destroys the user's sessions and
 * removes application passwords created during the grant.
 * {@see enforce()} is booted whether or not the module is switched on, so
 * turning the module off cannot extend anyone's access.
 *
 * User meta:
 *   _gemsec_ta            1 on every user that has (or had) a grant
 *   _gemsec_ta_role       role granted
 *   _gemsec_ta_prev_roles roles the user had before the grant
 *   _gemsec_ta_expires    unix time access ends
 *   _gemsec_ta_revoked    unix time access was revoked (absent otherwise)
 *   _gemsec_ta_ended      unix time the grant was torn down
 *   _gemsec_ta_created    unix time, _gemsec_ta_created_by granter's user id
 *   _gemsec_ta_history    capped list of [ time, event, detail, ip ]
 */
class TempAccess {

	const CRON = 'gemsecurity_temp_access_sweep';

	const META_FLAG       = '_gemsec_ta';
	const META_ROLE       = '_gemsec_ta_role';
	const META_PREV_ROLES = '_gemsec_ta_prev_roles';
	const META_EXPIRES    = '_gemsec_ta_expires';
	const META_REVOKED    = '_gemsec_ta_revoked';
	const META_ENDED      = '_gemsec_ta_ended';
	const META_CREATED    = '_gemsec_ta_created';
	const META_CREATED_BY = '_gemsec_ta_created_by';
	const META_HISTORY    = '_gemsec_ta_history';

	/** Grants an administrator may make per hour. */
	const MAX_GRANTS_PER_HOUR = 10;

	const HISTORY_LIMIT = 30;

	/** Longest access window that can be granted. */
	const MAX_SECONDS = 90 * DAY_IN_SECONDS;

	/** Shortest window. */
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

	/** Module boot: the sweep schedule. */
	public static function init() {
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
		// Nothing a user does while granted may outlive the grant.
		add_filter( 'map_meta_cap', [ __CLASS__, 'restrict_caps' ], 99, 4 );
		// Core gates deletion only on the plain delete_plugins capability, never
		// the per-plugin one, so deleting GemSecurity is stopped as it happens.
		add_action( 'delete_plugin', [ __CLASS__, 'refuse_delete' ] );
		add_filter( 'plugin_action_links', [ __CLASS__, 'hide_delete_link' ], 99, 2 );
		add_action( self::CRON, [ __CLASS__, 'sweep' ] );
	}

	/* ------------------------------------------------------------------ */
	/* State                                                               */
	/* ------------------------------------------------------------------ */

	/** Whether this user has (or had) a grant. */
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

	/** Whether this user holds a grant that is still live. */
	public static function is_live( $user_id ) {
		return self::is_temp( $user_id ) && 'active' === self::status( $user_id );
	}

	/**
	 * Tear down a grant that has ended: put the previous roles back, end the
	 * sessions and remove application passwords created during the grant. Runs
	 * once per ending (guarded by META_ENDED), whoever notices first — a request,
	 * the sweep, or revoke().
	 *
	 * @return bool True when this call did the teardown.
	 */
	private static function close_out( $user_id ) {
		if ( (int) get_user_meta( $user_id, self::META_ENDED, true ) > 0 ) {
			return false;
		}
		update_user_meta( $user_id, self::META_ENDED, time() );

		$user = get_userdata( $user_id );
		if ( $user ) {
			$granted = (string) get_user_meta( $user_id, self::META_ROLE, true );
			$prev    = array_values( array_filter( (array) get_user_meta( $user_id, self::META_PREV_ROLES, true ), 'is_string' ) );
			// Only undo our own change: if the administrator has since set a
			// different role by hand, that decision stands.
			if ( $granted && array_values( $user->roles ) === [ $granted ] ) {
				foreach ( $user->roles as $role ) {
					$user->remove_role( $role );
				}
				foreach ( $prev as $role ) {
					if ( get_role( $role ) ) {
						$user->add_role( $role );
					}
				}
			}
		}

		\WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		if ( class_exists( '\WP_Application_Passwords' ) ) {
			$since = (int) get_user_meta( $user_id, self::META_CREATED, true );
			foreach ( \WP_Application_Passwords::get_user_application_passwords( $user_id ) as $item ) {
				if ( isset( $item['created'], $item['uuid'] ) && (int) $item['created'] >= $since ) {
					\WP_Application_Passwords::delete_application_password( $user_id, $item['uuid'] );
				}
			}
		}
		return true;
	}

	/** Notice an expired grant: close it out and record that it expired. */
	private static function maybe_expire( $user_id ) {
		if ( 'expired' !== self::status( $user_id ) ) {
			return;
		}
		if ( self::close_out( $user_id ) ) {
			self::record( $user_id, 'expired', __( 'Access expired; the previous role was restored.', 'gemsecurity' ), Logger::SEVERITY_INFO );
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

	/**
	 * End every live grant: roles go back, sessions end. Run when GemSecurity is
	 * deactivated, since nothing enforces expiry after that.
	 *
	 * @return int Grants closed.
	 */
	public static function disable_all() {
		$ids = get_users( [
			'fields'     => 'ID',
			'number'     => -1,
			'blog_id'    => 0,
			'meta_key'   => self::META_FLAG, // phpcs:ignore WordPress.DB.SlowDBQuery
			'meta_value' => 1,               // phpcs:ignore WordPress.DB.SlowDBQuery
		] );
		$closed = 0;
		foreach ( $ids as $id ) {
			$id = (int) $id;
			if ( 'revoked' !== self::status( $id ) && ! (int) get_user_meta( $id, self::META_ENDED, true ) ) {
				update_user_meta( $id, self::META_REVOKED, time() );
				self::close_out( $id );
				++$closed;
			}
		}
		return $closed;
	}

	/* ------------------------------------------------------------------ */
	/* Enforcement filters                                                 */
	/* ------------------------------------------------------------------ */

	/** An ended grant is closed out the moment its user makes a request. */
	public static function filter_current_user( $user_id ) {
		if ( $user_id && self::is_temp( $user_id ) ) {
			self::maybe_expire( (int) $user_id );
		}
		return $user_id;
	}

	/** User-management capabilities a granted user never gets, whatever the role. */
	const DENIED_CAPS = [
		'create_users', 'add_users', 'promote_users', 'promote_user', 'delete_users', 'delete_user',
		'remove_users', 'remove_user', 'manage_network_users',
	];

	/**
	 * Stop a user holding a grant from making that access permanent: they may not
	 * create or promote users, edit anyone but themselves, or switch GemSecurity
	 * off (which would lift every limit in this class).
	 *
	 * @param string[] $caps
	 * @param string   $cap
	 * @param int      $user_id
	 * @param array    $args
	 * @return string[]
	 */
	public static function restrict_caps( $caps, $cap, $user_id, $args ) {
		if ( ! $user_id || ! self::is_live( $user_id ) ) {
			return $caps;
		}
		if ( in_array( $cap, self::DENIED_CAPS, true ) ) {
			return [ 'do_not_allow' ];
		}
		if ( 'edit_user' === $cap && ( empty( $args[0] ) || (int) $args[0] !== (int) $user_id ) ) {
			return [ 'do_not_allow' ];
		}
		if ( in_array( $cap, [ 'deactivate_plugin', 'delete_plugin' ], true ) && ! empty( $args[0] )
			&& preg_match( '#^gemsecurity(-pro)?/#', (string) $args[0] ) ) {
			return [ 'do_not_allow' ];
		}
		return $caps;
	}

	/** @param string $file Plugin basename about to be deleted. */
	public static function refuse_delete( $file ) {
		if ( self::is_live( get_current_user_id() ) && preg_match( '#^gemsecurity(-pro)?/#', (string) $file ) ) {
			wp_die( esc_html__( 'A user with temporary access cannot delete GemSecurity.', 'gemsecurity' ), '', [ 'response' => 403 ] );
		}
	}

	/**
	 * @param array  $links
	 * @param string $file
	 * @return array
	 */
	public static function hide_delete_link( $links, $file ) {
		if ( self::is_live( get_current_user_id() ) && preg_match( '#^gemsecurity(-pro)?/#', (string) $file ) ) {
			unset( $links['delete'] );
		}
		return $links;
	}

	/* ------------------------------------------------------------------ */
	/* Permissions                                                         */
	/* ------------------------------------------------------------------ */

	/**
	 * Who may manage temporary access. A user holding a grant never can, so
	 * short-lived access cannot mint itself more time or hand it to others.
	 */
	public static function can_manage() {
		$user = wp_get_current_user();
		return $user->exists()
			&& current_user_can( 'manage_options' )
			&& current_user_can( 'promote_users' )
			&& ! self::is_live( $user->ID );
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

	/**
	 * Check a role may be granted and that an elevated one was confirmed.
	 *
	 * @return string|\WP_Error The role slug.
	 */
	private static function check_role( array $args ) {
		$slug  = isset( $args['role'] ) ? sanitize_key( $args['role'] ) : '';
		$roles = wp_list_pluck( self::assignable_roles(), 'elevated', 'slug' );
		if ( ! isset( $roles[ $slug ] ) ) {
			return new \WP_Error( 'bad_role', __( 'Choose a role to grant.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		if ( $roles[ $slug ] && empty( $args['confirm_elevated'] ) ) {
			return new \WP_Error( 'confirm_elevated', __( 'This role can change the site. A user with temporary access cannot create users or switch GemSecurity off, but installing or editing plugins and themes runs code that can outlive the access. Confirm that you want to grant it.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		return $slug;
	}

	/**
	 * Why a user cannot be given a grant, or null when they can.
	 *
	 * @return \WP_Error|null
	 */
	private static function check_target( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return new \WP_Error( 'bad_user', __( 'That user does not exist.', 'gemsecurity' ), [ 'status' => 404 ] );
		}
		if ( (int) $user_id === get_current_user_id() ) {
			return new \WP_Error( 'self_grant', __( 'You cannot change your own access.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		if ( is_multisite() && is_super_admin( $user_id ) ) {
			return new \WP_Error( 'super_admin', __( 'Network administrators cannot be given temporary access.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		if ( $user->has_cap( 'manage_options' ) ) {
			return new \WP_Error( 'target_admin', __( 'This user already has full access. Temporary access is for users who do not.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		if ( ! current_user_can( 'promote_user', $user_id ) ) {
			return new \WP_Error( 'forbidden', __( 'You are not allowed to change this user’s role.', 'gemsecurity' ), [ 'status' => 403 ] );
		}
		return null;
	}

	/* ------------------------------------------------------------------ */
	/* Management actions (called by the REST controller)                  */
	/* ------------------------------------------------------------------ */

	/**
	 * Grant an existing user a role until a set time.
	 *
	 * @param array $args user_id, role, duration, expires_at, confirm_elevated.
	 * @return array|\WP_Error { id }
	 */
	public static function grant( array $args ) {
		$user_id = isset( $args['user_id'] ) ? absint( $args['user_id'] ) : 0;
		$err     = self::check_target( $user_id );
		if ( $err ) {
			return $err;
		}
		if ( self::is_live( $user_id ) ) {
			return new \WP_Error( 'already_granted', __( 'This user already has temporary access. Extend or revoke it instead.', 'gemsecurity' ), [ 'status' => 409 ] );
		}

		$slug = self::check_role( $args );
		if ( is_wp_error( $slug ) ) {
			return $slug;
		}

		$expires = self::resolve_expiry(
			isset( $args['duration'] ) ? sanitize_key( $args['duration'] ) : '',
			isset( $args['expires_at'] ) ? (int) $args['expires_at'] : 0,
			time()
		);
		if ( is_wp_error( $expires ) ) {
			return $expires;
		}

		$limit_key = 'ta_grant_' . get_current_user_id();
		$made      = (int) Store::get( $limit_key );
		if ( $made >= self::MAX_GRANTS_PER_HOUR ) {
			return new \WP_Error( 'rate_limited', __( 'Too many grants were made in the last hour. Try again later.', 'gemsecurity' ), [ 'status' => 429 ] );
		}
		Store::set( $limit_key, $made + 1, HOUR_IN_SECONDS );

		$user = get_userdata( $user_id );
		$now  = time();
		update_user_meta( $user_id, self::META_PREV_ROLES, array_values( $user->roles ) );
		update_user_meta( $user_id, self::META_ROLE, $slug );
		update_user_meta( $user_id, self::META_EXPIRES, $expires );
		update_user_meta( $user_id, self::META_CREATED, $now );
		update_user_meta( $user_id, self::META_CREATED_BY, get_current_user_id() );
		delete_user_meta( $user_id, self::META_REVOKED );
		delete_user_meta( $user_id, self::META_ENDED );
		update_user_meta( $user_id, self::META_FLAG, 1 );
		$user->set_role( $slug );

		$elevated = self::role_is_elevated( $slug );
		self::record(
			$user_id,
			'created',
			sprintf(
				/* translators: 1: email, 2: role, 3: expiry date. */
				__( 'Temporary access granted to %1$s with role "%2$s", ending %3$s.', 'gemsecurity' ),
				$user->user_email,
				$slug,
				wp_date( 'Y-m-d H:i', $expires )
			),
			$elevated ? Logger::SEVERITY_WARNING : Logger::SEVERITY_NOTICE
		);

		if ( Helper::get_setting( 'temp_access_notify_created', true ) ) {
			self::notify_admin(
				__( 'Temporary access granted', 'gemsecurity' ),
				sprintf(
					/* translators: 1: email, 2: role, 3: expiry date. */
					__( '%1$s was given temporary access with the "%2$s" role until %3$s.', 'gemsecurity' ),
					$user->user_email,
					$slug,
					wp_date( 'Y-m-d H:i', $expires )
				)
			);
		}

		return [ 'id' => $user_id ];
	}

	/**
	 * Extend or reopen access. Active grants grow from their current expiry;
	 * expired ones are granted again from now. Revoked grants stay revoked.
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
			return new \WP_Error( 'revoked', __( 'Revoked access cannot be extended. Grant it again instead.', 'gemsecurity' ), [ 'status' => 409 ] );
		}

		$current = (int) get_user_meta( $user_id, self::META_EXPIRES, true );
		$base    = 'active' === $status ? $current : time();
		$expires = self::resolve_expiry( sanitize_key( $duration ), $custom, $base );
		if ( is_wp_error( $expires ) ) {
			return $expires;
		}

		if ( 'expired' === $status ) {
			// The role was already taken back, so grant it again.
			$err = self::check_target( $user_id );
			if ( $err ) {
				return $err;
			}
			$user = get_userdata( $user_id );
			$role = (string) get_user_meta( $user_id, self::META_ROLE, true );
			if ( ! get_role( $role ) ) {
				return new \WP_Error( 'bad_role', __( 'The role for this grant no longer exists.', 'gemsecurity' ), [ 'status' => 409 ] );
			}
			update_user_meta( $user_id, self::META_PREV_ROLES, array_values( $user->roles ) );
			update_user_meta( $user_id, self::META_CREATED, time() );
			$user->set_role( $role );
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
		self::record( $user_id, 'revoked', __( 'Access revoked; the previous role was restored and sessions ended.', 'gemsecurity' ), Logger::SEVERITY_NOTICE );

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
			return new \WP_Error( 'not_temp', __( 'That user has no temporary access.', 'gemsecurity' ), [ 'status' => 404 ] );
		}
		return null;
	}

	private static function notify_admin( $title, $text ) {
		Mailer::send( Mailer::recipient(), '🔑', $title, [ [ 'type' => 'paragraph', 'text' => $text ] ] );
	}

	/* ------------------------------------------------------------------ */
	/* History                                                             */
	/* ------------------------------------------------------------------ */

	/** Write to the user's own history and to the site-wide audit log. */
	private static function record( $user_id, $event, $message, $severity ) {
		$history   = (array) get_user_meta( $user_id, self::META_HISTORY, true );
		$history[] = [ time(), $event, $message, Helper::get_ip_address() ];
		update_user_meta( $user_id, self::META_HISTORY, array_slice( array_values( array_filter( $history ) ), -self::HISTORY_LIMIT ) );

		Logger::log( 'temp_access_' . $event, $message, $severity, [ 'context' => [ 'target_user_id' => (int) $user_id ] ] );
	}

	/* ------------------------------------------------------------------ */
	/* Listing                                                             */
	/* ------------------------------------------------------------------ */

	/** Users that could be given access, matched by name, login or email. */
	public static function search_users( $term ) {
		$term = trim( (string) $term );
		if ( strlen( $term ) < 2 ) {
			return [];
		}
		$out = [];
		foreach ( get_users( [
			'search'         => '*' . $term . '*',
			'search_columns' => [ 'user_login', 'user_email', 'display_name' ],
			'number'         => 20,
			'exclude'        => [ get_current_user_id() ],
		] ) as $user ) {
			if ( $user->has_cap( 'manage_options' ) || self::is_live( $user->ID ) ) {
				continue;
			}
			$out[] = [
				'id'    => $user->ID,
				'name'  => $user->display_name,
				'email' => $user->user_email,
				'roles' => array_map(
					static function ( $r ) {
						return isset( wp_roles()->role_names[ $r ] ) ? translate_user_role( wp_roles()->role_names[ $r ] ) : $r;
					},
					$user->roles
				),
			];
		}
		return $out;
	}

	public static function items() {
		$users = get_users( [
			'number'     => 300,
			'orderby'    => 'registered',
			'order'      => 'DESC',
			'meta_key'   => self::META_FLAG, // phpcs:ignore WordPress.DB.SlowDBQuery
			'meta_value' => 1,               // phpcs:ignore WordPress.DB.SlowDBQuery
		] );

		$names = wp_roles()->role_names;
		$items = [];
		foreach ( $users as $user ) {
			self::maybe_expire( $user->ID );

			$status  = self::status( $user->ID );
			$history = array_values( array_filter( (array) get_user_meta( $user->ID, self::META_HISTORY, true ), 'is_array' ) );
			$last    = $history ? end( $history ) : null;
			$creator = get_userdata( (int) get_user_meta( $user->ID, self::META_CREATED_BY, true ) );
			$role    = (string) get_user_meta( $user->ID, self::META_ROLE, true );
			$prev    = array_map(
				static function ( $r ) use ( $names ) {
					return isset( $names[ $r ] ) ? translate_user_role( $names[ $r ] ) : $r;
				},
				array_filter( (array) get_user_meta( $user->ID, self::META_PREV_ROLES, true ), 'is_string' )
			);

			$items[] = [
				'id'         => $user->ID,
				'email'      => $user->user_email,
				'login'      => $user->user_login,
				'name'       => $user->display_name,
				'role'       => $role,
				'role_name'  => $role && isset( $names[ $role ] ) ? translate_user_role( $names[ $role ] ) : $role,
				'prev_roles' => array_values( $prev ),
				'elevated'   => $role ? self::role_is_elevated( $role ) : false,
				'status'     => $status,
				'created'    => (int) get_user_meta( $user->ID, self::META_CREATED, true ),
				'created_by' => $creator ? $creator->display_name : '',
				'expires'    => (int) get_user_meta( $user->ID, self::META_EXPIRES, true ),
				'revoked'    => (int) get_user_meta( $user->ID, self::META_REVOKED, true ),
				'last_event' => $last ? [ 'time' => (int) $last[0], 'event' => $last[1], 'message' => $last[2] ] : null,
				'history'    => array_map(
					static function ( $h ) {
						return [ 'time' => (int) $h[0], 'event' => $h[1], 'message' => $h[2], 'ip' => isset( $h[3] ) ? $h[3] : '' ];
					},
					array_reverse( array_slice( $history, -10 ) )
				),
			];
		}

		return $items;
	}
}
