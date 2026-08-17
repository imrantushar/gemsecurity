<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;
use GemSecurity\Mailer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Forced password resets — on demand, and on a schedule, per role.
 *
 * After a breach the useful question is not "is this password strong" but
 * "does the attacker still hold it". Every credential they may have taken has
 * to stop working at once, and an expiry *notice* does not do that: it asks
 * politely while the old password keeps signing people in.
 *
 * So a forced reset here means three things together, which is what makes it
 * an eviction rather than a suggestion:
 *
 *   1. every session for that user is destroyed, so a stolen cookie dies too —
 *      resetting a password while sessions live leaves the intruder signed in;
 *   2. the account is flagged, and the flag is checked *after* the password is
 *      verified, so the old password stops granting access;
 *   3. the user is emailed a reset link, so the account is recoverable without
 *      an administrator having to touch it.
 *
 * Plain passwords are never generated or emailed: the user sets their own
 * through the standard WordPress reset flow.
 */
class PasswordRotation {

	/** Set when a user must choose a new password before signing in again. */
	const FORCE_META = '_gemsec_pw_force_reset';

	/** Written by PasswordPolicy when a password is set; the rotation clock. */
	const SET_META = '_gemsec_pw_set';

	const CRON_HOOK = 'gemsecurity_password_rotation';

	public static function init() {
		$self = new self();

		// After WordPress has accepted the credentials — an unauthenticated
		// prober must not be able to enumerate which accounts are flagged.
		add_filter( 'authenticate', [ $self, 'block_flagged_login' ], 95, 1 );

		// Clearing the flag is tied to the password actually changing, not to
		// visiting a page, so the only way out is a real reset.
		add_action( 'after_password_reset', [ __CLASS__, 'clear_flag_for_user' ], 10, 1 );
		add_action( 'profile_update', [ __CLASS__, 'clear_flag_on_profile_update' ], 10, 1 );

		add_action( self::CRON_HOOK, [ __CLASS__, 'run_scheduled_rotation' ] );
		add_action( 'init', [ __CLASS__, 'schedule' ] );
		add_action( 'update_option_' . GEMSECURITY_SETTINGS_NAME, [ __CLASS__, 'reschedule' ], 10, 2 );
	}

	/* ------------------------------------------------------------------ */
	/* Enforcement                                                         */
	/* ------------------------------------------------------------------ */

	/**
	 * Refuse a sign-in while the account is flagged for reset.
	 *
	 * @param \WP_User|\WP_Error|null $user
	 * @return \WP_User|\WP_Error|null
	 */
	public function block_flagged_login( $user ) {
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}
		if ( ! get_user_meta( $user->ID, self::FORCE_META, true ) ) {
			return $user;
		}

		return new \WP_Error(
			'gemsecurity_password_reset_required',
			sprintf(
				/* translators: %s: lost-password URL. */
				__( '<strong>Password reset required.</strong> Your password must be changed before you can sign in. <a href="%s">Set a new password</a> — a link was emailed to you.', 'gemsecurity' ),
				esc_url( wp_lostpassword_url() )
			)
		);
	}

	/** @param \WP_User $user */
	public static function clear_flag_for_user( $user ) {
		if ( $user instanceof \WP_User ) {
			delete_user_meta( $user->ID, self::FORCE_META );
			update_user_meta( $user->ID, self::SET_META, time() );
		}
	}

	/** @param int $user_id */
	public static function clear_flag_on_profile_update( $user_id ) {
		// Only an actual new password lifts the flag.
		if ( ! empty( $_POST['pass1'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			delete_user_meta( $user_id, self::FORCE_META );
			update_user_meta( $user_id, self::SET_META, time() );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Forcing a reset                                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * Users a reset would apply to.
	 *
	 * @param array $args roles[], older_than_days, include_user_ids[], exclude_user_ids[]
	 * @return \WP_User[]
	 */
	public static function targets( array $args = [] ) {
		$roles   = isset( $args['roles'] ) ? array_filter( (array) $args['roles'] ) : [];
		$older   = isset( $args['older_than_days'] ) ? (int) $args['older_than_days'] : 0;
		$exclude = isset( $args['exclude_user_ids'] ) ? array_map( 'intval', (array) $args['exclude_user_ids'] ) : [];

		$query = [ 'fields' => 'all', 'number' => -1 ];
		if ( $roles ) {
			$query['role__in'] = $roles;
		}

		$users = get_users( $query );
		$out   = [];

		foreach ( $users as $user ) {
			if ( in_array( (int) $user->ID, $exclude, true ) ) {
				continue;
			}
			// Already flagged — no point counting them twice.
			if ( get_user_meta( $user->ID, self::FORCE_META, true ) ) {
				continue;
			}
			if ( $older > 0 ) {
				$set = (int) get_user_meta( $user->ID, self::SET_META, true );
				if ( ! $set ) {
					// Never stamped: start the clock rather than forcing a reset
					// on a password that may have been set five minutes ago.
					update_user_meta( $user->ID, self::SET_META, time() );
					continue;
				}
				if ( ( time() - $set ) < $older * DAY_IN_SECONDS ) {
					continue;
				}
			}
			$out[] = $user;
		}

		return $out;
	}

	/**
	 * Force the reset.
	 *
	 * @param array $args roles[], older_than_days, exclude_user_ids[], notify (bool), reason (string)
	 * @return array { count, users[], notified }
	 */
	public static function force_reset( array $args = [] ) {
		$notify   = ! isset( $args['notify'] ) || $args['notify'];
		$reason   = isset( $args['reason'] ) ? (string) $args['reason'] : 'manual';
		$targets  = self::targets( $args );
		$done     = [];
		$notified = 0;

		foreach ( $targets as $user ) {
			// Kill live sessions first: a reset that leaves the intruder's
			// cookie working has evicted nobody.
			$tokens = \WP_Session_Tokens::get_instance( $user->ID );
			$tokens->destroy_all();

			update_user_meta( $user->ID, self::FORCE_META, time() );

			if ( $notify && $user->user_email && self::send_reset_link( $user, $reason ) ) {
				$notified++;
			}

			$done[] = [ 'id' => (int) $user->ID, 'login' => $user->user_login, 'email' => $user->user_email ];
		}

		if ( $done ) {
			Logger::log(
				'passwords_force_reset',
				sprintf( 'Forced a password reset for %d user(s). Trigger: %s.', count( $done ), $reason ),
				Logger::SEVERITY_CRITICAL,
				[ 'context' => [ 'count' => count( $done ), 'reason' => $reason ] ]
			);
		}

		return [ 'count' => count( $done ), 'users' => $done, 'notified' => $notified ];
	}

	/**
	 * Email a user their own reset link. WordPress's own key/flow is used, so
	 * nothing here ever knows or transmits a password.
	 *
	 * @param \WP_User $user
	 * @param string   $reason
	 * @return bool
	 */
	private static function send_reset_link( $user, $reason ) {
		$key = get_password_reset_key( $user );
		if ( is_wp_error( $key ) ) {
			return false;
		}

		$link = network_site_url(
			'wp-login.php?action=rp&key=' . rawurlencode( $key ) . '&login=' . rawurlencode( $user->user_login ),
			'login'
		);

		$why = 'schedule' === $reason
			? __( 'Your password has reached the age limit set by this site’s security policy.', 'gemsecurity' )
			: __( 'An administrator has required every affected account to choose a new password.', 'gemsecurity' );

		return Mailer::send(
			$user->user_email,
			'🔒',
			__( 'Choose a new password to continue', 'gemsecurity' ),
			[
				[ 'type' => 'paragraph', 'text' => esc_html( $why ) ],
				[
					'type' => 'paragraph',
					'text' => __( 'Your current password no longer works and any signed-in sessions have been ended. Use the button below to set a new one.', 'gemsecurity' ),
				],
				[ 'type' => 'button', 'url' => $link, 'label' => __( 'Set a new password', 'gemsecurity' ) ],
				[
					'type' => 'notice',
					'tone' => 'info',
					'text' => __( 'If the link has expired, use “Lost your password?” on the sign-in page — it works the same way.', 'gemsecurity' ),
				],
			]
		);
	}

	/* ------------------------------------------------------------------ */
	/* Schedule                                                            */
	/* ------------------------------------------------------------------ */

	/** Keep the daily rotation check scheduled while the feature is on. */
	public static function schedule() {
		$next = wp_next_scheduled( self::CRON_HOOK );

		if ( ! Helper::get_setting( 'password_rotation_enabled', false ) ) {
			if ( $next ) {
				wp_unschedule_event( $next, self::CRON_HOOK );
			}
			return;
		}
		if ( ! $next ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * @param mixed $old
	 * @param mixed $new
	 */
	public static function reschedule( $old, $new ) {
		$before = is_array( $old ) && isset( $old['password_rotation_enabled'] ) ? $old['password_rotation_enabled'] : null;
		$after  = is_array( $new ) && isset( $new['password_rotation_enabled'] ) ? $new['password_rotation_enabled'] : null;
		if ( $before !== $after ) {
			self::schedule();
		}
	}

	/**
	 * Daily: flag anyone whose password is older than the configured age.
	 *
	 * @return array
	 */
	public static function run_scheduled_rotation() {
		if ( ! Helper::get_setting( 'password_rotation_enabled', false ) ) {
			return [ 'count' => 0, 'users' => [], 'notified' => 0 ];
		}

		$days = (int) Helper::get_setting( 'password_rotation_days', 90 );
		if ( $days <= 0 ) {
			return [ 'count' => 0, 'users' => [], 'notified' => 0 ];
		}

		return self::force_reset( [
			'roles'           => (array) Helper::get_setting( 'password_rotation_roles', [] ),
			'older_than_days' => $days,
			'reason'          => 'schedule',
			'notify'          => true,
		] );
	}

	/**
	 * Lift the flag from everyone — the way back if a reset was applied too
	 * broadly and users cannot get in.
	 *
	 * @return int Users cleared.
	 */
	public static function clear_all() {
		$users   = get_users( [ 'meta_key' => self::FORCE_META, 'fields' => 'ID', 'number' => -1 ] ); // phpcs:ignore WordPress.DB.SlowDBQuery
		$cleared = 0;
		foreach ( $users as $id ) {
			delete_user_meta( (int) $id, self::FORCE_META );
			$cleared++;
		}
		if ( $cleared ) {
			Logger::log(
				'passwords_force_reset_cleared',
				sprintf( 'Cleared the forced-reset flag for %d user(s).', $cleared ),
				Logger::SEVERITY_WARNING
			);
		}
		return $cleared;
	}

	/** How many accounts are currently waiting to choose a new password. */
	public static function pending_count() {
		return count( get_users( [ 'meta_key' => self::FORCE_META, 'fields' => 'ID', 'number' => -1 ] ) ); // phpcs:ignore WordPress.DB.SlowDBQuery
	}
}
