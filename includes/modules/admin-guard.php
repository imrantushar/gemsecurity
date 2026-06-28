<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Administrator Whitelist Guard.
 *
 * Enforces an allow-list of administrator email addresses. When the guard is
 * enabled:
 *
 *  - A brand-new user that registers / is created with the administrator role
 *    and is NOT on the whitelist is deleted automatically (kills back-door
 *    admin accounts created by a compromised site).
 *  - An existing user that is promoted to administrator while not whitelisted
 *    is reverted to their previous role (or deleted, per the configured
 *    `rogue_admin_action`).
 *
 * Hard safety guards — these accounts are NEVER auto-removed regardless of the
 * whitelist: the user performing the request, user ID 1, the site owner
 * (`admin_email`), multisite super admins, and any whitelisted address.
 */
class AdminGuard {

	/**
	 * IDs of users currently being created (not updated). While creation is in
	 * progress the role-change hooks fire in an undefined order, so we suppress
	 * them and let on_user_register make the single authoritative decision.
	 *
	 * @var array<int,bool>
	 */
	private static $creating = [];

	public static function init() {
		$self = new self();
		add_filter( 'insert_user_meta', [ $self, 'mark_creating' ], 10, 3 );
		// New accounts are caught at registration; role changes on existing
		// accounts are caught at set_user_role. In modern WordPress set_role()
		// internally fires add_user_role/remove_user_role *before* set_user_role,
		// so hooking those would double-process and corrupt the role — we don't.
		add_action( 'user_register', [ $self, 'on_user_register' ], 99, 1 );
		add_action( 'set_user_role', [ $self, 'on_set_user_role' ], 99, 3 );
	}

	/**
	 * Flag brand-new users so the role hooks skip them during creation.
	 *
	 * @param array    $meta
	 * @param \WP_User $user
	 * @param bool     $update
	 * @return array
	 */
	public function mark_creating( $meta, $user, $update ) {
		if ( ! $update && isset( $user->ID ) ) {
			self::$creating[ (int) $user->ID ] = true;
		}
		return $meta;
	}

	/* --------------------------------------------------------------------- */
	/* Hook handlers                                                          */
	/* --------------------------------------------------------------------- */

	/**
	 * Brand-new account created with administrator privileges → delete.
	 *
	 * @param int $user_id
	 */
	public function on_user_register( $user_id ) {
		$user_id = (int) $user_id;
		// Creation is complete — clear the in-progress flag for this user.
		unset( self::$creating[ $user_id ] );

		if ( ! $this->guard_enabled() ) {
			return;
		}

		$user = get_user_by( 'id', $user_id );
		if ( ! $this->is_unapproved_admin( $user ) ) {
			return;
		}

		$this->remove_rogue_admin( $user, 'delete', 'registration' );
	}

	/**
	 * Role replaced via set_role(). If the user becomes an unapproved admin,
	 * revert (or delete) per the configured action.
	 *
	 * @param int      $user_id
	 * @param string   $role
	 * @param string[] $old_roles
	 */
	public function on_set_user_role( $user_id, $role, $old_roles ) {
		if ( ! $this->guard_enabled() || 'administrator' !== $role ) {
			return;
		}

		// Skip while the account is being created — on_user_register handles it.
		if ( isset( self::$creating[ (int) $user_id ] ) ) {
			return;
		}

		$user = get_user_by( 'id', $user_id );
		if ( ! $this->is_unapproved_admin( $user ) ) {
			return;
		}

		$action  = Helper::get_setting( 'rogue_admin_action', 'demote' );
		$fallback = $this->pick_fallback_role( $old_roles );
		$this->remove_rogue_admin( $user, $action, 'promotion', $fallback );
	}

	/* --------------------------------------------------------------------- */
	/* Core logic                                                             */
	/* --------------------------------------------------------------------- */

	/**
	 * @param \WP_User|false $user
	 * @return bool True when the user is an administrator that is not approved.
	 */
	private function is_unapproved_admin( $user ) {
		if ( ! $user instanceof \WP_User ) {
			return false;
		}
		if ( ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return false;
		}
		if ( $this->is_protected( $user ) ) {
			return false;
		}
		return ! $this->is_whitelisted( $user );
	}

	/**
	 * Accounts that must never be auto-removed.
	 *
	 * @param \WP_User $user
	 * @return bool
	 */
	private function is_protected( $user ) {
		// The user performing the current request.
		if ( get_current_user_id() && (int) $user->ID === get_current_user_id() ) {
			return true;
		}
		// Founding user.
		if ( 1 === (int) $user->ID ) {
			return true;
		}
		// Site owner address.
		if ( strtolower( trim( $user->user_email ) ) === strtolower( trim( (string) get_option( 'admin_email' ) ) ) ) {
			return true;
		}
		// Multisite super admins.
		if ( is_multisite() && is_super_admin( $user->ID ) ) {
			return true;
		}
		return false;
	}

	/**
	 * @param \WP_User $user
	 * @return bool
	 */
	private function is_whitelisted( $user ) {
		$email = strtolower( trim( $user->user_email ) );
		return in_array( $email, $this->whitelist(), true );
	}

	/**
	 * Normalised list of whitelisted admin emails.
	 *
	 * @return string[]
	 */
	private function whitelist() {
		$list = (array) Helper::get_setting( 'admin_whitelist', [] );
		return array_values( array_filter( array_map( static function ( $e ) {
			return strtolower( trim( (string) $e ) );
		}, $list ) ) );
	}

	/**
	 * @param string[] $old_roles
	 * @return string
	 */
	private function pick_fallback_role( $old_roles ) {
		$old_roles = array_values( array_filter( (array) $old_roles, static function ( $r ) {
			return 'administrator' !== $r;
		} ) );
		return ! empty( $old_roles ) ? $old_roles[0] : 'subscriber';
	}

	/**
	 * Remove an unapproved administrator.
	 *
	 * @param \WP_User $user
	 * @param string   $action   'delete' or 'demote'.
	 * @param string   $origin   How the account became an admin.
	 * @param string   $fallback Role to assign when demoting.
	 */
	private function remove_rogue_admin( $user, $action, $origin, $fallback = 'subscriber' ) {
		if ( 'delete' === $action ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
			$email = $user->user_email;
			$login = $user->user_login;
			$id    = $user->ID;

			if ( is_multisite() ) {
				require_once ABSPATH . 'wp-admin/includes/ms.php';
				wpmu_delete_user( $id );
			} else {
				// Reassign any content to the site owner to avoid data loss.
				$owner = get_user_by( 'email', get_option( 'admin_email' ) );
				wp_delete_user( $id, $owner ? $owner->ID : null );
			}

			$this->log_removal( 'rogue_admin_deleted', $login, $email, $id, 'delete', $origin );
			$this->maybe_notify( $login, $email, 'delete', $origin );
			return;
		}

		// Demote.
		$user->set_role( $fallback );
		$this->after_removal( $user, 'demote', $origin );
	}

	/**
	 * @param \WP_User $user
	 * @param string   $action
	 * @param string   $origin
	 */
	private function after_removal( $user, $action, $origin ) {
		$this->log_removal( 'rogue_admin_demoted', $user->user_login, $user->user_email, $user->ID, $action, $origin );
		$this->maybe_notify( $user->user_login, $user->user_email, $action, $origin );
	}

	private function log_removal( $event, $login, $email, $id, $action, $origin ) {
		Logger::log(
			$event,
			sprintf(
				'Unapproved administrator "%s" (%s) was %s. Origin: %s.',
				$login,
				$email,
				'delete' === $action ? 'deleted' : 'demoted',
				$origin
			),
			Logger::SEVERITY_CRITICAL,
			[ 'context' => [ 'target_user_id' => $id, 'target_email' => $email, 'action' => $action, 'origin' => $origin ] ]
		);
	}

	/**
	 * Email the site owner when a rogue admin is neutralised.
	 */
	private function maybe_notify( $login, $email, $action, $origin ) {
		if ( ! Helper::get_setting( 'notify_on_rogue_admin', true ) ) {
			return;
		}

		$to   = get_option( 'admin_email' );
		$site = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
		$verb = 'delete' === $action ? __( 'deleted', 'gemsecurity' ) : __( 'demoted', 'gemsecurity' );

		$subject = sprintf( __( '[%s] Unapproved administrator blocked', 'gemsecurity' ), $site );
		$body = implode( "\n", [
			sprintf( __( 'GemSecurity %s an unapproved administrator account on %s.', 'gemsecurity' ), $verb, $site ),
			'',
			sprintf( __( 'Username: %s', 'gemsecurity' ), $login ),
			sprintf( __( 'Email:    %s', 'gemsecurity' ), $email ),
			sprintf( __( 'Trigger:  %s', 'gemsecurity' ), $origin ),
			sprintf( __( 'IP:       %s', 'gemsecurity' ), Helper::get_ip_address() ),
			'',
			__( 'If this administrator was legitimate, add their email to the GemSecurity admin whitelist and recreate the account.', 'gemsecurity' ),
		] );

		wp_mail( $to, $subject, $body );
	}

	/* --------------------------------------------------------------------- */
	/* Public helpers                                                         */
	/* --------------------------------------------------------------------- */

	private function guard_enabled() {
		// Never run during the initial WordPress install.
		if ( defined( 'WP_INSTALLING' ) && WP_INSTALLING ) {
			return false;
		}
		return (bool) Helper::get_setting( 'admin_whitelist_enabled', false );
	}

	/**
	 * Current administrator emails — used to seed the whitelist on enable.
	 *
	 * @return string[]
	 */
	public static function current_admin_emails() {
		$admins = get_users( [ 'role' => 'administrator', 'fields' => [ 'user_email' ] ] );
		return array_values( array_unique( array_filter( array_map( static function ( $u ) {
			return strtolower( trim( $u->user_email ) );
		}, $admins ) ) ) );
	}
}
