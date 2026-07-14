<?php
namespace GemSecurity\Security;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Filter-proof administrator enumeration + reconciliation.
 *
 * The WordPress Users list table and every get_users() / WP_User_Query call run
 * through the `pre_user_query` filter. Injected malware commonly hooks that
 * filter with something like `... AND ID != 12` so a back-door administrator is
 * invisible in wp-admin — yet count_users() (a raw usermeta count) still reports
 * the true total. That "Administrator (4)" link over a 3-row list is the classic
 * fingerprint of a hidden admin, and because the row is filtered out before it
 * renders there is no Delete link to click.
 *
 * This class reads administrators straight from wp_usermeta so no request-time
 * filter can conceal a row, hydrates each account by direct ID lookup (which is
 * likewise not subject to pre_user_query), and diffs the true set against the
 * filtered view to surface exactly which accounts are being hidden.
 */
class AdminAudit {

	/**
	 * The capabilities meta key for the current site (multisite-aware).
	 *
	 * @return string
	 */
	private static function caps_meta_key() {
		global $wpdb;
		return $wpdb->get_blog_prefix() . 'capabilities';
	}

	/**
	 * Every administrator ID as recorded in wp_usermeta. Bypasses WP_User_Query
	 * and therefore any pre_user_query concealment filter — this is the trusted
	 * source of truth for "who is really an administrator".
	 *
	 * @return int[]
	 */
	public static function raw_admin_ids() {
		global $wpdb;

		$key = self::caps_meta_key();

		// Cheap LIKE to pull candidate rows, then confirm by unserialising so we
		// match count_users() semantics (administrator capability actually truthy,
		// not merely a substring inside another value).
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value LIKE %s",
				$key,
				'%' . $wpdb->esc_like( '"administrator"' ) . '%'
			)
		);

		$ids = [];
		foreach ( (array) $rows as $row ) {
			$caps = maybe_unserialize( $row->meta_value );
			if ( is_array( $caps ) && ! empty( $caps['administrator'] ) ) {
				$ids[] = (int) $row->user_id;
			}
		}

		$ids = array_values( array_unique( $ids ) );
		sort( $ids );
		return $ids;
	}

	/**
	 * Administrator IDs visible through the normal query path — i.e. what
	 * wp-admin and get_users() return, with any pre_user_query filter applied.
	 *
	 * @return int[]
	 */
	public static function visible_admin_ids() {
		$ids = get_users( [ 'role' => 'administrator', 'fields' => 'ID' ] );
		$ids = array_values( array_unique( array_map( 'intval', (array) $ids ) ) );
		sort( $ids );
		return $ids;
	}

	/**
	 * IDs present in the database but missing from the filtered view — the
	 * administrators something is actively hiding.
	 *
	 * @return int[]
	 */
	public static function hidden_admin_ids() {
		return array_values( array_diff( self::raw_admin_ids(), self::visible_admin_ids() ) );
	}

	/**
	 * Detailed administrator list built from the RAW id set, so hidden accounts
	 * are always included. Each row carries `hidden`, `suspicious`, `whitelisted`,
	 * `protected` and `is_current` flags.
	 *
	 * @param int[]|null $hidden_ids Explicit set of ids to mark as hidden. Pass
	 *                               the reconciled set from HiddenAdmin (which
	 *                               merges the authoritative wp-admin probe) so a
	 *                               concealment that only triggers inside wp-admin
	 *                               is still reflected here. When null, falls back
	 *                               to a live diff against the current context.
	 * @return array<int,array>
	 */
	public static function admins( $hidden_ids = null ) {
		$raw       = self::raw_admin_ids();
		$hidden    = null === $hidden_ids ? array_diff( $raw, self::visible_admin_ids() ) : array_map( 'intval', (array) $hidden_ids );
		$whitelist = array_map( 'strtolower', (array) Helper::get_setting( 'admin_whitelist', [] ) );
		$current   = get_current_user_id();

		$out = [];
		foreach ( $raw as $id ) {
			// Direct-by-ID load — WP_User::get_data_by() runs its own query and is
			// not subject to pre_user_query, so this hydrates hidden accounts too.
			$user = get_userdata( $id );
			if ( ! $user ) {
				continue;
			}

			$email         = strtolower( trim( $user->user_email ) );
			$is_whitelisted = in_array( $email, $whitelist, true );
			$reasons       = self::suspicion_reasons( $user, $is_whitelisted );

			$out[] = [
				'id'                => $id,
				'login'             => $user->user_login,
				'display_name'      => $user->display_name,
				'email'             => $user->user_email,
				'whitelisted'       => $is_whitelisted,
				'protected'         => self::is_protected( $user ),
				'registered'        => $user->user_registered,
				'is_current'        => $id === (int) $current,
				'hidden'            => in_array( $id, $hidden, true ),
				'suspicious'        => ! empty( $reasons ),
				'suspicious_reason' => $reasons ? implode( '; ', $reasons ) : '',
			];
		}

		usort( $out, static function ( $a, $b ) {
			return strcasecmp( $a['display_name'], $b['display_name'] );
		} );

		return $out;
	}

	/**
	 * Heuristic reasons an administrator account looks planted rather than
	 * legitimate. Deliberately conservative so real admins are not flagged:
	 * an approved (whitelisted) account is never suspicious, and the strongest
	 * signal is an e-mail on a non-routable / reserved domain — the hallmark of
	 * an account injected straight into the database (e.g. sys@localhost.local).
	 *
	 * @param \WP_User $user
	 * @param bool     $is_whitelisted
	 * @return string[] Human-readable reasons (empty when nothing stands out).
	 */
	public static function suspicion_reasons( $user, $is_whitelisted ) {
		if ( $is_whitelisted || self::is_protected( $user ) ) {
			return [];
		}

		$reasons = [];
		$email   = strtolower( trim( (string) $user->user_email ) );

		if ( self::is_non_routable_email( $email ) ) {
			$reasons[] = __( 'e-mail uses a non-routable / placeholder domain', 'gemsecurity' );
		} elseif ( '' === $email || ! is_email( $email ) ) {
			$reasons[] = __( 'administrator has no valid e-mail address', 'gemsecurity' );
		}

		return $reasons;
	}

	/**
	 * Whether an e-mail address sits on a reserved, private or placeholder
	 * domain that a real user could never receive mail at.
	 *
	 * @param string $email
	 * @return bool
	 */
	private static function is_non_routable_email( $email ) {
		$at = strrpos( $email, '@' );
		if ( false === $at ) {
			return false;
		}
		$domain = substr( $email, $at + 1 );
		if ( '' === $domain ) {
			return false;
		}

		// Reserved TLDs (RFC 2606 / 6761) plus common private suffixes.
		$reserved_tlds = [ 'local', 'localhost', 'test', 'invalid', 'example', 'internal', 'lan', 'home', 'corp', 'localdomain' ];
		$labels        = explode( '.', $domain );
		$tld           = end( $labels );

		if ( in_array( $tld, $reserved_tlds, true ) ) {
			return true;
		}

		$reserved_domains = [ 'localhost', 'example.com', 'example.org', 'example.net' ];
		return in_array( $domain, $reserved_domains, true );
	}

	/**
	 * Reconcile the three administrator tallies and return a structured verdict.
	 *
	 *  - raw_count     : administrators recorded in the database (trusted).
	 *  - visible_count : administrators the normal query path returns.
	 *  - counted       : the number behind the "Administrator (N)" wp-admin link.
	 *
	 * A mismatch (hidden accounts present, or the count exceeding the visible
	 * rows) is the signature of a concealed back-door admin.
	 *
	 * @return array
	 */
	public static function audit() {
		$all    = self::admins();
		$hidden = array_values( array_filter( $all, static function ( $a ) {
			return $a['hidden'];
		} ) );
		$suspicious = array_values( array_filter( $all, static function ( $a ) {
			return $a['suspicious'];
		} ) );

		$counts        = count_users();
		$counted       = isset( $counts['avail_roles']['administrator'] ) ? (int) $counts['avail_roles']['administrator'] : 0;
		$visible_count = count( $all ) - count( $hidden );

		return [
			'raw_count'      => count( $all ),
			'visible_count'  => $visible_count,
			'counted'        => $counted,
			'hidden'         => array_values( $hidden ),
			'hidden_ids'     => array_map( static function ( $a ) {
				return $a['id'];
			}, $hidden ),
			'suspicious'     => $suspicious,
			'suspicious_ids' => array_map( static function ( $a ) {
				return $a['id'];
			}, $suspicious ),
			'mismatch'       => ! empty( $hidden ) || $counted > $visible_count,
			'checked_at'     => current_time( 'mysql' ),
		];
	}

	/**
	 * Accounts that must never be auto-removed — mirrors AdminGuard's hard
	 * safety guards: the current user, user ID 1, the site-owner address and
	 * multisite super admins.
	 *
	 * @param \WP_User $user
	 * @return bool
	 */
	public static function is_protected( $user ) {
		if ( ! $user instanceof \WP_User ) {
			return false;
		}
		if ( get_current_user_id() && (int) $user->ID === get_current_user_id() ) {
			return true;
		}
		if ( 1 === (int) $user->ID ) {
			return true;
		}
		if ( strtolower( trim( $user->user_email ) ) === strtolower( trim( (string) get_option( 'admin_email' ) ) ) ) {
			return true;
		}
		if ( is_multisite() && is_super_admin( $user->ID ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Remove a specific administrator by ID — used to clear a hidden / rogue
	 * admin the audit surfaced. Enforces the same hard protections as the guard
	 * and refuses to touch anyone who is not actually an administrator.
	 *
	 * @param int    $user_id
	 * @param string $action  'delete' | 'demote'.
	 * @return true|\WP_Error
	 */
	public static function remove_admin( $user_id, $action = 'delete' ) {
		$user_id = (int) $user_id;
		$user    = $user_id ? get_userdata( $user_id ) : false;

		if ( ! $user || ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return new \WP_Error( 'gs_not_admin', __( 'That user is not an administrator.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		if ( self::is_protected( $user ) ) {
			return new \WP_Error( 'gs_protected', __( 'That administrator is protected and cannot be auto-removed.', 'gemsecurity' ), [ 'status' => 403 ] );
		}

		$login  = $user->user_login;
		$email  = $user->user_email;
		$hidden = in_array( $user_id, self::hidden_admin_ids(), true );

		if ( 'demote' === $action ) {
			$user->set_role( 'subscriber' );
			self::log_removal( 'hidden_admin_demoted', $login, $email, $user_id, 'demote', $hidden );
			return true;
		}

		require_once ABSPATH . 'wp-admin/includes/user.php';
		if ( is_multisite() ) {
			require_once ABSPATH . 'wp-admin/includes/ms.php';
			wpmu_delete_user( $user_id );
		} else {
			// Reassign any content to the site owner to avoid data loss.
			$owner = get_user_by( 'email', get_option( 'admin_email' ) );
			wp_delete_user( $user_id, $owner ? $owner->ID : null );
		}

		self::log_removal( 'hidden_admin_deleted', $login, $email, $user_id, 'delete', $hidden );
		return true;
	}

	/**
	 * @param string $event
	 * @param string $login
	 * @param string $email
	 * @param int    $id
	 * @param string $action
	 * @param bool   $was_hidden
	 */
	private static function log_removal( $event, $login, $email, $id, $action, $was_hidden ) {
		Logger::log(
			$event,
			sprintf(
				'%1$s administrator "%2$s" (%3$s) was %4$s.',
				$was_hidden ? 'Hidden' : 'Unapproved',
				$login,
				$email,
				'delete' === $action ? 'deleted' : 'demoted to subscriber'
			),
			Logger::SEVERITY_CRITICAL,
			[ 'context' => [ 'target_user_id' => $id, 'target_email' => $email, 'action' => $action, 'was_hidden' => $was_hidden ] ]
		);
	}
}
