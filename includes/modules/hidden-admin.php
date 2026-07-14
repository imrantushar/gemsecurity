<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;
use GemSecurity\Security\AdminAudit;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hidden-administrator detector.
 *
 * AdminGuard watches user_register / set_user_role, so it catches back-door
 * admins created through WordPress. A more evasive attacker injects the admin
 * straight into the database (no hook fires) and conceals it with a
 * pre_user_query filter — often guarded by `is_admin()` or `$pagenow` so the row
 * only disappears on the Users screen while count_users() still reports the true
 * total. Because that guard means the filter is dormant during a REST request,
 * detection cannot rely on the REST context alone.
 *
 * This module therefore reconciles from three angles:
 *   1. A live raw-vs-visible diff (catches unconditional concealment anywhere).
 *   2. An authoritative probe on `load-users.php`, i.e. inside the exact wp-admin
 *      context where a guarded filter actually fires (catches the common variant).
 *   3. Persistence: a non-admin (REST/cron) reading may never *downgrade* a
 *      standing detection, so a filtered REST view cannot mask a live attack.
 *
 * It also surfaces heuristically suspicious admins (e.g. non-routable e-mail
 * domains) regardless of whether concealment is proven.
 */
class HiddenAdmin {

	const RESULT_OPTION = 'gemsecurity_hidden_admin_scan';
	const STATE_OPTION  = 'gemsecurity_hidden_admin_state';

	public static function init() {
		if ( ! self::enabled() ) {
			return;
		}
		// Authoritative probe: runs in the very wp-admin context where a
		// screen-guarded concealment filter is active, so the hidden row is
		// exposed by the same filter that hides it from the list.
		if ( is_admin() ) {
			add_action( 'load-users.php', [ __CLASS__, 'probe' ] );
		}
	}

	/**
	 * @return bool Whether hidden-admin detection is switched on.
	 */
	public static function enabled() {
		return (bool) Helper::get_setting( 'hidden_admin_detection', true );
	}

	/**
	 * Authoritative reconciliation, hooked on the Users screen load.
	 */
	public static function probe() {
		self::scan_and_store( true );
	}

	/**
	 * Reconcile, persist and alert. `$authoritative` marks a wp-admin-context run
	 * whose clean reading may be trusted to clear a prior detection; a
	 * non-authoritative (REST/cron) run may only ever *add* hidden accounts.
	 *
	 * @param bool $authoritative
	 * @return array The reconciled result.
	 */
	public static function scan_and_store( $authoritative = false ) {
		$result = self::reconcile( $authoritative );
		update_option( self::RESULT_OPTION, $result, false );

		$signature = implode( ',', $result['hidden_ids'] );
		$previous  = (string) get_option( self::STATE_OPTION, '' );

		if ( $signature !== $previous ) {
			update_option( self::STATE_OPTION, $signature, false );

			if ( ! empty( $result['hidden_ids'] ) ) {
				self::alert( $result );
			} elseif ( '' !== $previous ) {
				Logger::log(
					'hidden_admin_cleared',
					__( 'No hidden administrator accounts remain — the concealment is gone.', 'gemsecurity' ),
					Logger::SEVERITY_NOTICE
				);
			}
		}

		return $result;
	}

	/**
	 * Read-side reconciliation for the UI: refreshes + preserves the stored
	 * verdict and returns it alongside the full administrator list (with the
	 * reconciled hidden set applied).
	 *
	 * @return array { result: array, admins: array }
	 */
	public static function verdict() {
		$result = self::scan_and_store( false );
		return [
			'result' => $result,
			'admins' => AdminAudit::admins( $result['hidden_ids'] ),
		];
	}

	/**
	 * Drop an account from the stored verdict after it has been removed, so the
	 * UI and dashboard stop reporting a user that no longer exists.
	 *
	 * @param int $user_id
	 */
	public static function forget( $user_id ) {
		$user_id = (int) $user_id;
		$r       = self::get_last_result();
		if ( ! is_array( $r ) ) {
			return;
		}

		$drop = static function ( $a ) use ( $user_id ) {
			return (int) $a['id'] !== $user_id;
		};

		$r['hidden_ids']     = array_values( array_diff( (array) $r['hidden_ids'], [ $user_id ] ) );
		$r['hidden']         = array_values( array_filter( (array) $r['hidden'], $drop ) );
		$r['suspicious_ids'] = array_values( array_diff( (array) $r['suspicious_ids'], [ $user_id ] ) );
		$r['suspicious']     = array_values( array_filter( (array) $r['suspicious'], $drop ) );

		update_option( self::RESULT_OPTION, $r, false );
		update_option( self::STATE_OPTION, implode( ',', $r['hidden_ids'] ), false );
	}

	/**
	 * @return array|null Last stored reconciliation result.
	 */
	public static function get_last_result() {
		$r = get_option( self::RESULT_OPTION, null );
		return is_array( $r ) ? $r : null;
	}

	/* --------------------------------------------------------------------- */
	/* Internals                                                             */
	/* --------------------------------------------------------------------- */

	/**
	 * Compute the reconciled verdict for the current context.
	 *
	 * @param bool $authoritative
	 * @return array
	 */
	private static function reconcile( $authoritative ) {
		$audit = AdminAudit::audit();
		$raw   = AdminAudit::raw_admin_ids();

		// Hidden accounts seen live in this context (bounded to real admins).
		$live_hidden = array_values( array_intersect( $audit['hidden_ids'], $raw ) );

		if ( $authoritative ) {
			$hidden_ids = $live_hidden;
		} else {
			// Never downgrade a standing detection from a non-admin context, but
			// drop ids that are no longer administrators (deleted / demoted).
			$prev        = self::get_last_result();
			$prev_hidden = is_array( $prev ) && ! empty( $prev['hidden_ids'] )
				? array_intersect( (array) $prev['hidden_ids'], $raw )
				: [];
			$hidden_ids = array_values( array_unique( array_merge( $live_hidden, $prev_hidden ) ) );
		}

		sort( $hidden_ids );

		$all        = AdminAudit::admins( $hidden_ids );
		$hidden     = array_values( array_filter( $all, static function ( $a ) {
			return $a['hidden'];
		} ) );
		$suspicious = array_values( array_filter( $all, static function ( $a ) {
			return $a['suspicious'];
		} ) );

		$visible_count = count( $all ) - count( $hidden );

		return [
			'raw_count'      => count( $all ),
			'visible_count'  => $visible_count,
			'counted'        => $audit['counted'],
			'hidden'         => $hidden,
			'hidden_ids'     => array_map( static function ( $a ) {
				return $a['id'];
			}, $hidden ),
			'suspicious'     => $suspicious,
			'suspicious_ids' => array_map( static function ( $a ) {
				return $a['id'];
			}, $suspicious ),
			'mismatch'       => ! empty( $hidden ) || $audit['counted'] > $visible_count,
			'checked_at'     => current_time( 'mysql' ),
		];
	}

	/**
	 * Log a critical event and (optionally) email the site owner about newly
	 * detected hidden administrators.
	 *
	 * @param array $result
	 */
	private static function alert( $result ) {
		$count = count( $result['hidden'] );
		$names = implode( ', ', array_map( static function ( $a ) {
			return sprintf( '%s (%s)', $a['login'], $a['email'] );
		}, $result['hidden'] ) );

		Logger::log(
			'hidden_admin_detected',
			sprintf(
				/* translators: 1: count, 2: comma-separated account list. */
				_n(
					'%1$d hidden administrator account detected: %2$s. It exists in the database but is concealed from the Users screen — a strong indicator the site is compromised.',
					'%1$d hidden administrator accounts detected: %2$s. They exist in the database but are concealed from the Users screen — a strong indicator the site is compromised.',
					$count,
					'gemsecurity'
				),
				$count,
				$names
			),
			Logger::SEVERITY_CRITICAL,
			[
				'context' => [
					'hidden_ids' => $result['hidden_ids'],
					'counts'     => [
						'database' => $result['raw_count'],
						'visible'  => $result['visible_count'],
						'counted'  => $result['counted'],
					],
				],
			]
		);

		if ( Helper::get_setting( 'notify_on_hidden_admin', true ) ) {
			self::notify( $result, $names, $count );
		}
	}

	/**
	 * @param array  $result
	 * @param string $names
	 * @param int    $count
	 */
	private static function notify( $result, $names, $count ) {
		$to   = get_option( 'admin_email' );
		$site = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

		$subject = sprintf(
			/* translators: %s: site name. */
			__( '[%s] Hidden administrator account detected', 'gemsecurity' ),
			$site
		);

		$body = implode( "\n", [
			sprintf(
				/* translators: 1: count, 2: site name. */
				_n(
					'GemSecurity found %1$d administrator account on %2$s that is hidden from the WordPress Users screen.',
					'GemSecurity found %1$d administrator accounts on %2$s that are hidden from the WordPress Users screen.',
					$count,
					'gemsecurity'
				),
				$count,
				$site
			),
			'',
			sprintf( __( 'Account(s):            %s', 'gemsecurity' ), $names ),
			sprintf( __( 'Admins in database:    %d', 'gemsecurity' ), $result['raw_count'] ),
			sprintf( __( 'Admins visible in wp-admin: %d', 'gemsecurity' ), $result['visible_count'] ),
			'',
			__( 'A hidden administrator almost always means the site has been compromised. Open GemSecurity → Admin Guard to review and remove the account, then run a full malware scan and rotate every administrator password.', 'gemsecurity' ),
		] );

		wp_mail( $to, $subject, $body );
	}
}
