<?php
namespace GemSecurity\Modules;

use GemSecurity\Security\Quarantine;
use GemSecurity\Security\Recovery;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Incident response (Pro): turn the raw detection primitives into an
 * investigator's workflow — a correlated forensic timeline, safe quarantine
 * (move, don't delete) and one-click recovery actions.
 *
 * This page is the single home for containment. The quarantine index and the
 * force-logout action are the shared ones in {@see Quarantine} and
 * {@see Recovery}, so a file the malware scanner quarantined shows up here and
 * can be restored from either place.
 *
 * On-demand only; all work is driven from the REST controller.
 */
class IncidentResponse {

	/* ---------------- Forensic timeline ---------------- */

	/** Map an event_type to a coarse incident category. */
	private static function category( $event_type ) {
		$map = [
			'auth'     => [ 'login', '2fa', 'magic_link', 'credential', 'password', 'new_device', 'session' ],
			'file'     => [ 'scan', 'file', 'vpatch', 'malware', 'quarantine', 'integrity' ],
			'firewall' => [ 'waf', 'ban', 'bot', 'rate', '404', 'anomaly', 'ai_crawler', 'honeypot', 'antispam' ],
			'admin'    => [ 'admin', 'rogue', 'hidden', 'role', 'user', 'app_password' ],
			'content'  => [ 'post', 'plugin', 'theme', 'option', 'comment', 'payment', 'content' ],
		];
		foreach ( $map as $cat => $needles ) {
			foreach ( $needles as $n ) {
				if ( false !== strpos( $event_type, $n ) ) {
					return $cat;
				}
			}
		}
		return 'other';
	}

	/**
	 * @param int $days
	 * @return array
	 */
	public static function timeline( $days = 7 ) {
		global $wpdb;
		$table = $wpdb->prefix . 'gemsecurity_logs';
		$since = gmdate( 'Y-m-d H:i:s', time() - max( 1, (int) $days ) * DAY_IN_SECONDS );
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT id, event_type, severity, message, ip_address, created_at FROM {$table} WHERE created_at >= %s AND severity IN ('warning','critical') ORDER BY created_at DESC LIMIT 200", $since ), ARRAY_A ); // phpcs:ignore WordPress.DB

		return array_map( static function ( $r ) {
			return [
				'id'       => (int) $r['id'],
				'category' => self::category( $r['event_type'] ),
				'event'    => $r['event_type'],
				'severity' => $r['severity'],
				'message'  => $r['message'],
				'ip'       => $r['ip_address'],
				'time'     => $r['created_at'],
			];
		}, (array) $rows );
	}

	/* ---------------- Quarantine ---------------- */

	/**
	 * Move a suspicious file into quarantine (reversible).
	 *
	 * @param string $path Absolute path.
	 * @return array|\WP_Error
	 */
	public static function quarantine( $path ) {
		return Quarantine::add_file( $path );
	}

	/**
	 * Restore a quarantined file to its original location.
	 *
	 * @param string $id
	 * @return true|\WP_Error
	 */
	public static function restore( $id ) {
		return Quarantine::restore_file( $id );
	}

	/**
	 * Everything currently in quarantine, whichever scanner put it there.
	 *
	 * @return array<int,array>
	 */
	public static function quarantine_list() {
		return Quarantine::items();
	}

	/* ---------------- Recovery ---------------- */

	/**
	 * Run a guided recovery action.
	 *
	 * @param string $action
	 * @return array|\WP_Error
	 */
	public static function recover( $action ) {
		if ( 'logout_everyone' === $action ) {
			return [ 'affected' => Recovery::logout_all_users() ];
		}

		return new \WP_Error( 'gemsec_unknown_action', __( 'Unknown recovery action.', 'gemsecurity' ), [ 'status' => 400 ] );
	}

	/* ---------------- REST glue ---------------- */

	public static function rest_timeline( $req ) {
		return rest_ensure_response( [ 'success' => true, 'items' => self::timeline( (int) $req->get_param( 'days' ) ?: 7 ) ] );
	}
	public static function rest_quarantine_list() {
		return rest_ensure_response( [ 'success' => true, 'items' => self::quarantine_list() ] );
	}
	public static function rest_quarantine( $req ) {
		$path = (string) $req->get_param( 'path' );
		// Accept a root-relative path from the UI.
		if ( '' !== $path && 0 !== strpos( wp_normalize_path( $path ), wp_normalize_path( ABSPATH ) ) ) {
			$path = ABSPATH . ltrim( $path, '/' );
		}
		$r = self::quarantine( $path );
		return is_wp_error( $r ) ? $r : rest_ensure_response( [ 'success' => true ] + $r );
	}
	public static function rest_restore( $req ) {
		$r = self::restore( sanitize_text_field( (string) $req->get_param( 'id' ) ) );
		return is_wp_error( $r ) ? $r : rest_ensure_response( [ 'success' => true ] );
	}
	public static function rest_recover( $req ) {
		$r = self::recover( sanitize_key( (string) $req->get_param( 'action' ) ) );
		return is_wp_error( $r ) ? $r : rest_ensure_response( [ 'success' => true ] + $r );
	}
}
