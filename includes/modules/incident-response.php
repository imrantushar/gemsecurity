<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Incident response (Pro): turn the raw detection primitives into an
 * investigator's workflow — a correlated forensic timeline, safe quarantine
 * (move, don't delete) and one-click recovery actions.
 *
 * On-demand only; all work is driven from the REST controller.
 */
class IncidentResponse {

	const QUARANTINE_OPTION = 'gemsecurity_quarantine';

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

	private static function quarantine_dir() {
		$up  = wp_upload_dir();
		$dir = trailingslashit( $up['basedir'] ) . 'gemsecurity-quarantine';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
			@file_put_contents( $dir . '/.htaccess', "Deny from all\n" ); // phpcs:ignore
			@file_put_contents( $dir . '/index.php', "<?php // Silence is golden.\n" ); // phpcs:ignore
		}
		return $dir;
	}

	/**
	 * Move a suspicious file into quarantine (reversible).
	 *
	 * @param string $path Absolute path.
	 * @return array|\WP_Error
	 */
	public static function quarantine( $path ) {
		$path = wp_normalize_path( $path );
		$root = wp_normalize_path( ABSPATH );
		// Safety: only files under the WordPress root, and never wp-config.
		if ( 0 !== strpos( $path, $root ) || ! is_file( $path ) || false !== strpos( $path, 'wp-config.php' ) ) {
			return new \WP_Error( 'gemsec_bad_path', __( 'That file cannot be quarantined.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		$id     = substr( md5( $path . microtime() ), 0, 12 );
		$stored = self::quarantine_dir() . '/' . $id . '.quar';
		if ( ! @rename( $path, $stored ) ) { // phpcs:ignore
			return new \WP_Error( 'gemsec_move_failed', __( 'Could not move the file.', 'gemsecurity' ), [ 'status' => 500 ] );
		}

		$index   = get_option( self::QUARANTINE_OPTION, [] );
		$index   = is_array( $index ) ? $index : [];
		$index[] = [ 'id' => $id, 'orig' => $path, 'stored' => $stored, 'time' => gmdate( 'Y-m-d H:i:s' ) ];
		update_option( self::QUARANTINE_OPTION, $index, false );

		Logger::log( 'quarantine', sprintf( 'Quarantined %s.', str_replace( $root, '', $path ) ), Logger::SEVERITY_WARNING );
		return [ 'id' => $id ];
	}

	/**
	 * Restore a quarantined file to its original location.
	 *
	 * @param string $id
	 * @return true|\WP_Error
	 */
	public static function restore( $id ) {
		$index = get_option( self::QUARANTINE_OPTION, [] );
		$index = is_array( $index ) ? $index : [];
		foreach ( $index as $k => $item ) {
			if ( $item['id'] === $id ) {
				if ( ! @rename( $item['stored'], $item['orig'] ) ) { // phpcs:ignore
					return new \WP_Error( 'gemsec_restore_failed', __( 'Could not restore the file.', 'gemsecurity' ), [ 'status' => 500 ] );
				}
				unset( $index[ $k ] );
				update_option( self::QUARANTINE_OPTION, array_values( $index ), false );
				Logger::log( 'quarantine_restore', sprintf( 'Restored %s.', $item['orig'] ), Logger::SEVERITY_NOTICE );
				return true;
			}
		}
		return new \WP_Error( 'gemsec_not_found', __( 'Quarantine entry not found.', 'gemsecurity' ), [ 'status' => 404 ] );
	}

	public static function quarantine_list() {
		$index = get_option( self::QUARANTINE_OPTION, [] );
		$root  = wp_normalize_path( ABSPATH );
		return array_map( static function ( $i ) use ( $root ) {
			return [ 'id' => $i['id'], 'orig' => str_replace( $root, '', $i['orig'] ), 'time' => $i['time'] ];
		}, is_array( $index ) ? $index : [] );
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
			$n = 0;
			$user_ids = get_users( [ 'fields' => 'ID', 'number' => 1000 ] );
			foreach ( $user_ids as $uid ) {
				\WP_Session_Tokens::get_instance( $uid )->destroy_all();
				$n++;
			}
			Logger::log( 'recovery_logout_all', sprintf( 'Forced logout of %d users (incident recovery).', $n ), Logger::SEVERITY_WARNING );
			return [ 'affected' => $n ];
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
