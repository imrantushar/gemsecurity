<?php
namespace GemSecurity\Rest;

use GemSecurity\Helper;
use GemSecurity\Modules\SecurityHeaders;
use GemSecurity\Store;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Firewall extras REST controller: CSP violation ingest/list + a read-only
 * file-permission audit.
 */
class Firewall {

	/**
	 * POST /csp-report — public collector for browser CSP violation reports.
	 * (Browsers post here directly, so it has no auth; it only appends to a
	 * capped ring buffer and returns 204.)
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function csp_report( $request ) {
		// Public route, and every report is a DB write: cap it per IP, and
		// site-wide so rotating IPs cannot turn it into a write flood.
		if ( self::csp_rate_limited() ) {
			return new \WP_REST_Response( null, 204 );
		}
		$body = $request->get_json_params();
		$report = null;
		if ( isset( $body['csp-report'] ) && is_array( $body['csp-report'] ) ) {
			$report = $body['csp-report']; // report-uri format.
		} elseif ( is_array( $body ) ) {
			$report = $body; // report-to / raw.
		}
		if ( is_array( $report ) ) {
			SecurityHeaders::record_csp_report( $report );
		}
		return new \WP_REST_Response( null, 204 );
	}

	/** @return bool */
	private static function csp_rate_limited() {
		foreach ( [
			'gemsec_csp_rl_' . md5( Helper::get_ip_address() ) => 20,  // per IP
			'gemsec_csp_rl_all'                                  => 300, // site-wide
		] as $key => $max ) {
			$count = (int) Store::get( $key ) + 1;
			Store::set( $key, $count, 5 * MINUTE_IN_SECONDS );
			if ( $count > $max ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * GET /csp-violations — recent stored violations (admin only).
	 */
	public static function csp_violations() {
		$log = get_option( SecurityHeaders::CSP_LOG_OPTION, [] );
		return rest_ensure_response( [ 'success' => true, 'items' => is_array( $log ) ? $log : [] ] );
	}

	/**
	 * The paths file_permissions() audits, keyed by their relative display path
	 * (what the table shows) → [ absolute, recommended ]. Shared with the fix
	 * endpoint so a client can only chmod a path the audit itself lists.
	 *
	 * @return array<string,array{abs:string,rec:string}>
	 */
	private static function perm_targets() {
		$targets = [
			\GemSecurity\Paths::root() . 'wp-config.php'   => '0440',
			\GemSecurity\Paths::root() . '.htaccess'       => '0644',
			\GemSecurity\Paths::root()                     => '0755',
			\GemSecurity\Paths::root() . 'wp-admin'        => '0755',
			\GemSecurity\Paths::root() . WPINC             => '0755',
			\GemSecurity\Paths::content()                  => '0755',
			\GemSecurity\Paths::plugins()                  => '0755',
			get_theme_root()                               => '0755',
			\GemSecurity\Paths::uploads()                  => '0755',
		];
		if ( ! file_exists( \GemSecurity\Paths::root() . 'wp-config.php' ) && file_exists( dirname( \GemSecurity\Paths::root() ) . '/wp-config.php' ) ) {
			unset( $targets[ \GemSecurity\Paths::root() . 'wp-config.php' ] );
			$targets = [ dirname( \GemSecurity\Paths::root() ) . '/wp-config.php' => '0440' ] + $targets;
		}

		$out = [];
		foreach ( $targets as $abs => $rec ) {
			if ( ! file_exists( $abs ) ) {
				continue;
			}
			$rel = str_replace( wp_normalize_path( dirname( \GemSecurity\Paths::root() ) ) . '/', '../', \GemSecurity\Paths::relative( $abs ) );
			$out[ $rel ?: '/' ] = [ 'abs' => $abs, 'rec' => $rec ];
		}
		return $out;
	}

	/**
	 * GET /file-permissions — audit key paths for over-permissive modes.
	 */
	public static function file_permissions() {
		$rows = [];
		foreach ( self::perm_targets() as $rel => $t ) {
			$perms     = fileperms( $t['abs'] ) & 0777;
			$is_config = 'wp-config.php' === basename( $t['abs'] );
			$status    = 'ok';
			$note      = '';
			if ( $perms & 0002 ) {
				$status = 'critical';
				$note   = __( 'Anyone on the server can write to this.', 'gemsecurity' );
			} elseif ( $is_config && ( $perms & 0004 ) ) {
				$status = 'warning';
				$note   = __( 'Every account on the server can read the database password.', 'gemsecurity' );
			} elseif ( $is_config && ( $perms & 0020 ) ) {
				$status = 'warning';
				$note   = __( 'The group can change your configuration.', 'gemsecurity' );
			}
			$rows[] = [
				'path'        => $rel,
				'perms'       => '0' . decoct( $perms ),
				'recommended' => $t['rec'],
				'status'      => $status,
				'note'        => $note,
				// Signals to the UI that a Fix button should be offered. A
				// row is only fixable when it is not already at the
				// recommended mode (and it is owned by the web server, so
				// chmod will succeed — else PHP returns false and we report
				// a helpful error instead).
				'fixable'     => $status !== 'ok',
			];
		}

		return rest_ensure_response( [ 'success' => true, 'items' => $rows ] );
	}

	/**
	 * POST /file-permissions/fix — chmod one audited path to its recommended
	 * mode. Only paths listed by the audit are accepted.
	 */
	public static function file_permissions_fix( \WP_REST_Request $req ) {
		$rel = (string) $req->get_param( 'path' );
		$targets = self::perm_targets();
		if ( '' === $rel || ! isset( $targets[ $rel ] ) ) {
			return new \WP_Error( 'gemsecurity_bad_path', __( 'Unknown path.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		$abs = $targets[ $rel ]['abs'];
		$rec = octdec( $targets[ $rel ]['rec'] );

		// chmod is a no-op (returns true) when PHP already has the mode set
		// but WILL return false when the file is owned by another user and
		// PHP cannot change its mode. Clear the stat cache so the next read
		// reflects the new mode.
		$ok = @chmod( $abs, $rec );
		clearstatcache( true, $abs );

		if ( ! $ok ) {
			$owner = function_exists( 'posix_getpwuid' ) && function_exists( 'fileowner' )
				? ( posix_getpwuid( fileowner( $abs ) )['name'] ?? '' )
				: '';
			return new \WP_Error(
				'gemsecurity_chmod_failed',
				$owner
					/* translators: %s: the user who owns the file. */
					? sprintf( __( 'The web server could not change this file. It is owned by %s — ask your host to run: chmod on your behalf, or set the mode yourself over SSH / SFTP.', 'gemsecurity' ), $owner )
					: __( 'The web server could not change this file. Set the mode manually over SSH / SFTP.', 'gemsecurity' ),
				[ 'status' => 403, 'current' => '0' . decoct( fileperms( $abs ) & 0777 ), 'recommended' => $targets[ $rel ]['rec'] ]
			);
		}

		return rest_ensure_response( [
			'success'     => true,
			'path'        => $rel,
			'perms'       => '0' . decoct( fileperms( $abs ) & 0777 ),
			'recommended' => $targets[ $rel ]['rec'],
		] );
	}
}
