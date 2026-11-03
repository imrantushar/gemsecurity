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
	 * (what the table shows) → [ absolute, recommended ]. Read-only: the audit
	 * reports modes and never changes them.
	 *
	 * @return array<string,array{abs:string,rec:string}>
	 */
	private static function perm_targets() {
		$targets = [
			\GemSecurity\Paths::root() . 'wp-config.php'   => '0440',
			\GemSecurity\Paths::root() . '.htaccess'       => '0644',
			\GemSecurity\Paths::root()                     => '0755',
			\GemSecurity\Paths::root() . 'wp-admin'        => '0755',
			\GemSecurity\Paths::includes()          => '0755',
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
				// Always false: the audit is read-only, there is no Fix button.
				'fixable'     => false,
			];
		}

		return rest_ensure_response( [ 'success' => true, 'items' => $rows ] );
	}

}
