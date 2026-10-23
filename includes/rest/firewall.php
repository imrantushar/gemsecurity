<?php
namespace GemSecurity\Rest;

use GemSecurity\Helper;
use GemSecurity\Modules\SecurityHeaders;

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
			$count = (int) get_transient( $key ) + 1;
			set_transient( $key, $count, 5 * MINUTE_IN_SECONDS );
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
	 * GET /file-permissions — audit key paths for over-permissive modes.
	 */
	public static function file_permissions() {
		// path => recommended mode. Matches WordPress's hardening guide: code
		// (root, wp-admin, wp-includes, plugins) writable only by the owner,
		// wp-content and uploads writable by the web server too, and
		// wp-config.php readable by as few as possible (it holds the database
		// password) — 400/440 where the host allows, 640 at most.
		$targets = [
			ABSPATH . 'wp-config.php'   => '0440',
			ABSPATH . '.htaccess'       => '0644',
			ABSPATH                     => '0755',
			ABSPATH . 'wp-admin'        => '0755',
			ABSPATH . WPINC             => '0755',
			WP_CONTENT_DIR              => '0755',
			WP_PLUGIN_DIR               => '0755',
			get_theme_root()            => '0755',
			WP_CONTENT_DIR . '/uploads' => '0755',
		];
		// wp-config.php may live one level above the install.
		if ( ! file_exists( ABSPATH . 'wp-config.php' ) && file_exists( dirname( ABSPATH ) . '/wp-config.php' ) ) {
			unset( $targets[ ABSPATH . 'wp-config.php' ] );
			$targets = [ dirname( ABSPATH ) . '/wp-config.php' => '0440' ] + $targets;
		}

		$rows = [];
		foreach ( $targets as $path => $recommended ) {
			if ( ! file_exists( $path ) ) {
				continue;
			}
			$perms     = fileperms( $path ) & 0777;
			$is_config = 'wp-config.php' === basename( $path );
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
				'path'        => str_replace( wp_normalize_path( dirname( ABSPATH ) ) . '/', '../', str_replace( ABSPATH, '', $path ) ) ?: '/',
				'perms'       => '0' . decoct( $perms ),
				'recommended' => $recommended,
				'status'      => $status,
				'note'        => $note,
			];
		}

		return rest_ensure_response( [ 'success' => true, 'items' => $rows ] );
	}
}
