<?php
namespace GemSecurity\Rest;

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
		// path => [ recommended octal, warn-if-group/other-writable ].
		$targets = [
			ABSPATH . 'wp-config.php'    => '0640',
			ABSPATH . '.htaccess'        => '0644',
			WP_CONTENT_DIR               => '0755',
			WP_CONTENT_DIR . '/uploads'  => '0755',
			ABSPATH                      => '0755',
		];

		$rows = [];
		foreach ( $targets as $path => $recommended ) {
			if ( ! file_exists( $path ) ) {
				continue;
			}
			$perms = fileperms( $path ) & 0777;
			$octal = '0' . decoct( $perms );
			// Flag world-writable (o+w) as critical, group-writable as warning.
			$world_writable = (bool) ( $perms & 0002 );
			$group_writable = (bool) ( $perms & 0020 );
			$status = 'ok';
			if ( $world_writable ) {
				$status = 'critical';
			} elseif ( $group_writable && false !== strpos( $path, 'wp-config' ) ) {
				$status = 'warning';
			}
			$rows[] = [
				'path'        => str_replace( ABSPATH, '', $path ) ?: '/',
				'perms'       => $octal,
				'recommended' => $recommended,
				'status'      => $status,
			];
		}

		return rest_ensure_response( [ 'success' => true, 'items' => $rows ] );
	}
}
