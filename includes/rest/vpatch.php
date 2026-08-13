<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\VirtualPatch;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Virtual-patch REST controller — lists the CVEs currently being mitigated on
 * this site.
 */
class Vpatch {

	/**
	 * GET /vpatch
	 */
	public static function get() {
		$rules = VirtualPatch::applicable_rules();
		$items = array_map( static function ( $r ) {
			return [
				'id'                => $r['id'],
				'cve'               => isset( $r['cve'] ) ? $r['cve'] : '',
				'title'             => isset( $r['title'] ) ? $r['title'] : '',
				'plugin'            => isset( $r['plugin'] ) ? $r['plugin'] : '*',
				'max_version'       => isset( $r['max_version'] ) ? $r['max_version'] : '',
				'installed_version' => isset( $r['installed_version'] ) ? $r['installed_version'] : '',
				'severity'          => isset( $r['severity'] ) ? $r['severity'] : 'high',
			];
		}, $rules );

		return rest_ensure_response( [
			'success'   => true,
			'count'     => count( $items ),
			'total'     => count( VirtualPatch::rules() ),
			'items'     => $items,
		] );
	}
}
