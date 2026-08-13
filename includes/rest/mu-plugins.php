<?php
namespace GemSecurity\Rest;

use GemSecurity\Security\MuPlugins as MuPluginsInventory;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Must-Use plugin inventory endpoint.
 */
class MuPlugins {

	/**
	 * GET /mu-plugins
	 */
	public static function get() {
		return rest_ensure_response( array_merge(
			[ 'success' => true ],
			MuPluginsInventory::inventory()
		) );
	}
}
