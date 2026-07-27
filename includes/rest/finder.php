<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\Finder as FinderModule;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Code & database search controller.
 */
class Finder {

	/**
	 * POST /search — grep files + database for a term.
	 */
	public static function search( \WP_REST_Request $request ) {
		$term  = (string) $request->get_param( 'term' );
		$regex = (bool) $request->get_param( 'regex' );
		$scope = $request->get_param( 'scope' );
		$scope = is_array( $scope ) ? array_map( 'sanitize_key', $scope ) : [ 'files', 'database' ];

		$result = FinderModule::search( $term, [ 'regex' => $regex, 'scope' => $scope ] );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response( [
			'success' => true,
			'result'  => $result,
		] );
	}
}
