<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\Scanner as ScannerModule;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scanner controller.
 */
class Scanner {

	/**
	 * GET /scan — last stored scan result.
	 */
	public static function last() {
		return rest_ensure_response( [
			'success' => true,
			'result'  => ScannerModule::get_last_result(),
		] );
	}

	/**
	 * POST /scan — run a fresh scan.
	 */
	public static function run() {
		$result = ScannerModule::run_and_store();

		return rest_ensure_response( [
			'success' => true,
			'result'  => $result,
		] );
	}
}
