<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\Scanner as ScannerModule;
use GemSecurity\Security\Vulnerability;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scanner controller — file integrity + known vulnerabilities.
 */
class Scanner {

	/**
	 * GET /scan — last stored results.
	 */
	public static function last() {
		return rest_ensure_response( [
			'success' => true,
			'result'  => ScannerModule::get_last_result(),
			'vuln'    => Vulnerability::get_last_result(),
		] );
	}

	/**
	 * POST /scan — run a fresh file scan and vulnerability scan.
	 */
	public static function run() {
		$result = ScannerModule::run_and_store();
		$vuln   = Vulnerability::run_and_store();

		return rest_ensure_response( [
			'success' => true,
			'result'  => $result,
			'vuln'    => $vuln,
		] );
	}
}
