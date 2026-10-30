<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\Scanner as ScannerModule;
use GemSecurity\Modules\FileWatcher;
use GemSecurity\Security\CoreFile;
use GemSecurity\Security\Quarantine;
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

	/**
	 * POST /scan/quarantine — move a flagged file out of the way, reversibly.
	 *
	 * Deliberately part of the free Scanner rather than the Pro incident
	 * workflow: finding a back-door in an .htaccess and then being told to
	 * upgrade before you can remove it is not a security product. It goes
	 * through the shared quarantine, so it is a move rather than a delete and
	 * shows up in the one restore list alongside everything else.
	 */
	public static function quarantine( $req ) {
		$path = (string) $req->get_param( 'path' );
		$path = wp_normalize_path( trim( $path ) );

		// The UI sends a root-relative path.
		if ( '' !== $path && 0 !== strpos( $path, wp_normalize_path( ABSPATH ) ) ) {
			$path = wp_normalize_path( ABSPATH ) . ltrim( $path, '/' );
		}

		$res = Quarantine::add_file( $path );
		if ( is_wp_error( $res ) ) {
			return $res;
		}

		// Re-scan so the finding disappears from the list it was actioned from
		// rather than lingering until the next manual scan.
		return rest_ensure_response( [
			'success' => true,
			'entry'   => $res,
			'result'  => ScannerModule::run_and_store(),
		] );
	}

	/**
	 * GET /scan/core-file — the flagged file as it is now and as WordPress.org ships it.
	 */
	public static function core_file( $req ) {
		$res = CoreFile::inspect( (string) $req->get_param( 'file' ) );
		return is_wp_error( $res ) ? $res : rest_ensure_response( $res );
	}

	/**
	 * POST /scan/core-file — restore the original, or save an edited copy.
	 */
	public static function core_file_fix( $req ) {
		$file = (string) $req->get_param( 'file' );
		$res  = 'save' === $req->get_param( 'action' )
			? CoreFile::save( $file, (string) $req->get_param( 'content' ) )
			: CoreFile::restore( $file );
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		return rest_ensure_response( [ 'success' => true, 'result' => ScannerModule::run_and_store() ] );
	}

	/**
	 * POST /scan/baseline — capture a fresh known-good file baseline.
	 *
	 * Use this after cleaning a site so the change watcher measures drift from
	 * the clean state forward (the previous baseline is overwritten).
	 */
	public static function reset_baseline() {
		$baseline = FileWatcher::establish_baseline();

		return rest_ensure_response( [
			'success'  => true,
			'baseline' => $baseline,
		] );
	}
}
