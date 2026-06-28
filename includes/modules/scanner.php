<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Malware / integrity scanner.
 *
 * Two high-signal checks:
 *   1. Core file integrity — compares WordPress core files against the official
 *      checksums published on api.wordpress.org.
 *   2. Suspicious files — flags PHP files living in the uploads directory
 *      (a classic malware hiding spot) and any files matching known web-shell
 *      code patterns.
 */
class Scanner {

	const RESULT_OPTION = 'gemsecurity_last_scan';

	/** Heuristic code patterns commonly found in web shells / injected malware. */
	private static function malware_patterns() {
		return [
			'eval\s*\('            => 'eval()',
			'base64_decode\s*\('   => 'base64_decode()',
			'gzinflate\s*\('       => 'gzinflate()',
			'str_rot13\s*\('       => 'str_rot13()',
			'shell_exec\s*\('      => 'shell_exec()',
			'\bpassthru\s*\('      => 'passthru()',
			'\bsystem\s*\('        => 'system()',
			'\bproc_open\s*\('     => 'proc_open()',
			'\bpopen\s*\('         => 'popen()',
			'preg_replace\s*\(\s*[\'"][^\'"]*\/e' => 'preg_replace /e modifier',
			'\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]*\]\s*\(' => 'dynamic call on request data',
			'move_uploaded_file\s*\(' => 'move_uploaded_file()',
			'create_function\s*\('  => 'create_function()',
		];
	}

	/**
	 * Run the scan and return the structured result. Bounded so it is safe to
	 * call from a web request.
	 *
	 * @return array
	 */
	public static function run() {
		@set_time_limit( 0 );

		$core_issues = self::scan_core_integrity();
		$suspicious  = self::scan_suspicious_files();

		$issue_count = count( $core_issues ) + count( $suspicious );

		$result = [
			'scanned_at'      => current_time( 'mysql' ),
			'wp_version'      => get_bloginfo( 'version' ),
			'core_issues'     => $core_issues,
			'suspicious'      => $suspicious,
			'issue_count'     => $issue_count,
			'status'          => $issue_count > 0 ? 'issues' : 'clean',
		];

		return $result;
	}

	/**
	 * Run the scan, persist the result, and log a summary.
	 *
	 * @return array
	 */
	public static function run_and_store() {
		$result = self::run();
		update_option( self::RESULT_OPTION, $result, false );

		Logger::log(
			'scan_completed',
			sprintf(
				'Security scan finished — %d issue(s) found (%d core, %d suspicious file(s)).',
				$result['issue_count'],
				count( $result['core_issues'] ),
				count( $result['suspicious'] )
			),
			$result['issue_count'] > 0 ? Logger::SEVERITY_WARNING : Logger::SEVERITY_INFO
		);

		return $result;
	}

	/**
	 * @return array|null Last stored scan result.
	 */
	public static function get_last_result() {
		$result = get_option( self::RESULT_OPTION, null );
		return is_array( $result ) ? $result : null;
	}

	/* --------------------------------------------------------------------- */
	/* Core integrity                                                         */
	/* --------------------------------------------------------------------- */

	/**
	 * @return array List of { file, issue }.
	 */
	private static function scan_core_integrity() {
		require_once ABSPATH . 'wp-admin/includes/update.php';
		require_once ABSPATH . 'wp-admin/includes/file.php';

		$version  = get_bloginfo( 'version' );
		$locale   = get_locale();
		$checksums = function_exists( 'get_core_checksums' ) ? get_core_checksums( $version, $locale ) : false;

		if ( empty( $checksums ) || ! is_array( $checksums ) ) {
			// Try the en_US fallback.
			$checksums = function_exists( 'get_core_checksums' ) ? get_core_checksums( $version, 'en_US' ) : false;
		}

		if ( empty( $checksums ) || ! is_array( $checksums ) ) {
			return [];
		}

		$issues = [];
		foreach ( $checksums as $file => $checksum ) {
			// wp-content is user-owned; skip it.
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue;
			}
			$path = ABSPATH . $file;
			if ( ! file_exists( $path ) ) {
				$issues[] = [ 'file' => $file, 'issue' => 'missing' ];
				continue;
			}
			if ( md5_file( $path ) !== $checksum ) {
				$issues[] = [ 'file' => $file, 'issue' => 'modified' ];
			}
			if ( count( $issues ) >= 200 ) {
				break;
			}
		}

		return $issues;
	}

	/* --------------------------------------------------------------------- */
	/* Suspicious files                                                       */
	/* --------------------------------------------------------------------- */

	/**
	 * @return array List of { file, reason, severity }.
	 */
	private static function scan_suspicious_files() {
		$findings = [];

		$upload_dir = wp_upload_dir();
		$roots = [
			$upload_dir['basedir'] => 'uploads',
			WP_CONTENT_DIR . '/mu-plugins' => 'mu-plugins',
		];

		$max_files = 5000;
		$max_bytes = 2 * MB_IN_BYTES;
		$scanned   = 0;

		foreach ( $roots as $root => $label ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}

			try {
				$iterator = new \RecursiveIteratorIterator(
					new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS )
				);
			} catch ( \Exception $e ) {
				continue;
			}

			foreach ( $iterator as $file ) {
				if ( $scanned >= $max_files ) {
					break 2;
				}
				if ( ! $file->isFile() ) {
					continue;
				}

				$ext  = strtolower( $file->getExtension() );
				$path = $file->getPathname();
				$rel  = str_replace( ABSPATH, '', $path );

				// PHP in the uploads directory is a strong red flag on its own.
				if ( 'uploads' === $label && in_array( $ext, [ 'php', 'phtml', 'php5', 'php7', 'phar' ], true ) ) {
					$findings[] = [
						'file'     => $rel,
						'reason'   => __( 'Executable PHP file inside the uploads directory.', 'gemsecurity' ),
						'severity' => 'critical',
					];
					$scanned++;
					continue;
				}

				// Pattern scan PHP files.
				if ( ! in_array( $ext, [ 'php', 'phtml', 'php5', 'php7', 'inc' ], true ) ) {
					continue;
				}
				$scanned++;
				if ( $file->getSize() > $max_bytes ) {
					continue;
				}

				$contents = @file_get_contents( $path );
				if ( false === $contents ) {
					continue;
				}

				$hits = [];
				foreach ( self::malware_patterns() as $pattern => $label_human ) {
					if ( preg_match( '/' . $pattern . '/i', $contents ) ) {
						$hits[] = $label_human;
					}
				}

				// Require at least two distinct signals to reduce false positives.
				if ( count( $hits ) >= 2 ) {
					$findings[] = [
						'file'     => $rel,
						'reason'   => sprintf( __( 'Suspicious code patterns: %s', 'gemsecurity' ), implode( ', ', array_slice( $hits, 0, 5 ) ) ),
						'severity' => 'warning',
					];
				}

				if ( count( $findings ) >= 200 ) {
					break 2;
				}
			}
		}

		return $findings;
	}
}
