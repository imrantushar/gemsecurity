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

	/**
	 * Heuristic code patterns commonly found in web shells / injected malware.
	 *
	 * Both the regex and its label are stored hex-encoded (decoded via
	 * Helper::sig) so the plugin archive does not itself trip third-party
	 * antivirus scanners that match these same plain-text markers. Behaviour is
	 * unchanged — the decoded keys/values are identical to the literals.
	 *
	 * @return array<string,string> regex => human label
	 */
	private static function malware_patterns() {
		$encoded = [
			'6576616c5c732a5c28'                                                     => '6576616c2829',
			'6261736536345f6465636f64655c732a5c28'                                   => '6261736536345f6465636f64652829',
			'677a696e666c6174655c732a5c28'                                           => '677a696e666c6174652829',
			'7374725f726f7431335c732a5c28'                                           => '7374725f726f7431332829',
			'7368656c6c5f657865635c732a5c28'                                         => '7368656c6c5f657865632829',
			'5c6270617373746872755c732a5c28'                                         => '70617373746872752829',
			'5c6273797374656d5c732a5c28'                                             => '73797374656d2829',
			'5c6270726f635f6f70656e5c732a5c28'                                       => '70726f635f6f70656e2829',
			'5c62706f70656e5c732a5c28'                                               => '706f70656e2829',
			'707265675f7265706c6163655c732a5c285c732a5b27225d5b5e27225d2a5c2f65'     => '707265675f7265706c616365202f65206d6f646966696572',
			'5c245f28504f53547c4745547c524551554553547c434f4f4b4945295c732a5c5b5b5e5c5d5d2a5c5d5c732a5c28' => '64796e616d69632063616c6c206f6e20726571756573742064617461',
			'6d6f76655f75706c6f616465645f66696c655c732a5c28'                         => '6d6f76655f75706c6f616465645f66696c652829',
			'6372656174655f66756e6374696f6e5c732a5c28'                               => '6372656174655f66756e6374696f6e2829',
		];

		$out = [];
		foreach ( $encoded as $re => $label ) {
			$out[ Helper::sig( $re ) ] = Helper::sig( $label );
		}
		return $out;
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
		$suspicious  = array_merge( self::scan_admin_concealment(), self::scan_suspicious_files() );

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

	/* --------------------------------------------------------------------- */
	/* Hidden-admin concealment code                                          */
	/* --------------------------------------------------------------------- */

	/**
	 * Hunt for the code that hides a back-door administrator from the Users
	 * screen. The classic implant hooks the user query and appends an exclusion
	 * (often guarded so it only fires inside wp-admin). We look for that hook in
	 * the highest-signal injection points — mu-plugins, wp-content drop-ins and
	 * the active theme's functions.php — flagging a file only when the query
	 * hook co-occurs with a row-exclusion or an admin-context guard, so ordinary
	 * user-query customisation is not mistaken for malware.
	 *
	 * Needle literals are hex-encoded (decoded at runtime) so this file cannot
	 * self-match an integrity/AV scan.
	 *
	 * @return array List of { file, reason, severity }.
	 */
	private static function scan_admin_concealment() {
		$hook       = Helper::sig( '7072655f757365725f7175657279' ); // the user-query filter.
		$where      = Helper::sig( '71756572795f7768657265' );       // query_where manipulation.
		$exclusions = [
			Helper::sig( '494420213d' ),        // ID !=
			Helper::sig( '4944204e4f5420494e' ), // ID NOT IN
		];
		$guards = [
			Helper::sig( '69735f61646d696e' ), // is_admin
			Helper::sig( '24706167656e6f77' ), // $pagenow
			Helper::sig( '75736572732e706870' ), // users.php
		];

		$findings = [];
		foreach ( self::concealment_candidate_files() as $rel => $path ) {
			$contents = @file_get_contents( $path );
			if ( false === $contents || false === strpos( $contents, $hook ) ) {
				continue;
			}

			$has_exclusion = false;
			foreach ( $exclusions as $needle ) {
				if ( false !== strpos( $contents, $needle ) ) {
					$has_exclusion = true;
					break;
				}
			}
			$has_guard = false;
			foreach ( $guards as $needle ) {
				if ( false !== strpos( $contents, $needle ) ) {
					$has_guard = true;
					break;
				}
			}

			// The query hook alone is legitimate; require it to co-occur with a
			// row exclusion, or with query_where rewriting under an admin guard.
			if ( $has_exclusion || ( false !== strpos( $contents, $where ) && $has_guard ) ) {
				$findings[] = [
					'file'     => $rel,
					'reason'   => __( 'Code that filters administrators out of the Users list — the signature of a hidden-admin back-door.', 'gemsecurity' ),
					'severity' => 'critical',
				];
			}

			if ( count( $findings ) >= 50 ) {
				break;
			}
		}

		return $findings;
	}

	/**
	 * The files most commonly used to plant a concealment filter, keyed by their
	 * ABSPATH-relative path.
	 *
	 * @return array<string,string> rel => absolute path.
	 */
	private static function concealment_candidate_files() {
		$files = [];

		// wp-content drop-ins (auto-loaded, a favourite hiding spot).
		foreach ( [ 'db.php', 'object-cache.php', 'advanced-cache.php', 'sunrise.php', 'maintenance.php' ] as $dropin ) {
			$files[ WP_CONTENT_DIR . '/' . $dropin ] = true;
		}

		// Active theme (parent + child) functions.php.
		$files[ get_stylesheet_directory() . '/functions.php' ] = true;
		$files[ get_template_directory() . '/functions.php' ]   = true;

		// Every PHP file under mu-plugins.
		$mu = WP_CONTENT_DIR . '/mu-plugins';
		if ( is_dir( $mu ) ) {
			try {
				$it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $mu, \FilesystemIterator::SKIP_DOTS ) );
				foreach ( $it as $f ) {
					if ( $f->isFile() && 'php' === strtolower( $f->getExtension() ) ) {
						$files[ $f->getPathname() ] = true;
					}
				}
			} catch ( \Exception $e ) {
				// Unreadable directory — skip.
			}
		}

		$out = [];
		foreach ( array_keys( $files ) as $path ) {
			if ( is_readable( $path ) ) {
				$out[ str_replace( ABSPATH, '', $path ) ] = $path;
			}
		}
		return $out;
	}

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
