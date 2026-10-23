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
			// include/require of an image, icon or text file — how a tiny stub
			// loads a backdoor disguised as something that is not PHP.
			'5c6228696e636c7564657c7265717569726529285f6f6e6365293f5c732a5c283f5c732a5b27225d5b5e27225d2b5c2e2869636f7c706e677c6a70653f677c6769667c626d707c776562707c7478747c6c6f677c6461747c746d707c62616b295b27225d' => '696e636c756465206f66206120646973677569736564206e6f6e2d5048502066696c65',
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
		$foreign     = self::scan_foreign_files();
		$suspicious  = array_merge( self::scan_admin_concealment(), self::scan_suspicious_files(), self::scan_tampered_stubs() );
		$htaccess    = \GemSecurity\Security\HtaccessScan::run();

		// File change watcher — baseline diff + injection heuristics over the
		// active theme, mu-plugins and drop-ins (and the database). Enabled by
		// default; catches tampering the core-checksum pass cannot see.
		$file_watcher = Helper::get_setting( 'file_watcher_enabled', true ) ? FileWatcher::run() : null;

		// Outbound link / malicious-site detector — surfaces external domains the
		// site links to and flags blocklisted, cloaked or spam-category ones.
		$link_scan = Helper::get_setting( 'link_scanner_enabled', true ) ? LinkScanner::run() : null;

		// Auto-executed code inventory — mu-plugins, nested payloads and drop-ins.
		// A compact summary rides the scan result (counted + logged); the full
		// item list is served by the /mu-plugins endpoint the UI reads.
		$mu        = \GemSecurity\Security\MuPlugins::inventory();
		$mu_summary = [
			'count'            => (int) $mu['count'],
			'suspicious_count' => (int) $mu['suspicious_count'],
			'relocated'        => ! empty( $mu['relocated'] ),
			'has_loader'       => ! empty( $mu['has_loader'] ),
		];

		// .htaccess findings count like any other: they are execution grants and
		// traffic redirects, so a scan that found one is not a clean scan.
		$issue_count = count( $core_issues ) + count( $foreign ) + count( $suspicious )
			+ count( $htaccess )
			+ ( $file_watcher ? (int) $file_watcher['issue_count'] : 0 )
			+ ( $link_scan ? (int) $link_scan['issue_count'] : 0 )
			+ $mu_summary['suspicious_count'];

		$result = [
			'scanned_at'      => current_time( 'mysql' ),
			'wp_version'      => get_bloginfo( 'version' ),
			'core_issues'     => $core_issues,
			'foreign_files'   => $foreign,
			'htaccess'        => $htaccess,
			'suspicious'      => $suspicious,
			'file_watcher'    => $file_watcher,
			'link_scan'       => $link_scan,
			'mu_plugins'      => $mu_summary,
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

		$fw = $result['file_watcher'] ?? null;
		Logger::log(
			'scan_completed',
			sprintf(
				'Security scan finished — %d issue(s) found (%d core, %d foreign file(s), %d suspicious file(s), %d .htaccess rule(s), %d changed file(s), %d injection(s), %d mu-plugin/drop-in, %d flagged link domain(s)).',
				$result['issue_count'],
				count( $result['core_issues'] ),
				count( $result['foreign_files'] ),
				count( $result['suspicious'] ),
				count( $result['htaccess'] ),
				$fw ? (int) $fw['change_count'] : 0,
				$fw ? (int) $fw['injection_count'] : 0,
				(int) ( $result['mu_plugins']['suspicious_count'] ?? 0 ),
				(int) ( $result['link_scan']['flagged_count'] ?? 0 )
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
	 * The official core file → md5 manifest for this exact version, memoised for
	 * the request. Keys are ABSPATH-relative paths with forward slashes.
	 *
	 * @return array<string,string>
	 */
	private static function core_checksums() {
		static $cache = null;
		if ( null !== $cache ) {
			return $cache;
		}

		require_once ABSPATH . 'wp-admin/includes/update.php';
		require_once ABSPATH . 'wp-admin/includes/file.php';

		$version   = get_bloginfo( 'version' );
		$checksums = function_exists( 'get_core_checksums' ) ? get_core_checksums( $version, get_locale() ) : false;
		if ( empty( $checksums ) || ! is_array( $checksums ) ) {
			$checksums = function_exists( 'get_core_checksums' ) ? get_core_checksums( $version, 'en_US' ) : false;
		}

		return $cache = ( is_array( $checksums ) ? $checksums : [] );
	}

	/**
	 * @return array List of { file, issue }.
	 */
	private static function scan_core_integrity() {
		$checksums = self::core_checksums();
		if ( empty( $checksums ) ) {
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
	/* Foreign / unexpected files                                             */
	/* --------------------------------------------------------------------- */

	/**
	 * Detect files that do not belong to WordPress: executable files present in
	 * the core directories (wp-admin, wp-includes) or the site root that are NOT
	 * part of the official release, and auto-loaded plugin files that hide from
	 * the Plugins screen. The core-integrity pass above only checks that KNOWN
	 * core files are unmodified; it cannot see EXTRA files dropped alongside them
	 * — which is exactly where a disguised implant like a fake "wp-core-updater"
	 * lives.
	 *
	 * @return array List of { file, reason, severity }.
	 */
	private static function scan_foreign_files() {
		return array_merge( self::scan_core_extras(), self::scan_hidden_plugins() );
	}

	/**
	 * Executable files sitting inside the core directories (or the site root)
	 * that are not in the official checksum manifest for this version.
	 *
	 * @return array
	 */
	private static function scan_core_extras() {
		$checksums = self::core_checksums();
		if ( empty( $checksums ) ) {
			return []; // Without the manifest we cannot tell core from foreign.
		}

		$exec = [ 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'inc', 'phar' ];
		$findings = [];
		$count    = 0;

		// wp-admin and wp-includes must be 100% core — anything executable there
		// that is not in the manifest is a high-confidence implant.
		foreach ( [ 'wp-admin', 'wp-includes' ] as $dir ) {
			$root = ABSPATH . $dir;
			if ( ! is_dir( $root ) ) {
				continue;
			}
			try {
				$it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ) );
			} catch ( \Exception $e ) {
				continue;
			}
			foreach ( $it as $file ) {
				if ( $count >= 200 ) {
					break 2;
				}
				if ( ! $file->isFile() || ! in_array( strtolower( $file->getExtension() ), $exec, true ) ) {
					continue;
				}
				$rel = str_replace( '\\', '/', str_replace( ABSPATH, '', $file->getPathname() ) );
				if ( ! isset( $checksums[ $rel ] ) && ! \GemSecurity\Security\SafeFiles::is_safe( $file->getPathname() ) ) {
					$findings[] = [
						'file'     => $rel,
						'reason'   => __( 'Executable file inside a WordPress core directory that is not part of the official release — a disguised implant hides here.', 'gemsecurity' ),
						'severity' => 'critical',
					];
					$count++;
				}
			}
		}

		// Top-level PHP in the site root (non-recursive). wp-config.php is the one
		// legitimate non-manifest root PHP file.
		$allow_root = [ 'wp-config.php' => true ];
		foreach ( (array) glob( ABSPATH . '*.php' ) as $path ) {
			$rel = str_replace( '\\', '/', str_replace( ABSPATH, '', $path ) );
			if ( isset( $checksums[ $rel ] ) || isset( $allow_root[ $rel ] ) ) {
				continue;
			}
			$findings[] = [
				'file'     => $rel,
				'reason'   => __( 'Unexpected PHP file in the WordPress root — not part of the official release.', 'gemsecurity' ),
				'severity' => 'critical',
			];
			if ( ++$count >= 200 ) {
				break;
			}
		}

		return $findings;
	}

	/**
	 * Plugin files that run but hide from the Plugins screen: an entry in
	 * active_plugins with no corresponding header (so it never lists), and loose
	 * top-level PHP files in the plugins folder that are not registered plugins.
	 * This is the exact concealment used by disguised droppers.
	 *
	 * @return array
	 */
	private static function scan_hidden_plugins() {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		$findings = [];
		$listed   = array_flip( array_keys( get_plugins() ) );

		$active = (array) get_option( 'active_plugins', [] );
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', [] ) ) );
		}

		$flagged = [];
		foreach ( array_unique( $active ) as $plugin ) {
			if ( ! isset( $listed[ $plugin ] ) ) {
				$rel             = 'wp-content/plugins/' . $plugin;
				$flagged[ $rel ] = true;
				$findings[]      = [
					'file'     => $rel,
					'reason'   => __( 'Active plugin that does not appear on the Plugins screen — an auto-loaded file concealing itself (classic malware behaviour).', 'gemsecurity' ),
					'severity' => 'critical',
				];
			}
		}

		// Loose *.php directly in the plugins folder that WordPress does not
		// recognise as a plugin (no header) — a favourite dropper location.
		foreach ( (array) glob( WP_PLUGIN_DIR . '/*.php' ) as $path ) {
			$base = basename( $path );
			if ( isset( $listed[ $base ] ) ) {
				continue; // A legitimate single-file plugin (has a header).
			}
			// The same inert/reviewed test the suspicious-file pass uses.
			// wp-content/plugins/index.php is WordPress's own silence stub and
			// is in every install ever made; reporting it as a possible dropper
			// is exactly the noise that teaches people to skim the list.
			if ( \GemSecurity\Security\SafeFiles::is_safe( $path ) ) {
				continue;
			}
			$rel = 'wp-content/plugins/' . $base;
			if ( isset( $flagged[ $rel ] ) ) {
				continue;
			}
			$findings[] = [
				'file'     => $rel,
				'reason'   => __( 'Loose PHP file in the plugins folder that is not a registered plugin — review it; disguised droppers live here.', 'gemsecurity' ),
				'severity' => 'warning',
			];
		}

		return $findings;
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
	 * index.php files in plugins and themes that should be empty but are not.
	 *
	 * Nearly every folder carries an index.php holding only "Silence is
	 * golden", so it is the last file anyone opens — which is why attackers
	 * append to it. The suspicious-file pass only walks uploads and
	 * mu-plugins, so a stub edited inside a plugin or theme went unreported.
	 *
	 * Only evidence is reported; an index.php that is a real template is not:
	 *  - the stub comment with code added beyond an ABSPATH guard,
	 *  - include/require of an image, icon or text file,
	 *  - a strong malware signature (eval, gzinflate, shell calls, …).
	 *
	 * @return array List of { file, reason, severity }.
	 */
	private static function scan_tampered_stubs() {
		$findings = [];
		$patterns = self::malware_patterns();
		// base64_decode() and move_uploaded_file() have everyday uses; on their
		// own they are not evidence. Everything else in the list is.
		$weak     = [ Helper::sig( '6261736536345f6465636f64652829' ), Helper::sig( '6d6f76655f75706c6f616465645f66696c652829' ) ];
		$skip_dir = [ 'node_modules', '.git', '.svn' ];
		$visited  = 0;

		foreach ( [ WP_PLUGIN_DIR, get_theme_root() ] as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			$root = wp_normalize_path( untrailingslashit( $root ) );
			try {
				$iterator = new \RecursiveIteratorIterator(
					new \RecursiveCallbackFilterIterator(
						new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ),
						static function ( $f ) use ( $skip_dir ) {
							return ! ( $f->isDir() && in_array( $f->getFilename(), $skip_dir, true ) );
						}
					)
				);
			} catch ( \Exception $e ) {
				continue;
			}

			foreach ( $iterator as $file ) {
				if ( 'index.php' !== $file->getFilename() ) {
					continue;
				}
				if ( ++$visited > 20000 ) {
					break 2;
				}
				$path = $file->getPathname();
				if ( \GemSecurity\Security\SafeFiles::is_safe( $path ) || $file->getSize() > 512 * KB_IN_BYTES ) {
					continue; // Empty stub, reviewed file, or too big to be a stub.
				}
				$contents = @file_get_contents( $path ); // phpcs:ignore
				if ( false === $contents || self::is_guard_only( $contents ) ) {
					continue;
				}

				$reason = '';
				if ( preg_match( '/silence\s+is\s+golden/i', $contents ) ) {
					$reason = __( '"Silence is golden" index.php with code added to it.', 'gemsecurity' );
				} else {
					foreach ( $patterns as $pattern => $label ) {
						if ( ! in_array( $label, $weak, true ) && preg_match( '/' . $pattern . '/i', $contents ) ) {
							/* translators: %s: name of the matched code pattern. */
							$reason = sprintf( __( 'index.php contains %s.', 'gemsecurity' ), $label );
							break;
						}
					}
				}
				if ( '' === $reason ) {
					continue; // A real template. Code alone is not evidence.
				}

				$findings[] = [
					'file'     => str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $path ) ),
					'reason'   => $reason,
					'severity' => 'critical',
				];
				if ( count( $findings ) >= 200 ) {
					break 2;
				}
			}
		}

		return $findings;
	}

	/**
	 * Whether a PHP file does nothing but stop direct access — the other common
	 * stub: `<?php defined( 'ABSPATH' ) || exit;` — optionally after a
	 * declare( strict_types ) or namespace line.
	 *
	 * @param string $source
	 * @return bool
	 */
	private static function is_guard_only( $source ) {
		if ( ! function_exists( 'token_get_all' ) ) {
			return false;
		}
		$tokens = @token_get_all( $source ); // phpcs:ignore
		if ( ! is_array( $tokens ) ) {
			return false;
		}
		$code = '';
		foreach ( $tokens as $t ) {
			if ( is_array( $t ) ) {
				if ( in_array( $t[0], [ T_OPEN_TAG, T_CLOSE_TAG, T_COMMENT, T_DOC_COMMENT, T_WHITESPACE ], true ) ) {
					continue;
				}
				if ( T_INLINE_HTML === $t[0] ) {
					if ( '' !== trim( $t[1] ) ) {
						return false;
					}
					continue;
				}
				$code .= $t[1];
			} else {
				$code .= $t;
			}
		}
		$code  = strtolower( $code );
		$guard = '(if\(!defined\([\'"](abspath|wpinc)[\'"]\)\)\{?(exit|die)(\([^)]*\))?;?\}?|defined\([\'"](abspath|wpinc)[\'"]\)(\|\||or)(exit|die)(\([^)]*\))?;?)';
		// Directives that only change how the file is compiled — Akismet's own
		// stub opens with declare( strict_types = 1 ).
		$code = (string) preg_replace( '/^(declare\\(strict_types=[01]\\);|namespace[a-z0-9_\\\\]+;)+/', '', $code );
		return '' === $code || (bool) preg_match( '/^(' . $guard . ')+$/', $code );
	}

	/**
	 * Heuristic pattern pass over uploads and mu-plugins.
	 *
	 * This is the free tier's malware check. When Pro is active its signature
	 * scanner covers the same files with a far larger rule set, and running
	 * both produced two overlapping lists of the same findings on one page —
	 * so the heuristic pass stands down and the "Suspicious files" card gives
	 * way to the malware scanner's results.
	 *
	 * The uploads-directory PHP check is not a heuristic and stays either way:
	 * an executable file there is a finding regardless of its contents, and
	 * the signature scanner deliberately skips asset directories.
	 *
	 * @return array List of { file, reason, severity }.
	 */
	private static function scan_suspicious_files() {
		$findings       = [];
		$patterns_only  = ! Helper::is_pro_active();

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

				// "Silence is golden" index.php files, and anything a person
				// has reviewed and marked safe, are not findings.
				if ( \GemSecurity\Security\SafeFiles::is_safe( $path ) ) {
					continue;
				}

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
				if ( ! $patterns_only ) {
					continue;
				}
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
