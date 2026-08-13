<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * File change watcher (file integrity monitor).
 *
 * WordPress core files can be verified against the official checksums published
 * on api.wordpress.org (see {@see Scanner::scan_core_integrity()}). Everything
 * under wp-content has no authoritative checksum, so tampering there — the most
 * common place a hack actually lives — goes unnoticed by a checksum scan.
 *
 * This watcher closes that gap with two complementary passes over the highest
 * risk, lowest churn locations (the active theme, mu-plugins and the wp-content
 * drop-ins):
 *
 *   1. Baseline diff — on the first scan it snapshots a hash of every watched
 *      file; on later scans it reports any file that was added, modified or
 *      removed since. This catches *future* tampering with certainty.
 *
 *   2. Injection heuristics — content signatures that fire on the very first
 *      scan, so an implant that is *already* present is flagged immediately.
 *      Two high-signal families:
 *        - Hidden off-screen blocks that link out to external URLs (the classic
 *          SEO spam / link-injection cloak — a container pushed thousands of
 *          pixels off-canvas wrapping `<a href="http…">` links).
 *        - Obfuscated code loaders (eval + base64_decode/gzinflate/str_rot13).
 *      The same injection signatures are also run over the database (autoloaded
 *      options and recent post content), because this style of spam is very
 *      often stored there rather than in a file.
 *
 * Regex/needle literals that would otherwise trip a third-party antivirus on the
 * plugin archive itself are stored hex-encoded and decoded at runtime via
 * {@see Helper::sig()} — behaviour is identical to the plain literals.
 */
class FileWatcher {

	const BASELINE_OPTION = 'gemsecurity_file_baseline';

	/** Bounds so the watcher is always safe to run inside a web request. */
	const MAX_FILES      = 8000;
	const MAX_FILE_BYTES = 2097152;   // 2 MB — skip hashing/reading larger files.
	const MAX_DB_OPTIONS = 1500;   // cap on options matching the SQL pre-filter.
	const MAX_DB_POSTS   = 200;
	const MAX_REPORTED   = 200;       // cap each result list.

	/** File extensions worth watching for code/markup injection. */
	private static function watched_extensions() {
		return [ 'php', 'phtml', 'php5', 'php7', 'inc', 'js', 'html', 'htm', 'htaccess' ];
	}

	/* --------------------------------------------------------------------- */
	/* Public API                                                            */
	/* --------------------------------------------------------------------- */

	/**
	 * Run the watcher and return the structured result. Establishes the baseline
	 * automatically on first run.
	 *
	 * @return array
	 */
	public static function run() {
		@set_time_limit( 0 );

		$current  = self::hash_watched_files();
		$baseline = self::get_baseline();

		$baseline_created = false;
		$changes          = [];

		if ( empty( $baseline ) || empty( $baseline['hashes'] ) || ! is_array( $baseline['hashes'] ) ) {
			// No known-good baseline yet — capture the current state as the
			// reference point. Nothing to compare against on this first pass, but
			// the injection heuristics below still run so an implant that is
			// already present is not silently blessed into the baseline.
			self::store_baseline( $current );
			$baseline_created = true;
			$baseline         = self::get_baseline();
		} else {
			$changes = self::diff( $baseline['hashes'], $current );
		}

		$injections = self::scan_injections( $current );

		$change_count    = count( $changes );
		$injection_count = count( $injections );

		return [
			'baseline'         => [
				'established_at' => $baseline['created_at'] ?? null,
				'file_count'     => isset( $baseline['hashes'] ) ? count( $baseline['hashes'] ) : 0,
				'just_created'   => $baseline_created,
			],
			'watched_count'    => count( $current ),
			'changes'          => array_slice( $changes, 0, self::MAX_REPORTED ),
			'injections'       => array_slice( $injections, 0, self::MAX_REPORTED ),
			'change_count'     => $change_count,
			'injection_count'  => $injection_count,
			'issue_count'      => $change_count + $injection_count,
		];
	}

	/**
	 * Capture a fresh known-good baseline from the current file state. Call this
	 * after cleaning a site so drift is measured from the clean point forward.
	 *
	 * @return array { established_at, file_count }
	 */
	public static function establish_baseline() {
		$current = self::hash_watched_files();
		self::store_baseline( $current );

		return [
			'established_at' => current_time( 'mysql' ),
			'file_count'     => count( $current ),
		];
	}

	/**
	 * @return array|null Stored baseline, or null when none exists.
	 */
	public static function get_baseline() {
		$baseline = get_option( self::BASELINE_OPTION, null );
		return is_array( $baseline ) ? $baseline : null;
	}

	private static function store_baseline( array $hashes ) {
		update_option(
			self::BASELINE_OPTION,
			[
				'created_at' => current_time( 'mysql' ),
				'wp_version' => get_bloginfo( 'version' ),
				'hashes'     => $hashes,
			],
			false // never autoload — this can be a large array.
		);
	}

	/* --------------------------------------------------------------------- */
	/* Baseline: hashing + diff                                              */
	/* --------------------------------------------------------------------- */

	/**
	 * Hash every watched file, keyed by its ABSPATH-relative path.
	 *
	 * @return array<string,string> rel => md5.
	 */
	private static function hash_watched_files() {
		$exts    = array_flip( self::watched_extensions() );
		$hashes  = [];
		$scanned = 0;

		foreach ( self::watched_roots() as $root ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}
			try {
				$it = new \RecursiveIteratorIterator(
					new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS )
				);
			} catch ( \Exception $e ) {
				continue;
			}

			foreach ( $it as $file ) {
				if ( $scanned >= self::MAX_FILES ) {
					break 2;
				}
				if ( ! $file->isFile() ) {
					continue;
				}
				$ext = strtolower( $file->getExtension() );
				// `.htaccess` reports an empty extension via SplFileInfo.
				if ( '' === $ext ) {
					if ( '.htaccess' !== $file->getFilename() ) {
						continue;
					}
					$ext = 'htaccess';
				}
				if ( ! isset( $exts[ $ext ] ) ) {
					continue;
				}
				if ( $file->getSize() > self::MAX_FILE_BYTES ) {
					continue;
				}

				$path = $file->getPathname();
				$md5  = @md5_file( $path );
				if ( false === $md5 ) {
					continue;
				}
				$hashes[ self::rel( $path ) ] = $md5;
				$scanned++;
			}
		}

		// Drop-ins live directly in wp-content and are individually named.
		foreach ( self::dropin_files() as $path ) {
			if ( is_readable( $path ) && filesize( $path ) <= self::MAX_FILE_BYTES ) {
				$md5 = @md5_file( $path );
				if ( false !== $md5 ) {
					$hashes[ self::rel( $path ) ] = $md5;
				}
			}
		}

		return $hashes;
	}

	/**
	 * Compare a baseline hash map against the current one.
	 *
	 * @param array<string,string> $baseline
	 * @param array<string,string> $current
	 * @return array List of { file, status: added|modified|deleted }.
	 */
	private static function diff( array $baseline, array $current ) {
		$changes = [];

		foreach ( $current as $rel => $hash ) {
			if ( ! isset( $baseline[ $rel ] ) ) {
				$changes[] = [ 'file' => $rel, 'status' => 'added' ];
			} elseif ( $baseline[ $rel ] !== $hash ) {
				$changes[] = [ 'file' => $rel, 'status' => 'modified' ];
			}
			if ( count( $changes ) >= self::MAX_REPORTED ) {
				return $changes;
			}
		}
		foreach ( $baseline as $rel => $hash ) {
			if ( ! isset( $current[ $rel ] ) ) {
				$changes[] = [ 'file' => $rel, 'status' => 'deleted' ];
			}
			if ( count( $changes ) >= self::MAX_REPORTED ) {
				break;
			}
		}

		return $changes;
	}

	/* --------------------------------------------------------------------- */
	/* Watched locations                                                     */
	/* --------------------------------------------------------------------- */

	/**
	 * Directory roots the watcher walks (active child + parent theme, mu-plugins).
	 *
	 * @return string[]
	 */
	private static function watched_roots() {
		$roots = [
			get_stylesheet_directory(),
			get_template_directory(),
			WP_CONTENT_DIR . '/mu-plugins',
		];
		return array_values( array_unique( array_filter( $roots ) ) );
	}

	/**
	 * Absolute paths of the wp-content drop-ins WordPress auto-loads.
	 *
	 * @return string[]
	 */
	private static function dropin_files() {
		$out = [];
		foreach ( [ 'db.php', 'object-cache.php', 'advanced-cache.php', 'sunrise.php', 'maintenance.php' ] as $dropin ) {
			$out[] = WP_CONTENT_DIR . '/' . $dropin;
		}
		return $out;
	}

	private static function rel( $path ) {
		return str_replace( ABSPATH, '', $path );
	}

	/* --------------------------------------------------------------------- */
	/* Injection heuristics (files + database)                               */
	/* --------------------------------------------------------------------- */

	/**
	 * Scan watched files and the database for injection signatures.
	 *
	 * @param array<string,string> $watched Current watched-file map (rel => md5)
	 *                                       — its keys tell us which files to read.
	 * @return array List of { file, reason, severity }.
	 */
	private static function scan_injections( array $watched ) {
		$findings = [];

		// ---- Files -------------------------------------------------------
		foreach ( array_keys( $watched ) as $rel ) {
			$path = ABSPATH . $rel;
			$code = @file_get_contents( $path );
			if ( false === $code ) {
				continue;
			}

			$reason = self::injection_reason( $code );
			if ( $reason ) {
				$findings[] = [
					'file'     => $rel,
					'reason'   => $reason['label'],
					'severity' => $reason['severity'],
				];
			}
			if ( count( $findings ) >= self::MAX_REPORTED ) {
				return $findings;
			}
		}

		// ---- Database ----------------------------------------------------
		foreach ( self::scan_database() as $finding ) {
			$findings[] = $finding;
			if ( count( $findings ) >= self::MAX_REPORTED ) {
				break;
			}
		}

		return $findings;
	}

	/**
	 * Inspect a blob of content (file body or stored HTML) for the two injection
	 * families and return the highest-signal match, or null.
	 *
	 * @param string $content
	 * @return array|null { label, severity }
	 */
	private static function injection_reason( $content ) {
		// 1) Hidden off-screen block linking to external URLs — SEO spam cloak.
		if ( self::has_hidden_external_links( $content ) ) {
			return [
				'label'    => __( 'Hidden off-screen block linking to external sites — the signature of SEO spam / link injection.', 'gemsecurity' ),
				'severity' => 'critical',
			];
		}

		// 2) Obfuscated code loader — require two distinct signals to avoid
		//    flagging code that merely uses base64 for legitimate reasons.
		$hits = 0;
		foreach ( self::loader_signatures() as $pattern ) {
			if ( preg_match( '/' . $pattern . '/i', $content ) ) {
				$hits++;
			}
		}
		if ( $hits >= 2 ) {
			return [
				'label'    => __( 'Obfuscated code loader (e.g. eval on decoded/inflated data) — a common malware pattern.', 'gemsecurity' ),
				'severity' => 'warning',
			];
		}

		return null;
	}

	/**
	 * True when the content contains an element pushed far off-screen that also
	 * wraps an absolute (http/https) link. Legitimate off-screen content — e.g.
	 * accessibility skip-links — points at page fragments (#main), not external
	 * URLs, which keeps the false-positive rate low.
	 *
	 * @param string $content
	 * @return bool
	 */
	private static function has_hidden_external_links( $content ) {
		// A large negative offset on a positioning/indent property (top:-10001px,
		// left:-9999px, text-indent:-9999px, …).
		$offscreen = '/(?:top|left|right|bottom|text-indent|margin-left|margin-top)\s*:\s*-\s*[1-9][0-9]{3,}\s*px/i';
		if ( ! preg_match( $offscreen, $content ) ) {
			return false;
		}
		// …co-occurring with an anchor pointing at an external absolute URL.
		$external_link = '/<a\b[^>]*\bhref\s*=\s*["\']https?:\/\//i';
		return (bool) preg_match( $external_link, $content );
	}

	/**
	 * Obfuscated-loader regexes, hex-encoded so this file does not self-match an
	 * integrity/AV scan. Decoded via {@see Helper::sig()}.
	 *
	 * @return string[]
	 */
	private static function loader_signatures() {
		$encoded = [
			'6576616c5c732a5c28',                     // eval\s*\(
			'6261736536345f6465636f64655c732a5c28',   // base64_decode\s*\(
			'677a696e666c6174655c732a5c28',           // gzinflate\s*\(
			'7374725f726f7431335c732a5c28',           // str_rot13\s*\(
			'677a756e636f6d70726573735c732a5c28',     // gzuncompress\s*\(
		];
		$out = [];
		foreach ( $encoded as $hex ) {
			$out[] = Helper::sig( $hex );
		}
		return $out;
	}

	/**
	 * Scan autoloaded options and recent post content for the hidden-external-link
	 * cloak. This style of spam is frequently stored in the database (a theme
	 * option, a "custom HTML / footer code" field, or injected post content)
	 * rather than in a PHP file.
	 *
	 * @return array List of { file, reason, severity } where `file` is a
	 *               human-readable database source label.
	 */
	private static function scan_database() {
		global $wpdb;
		$findings = [];

		$label = __( 'Hidden off-screen block linking to external sites — the signature of SEO spam / link injection.', 'gemsecurity' );

		// Options — cheaply pre-filtered in SQL to values that could plausibly
		// contain an off-screen anchor (must mention both "px" and an anchor
		// tag). Deliberately not restricted by autoload: the value name for
		// "autoloaded" changed across WordPress versions ('yes' → 'on'/'auto'),
		// and spam can live in any option. The LIKE filter + LIMIT keep it cheap.
		$options = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options}
				 WHERE option_value LIKE %s
				   AND option_value LIKE %s
				 LIMIT %d",
				'%px%',
				'%<a %',
				self::MAX_DB_OPTIONS
			),
			ARRAY_A
		);
		foreach ( (array) $options as $row ) {
			if ( self::has_hidden_external_links( (string) $row['option_value'] ) ) {
				$findings[] = [
					'file'     => sprintf( 'database: %s (%s)', 'wp_options', $row['option_name'] ),
					'reason'   => $label,
					'severity' => 'critical',
				];
			}
		}

		// Recently modified published posts/pages.
		$posts = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_title, post_content FROM {$wpdb->posts}
				 WHERE post_status = 'publish'
				   AND post_content LIKE %s
				   AND post_content LIKE %s
				 ORDER BY post_modified DESC
				 LIMIT %d",
				'%px%',
				'%<a %',
				self::MAX_DB_POSTS
			),
			ARRAY_A
		);
		foreach ( (array) $posts as $row ) {
			if ( self::has_hidden_external_links( (string) $row['post_content'] ) ) {
				$findings[] = [
					'file'     => sprintf( 'database: wp_posts #%d (%s)', (int) $row['ID'], $row['post_title'] ),
					'reason'   => $label,
					'severity' => 'critical',
				];
			}
			if ( count( $findings ) >= self::MAX_REPORTED ) {
				break;
			}
		}

		return $findings;
	}
}
