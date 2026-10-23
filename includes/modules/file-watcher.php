<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

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

	const BASELINE_OPTION    = 'gemsecurity_file_baseline';
	const REBUILD_CRON_HOOK  = 'gemsecurity_rebuild_baseline';
	const REBUILD_LOCK       = 'gemsecurity_rebaseline_lock';
	const CHECKSUMS_TRANSIENT_PREFIX = 'gemsecurity_core_checksums_';
	const CHECKSUMS_TTL      = DAY_IN_SECONDS;

	/**
	 * Wire the update-lifecycle hooks so a legitimate WordPress / plugin / theme
	 * update rebuilds the baseline instead of being reported as tampering.
	 *
	 * Core WP upgrader fires `_core_updated_successfully` / `automatic_updates_complete`
	 * / `upgrader_process_complete`. Updates deployed outside the upgrader
	 * (WP-CLI, managed hosts, Composer, git) never fire those hooks, so
	 * `admin_init` watches version drift of core *and* every plugin/theme and
	 * schedules a rebuild when any version moves.
	 *
	 * Every rebuild path funnels through {@see schedule_rebuild()}, which
	 * debounces concurrent triggers and runs the (expensive) hashing in a
	 * one-off cron job so no admin page is ever blocked by it.
	 */
	public static function init() {
		add_action( '_core_updated_successfully', [ __CLASS__, 'on_core_updated' ] );
		add_action( 'automatic_updates_complete', [ __CLASS__, 'on_auto_updates' ] );
		add_action( 'upgrader_process_complete', [ __CLASS__, 'on_upgrader_complete' ], 10, 2 );
		add_action( 'admin_init', [ __CLASS__, 'detect_version_drift' ] );
		add_action( self::REBUILD_CRON_HOOK, [ __CLASS__, 'run_scheduled_rebuild' ] );
	}

	/** @see init() */
	public static function on_core_updated() {
		self::schedule_rebuild( 'core-updated' );
	}

	/** @see init() */
	public static function on_auto_updates() {
		self::schedule_rebuild( 'auto-updates-complete' );
	}

	/**
	 * `upgrader_process_complete` fires for core, plugin, theme and translation
	 * updates. Translations don't change watched files, so ignore them.
	 *
	 * @param \WP_Upgrader $upgrader
	 * @param array        $hook_extra
	 */
	public static function on_upgrader_complete( $upgrader, $hook_extra ) {
		$type = isset( $hook_extra['type'] ) ? (string) $hook_extra['type'] : '';
		if ( in_array( $type, [ 'core', 'plugin', 'theme' ], true ) ) {
			self::schedule_rebuild( 'upgrader:' . $type );
		}
	}

	/**
	 * Rebuild the baseline when the installed version of WordPress, or any
	 * plugin/theme we have hashes for, has moved since the last baseline. This
	 * is the catch-all for deployments that bypass the WP upgrader entirely
	 * (git pull, Composer install, SFTP, container redeploy).
	 */
	public static function detect_version_drift() {
		$baseline = self::get_baseline();
		if ( empty( $baseline ) ) {
			return;
		}
		if ( ! empty( $baseline['wp_version'] ) && $baseline['wp_version'] !== get_bloginfo( 'version' ) ) {
			self::schedule_rebuild( 'core-version-drift' );
			return;
		}

		$old = isset( $baseline['extension_versions'] ) && is_array( $baseline['extension_versions'] ) ? $baseline['extension_versions'] : [];
		$new = self::extension_versions();
		if ( $old !== $new ) {
			// Find the first slug that moved — useful log breadcrumb.
			$changed = '';
			foreach ( $new as $slug => $ver ) {
				if ( ! isset( $old[ $slug ] ) || $old[ $slug ] !== $ver ) {
					$changed = $slug;
					break;
				}
			}
			if ( ! $changed ) {
				foreach ( $old as $slug => $ver ) {
					if ( ! isset( $new[ $slug ] ) ) {
						$changed = $slug . ' (removed)';
						break;
					}
				}
			}
			self::schedule_rebuild( 'ext-version-drift:' . $changed );
		}
	}

	/**
	 * Debounced scheduler: at most one baseline rebuild in flight at a time.
	 * The 5-minute lock covers bursts (bulk plugin updates, concurrent admin
	 * requests both detecting the drift) by collapsing them into one run.
	 *
	 * @param string $reason Short tag for the log entry.
	 */
	private static function schedule_rebuild( $reason ) {
		// Transient-based lock. If one is already pending, do nothing.
		if ( false !== get_transient( self::REBUILD_LOCK ) ) {
			return;
		}
		set_transient( self::REBUILD_LOCK, $reason, 5 * MINUTE_IN_SECONDS );

		// Already in a cron context? Just run it — scheduling nested events
		// would just defer the work by one tick.
		if ( wp_doing_cron() ) {
			self::run_scheduled_rebuild( $reason );
			return;
		}

		if ( ! wp_next_scheduled( self::REBUILD_CRON_HOOK, [ $reason ] ) ) {
			wp_schedule_single_event( time() + 5, self::REBUILD_CRON_HOOK, [ $reason ] );
		}
	}

	/**
	 * Cron callback. Rebuilds the baseline, releases the lock, and logs the
	 * event. `$reason` is forwarded from {@see schedule_rebuild()} so the
	 * audit log says *why* a baseline rotated — important for forensics when
	 * reviewing whether a rebuild was legitimate.
	 *
	 * @param string $reason
	 */
	public static function run_scheduled_rebuild( $reason = '' ) {
		// Flush the cached checksum manifest — the installed WP version may
		// have moved, so the old cached manifest no longer applies.
		self::flush_checksums_cache();

		$result = self::establish_baseline();
		delete_transient( self::REBUILD_LOCK );

		if ( class_exists( Logger::class ) ) {
			Logger::log(
				'file_baseline_rebuilt',
				sprintf(
					/* translators: 1 reason tag, 2 file count */
					__( 'File baseline rebuilt (reason: %1$s, %2$d file(s) hashed).', 'gemsecurity' ),
					$reason ?: 'unspecified',
					(int) ( $result['file_count'] ?? 0 )
				),
				Logger::SEVERITY_INFO
			);
		}
	}

	/**
	 * Bounds so the watcher is always safe to run inside a web request.
	 * MAX_FILES is the *default* cap — see {@see max_files()}, which lets an
	 * addon raise it when it also widens the watched roots.
	 */
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

			// Self-heal: any change that lands inside WordPress core and matches
			// the official checksum for the installed version is a legitimate
			// core update, not tampering. Drop it from the diff and absorb the
			// new hashes into the baseline so the next scan is quiet.
			$changes = self::absorb_legitimate_core_updates( $changes, $current, $baseline['hashes'] );
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
				'created_at'         => current_time( 'mysql' ),
				'wp_version'         => get_bloginfo( 'version' ),
				'extension_versions' => self::extension_versions(),
				'hashes'             => $hashes,
			],
			false // never autoload — this can be a large array.
		);
	}

	/**
	 * Current version strings for every installed plugin and theme, keyed by
	 * their canonical slug (plugin basename or theme stylesheet name). Used by
	 * {@see detect_version_drift()} to catch upgrades that bypass the WP
	 * upgrader (git pull, Composer, SFTP, container redeploy).
	 *
	 * @return array<string,string>
	 */
	private static function extension_versions() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$out = [];

		foreach ( (array) get_plugins() as $file => $data ) {
			$out[ 'plugin:' . $file ] = isset( $data['Version'] ) ? (string) $data['Version'] : '';
		}

		foreach ( (array) wp_get_themes() as $slug => $theme ) {
			$out[ 'theme:' . $slug ] = (string) $theme->get( 'Version' );
		}

		ksort( $out );
		return $out;
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
		$max     = self::max_files();

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
				if ( $scanned >= $max ) {
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

	/**
	 * Drop changes for WordPress core files that are legitimate for the
	 * installed version — matching the official WP.org manifest, or removed
	 * from core across versions — and silently refresh the baseline for them
	 * so the next scan is clean. Files outside core (or ones whose current
	 * hash does NOT match the official manifest) are left in the diff.
	 *
	 * If the manifest is unreachable (network error, unknown version) we skip
	 * the entire pass and *return the changes untouched* rather than
	 * absorbing. Blessing files we can't verify would be worse than the
	 * transient false positive.
	 *
	 * @param array $changes  Diff from {@see diff()}.
	 * @param array $current  rel => md5 (current state).
	 * @param array $baseline rel => md5 (stored baseline).
	 * @return array Filtered change list.
	 */
	private static function absorb_legitimate_core_updates( array $changes, array $current, array $baseline ) {
		if ( empty( $changes ) ) {
			return $changes;
		}
		$checksums = self::core_checksums();
		if ( empty( $checksums ) ) {
			return $changes;
		}

		$kept       = [];
		$absorbed   = false;
		$new_hashes = $baseline;
		foreach ( $changes as $change ) {
			$rel    = isset( $change['file'] ) ? (string) $change['file'] : '';
			$status = isset( $change['status'] ) ? $change['status'] : '';
			$in_manifest = isset( $checksums[ $rel ] );
			$in_core     = self::is_core_path( $rel );

			if ( 'deleted' === $status ) {
				// Baseline had the file, current state doesn't. If it was a
				// core file that the new manifest no longer lists, it was
				// legitimately removed between versions — drop from baseline
				// silently. Core files still in the manifest, or anything
				// outside core, keep as a finding.
				if ( $in_core && ! $in_manifest ) {
					unset( $new_hashes[ $rel ] );
					$absorbed = true;
					continue;
				}
				$kept[] = $change;
				continue;
			}

			if ( ! $in_manifest ) {
				$kept[] = $change; // Not a core file — keep the finding.
				continue;
			}

			$hash = isset( $current[ $rel ] ) ? $current[ $rel ] : null;
			if ( $hash && $hash === $checksums[ $rel ] ) {
				// Legitimate core content for this version — absorb it.
				$new_hashes[ $rel ] = $hash;
				$absorbed           = true;
				continue;
			}

			// Core file whose hash does NOT match the official manifest — this
			// is a real tampering finding, keep it.
			$kept[] = $change;
		}

		if ( $absorbed ) {
			self::store_baseline( $new_hashes );
		}

		return $kept;
	}

	/**
	 * Is this ABSPATH-relative path inside WordPress core?
	 *
	 * @param string $rel
	 * @return bool
	 */
	private static function is_core_path( $rel ) {
		return 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' );
	}

	/**
	 * The official core file → md5 manifest for the installed version.
	 *
	 * Cached locally in a 24h transient so a scan does not depend on
	 * api.wordpress.org being reachable at that moment, and so repeat calls
	 * within the request are free. WordPress core also caches internally via
	 * `wp_update_core_checksums` transient, but that one is only populated
	 * when the core update system runs — not every scan path visits it, and
	 * if it is cleared the next scan silently loses the entire self-heal pass.
	 *
	 * @return array<string,string> rel => md5. Empty when the manifest is
	 *                              unavailable (caller must treat as "cannot
	 *                              verify" and skip the self-heal, not
	 *                              "nothing to absorb").
	 */
	private static function core_checksums() {
		static $cache = null;
		if ( null !== $cache ) {
			return $cache;
		}

		$version = get_bloginfo( 'version' );
		$locale  = get_locale();
		$key     = self::CHECKSUMS_TRANSIENT_PREFIX . md5( $version . '|' . $locale );

		$sums = get_transient( $key );
		if ( is_array( $sums ) && ! empty( $sums ) ) {
			return $cache = $sums;
		}

		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		if ( ! function_exists( 'get_core_checksums' ) ) {
			return $cache = [];
		}

		$sums = get_core_checksums( $version, $locale );
		if ( empty( $sums ) || ! is_array( $sums ) ) {
			$sums = get_core_checksums( $version, 'en_US' );
		}
		$sums = is_array( $sums ) ? $sums : [];

		if ( ! empty( $sums ) ) {
			set_transient( $key, $sums, self::CHECKSUMS_TTL );
		}

		return $cache = $sums;
	}

	/**
	 * Clear every cached checksum manifest. Called when the baseline is
	 * rebuilt because the installed WP version may have changed, which would
	 * invalidate any manifest cached under the old version/locale key.
	 */
	private static function flush_checksums_cache() {
		global $wpdb;
		$like = $wpdb->esc_like( '_transient_' . self::CHECKSUMS_TRANSIENT_PREFIX ) . '%';
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $like ) );
		$like = $wpdb->esc_like( '_transient_timeout_' . self::CHECKSUMS_TRANSIENT_PREFIX ) . '%';
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $like ) );
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

		/**
		 * Directories the baseline covers.
		 *
		 * There is exactly one file-change baseline on a site. Pro widens it to
		 * core / plugins / all themes through this filter rather than running a
		 * second baseline of its own — two baselines meant two snapshots, two
		 * crons and two "files changed" lists over overlapping trees.
		 *
		 * Widening this widens *hashing* only. The injection heuristics run
		 * over {@see heuristic_roots()}, which is deliberately not filterable.
		 *
		 * @param string[] $roots Absolute directory paths.
		 */
		$roots = (array) apply_filters( 'gemsecurity/file_watcher/roots', $roots );

		return array_values( array_unique( array_filter( $roots ) ) );
	}

	/**
	 * Directories whose *contents* are worth pattern-matching.
	 *
	 * Only the locations with no authoritative checksum. WordPress core has
	 * one — {@see Scanner::scan_core_integrity()} verifies it file by file
	 * against api.wordpress.org — so running content heuristics over core adds
	 * nothing and costs a great deal: core legitimately ships gzinflate/eval
	 * idioms (class-wp-http-encoding.php, class-pclzip.php, Requests, SimplePie)
	 * and minified assets that match the hidden-off-screen-block signature
	 * (wp-tinymce.js). Every one of those was reported as malware the moment
	 * the baseline scopes were widened to include wp-admin and wp-includes.
	 *
	 * Not filterable on purpose: an addon may widen what is hashed, but
	 * widening what is pattern-matched is how a scanner starts crying wolf.
	 *
	 * @return string[]
	 */
	private static function heuristic_roots() {
		$roots = [
			get_stylesheet_directory(),
			get_template_directory(),
			WP_CONTENT_DIR . '/mu-plugins',
		];
		return array_values( array_unique( array_filter( $roots ) ) );
	}

	/**
	 * Is this ABSPATH-relative path inside a directory we pattern-match?
	 *
	 * @param string $rel
	 * @return bool
	 */
	private static function is_heuristic_target( $rel ) {
		$abs = wp_normalize_path( ABSPATH . $rel );
		foreach ( self::heuristic_roots() as $root ) {
			if ( 0 === strpos( $abs, trailingslashit( wp_normalize_path( $root ) ) ) ) {
				return true;
			}
		}
		// Drop-ins sit loose in wp-content and are watched individually.
		return in_array( $abs, array_map( 'wp_normalize_path', self::dropin_files() ), true );
	}

	/**
	 * Upper bound on files hashed in one pass.
	 *
	 * @return int
	 */
	private static function max_files() {
		/**
		 * Filter the file cap. Anything adding roots via
		 * `gemsecurity/file_watcher/roots` should raise this to match, or the
		 * walk stops part-way through and the diff reports phantom removals.
		 *
		 * @param int $max
		 */
		return max( 1, (int) apply_filters( 'gemsecurity/file_watcher/max_files', self::MAX_FILES ) );
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
			// Hashed-but-not-heuristic locations (core, when Pro widens the
			// baseline) are diffed for change and left alone otherwise.
			if ( ! self::is_heuristic_target( $rel ) ) {
				continue;
			}

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
