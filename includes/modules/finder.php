<?php
namespace GemSecurity\Modules;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Code & database finder — a "grep from the dashboard".
 *
 * Searches the site's own files (everything under wp-content: plugins, themes,
 * mu-plugins, drop-ins and uploads) and its database (options, posts, post meta
 * and comments) for a term, returning the file/line or table/row where it
 * occurs. Purpose-built for incident response: when a scan (or a browser) shows
 * an injected string, this locates every place it lives so it can be removed —
 * no SSH required.
 *
 * Read-only and bounded: it never modifies anything, caps how much it reads and
 * how many matches it returns, and skips binary files, so it is safe to run from
 * a web request.
 */
class Finder {

	const MAX_FILES        = 20000;
	const MAX_FILE_BYTES   = 3145728; // 3 MB — skip larger files.
	const MAX_MATCHES      = 500;     // overall cap.
	const MAX_PER_FILE     = 20;      // stop after N hits in one file.
	const MAX_DB_PER_TABLE = 100;
	const SNIPPET_LEN      = 180;

	/** Text extensions worth searching. */
	private static function text_extensions() {
		return [
			'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'inc', 'phar',
			'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'json', 'css', 'scss',
			'html', 'htm', 'xml', 'txt', 'md', 'po', 'pot', 'htaccess', 'sql', 'ini', 'conf',
		];
	}

	/**
	 * Run a search.
	 *
	 * @param string $term  Search term (literal by default).
	 * @param array  $opts  { regex: bool, scope: string[] ('files','database') }.
	 * @return array|\WP_Error
	 */
	public static function search( $term, array $opts = [] ) {
		$term = (string) $term;
		if ( strlen( trim( $term ) ) < 2 ) {
			return new \WP_Error( 'gemsecurity_search_short', __( 'Enter at least 2 characters to search.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		$regex = ! empty( $opts['regex'] );
		$scope = ! empty( $opts['scope'] ) && is_array( $opts['scope'] ) ? $opts['scope'] : [ 'files', 'database' ];

		// Build (and validate) the PCRE pattern used for file scanning.
		$pattern = $regex ? '/' . str_replace( '/', '\\/', $term ) . '/i' : '/' . preg_quote( $term, '/' ) . '/i';
		if ( false === @preg_match( $pattern, '' ) ) {
			return new \WP_Error( 'gemsecurity_search_regex', __( 'That regular expression is not valid.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		@set_time_limit( 0 );

		$files     = in_array( 'files', $scope, true ) ? self::search_files( $pattern ) : [ 'matches' => [], 'files_scanned' => 0, 'truncated' => false ];
		$database  = in_array( 'database', $scope, true ) ? self::search_database( $term, $regex ) : [ 'matches' => [], 'truncated' => false ];

		return [
			'term'          => $term,
			'regex'         => $regex,
			'scope'         => $scope,
			'files_scanned' => $files['files_scanned'],
			'file_matches'  => $files['matches'],
			'db_matches'    => $database['matches'],
			'file_count'    => count( $files['matches'] ),
			'db_count'      => count( $database['matches'] ),
			'truncated'     => $files['truncated'] || $database['truncated'],
		];
	}

	/* --------------------------------------------------------------------- */
	/* File search                                                           */
	/* --------------------------------------------------------------------- */

	/** Dependency / VCS / build directories that are never worth searching. */
	private static function skip_dirs() {
		return [ 'node_modules', '.git', '.svn', '.hg', 'bower_components', '.cache' ];
	}

	/**
	 * @param string $pattern Validated PCRE pattern.
	 * @return array { matches: array, files_scanned: int, truncated: bool }
	 */
	private static function search_files( $pattern ) {
		$exts    = array_flip( self::text_extensions() );
		$matches = [];
		$scanned = 0;
		$trunc   = false;

		// The wp-content drop-ins live directly in wp-content — search them and
		// any other top-level PHP first (tiny, and a favourite hiding spot).
		foreach ( (array) glob( WP_CONTENT_DIR . '/*.php' ) as $path ) {
			self::scan_file( $path, $pattern, $exts, $matches, $scanned );
		}

		// Search high-signal locations before the big ones, so mu-plugins, the
		// active theme and drop-ins are always fully covered even when the
		// plugins/uploads trees are large enough to hit the cap.
		$roots = array_values( array_unique( array_filter( [
			WP_CONTENT_DIR . '/mu-plugins',
			get_stylesheet_directory(),
			get_template_directory(),
			WP_CONTENT_DIR . '/plugins',
			WP_CONTENT_DIR . '/uploads',
		], 'is_dir' ) ) );

		foreach ( $roots as $root ) {
			if ( self::walk_root( $root, $pattern, $exts, $matches, $scanned ) ) {
				$trunc = true;
			}
			if ( $scanned >= self::MAX_FILES || count( $matches ) >= self::MAX_MATCHES ) {
				$trunc = true;
				break;
			}
		}

		return [ 'matches' => $matches, 'files_scanned' => $scanned, 'truncated' => $trunc ];
	}

	/**
	 * Recursively search one directory tree (pruning dependency/VCS dirs),
	 * sharing the overall file and match budget.
	 *
	 * @param string $root
	 * @param string $pattern
	 * @param array  $exts
	 * @param array  $matches  (by reference)
	 * @param int    $scanned  (by reference)
	 * @return bool Whether the budget was hit while walking this root.
	 */
	private static function walk_root( $root, $pattern, array $exts, array &$matches, &$scanned ) {
		$skip = self::skip_dirs();
		try {
			$dir    = new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS );
			$filter = new \RecursiveCallbackFilterIterator( $dir, static function ( $current ) use ( $skip ) {
				return $current->isDir() ? ! in_array( $current->getFilename(), $skip, true ) : true;
			} );
			$it = new \RecursiveIteratorIterator( $filter );
		} catch ( \Exception $e ) {
			return false;
		}

		foreach ( $it as $file ) {
			if ( $scanned >= self::MAX_FILES || count( $matches ) >= self::MAX_MATCHES ) {
				return true;
			}
			if ( $file->isFile() ) {
				self::scan_file( $file->getPathname(), $pattern, $exts, $matches, $scanned );
			}
		}
		return false;
	}

	/**
	 * Search a single file, appending any line matches (up to MAX_PER_FILE).
	 *
	 * @param string $path
	 * @param string $pattern
	 * @param array  $exts
	 * @param array  $matches (by reference)
	 * @param int    $scanned (by reference)
	 */
	private static function scan_file( $path, $pattern, array $exts, array &$matches, &$scanned ) {
		$name = basename( $path );
		$ext  = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
		if ( '' === $ext && '.htaccess' === $name ) {
			$ext = 'htaccess';
		}
		if ( ! isset( $exts[ $ext ] ) ) {
			return;
		}
		if ( ! is_file( $path ) || filesize( $path ) > self::MAX_FILE_BYTES ) {
			return;
		}

		$contents = @file_get_contents( $path );
		if ( false === $contents || '' === $contents ) {
			return;
		}
		$scanned++;
		if ( false !== strpos( $contents, "\0" ) ) {
			return; // binary.
		}
		if ( ! preg_match( $pattern, $contents ) ) {
			return;
		}

		$rel      = str_replace( ABSPATH, '', $path );
		$lines    = preg_split( '/\r\n|\r|\n/', $contents );
		$per_file = 0;
		foreach ( $lines as $i => $line ) {
			if ( preg_match( $pattern, $line ) ) {
				$matches[] = [
					'file'    => $rel,
					'line'    => $i + 1,
					'snippet' => self::snippet_line( $line ),
				];
				if ( ++$per_file >= self::MAX_PER_FILE || count( $matches ) >= self::MAX_MATCHES ) {
					break;
				}
			}
		}
	}

	/* --------------------------------------------------------------------- */
	/* Database search                                                       */
	/* --------------------------------------------------------------------- */

	/**
	 * Search the highest-signal content tables. Literal terms use LIKE; regex
	 * terms use MySQL REGEXP.
	 *
	 * @param string $term
	 * @param bool   $regex
	 * @return array { matches: array, truncated: bool }
	 */
	private static function search_database( $term, $regex ) {
		global $wpdb;
		$matches = [];
		$trunc   = false;

		$op  = $regex ? 'REGEXP' : 'LIKE';
		$val = $regex ? $term : '%' . $wpdb->esc_like( $term ) . '%';

		$queries = [
			[
				'label'  => 'wp_options',
				'sql'    => "SELECT option_id AS id, option_name AS ref, option_value AS val FROM {$wpdb->options} WHERE option_value {$op} %s LIMIT %d",
				'source' => 'wp_options',
			],
			[
				'label'  => 'wp_posts',
				'sql'    => "SELECT ID AS id, post_title AS ref, post_content AS val FROM {$wpdb->posts} WHERE post_content {$op} %s LIMIT %d",
				'source' => 'wp_posts',
			],
			[
				'label'  => 'wp_postmeta',
				'sql'    => "SELECT meta_id AS id, meta_key AS ref, meta_value AS val FROM {$wpdb->postmeta} WHERE meta_value {$op} %s LIMIT %d",
				'source' => 'wp_postmeta',
			],
			[
				'label'  => 'wp_comments',
				'sql'    => "SELECT comment_ID AS id, comment_author AS ref, comment_content AS val FROM {$wpdb->comments} WHERE comment_content {$op} %s LIMIT %d",
				'source' => 'wp_comments',
			],
		];

		foreach ( $queries as $q ) {
			$rows = $wpdb->get_results( $wpdb->prepare( $q['sql'], $val, self::MAX_DB_PER_TABLE ), ARRAY_A );
			if ( count( (array) $rows ) >= self::MAX_DB_PER_TABLE ) {
				$trunc = true;
			}
			foreach ( (array) $rows as $r ) {
				$matches[] = [
					'source'  => $q['source'],
					'id'      => (int) $r['id'],
					'ref'     => (string) $r['ref'],
					'snippet' => self::snippet_around( (string) $r['val'], $term, $regex ),
				];
				if ( count( $matches ) >= self::MAX_MATCHES ) {
					return [ 'matches' => $matches, 'truncated' => true ];
				}
			}
		}

		return [ 'matches' => $matches, 'truncated' => $trunc ];
	}

	/* --------------------------------------------------------------------- */
	/* Snippet helpers                                                       */
	/* --------------------------------------------------------------------- */

	/**
	 * Trim a matched line for display.
	 *
	 * @param string $line
	 * @return string
	 */
	private static function snippet_line( $line ) {
		$line = trim( $line );
		if ( strlen( $line ) <= self::SNIPPET_LEN ) {
			return $line;
		}
		return substr( $line, 0, self::SNIPPET_LEN ) . '…';
	}

	/**
	 * Extract a window of text around the first match inside a value.
	 *
	 * @param string $value
	 * @param string $term
	 * @param bool   $regex
	 * @return string
	 */
	private static function snippet_around( $value, $term, $regex ) {
		$value = (string) $value;
		$pos   = false;
		if ( ! $regex ) {
			$pos = stripos( $value, $term );
		}
		if ( false === $pos ) {
			// Regex, or literal not found in the raw value (serialized/escaped) —
			// fall back to the head of the value.
			return self::snippet_line( $value );
		}
		$start   = max( 0, $pos - 60 );
		$snippet = substr( $value, $start, self::SNIPPET_LEN );
		return ( $start > 0 ? '…' : '' ) . trim( $snippet ) . ( strlen( $value ) > $start + self::SNIPPET_LEN ? '…' : '' );
	}
}
