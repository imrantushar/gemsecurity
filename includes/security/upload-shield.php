<?php
namespace GemSecurity\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Upload Shield — no executable file gets onto the server through an upload.
 *
 * Layers, from earliest to last line of defence:
 *  1. Every request's $_FILES is inspected while must-use plugins load —
 *     before ANY plugin's handler (contact forms, file managers, page-builder
 *     importers that call move_uploaded_file() directly) can save the file.
 *     A blocked file's temp copy is deleted and its slot marked
 *     UPLOAD_ERR_EXTENSION, so handlers fail the upload gracefully.
 *  2. Core's wp_handle_upload / sideload prefilters (covers files fetched from
 *     a URL, which never appear in $_FILES) with a readable error message.
 *  3. `unfiltered_upload` is denied to everyone, and script-capable markup
 *     types can be dropped from the allowed MIME list.
 *  4. uploads/.htaccess forbids running scripts there (Apache/LiteSpeed), and
 *     a live probe reports whether PHP in uploads actually executes on this
 *     server — the only honest test, since nginx ignores .htaccess.
 *
 * A file is refused when ANY dot-separated part of its name is an executable
 * extension (so "shell.php.jpg", which Apache's AddHandler runs, is caught),
 * after stripping the null bytes / trailing dots and spaces used to dodge
 * naive checks; or when its content carries PHP (an image with PHP in its
 * EXIF comment is the classic polyglot); or when an SVG carries script.
 */
class UploadShield {

	/** Read this much of a file when sniffing content (head + tail). */
	const SNIFF_HEAD = 524288;
	const SNIFF_TAIL = 65536;

	private static $markup = false;

	public static function boot( $block_markup ) {
		self::$markup = (bool) $block_markup;
		try {
			self::scan_request_files();
		} catch ( \Throwable $e ) {
			// Fail open.
		}
		add_filter( 'wp_handle_upload_prefilter', [ __CLASS__, 'prefilter' ], 1 );
		add_filter( 'wp_handle_sideload_prefilter', [ __CLASS__, 'prefilter' ], 1 );
		add_filter( 'upload_mimes', [ __CLASS__, 'mimes' ], 99 );
		add_filter( 'map_meta_cap', [ __CLASS__, 'deny_unfiltered' ], 99, 2 );
	}

	/** Extensions that a web server or OS can execute. */
	public static function exec_extensions() {
		return [
			'php', 'php2', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8', 'phtml', 'pht', 'phps', 'phar', 'pgif', 'inc',
			'shtml', 'shtm', 'stm', 'cgi', 'fcgi', 'pl', 'pm', 'py', 'pyc', 'rb', 'sh', 'bash', 'zsh', 'ksh',
			'asp', 'aspx', 'ascx', 'ashx', 'asmx', 'axd', 'cer', 'asa', 'jsp', 'jspx', 'jsw', 'war', 'cfm', 'cfc',
			'exe', 'com', 'bat', 'cmd', 'msi', 'dll', 'so', 'scr', 'vbs', 'vbe', 'wsf', 'ps1', 'jar', 'htaccess',
		];
	}

	/** Script-capable markup (XSS when served from your domain). */
	public static function markup_extensions() {
		return [ 'svg', 'svgz', 'html', 'htm', 'xhtml', 'xht', 'js', 'mjs', 'swf' ];
	}

	/** Server config files that change how the directory is executed. */
	private static function config_names() {
		return [ '.htaccess', '.user.ini', 'php.ini', 'web.config', '.htpasswd' ];
	}

	/**
	 * Why a file must be refused, or '' when it is fine. Reasons are plain
	 * English (log/email text): this runs while mu-plugins load, before
	 * translations may be loaded.
	 *
	 * @param string $name Client-supplied file name.
	 * @param string $path Temp file on disk (optional, for content sniffing).
	 * @return string
	 */
	public static function verdict( $name, $path = '' ) {
		$clean = strtolower( rtrim( str_replace( "\0", '', (string) $name ), " .\t\r\n" ) );
		$clean = basename( str_replace( '\\', '/', $clean ) );

		if ( in_array( $clean, self::config_names(), true ) ) {
			return 'server configuration file';
		}

		$parts = array_map( 'trim', explode( '.', $clean ) );
		array_shift( $parts ); // The part before the first dot is the base name.
		$deny = self::exec_extensions();
		if ( self::$markup ) {
			$deny = array_merge( $deny, self::markup_extensions() );
		}
		// The final extension is checked against everything; inner ones only
		// against what a server handler executes ("shell.php.jpg" runs under
		// Apache AddHandler, but "screenshot.example.com.png" is harmless).
		$final = $parts ? $parts[ count( $parts ) - 1 ] : '';
		if ( '' !== $final && in_array( $final, $deny, true ) ) {
			return 'executable extension .' . $final;
		}
		foreach ( array_slice( $parts, 0, -1 ) as $ext ) {
			if ( preg_match( '/^(php\d?|phtml|pht|phar|cgi|fcgi|pl|py|asp|aspx|shtml|jsp)$/', $ext ) ) {
				return 'hidden executable extension .' . $ext;
			}
		}

		if ( '' === $path || ! is_file( $path ) || ! is_readable( $path ) ) {
			return '';
		}
		$last = end( $parts );
		if ( in_array( $last, [ 'zip', 'gz', 'tgz', 'bz2', 'xz', '7z', 'rar' ], true ) ) {
			return ''; // Compressed — content is not inspectable as plain bytes.
		}

		$size = (int) @filesize( $path ); // phpcs:ignore
		$fh   = @fopen( $path, 'rb' ); // phpcs:ignore
		if ( ! $fh ) {
			return '';
		}
		$buf = (string) fread( $fh, self::SNIFF_HEAD );
		if ( $size > self::SNIFF_HEAD + self::SNIFF_TAIL ) {
			fseek( $fh, -self::SNIFF_TAIL, SEEK_END );
			$buf .= (string) fread( $fh, self::SNIFF_TAIL );
		}
		fclose( $fh );

		// "<?php" (any case) and the phar stub. Not "<?=" or a bare "<?":
		// three random bytes match too often inside ordinary binary files.
		if ( false !== stripos( $buf, '<?php' ) || false !== stripos( $buf, '__halt_compiler' ) || preg_match( '/<script[^>]+language\s*=\s*["\']?php/i', $buf ) ) {
			return 'contains PHP code';
		}

		// SVG logos are fine; SVG with script or event handlers is an XSS payload.
		if ( in_array( $last, [ 'svg', 'svgz' ], true ) || false !== stripos( substr( $buf, 0, 1024 ), '<svg' ) ) {
			if ( preg_match( '/<script\b|\bon[a-z]+\s*=|javascript:|<foreignObject\b|<iframe\b|<embed\b/i', $buf ) ) {
				return 'SVG contains script';
			}
		}
		return '';
	}

	/* ------------------------------------------------------------------ */
	/* Layer 1: every request's $_FILES                                   */
	/* ------------------------------------------------------------------ */

	private static function scan_request_files() {
		if ( empty( $_FILES ) || ! is_array( $_FILES ) ) {
			return;
		}
		foreach ( $_FILES as $field => $info ) {
			if ( ! is_array( $info ) || ! isset( $info['name'] ) ) {
				continue;
			}
			// Normalise single and multi (name[]) uploads into leaf paths.
			foreach ( self::leaves( $info['name'] ) as $keys ) {
				$name = self::dig( $info['name'], $keys );
				$tmp  = isset( $info['tmp_name'] ) ? self::dig( $info['tmp_name'], $keys ) : '';
				if ( ! is_string( $name ) || '' === $name ) {
					continue;
				}
				$why = self::verdict( $name, is_string( $tmp ) ? $tmp : '' );
				/**
				 * Allow a specific upload the shield would refuse.
				 *
				 * @param bool   $allow
				 * @param string $name
				 * @param string $why
				 */
				if ( '' === $why || apply_filters( 'gemsecurity/upload_shield_allow', false, $name, $why ) ) {
					continue;
				}
				if ( is_string( $tmp ) && '' !== $tmp && is_file( $tmp ) ) {
					@unlink( $tmp ); // phpcs:ignore
				}
				self::poke( $_FILES[ $field ], $keys, UPLOAD_ERR_EXTENSION, 0 );
				self::$blocked[ strtolower( $name ) ] = $why;
				$ip  = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : ''; // phpcs:ignore
				$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : ''; // phpcs:ignore
				PluginGuard::queue_event( 'upload_blocked', 'upload:' . $ip, sprintf( '%s — %s (%s)', sanitize_file_name( $name ), $why, strtok( $uri, '?' ) ) );
			}
		}
	}

	/** Names blocked in layer 1, so the prefilter can explain why. */
	private static $blocked = [];

	/** Key paths to every leaf of a (possibly nested) $_FILES name entry. */
	private static function leaves( $node, array $prefix = [] ) {
		if ( ! is_array( $node ) ) {
			return [ $prefix ];
		}
		$out = [];
		foreach ( $node as $k => $child ) {
			$out = array_merge( $out, self::leaves( $child, array_merge( $prefix, [ $k ] ) ) );
		}
		return $out;
	}

	private static function dig( $node, array $keys ) {
		foreach ( $keys as $k ) {
			if ( ! is_array( $node ) || ! isset( $node[ $k ] ) ) {
				return null;
			}
			$node = $node[ $k ];
		}
		return $node;
	}

	/** Mark one leaf failed: error code set, temp path and size cleared. */
	private static function poke( array &$info, array $keys, $error, $size ) {
		foreach ( [ 'error' => $error, 'tmp_name' => '', 'size' => $size ] as $field => $val ) {
			if ( ! isset( $info[ $field ] ) ) {
				continue;
			}
			if ( ! $keys ) {
				$info[ $field ] = $val;
				continue;
			}
			$ref = &$info[ $field ];
			foreach ( $keys as $k ) {
				if ( ! is_array( $ref ) || ! array_key_exists( $k, $ref ) ) {
					unset( $ref );
					continue 2;
				}
				$ref = &$ref[ $k ];
			}
			$ref = $val;
			unset( $ref );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Layer 2/3: core upload paths                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * @param array $file
	 * @return array
	 */
	public static function prefilter( $file ) {
		$name = isset( $file['name'] ) ? (string) $file['name'] : '';
		$why  = isset( self::$blocked[ strtolower( $name ) ] ) ? self::$blocked[ strtolower( $name ) ] : self::verdict( $name, isset( $file['tmp_name'] ) ? (string) $file['tmp_name'] : '' );
		if ( '' !== $why && ! apply_filters( 'gemsecurity/upload_shield_allow', false, $name, $why ) ) {
			if ( ! isset( self::$blocked[ strtolower( $name ) ] ) ) {
				$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : ''; // phpcs:ignore
				PluginGuard::queue_event( 'upload_blocked', 'upload:' . $ip, sprintf( '%s — %s', sanitize_file_name( $name ), $why ) );
			}
			/* translators: %s: reason. */
			$file['error'] = sprintf( __( 'GemSecurity Upload Shield refused this file (%s).', 'gemsecurity' ), $why );
		}
		return $file;
	}

	/**
	 * @param array $mimes
	 * @return array
	 */
	public static function mimes( $mimes ) {
		$deny = self::exec_extensions();
		if ( self::$markup ) {
			$deny = array_merge( $deny, self::markup_extensions() );
		}
		foreach ( array_keys( (array) $mimes ) as $exts ) {
			foreach ( explode( '|', $exts ) as $e ) {
				if ( in_array( $e, $deny, true ) ) {
					unset( $mimes[ $exts ] );
					break;
				}
			}
		}
		return $mimes;
	}

	/** Nobody may bypass the MIME allowlist (ALLOW_UNFILTERED_UPLOADS included). */
	public static function deny_unfiltered( $caps, $cap ) {
		return 'unfiltered_upload' === $cap ? [ 'do_not_allow' ] : $caps;
	}

	/* ------------------------------------------------------------------ */
	/* Layer 4: no execution inside uploads                               */
	/* ------------------------------------------------------------------ */

	const MARKER = 'GemSecurity Upload Shield';

	/** uploads/.htaccess (kept for callers that only care about uploads). */
	public static function htaccess_path() {
		$up = wp_get_upload_dir();
		return trailingslashit( $up['basedir'] ) . '.htaccess';
	}

	/**
	 * Directories that must never run code, with the few files core itself
	 * needs reachable there. wp-content as a whole is NOT included: a rule
	 * there applies to every plugin below it, and re-allowing plugins/ would
	 * also override any password protection on the site.
	 *
	 * @return array<string,string[]> dir => allowed file names
	 */
	public static function htaccess_targets() {
		$up      = wp_get_upload_dir();
		$targets = [
			untrailingslashit( $up['basedir'] )      => [],
			untrailingslashit( ABSPATH ) . '/' . WPINC => [ 'wp-tinymce.php', 'ms-files.php' ],
			WP_LANG_DIR                              => [],
			WP_CONTENT_DIR . '/upgrade'              => [],
			WP_CONTENT_DIR . '/upgrade-temp-backup'  => [],
		];
		/**
		 * Filter the directories Upload Shield locks against script execution.
		 *
		 * @param array<string,string[]> $targets dir => allowed file names.
		 */
		$targets = (array) apply_filters( 'gemsecurity/no_exec_dirs', $targets );
		return array_filter( $targets, static function ( $dir ) {
			return is_dir( $dir );
		}, ARRAY_FILTER_USE_KEY );
	}

	/** Write/refresh the deny block in every target's .htaccess (Apache, LiteSpeed). */
	public static function install_htaccess() {
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		$exts = implode( '|', array_diff( self::exec_extensions(), [ 'htaccess', 'exe', 'msi', 'dll', 'so', 'scr', 'com', 'bat', 'cmd', 'vbs', 'vbe', 'wsf', 'ps1', 'jar' ] ) );
		$ok   = true;
		foreach ( self::htaccess_targets() as $dir => $allow ) {
			$lines = [
				'<FilesMatch "(?i)\.(' . $exts . ')(\.|$)">',
				'	<IfModule mod_authz_core.c>',
				'		Require all denied',
				'	</IfModule>',
				'	<IfModule !mod_authz_core.c>',
				'		Order allow,deny',
				'		Deny from all',
				'	</IfModule>',
				'</FilesMatch>',
			];
			foreach ( $allow as $file ) {
				$lines = array_merge( $lines, [
					'<Files "' . $file . '">',
					'	<IfModule mod_authz_core.c>',
					'		Require all granted',
					'	</IfModule>',
					'	<IfModule !mod_authz_core.c>',
					'		Order allow,deny',
					'		Allow from all',
					'	</IfModule>',
					'</Files>',
				] );
			}
			$path = $dir . '/.htaccess';
			if ( ! file_exists( $path ) && ! is_writable( $dir ) ) {
				$ok = false;
				continue;
			}
			$ok = insert_with_markers( $path, self::MARKER, $lines ) && $ok;
		}
		return $ok;
	}

	public static function remove_htaccess() {
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		$ok = true;
		foreach ( array_keys( self::htaccess_targets() ) as $dir ) {
			$path = $dir . '/.htaccess';
			if ( ! is_file( $path ) ) {
				continue;
			}
			// Cut our whole section (markers included) and keep everything else
			// byte-for-byte; delete the file only if nothing else was in it.
			$body = (string) @file_get_contents( $path ); // phpcs:ignore
			$rest = preg_replace( '/\n?# BEGIN ' . preg_quote( self::MARKER, '/' ) . '.*?# END ' . preg_quote( self::MARKER, '/' ) . '\n?/s', '', $body );
			if ( '' === trim( (string) $rest ) ) {
				@unlink( $path ); // phpcs:ignore
			} elseif ( $rest !== $body ) {
				$ok = false !== @file_put_contents( $path, $rest, LOCK_EX ) && $ok; // phpcs:ignore
			}
		}
		return $ok;
	}

	/** True when every target directory carries the block. */
	public static function htaccess_installed() {
		foreach ( array_keys( self::htaccess_targets() ) as $dir ) {
			$path = $dir . '/.htaccess';
			if ( ! is_file( $path ) || false === strpos( (string) @file_get_contents( $path ), 'BEGIN ' . self::MARKER ) ) { // phpcs:ignore
				return false;
			}
		}
		return true;
	}

	/** Relative paths of the protected directories (for the UI). */
	public static function htaccess_dirs() {
		return array_map( static function ( $dir ) {
			return str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $dir ) );
		}, array_keys( self::htaccess_targets() ) );
	}

	/**
	 * Live test: does a PHP file inside uploads run when requested?
	 *
	 * @return array { result: executes|blocked|unknown, detail, at }
	 */
	public static function probe() {
		$up   = wp_get_upload_dir();
		$name = 'gemsecurity-probe-' . wp_generate_password( 12, false ) . '.php';
		$file = trailingslashit( $up['basedir'] ) . $name;
		$mark = 'GSPROBE' . wp_generate_password( 8, false );
		$out  = [ 'result' => 'unknown', 'detail' => '', 'at' => current_time( 'mysql' ) ];

		if ( false === @file_put_contents( $file, "<?php echo '" . substr( $mark, 0, 4 ) . "' . '" . substr( $mark, 4 ) . "';" ) ) { // phpcs:ignore
			$out['detail'] = __( 'Could not write a test file to the uploads folder.', 'gemsecurity' );
			return $out;
		}
		$resp = wp_remote_get( trailingslashit( $up['baseurl'] ) . $name, [ 'timeout' => 8, 'sslverify' => false, 'redirection' => 0 ] );
		@unlink( $file ); // phpcs:ignore

		if ( is_wp_error( $resp ) ) {
			$out['detail'] = $resp->get_error_message();
			return $out;
		}
		$code = (int) wp_remote_retrieve_response_code( $resp );
		if ( false !== strpos( wp_remote_retrieve_body( $resp ), $mark ) ) {
			$out['result'] = 'executes';
			$out['detail'] = __( 'A PHP file placed in uploads ran when requested. A backdoor dropped there by any route would run too.', 'gemsecurity' );
		} else {
			$out['result'] = 'blocked';
			/* translators: %d: HTTP status. */
			$out['detail'] = sprintf( __( 'The test file did not run (HTTP %d).', 'gemsecurity' ), $code );
		}
		return $out;
	}

	/** Server config to paste where .htaccess has no effect. */
	public static function nginx_snippet() {
		$paths = [];
		foreach ( self::htaccess_dirs() as $rel ) {
			$paths[] = preg_quote( '/' . ltrim( $rel, '/' ), '#' );
		}
		return "location ~* ^(" . implode( '|', $paths ) . ")/.*\\.(php[0-9]?|phtml|phar|pht|phps|cgi|pl|py|sh)(\\.|$) {\n"
			. "    # wp-includes/js/tinymce/wp-tinymce.php and wp-includes/ms-files.php must stay reachable:\n"
			. "    # put an exact-match location for them above this block if you use the classic editor or multisite.\n"
			. "    deny all;\n}";
	}
}
