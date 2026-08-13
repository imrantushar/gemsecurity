<?php
namespace GemSecurity\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Auto-executed code inventory: must-use plugins, their nested payloads, and the
 * wp-content drop-ins.
 *
 * WordPress auto-executes every top-level *.php file in wp-content/mu-plugins/
 * on every request, but the Plugins → Must-Use screen only lists files that
 * carry a plugin header. A headerless dropper — most notoriously a weaponised
 * index.php masquerading as the "Silence is golden" stub — therefore runs while
 * staying completely invisible in wp-admin.
 *
 * Three further auto-execution vectors are just as invisible and are covered here
 * too:
 *   - Drop-ins: db.php, object-cache.php, advanced-cache.php, sunrise.php and
 *     maintenance.php in wp-content/ are loaded by core with no UI listing at
 *     all. A malicious db.php is a favourite persistence mechanism.
 *   - Nested payloads: WordPress only auto-loads top-level mu-plugin files, but a
 *     top-level "loader" can pull in PHP from a subdirectory, hiding the real
 *     payload one level down where a top-level-only scan never looks.
 *   - Relocation: defining WPMU_PLUGIN_DIR to a non-standard path moves the whole
 *     mu-plugins directory somewhere the site owner may not expect.
 *
 * This inventory lists every one of these auto-loaded files (header or not) so a
 * site owner can spot the ones they never installed, and flags the tell-tale
 * signs of a malicious drop.
 */
class MuPlugins {

	/** Bound the nested walk so the inventory is always web-request safe. */
	const MAX_NESTED_FILES = 1000;

	/**
	 * Drop-in files WordPress auto-loads from wp-content/ (no admin listing).
	 *
	 * @return string[]
	 */
	private static function dropin_names() {
		return [ 'db.php', 'object-cache.php', 'advanced-cache.php', 'sunrise.php', 'maintenance.php' ];
	}

	/**
	 * @return array {
	 *   dir_exists: bool,
	 *   dir: string,          // relative path
	 *   relocated: bool,      // WPMU_PLUGIN_DIR points outside the default location
	 *   count: int,
	 *   suspicious_count: int,
	 *   items: array<int,array>
	 * }
	 */
	public static function inventory() {
		$dir         = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		$default_dir = WP_CONTENT_DIR . '/mu-plugins';
		$relocated   = wp_normalize_path( untrailingslashit( $dir ) ) !== wp_normalize_path( $default_dir );

		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		$items      = [];
		$suspicious = 0;

		$add = static function ( array $item ) use ( &$items, &$suspicious ) {
			if ( 'ok' !== $item['severity'] ) {
				$suspicious++;
			}
			$items[] = $item;
		};

		// ---- Top-level mu-plugin files -----------------------------------
		$has_subdir_loader = false;
		if ( is_dir( $dir ) ) {
			$files = glob( trailingslashit( $dir ) . '*.php' );
			$files = is_array( $files ) ? $files : [];

			foreach ( $files as $path ) {
				if ( ! is_file( $path ) ) {
					continue;
				}

				$contents = (string) @file_get_contents( $path );
				$header   = get_plugin_data( $path, false, false );
				$name     = ! empty( $header['Name'] ) ? $header['Name'] : '';
				$has_head = '' !== $name;
				$stub     = self::is_silence_stub( $contents );

				if ( self::is_subdir_loader( $contents ) ) {
					$has_subdir_loader = true;
				}

				$reasons = self::suspicion_reasons( basename( $path ), $contents, $has_head, $stub );
				$add( [
					'file'       => basename( $path ),
					'path'       => self::rel( $path ),
					'type'       => 'mu-plugin',
					'name'       => $has_head ? $name : '—',
					'version'    => ! empty( $header['Version'] ) ? $header['Version'] : '',
					'has_header' => $has_head,
					'is_stub'    => $stub,
					'size'       => size_format( (int) @filesize( $path ) ),
					'modified'   => gmdate( 'Y-m-d H:i', (int) @filemtime( $path ) ),
					'severity'   => self::severity( $reasons ),
					'reason'     => $reasons ? implode( '; ', $reasons ) : '',
				] );
			}

			// ---- Nested payloads -----------------------------------------
			// WordPress does not auto-load these, so we only surface a nested
			// file when it carries a concrete malware marker (headerless nested
			// includes are normal and would otherwise be noise). A top-level
			// loader that pulls in a subdirectory is itself worth noting.
			foreach ( self::nested_suspicious( $dir ) as $item ) {
				$add( $item );
			}
		}

		// ---- Drop-ins ----------------------------------------------------
		foreach ( self::dropin_names() as $dropin ) {
			$path = WP_CONTENT_DIR . '/' . $dropin;
			if ( ! is_file( $path ) ) {
				continue;
			}
			$contents = (string) @file_get_contents( $path );
			$markers  = self::malware_reasons( $contents );
			$sev      = empty( $markers ) ? 'ok' : ( self::has_hard_marker( $markers ) ? 'critical' : 'warning' );
			$add( [
				'file'       => $dropin,
				'path'       => self::rel( $path ),
				'type'       => 'dropin',
				'name'       => sprintf( __( 'Drop-in (%s)', 'gemsecurity' ), $dropin ),
				'version'    => '',
				'has_header' => false,
				'is_stub'    => false,
				'size'       => size_format( (int) @filesize( $path ) ),
				'modified'   => gmdate( 'Y-m-d H:i', (int) @filemtime( $path ) ),
				'severity'   => $sev,
				'reason'     => $markers
					? implode( '; ', $markers )
					: __( 'auto-executed drop-in — safe if you (or a caching/debug plugin) installed it', 'gemsecurity' ),
			] );
		}

		// Suspicious first, then most-recently-modified.
		usort( $items, static function ( $a, $b ) {
			$rank = [ 'critical' => 0, 'warning' => 1, 'ok' => 2 ];
			if ( $rank[ $a['severity'] ] !== $rank[ $b['severity'] ] ) {
				return $rank[ $a['severity'] ] <=> $rank[ $b['severity'] ];
			}
			return strcmp( $b['modified'], $a['modified'] );
		} );

		return [
			'dir_exists'       => is_dir( $dir ),
			'dir'              => self::rel( untrailingslashit( $dir ) ),
			'relocated'        => $relocated,
			'has_loader'       => $has_subdir_loader,
			'count'            => count( $items ),
			'suspicious_count' => $suspicious,
			'items'            => $items,
		];
	}

	/**
	 * ABSPATH-relative, normalised path.
	 *
	 * @param string $path
	 * @return string
	 */
	private static function rel( $path ) {
		return str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $path ) );
	}

	/**
	 * Walk subdirectories of the mu-plugins dir and return items for any nested
	 * PHP file carrying a concrete malware marker.
	 *
	 * @param string $dir
	 * @return array<int,array>
	 */
	private static function nested_suspicious( $dir ) {
		$out     = [];
		$scanned = 0;
		try {
			$it = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS )
			);
		} catch ( \Exception $e ) {
			return $out;
		}

		foreach ( $it as $file ) {
			if ( $scanned >= self::MAX_NESTED_FILES ) {
				break;
			}
			if ( ! $file->isFile() ) {
				continue;
			}
			// Top-level files are handled separately; only look one or more
			// directories deep.
			if ( wp_normalize_path( $file->getPath() ) === wp_normalize_path( untrailingslashit( $dir ) ) ) {
				continue;
			}
			if ( 'php' !== strtolower( $file->getExtension() ) ) {
				continue;
			}
			$scanned++;

			$contents = (string) @file_get_contents( $file->getPathname() );
			$markers  = self::malware_reasons( $contents );
			if ( empty( $markers ) ) {
				continue;
			}
			$out[] = [
				'file'       => $file->getFilename(),
				'path'       => self::rel( $file->getPathname() ),
				'type'       => 'mu-plugin-nested',
				'name'       => __( 'Nested mu-plugin payload', 'gemsecurity' ),
				'version'    => '',
				'has_header' => false,
				'is_stub'    => false,
				'size'       => size_format( (int) $file->getSize() ),
				'modified'   => gmdate( 'Y-m-d H:i', (int) $file->getMTime() ),
				'severity'   => self::has_hard_marker( $markers ) ? 'critical' : 'warning',
				'reason'     => implode( '; ', $markers ),
			];
		}

		return $out;
	}

	/**
	 * Whether the code dynamically includes sibling files from its own directory
	 * — the "top-level loader hiding the payload in a subfolder" pattern.
	 *
	 * @param string $contents
	 * @return bool
	 */
	private static function is_subdir_loader( $contents ) {
		$sig = static function ( $hex ) {
			return (string) hex2bin( $hex );
		};
		$self_dir = false !== stripos( $contents, $sig( '5f5f4449525f5f' ) )            // __DIR__
			|| false !== stripos( $contents, $sig( '6469726e616d6528' ) );               // dirname(
		$enumerate = false !== stripos( $contents, $sig( '676c6f6228' ) )                // glob(
			|| false !== stripos( $contents, $sig( '7363616e64697228' ) )                // scandir(
			|| false !== stripos( $contents, $sig( '6f70656e64697228' ) );               // opendir(
		$includes = (bool) preg_match( '/\b(?:include|require)(?:_once)?\b/i', $contents );

		return $self_dir && $enumerate && $includes;
	}

	/**
	 * Whether a file is an innocuous placeholder (only PHP open tag / comments /
	 * whitespace once code is stripped) — the legitimate "Silence is golden" stub.
	 *
	 * @param string $contents
	 * @return bool
	 */
	private static function is_silence_stub( $contents ) {
		$code = preg_replace( '#/\*.*?\*/#s', '', $contents );      // block comments.
		$code = preg_replace( '#(^|\s)//.*$#m', '', (string) $code ); // line comments.
		$code = preg_replace( '#(^|\s)\#.*$#m', '', (string) $code ); // hash comments.
		$code = str_ireplace( [ '<?php', '<?', '?>' ], '', (string) $code );
		return '' === trim( (string) $code );
	}

	/**
	 * Reasons a mu-plugin file looks malicious. Literals are hex-encoded so this
	 * file cannot self-flag an antivirus/integrity scan.
	 *
	 * @param string $file
	 * @param string $contents
	 * @param bool   $has_header
	 * @param bool   $is_stub
	 * @return string[]
	 */
	private static function suspicion_reasons( $file, $contents, $has_header, $is_stub ) {
		$reasons = self::malware_reasons( $contents );

		// Structural red flag: auto-loaded, has real code, but no plugin header
		// (a legitimate mu-plugin normally identifies itself).
		if ( ! $has_header && ! $is_stub && empty( $reasons ) ) {
			$reasons[] = __( 'auto-loaded file with no plugin header — review it', 'gemsecurity' );
		}

		return $reasons;
	}

	/**
	 * Concrete malware markers in a blob of code (no structural heuristics). Used
	 * for top-level mu-plugins, their nested payloads and the drop-ins alike.
	 *
	 * Literals are hex-encoded so this file cannot self-flag an antivirus /
	 * integrity scan.
	 *
	 * @param string $contents
	 * @return string[]
	 */
	private static function malware_reasons( $contents ) {
		$reasons = [];
		$sig     = static function ( $hex ) {
			return (string) hex2bin( $hex );
		};
		$has = static function ( $needle ) use ( $contents ) {
			return '' !== $needle && false !== stripos( $contents, $needle );
		};

		// Admin-hiding filter.
		if ( $has( $sig( '7072655f757365725f7175657279' ) ) ) { // pre_user_query
			$reasons[] = __( 'contains code that filters the administrator list (hidden-admin back-door)', 'gemsecurity' );
		}
		// Client-side injection markers.
		if ( $has( $sig( '66616b655f63617074636861' ) ) || $has( $sig( '5f3078' ) ) ) { // fake_captcha / _0x
			$reasons[] = __( 'contains an obfuscated script-injection payload', 'gemsecurity' );
		}
		// Execute-obfuscated-payload combo.
		$has_eval = (bool) preg_match( '/' . $sig( '6576616c' ) . '\s*\(/i', $contents ); // eval(
		$decoders = $has( $sig( '6261736536345f6465636f6465' ) ) // base64_decode
			|| $has( $sig( '677a696e666c617465' ) )               // gzinflate
			|| $has( $sig( '7374725f726f743133' ) )               // str_rot13
			|| $has( $sig( '61746f6228' ) );                      // atob(
		if ( $has_eval && $decoders ) {
			$reasons[] = __( 'executes an obfuscated / encoded payload', 'gemsecurity' );
		}

		return $reasons;
	}

	/**
	 * Whether any of the given reasons is a concrete malware marker (as opposed
	 * to the soft "no plugin header" structural note).
	 *
	 * @param string[] $reasons
	 * @return bool
	 */
	private static function has_hard_marker( $reasons ) {
		foreach ( $reasons as $r ) {
			if ( false === strpos( $r, 'no plugin header' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param string[] $reasons
	 * @return string 'ok' | 'warning' | 'critical'.
	 */
	private static function severity( $reasons ) {
		if ( empty( $reasons ) ) {
			return 'ok';
		}
		// Any concrete malware marker is critical; a bare "no header" note is a warning.
		foreach ( $reasons as $r ) {
			if ( false === strpos( $r, 'no plugin header' ) ) {
				return 'critical';
			}
		}
		return 'warning';
	}
}
