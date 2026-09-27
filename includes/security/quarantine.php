<?php
namespace GemSecurity\Security;

use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The site's single quarantine store.
 *
 * Quarantine is "move, don't delete": a suspicious file is renamed into a
 * web-inaccessible folder under uploads and indexed, so the action is always
 * reversible. Injected database payloads are snapshotted the same way, with
 * the original value held in the index instead of on disk.
 *
 * There used to be two of these — one behind Incident Response and one behind
 * the Pro malware scanner — writing into the *same* directory but keeping
 * separate indexes, so a file quarantined by one was invisible (and
 * unrestorable) in the other. Both now go through this class, and the legacy
 * indexes are folded in on upgrade by {@see migrate_legacy()}.
 *
 * Entries are keyed by id. Shape:
 *   id             string  Index key; a file entry is stored at "<id>.quar".
 *   type           string  'file' | 'db'
 *   label          string  Human label (root-relative path, or option/post ref)
 *   relative       string  Root-relative path for file entries
 *   original       string  Absolute original path for file entries
 *   db_source      string  For db entries: 'option' | 'post'
 *   db_ref         string  For db entries: the option name or post ID
 *   original       string  For db entries: the original value, verbatim
 *   quarantined_at string  MySQL datetime
 */
class Quarantine {

	const OPTION = 'gemsecurity_quarantine';

	/** Legacy Pro state option whose ['quarantine'] map is folded in on upgrade. */
	const LEGACY_PRO_OPTION = 'gemsecurity_pro_malware';

	/**
	 * Core files WordPress cannot boot without. If one of these is infected the
	 * answer is to replace it from a clean copy of core, not to move it away
	 * and take the site down.
	 */
	const PROTECTED = [ 'wp-config.php', 'wp-load.php', 'wp-settings.php', 'wp-blog-header.php', 'index.php' ];

	/* ------------------------------------------------------------------ */
	/* Store                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * The quarantine directory, created and hard-denied on first use.
	 *
	 * @return string
	 */
	public static function dir() {
		$up  = wp_get_upload_dir();
		$dir = trailingslashit( $up['basedir'] ) . 'gemsecurity-quarantine';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
			// Both directives: Require is Apache 2.4, Deny is 2.2.
			@file_put_contents( $dir . '/.htaccess', "Require all denied\nDeny from all\n" ); // phpcs:ignore
			@file_put_contents( $dir . '/index.php', "<?php // Silence is golden.\n" ); // phpcs:ignore
		}
		return $dir;
	}

	/**
	 * Every entry, keyed by id.
	 *
	 * @return array<string,array>
	 */
	public static function all() {
		$store = get_option( self::OPTION, [] );
		return is_array( $store ) ? $store : [];
	}

	/**
	 * Entries as a plain list, newest first — what the REST controllers return.
	 *
	 * @return array<int,array>
	 */
	public static function items() {
		$items = array_values( self::all() );
		usort( $items, static function ( $a, $b ) {
			return strcmp( (string) ( $b['quarantined_at'] ?? '' ), (string) ( $a['quarantined_at'] ?? '' ) );
		} );
		return $items;
	}

	/**
	 * @param string $id
	 * @return array|null
	 */
	public static function get( $id ) {
		$store = self::all();
		return isset( $store[ $id ] ) ? $store[ $id ] : null;
	}

	/**
	 * @param array<string,array> $store
	 * @return void
	 */
	public static function save( array $store ) {
		update_option( self::OPTION, $store, false );
	}

	/**
	 * Drop one entry from the index without touching the stored payload.
	 *
	 * @param string $id
	 * @return void
	 */
	public static function forget( $id ) {
		$store = self::all();
		unset( $store[ $id ] );
		self::save( $store );
	}

	/* ------------------------------------------------------------------ */
	/* Files                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Move a file into quarantine.
	 *
	 * @param string $path Absolute path, anywhere inside the WordPress install.
	 * @return array|\WP_Error The stored entry.
	 */
	public static function add_file( $path ) {
		$abs  = wp_normalize_path( (string) $path );
		$root = wp_normalize_path( untrailingslashit( ABSPATH ) );

		// Anywhere in the install, not just wp-content: real infections drop
		// their stubs into wp-admin and wp-includes too. The plugin's own
		// directory is off limits so a scan can never quarantine the scanner.
		if ( '' === $abs || 0 !== strpos( $abs, $root ) || false !== strpos( $abs, '/gemsecurity' ) ) {
			return new \WP_Error(
				'gemsecurity_quarantine_denied',
				__( 'That file is outside the WordPress installation.', 'gemsecurity' ),
				[ 'status' => 400 ]
			);
		}

		if ( in_array( basename( $abs ), self::PROTECTED, true ) && dirname( $abs ) === $root ) {
			return new \WP_Error(
				'gemsecurity_quarantine_protected',
				sprintf(
					/* translators: %s: file name. */
					__( '%s is required to run WordPress. Replace it with a clean copy instead of quarantining it.', 'gemsecurity' ),
					basename( $abs )
				),
				[ 'status' => 400 ]
			);
		}

		if ( ! is_file( $abs ) ) {
			return new \WP_Error( 'gemsecurity_quarantine_missing', __( 'File no longer exists.', 'gemsecurity' ), [ 'status' => 404 ] );
		}

		$id   = md5( $abs . microtime() );
		$dest = self::dir() . '/' . $id . '.quar';

		if ( ! @rename( $abs, $dest ) ) { // phpcs:ignore
			return new \WP_Error( 'gemsecurity_quarantine_failed', __( 'Could not move the file.', 'gemsecurity' ), [ 'status' => 500 ] );
		}

		$relative = str_replace( wp_normalize_path( ABSPATH ), '', $abs );

		$store        = self::all();
		$store[ $id ] = [
			'id'             => $id,
			'type'           => 'file',
			'original'       => $abs,
			'relative'       => $relative,
			'label'          => $relative,
			'quarantined_at' => current_time( 'mysql' ),
		];
		self::save( $store );

		Logger::log( 'quarantine', sprintf( 'Quarantined %s.', $relative ), Logger::SEVERITY_WARNING );

		return $store[ $id ];
	}

	/**
	 * Record a database snapshot (an injected option or post value that was
	 * excised). The caller has already written the cleaned value.
	 *
	 * @param string $source   'option' | 'post'.
	 * @param string $ref      Option name or post ID.
	 * @param string $original The original value, verbatim.
	 * @param string $label    Human label for the UI.
	 * @return array The stored entry.
	 */
	public static function add_db( $source, $ref, $original, $label = '' ) {
		$id           = md5( 'db:' . $source . ':' . $ref . ':' . microtime() );
		$store        = self::all();
		$store[ $id ] = [
			'id'             => $id,
			'type'           => 'db',
			'db_source'      => (string) $source,
			'db_ref'         => (string) $ref,
			'original'       => (string) $original,
			'label'          => $label ? (string) $label : sprintf( '%s: %s', $source, $ref ),
			'quarantined_at' => current_time( 'mysql' ),
		];
		self::save( $store );

		return $store[ $id ];
	}

	/**
	 * Put a quarantined file back where it came from.
	 *
	 * Database entries are not handled here — restoring one means writing a
	 * value back into an option or a post, which is the caller's job; use
	 * {@see get()} and {@see forget()} for those.
	 *
	 * @param string $id
	 * @return true|\WP_Error
	 */
	public static function restore_file( $id ) {
		$entry = self::get( $id );
		if ( ! $entry ) {
			return new \WP_Error( 'gemsecurity_restore_missing', __( 'Quarantine entry not found.', 'gemsecurity' ), [ 'status' => 404 ] );
		}
		if ( 'file' !== ( $entry['type'] ?? 'file' ) ) {
			return new \WP_Error( 'gemsecurity_restore_type', __( 'That entry is a database snapshot, not a file.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		$src = self::dir() . '/' . $id . '.quar';
		$dst = $entry['original'];

		if ( ! is_file( $src ) || ! @rename( $src, $dst ) ) { // phpcs:ignore
			return new \WP_Error( 'gemsecurity_restore_failed', __( 'Could not restore the file.', 'gemsecurity' ), [ 'status' => 500 ] );
		}

		self::forget( $id );
		Logger::log( 'quarantine_restore', sprintf( 'Restored %s.', $entry['label'] ), Logger::SEVERITY_NOTICE );
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Upgrade                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * Fold the two legacy indexes into this one.
	 *
	 * The old Incident Response index was a *list* of
	 * `[ id, orig, stored, time ]`; the old Pro malware index was a keyed map
	 * living inside the Pro scanner's state option. Both wrote their payloads
	 * into this same directory, so nothing has to move on disk — only the
	 * bookkeeping is merged. Idempotent: entries already keyed by id are left
	 * alone, and the legacy Pro map is cleared once folded in.
	 *
	 * @return void
	 */
	public static function migrate_legacy() {
		$store = get_option( self::OPTION, [] );
		$store = is_array( $store ) ? $store : [];

		// Legacy Incident Response entries are the numerically-indexed ones.
		$merged = [];
		foreach ( $store as $key => $entry ) {
			if ( ! is_array( $entry ) || empty( $entry['id'] ) ) {
				continue;
			}
			$id = (string) $entry['id'];
			if ( is_int( $key ) || ! isset( $entry['type'] ) ) {
				$relative        = isset( $entry['orig'] )
					? str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $entry['orig'] ) )
					: $id;
				$merged[ $id ] = [
					'id'             => $id,
					'type'           => 'file',
					'original'       => isset( $entry['orig'] ) ? $entry['orig'] : '',
					'relative'       => $relative,
					'label'          => $relative,
					'quarantined_at' => isset( $entry['time'] ) ? $entry['time'] : current_time( 'mysql' ),
				];
				continue;
			}
			$merged[ $id ] = $entry;
		}

		// Legacy Pro malware entries.
		$pro = get_option( self::LEGACY_PRO_OPTION, [] );
		if ( is_array( $pro ) && ! empty( $pro['quarantine'] ) && is_array( $pro['quarantine'] ) ) {
			foreach ( $pro['quarantine'] as $id => $entry ) {
				if ( is_array( $entry ) && ! isset( $merged[ $id ] ) ) {
					$entry['id']   = (string) $id;
					$merged[ $id ] = $entry;
				}
			}
			$pro['quarantine'] = [];
			update_option( self::LEGACY_PRO_OPTION, $pro, false );
		}

		self::save( $merged );
	}
}
