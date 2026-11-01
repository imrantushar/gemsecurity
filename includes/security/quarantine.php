<?php
namespace GemSecurity\Security;

use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The site's single quarantine store.
 *
 * Quarantine is "store, then remove": a suspicious file's bytes are copied
 * into a non-autoloaded option (never onto disk, so no executable code is
 * ever written anywhere) and the original is deleted, so the action is always
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
 *   id             string  Index key; a file's bytes live in option BLOB_PREFIX . id.
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

	/** Option prefix for a quarantined file's payload. */
	const BLOB_PREFIX = 'gemsecurity_quarantine_blob_';

	/** Largest file quarantined (payloads are held in the database). */
	const MAX_BYTES = 8388608;

	/**
	 * Folder earlier releases moved quarantined files into. Read-only now: it is
	 * never created, only drained by {@see payload()} / {@see delete_payload()}.
	 *
	 * @return string
	 */
	public static function dir() {
		return trailingslashit( wp_upload_dir( null, false )['basedir'] ) . 'gemsecurity-quarantine';
	}

	/**
	 * A quarantined file's original bytes.
	 *
	 * @param string $id
	 * @return string|null
	 */
	public static function payload( $id ) {
		$id   = sanitize_key( $id );
		$blob = get_option( self::BLOB_PREFIX . $id, null );
		if ( is_string( $blob ) ) {
			$raw = base64_decode( $blob, true );
			return false === $raw ? null : $raw;
		}
		$legacy = self::dir() . '/' . $id . '.quar';
		return is_file( $legacy ) ? (string) file_get_contents( $legacy ) : null; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
	}

	/**
	 * Remove a quarantined file's stored bytes (and any legacy on-disk copy).
	 *
	 * @param string $id
	 * @return void
	 */
	public static function delete_payload( $id ) {
		$id = sanitize_key( $id );
		delete_option( self::BLOB_PREFIX . $id );
		$legacy = self::dir() . '/' . $id . '.quar';
		if ( is_file( $legacy ) ) {
			wp_delete_file( $legacy );
		}
	}

	/**
	 * Every entry, keyed by id.
	 *
	 * @return array<string,array>
	 */
	public static function all() {
		$store = \GemSecurity\OptionStore::get_state( 'quarantine', [] );
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
		\GemSecurity\OptionStore::set_state( 'quarantine', $store );
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
		// Resolve to the real path first: wp_normalize_path() leaves "../" in
		// place, so "ABSPATH/../../elsewhere" used to pass the prefix check,
		// and a symlink could point anywhere.
		$real = (string) $path !== '' ? realpath( (string) $path ) : false;
		$abs  = $real ? wp_normalize_path( $real ) : '';
		$root = wp_normalize_path( (string) realpath( \GemSecurity\Paths::root() ) );
		$root = '' === $root ? wp_normalize_path( untrailingslashit( \GemSecurity\Paths::root() ) ) : $root;

		// Anywhere in the install, not just wp-content: real infections drop
		// their stubs into wp-admin and wp-includes too. Compared with a
		// trailing slash so /var/www/site2 is not "inside" /var/www/site. The
		// plugin's own directories are off limits so a scan can never
		// quarantine the scanner.
		$plugins = wp_normalize_path( (string) realpath( \GemSecurity\Paths::plugins() ) );
		$own     = '' !== $plugins && preg_match( '#^' . preg_quote( trailingslashit( $plugins ), '#' ) . 'gemsecurity(-pro)?/#', $abs );
		if ( '' === $abs || 0 !== strpos( $abs, trailingslashit( $root ) ) || $own ) {
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

		if ( filesize( $abs ) > self::MAX_BYTES ) {
			return new \WP_Error( 'gemsecurity_quarantine_size', __( 'That file is too large to quarantine. Delete it or replace it with a clean copy.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		$id   = md5( $abs . microtime() );
		$body = file_get_contents( $abs ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( false === $body || ! add_option( self::BLOB_PREFIX . $id, base64_encode( $body ), '', false ) ) {
			return new \WP_Error( 'gemsecurity_quarantine_failed', __( 'Could not quarantine the file.', 'gemsecurity' ), [ 'status' => 500 ] );
		}
		wp_delete_file( $abs );
		if ( file_exists( $abs ) ) {
			delete_option( self::BLOB_PREFIX . $id );
			return new \WP_Error( 'gemsecurity_quarantine_failed', __( 'Could not remove the file.', 'gemsecurity' ), [ 'status' => 500 ] );
		}

		$relative = \GemSecurity\Paths::relative( $abs );

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
	 * Keep a copy of a file that is about to be overwritten, leaving it in place.
	 *
	 * @param string $path   Absolute path.
	 * @param string $source Who took the snapshot (shown in the entry).
	 * @return array|\WP_Error The stored entry.
	 */
	public static function snapshot( $path, $source ) {
		$abs = wp_normalize_path( (string) $path );
		if ( ! is_file( $abs ) || filesize( $abs ) > self::MAX_BYTES ) {
			return new \WP_Error( 'gemsecurity_quarantine_failed', __( 'Could not keep a copy of the current file.', 'gemsecurity' ), [ 'status' => 500 ] );
		}
		$id   = md5( 'snap:' . $abs . microtime() );
		$body = file_get_contents( $abs ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( false === $body || ! add_option( self::BLOB_PREFIX . $id, base64_encode( $body ), '', false ) ) {
			return new \WP_Error( 'gemsecurity_quarantine_failed', __( 'Could not keep a copy of the current file.', 'gemsecurity' ), [ 'status' => 500 ] );
		}
		$relative     = \GemSecurity\Paths::relative( $abs );
		$store        = self::all();
		$store[ $id ] = [
			'id'             => $id,
			'type'           => 'file',
			'original'       => $abs,
			'relative'       => $relative,
			'label'          => $relative,
			'source'         => (string) $source,
			'quarantined_at' => current_time( 'mysql' ),
		];
		self::save( $store );
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

		$body = self::payload( $id );
		// A snapshot was taken of a file that was then replaced, so it may
		// overwrite; a quarantined file was removed and must not.
		$overwrite = 'core-file' === ( $entry['source'] ?? '' );
		if ( null === $body || ! self::write_back( $entry['original'], $body, $overwrite ) ) {
			return new \WP_Error( 'gemsecurity_restore_failed', __( 'Could not restore the file.', 'gemsecurity' ), [ 'status' => 500 ] );
		}

		self::delete_payload( $id );
		self::forget( $id );
		Logger::log( 'quarantine_restore', sprintf( 'Restored %s.', $entry['label'] ), Logger::SEVERITY_NOTICE );
		return true;
	}

	/**
	 * Put a file's bytes back at the path it was quarantined from.
	 *
	 * @param string $path Absolute original path.
	 * @param string $body
	 * @param bool   $overwrite Replace an existing file.
	 * @return bool
	 */
	public static function write_back( $path, $body, $overwrite = false ) {
		$path = (string) $path;
		if ( '' === $path || ( ! $overwrite && file_exists( $path ) ) || ( ! is_dir( dirname( $path ) ) && ! wp_mkdir_p( dirname( $path ) ) ) ) {
			return false;
		}
		return false !== file_put_contents( $path, $body, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- restores the site's own file to where it came from.
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
	 * into the legacy directory, which {@see payload()} still reads — only the
	 * bookkeeping is merged. Idempotent: entries already keyed by id are left
	 * alone, and the legacy Pro map is cleared once folded in.
	 *
	 * @return void
	 */
	public static function migrate_legacy() {
		$store = self::all();

		// Legacy Incident Response entries are the numerically-indexed ones.
		$merged = [];
		foreach ( $store as $key => $entry ) {
			if ( ! is_array( $entry ) || empty( $entry['id'] ) ) {
				continue;
			}
			$id = (string) $entry['id'];
			if ( is_int( $key ) || ! isset( $entry['type'] ) ) {
				$relative        = isset( $entry['orig'] )
					? \GemSecurity\Paths::relative( wp_normalize_path( $entry['orig'] ) )
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
