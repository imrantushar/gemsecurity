<?php
namespace GemSecurity\Security;

use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Look at, restore or edit one WordPress core file the scanner flagged.
 *
 * The "original" is the file as WordPress.org published it for this exact
 * version, fetched from core.svn.wordpress.org and accepted only if it matches
 * the official checksum — so a bad mirror or a proxy cannot hand back a
 * tampered file as the reference.
 */
class CoreFile {

	/** Largest file shown or written through the popup. */
	const MAX_BYTES = 1048576;

	/**
	 * Resolve a flagged core file to its absolute path, or an error when it is
	 * not a file the scanner itself would flag (so this cannot be pointed at
	 * wp-config.php, plugins, or anything outside core).
	 *
	 * @param string $file Root-relative path as listed by the scanner.
	 * @return array|\WP_Error { file, path, sum }
	 */
	public static function resolve( $file ) {
		$file = ltrim( wp_normalize_path( trim( (string) $file ) ), '/' );
		if ( '' === $file || false !== strpos( $file, '..' ) || 0 === strpos( $file, 'wp-content/' ) ) {
			return new \WP_Error( 'gemsecurity_core_file', __( 'That is not a WordPress core file.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		$sums = self::checksums();
		if ( empty( $sums[ $file ] ) ) {
			return new \WP_Error( 'gemsecurity_core_file', __( 'That file is not part of this WordPress release.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		return [ 'file' => $file, 'path' => \GemSecurity\Paths::root() . $file, 'sum' => $sums[ $file ] ];
	}

	/** @return array<string,string> */
	private static function checksums() {
		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		$version = get_bloginfo( 'version' );
		$sums    = get_core_checksums( $version, get_locale() );
		if ( empty( $sums ) || ! is_array( $sums ) ) {
			$sums = get_core_checksums( $version, 'en_US' );
		}
		return is_array( $sums ) ? $sums : [];
	}

	/**
	 * Everything the popup needs.
	 *
	 * @param string $file
	 * @return array|\WP_Error
	 */
	public static function inspect( $file ) {
		$r = self::resolve( $file );
		if ( is_wp_error( $r ) ) {
			return $r;
		}

		$current = '';
		$exists  = is_file( $r['path'] );
		if ( $exists ) {
			if ( filesize( $r['path'] ) > self::MAX_BYTES ) {
				return new \WP_Error( 'gemsecurity_core_file', __( 'This file is too large to show here.', 'gemsecurity' ), [ 'status' => 413 ] );
			}
			$fs      = self::fs();
			$current = $fs ? (string) $fs->get_contents( $r['path'] ) : '';
		}

		$original = self::original( $r );

		return [
			'file'           => $r['file'],
			'version'        => get_bloginfo( 'version' ),
			'exists'         => $exists,
			'current'        => $current,
			'original'       => is_wp_error( $original ) ? '' : $original,
			'original_error' => is_wp_error( $original ) ? $original->get_error_message() : '',
		];
	}

	/**
	 * @param array $r Result of resolve().
	 * @return string|\WP_Error
	 */
	private static function original( array $r ) {
		$key    = 'gemsec_core_' . md5( get_bloginfo( 'version' ) . $r['file'] );
		$cached = get_transient( $key );
		if ( is_string( $cached ) ) {
			return $cached;
		}

		$url = 'https://core.svn.wordpress.org/tags/' . rawurlencode( get_bloginfo( 'version' ) ) . '/' . implode( '/', array_map( 'rawurlencode', explode( '/', $r['file'] ) ) );
		$res = wp_remote_get( $url, [ 'timeout' => 15 ] );
		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			return new \WP_Error( 'gemsecurity_core_original', __( 'Could not download the original file from WordPress.org.', 'gemsecurity' ) );
		}
		$body = (string) wp_remote_retrieve_body( $res );
		if ( md5( $body ) !== $r['sum'] ) {
			return new \WP_Error( 'gemsecurity_core_original', __( 'The downloaded file did not match the official checksum, so it was discarded.', 'gemsecurity' ) );
		}
		set_transient( $key, $body, HOUR_IN_SECONDS );
		return $body;
	}

	/**
	 * Put the official file back.
	 *
	 * @param string $file
	 * @return true|\WP_Error
	 */
	public static function restore( $file ) {
		$r = self::resolve( $file );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		$original = self::original( $r );
		if ( is_wp_error( $original ) ) {
			return $original;
		}
		return self::write( $r, $original, 'restored' );
	}

	/**
	 * Write a file, keeping a copy of what it replaces.
	 *
	 * @param array  $r
	 * @param string $content
	 * @param string $what    restored
	 * @return true|\WP_Error
	 */
	private static function write( array $r, $content, $what ) {
		$fs = self::fs();
		if ( ! $fs ) {
			return new \WP_Error( 'gemsecurity_core_write', __( 'WordPress cannot write files on this server without FTP credentials.', 'gemsecurity' ), [ 'status' => 500 ] );
		}

		if ( $fs->exists( $r['path'] ) ) {
			// Keep what is being replaced in the quarantine store (database, not
			// disk), so it can still be inspected or put back.
			$kept = Quarantine::snapshot( $r['path'], 'core-file' );
			if ( is_wp_error( $kept ) ) {
				return $kept;
			}
		} elseif ( ! $fs->is_dir( dirname( $r['path'] ) ) ) {
			$fs->mkdir( dirname( $r['path'] ) );
		}

		if ( ! $fs->put_contents( $r['path'], $content, FS_CHMOD_FILE ) ) {
			return new \WP_Error( 'gemsecurity_core_write', __( 'Could not write the file. Check its permissions.', 'gemsecurity' ), [ 'status' => 500 ] );
		}
		if ( function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $r['path'], true );
		}

		Logger::log(
			'core_file_' . $what,
			sprintf( 'Core file %1$s %2$s from the scanner.', $r['file'], $what ),
			Logger::SEVERITY_WARNING
		);
		return true;
	}

	/** @return \WP_Filesystem_Base|null */
	private static function fs() {
		global $wp_filesystem;
		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( ! $wp_filesystem && ! WP_Filesystem() ) {
			return null;
		}
		return $wp_filesystem;
	}
}
