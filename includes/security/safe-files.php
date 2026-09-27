<?php
namespace GemSecurity\Security;

use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Files the scanners should stop reporting.
 *
 * Two kinds:
 *
 *  - **Inert by inspection.** WordPress and nearly every plugin drop an
 *    `index.php` containing nothing but `<?php // Silence is golden.` into
 *    their directories, to stop the web server listing the folder. It is the
 *    single most common file in a WordPress install and it cannot do anything
 *    — flagging it teaches people to ignore the scanner, which is worse than
 *    not scanning. Files with no executable statement at all are skipped
 *    automatically, no configuration needed.
 *
 *  - **Reviewed by a person.** A scanner works on patterns, so some findings
 *    will be code that is unusual but legitimate — a plugin doing something
 *    odd, a theme with an inline template. Once somebody has actually read the
 *    file, they can mark it safe and stop seeing it.
 *
 * A marked file is remembered by its hash, not just its path. If the contents
 * change the entry no longer matches and the file is reported again — an
 * allowlist that survives an attacker rewriting the file it points at would be
 * a permanent blind spot, which is exactly what an attacker wants.
 */
class SafeFiles {

	const OPTION = 'gemsecurity_safe_files';

	/** In-request cache of the stored list. */
	private static $cache = null;

	/**
	 * The stored allowlist: relative path => { hash, marked_at, marked_by }.
	 *
	 * @return array<string,array>
	 */
	public static function all() {
		if ( null === self::$cache ) {
			$stored      = get_option( self::OPTION, [] );
			self::$cache = is_array( $stored ) ? $stored : [];
		}
		return self::$cache;
	}

	/** ABSPATH-relative, forward-slashed path for an absolute one. */
	public static function relative( $abs ) {
		return str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $abs ) );
	}

	/**
	 * Should this file be reported at all?
	 *
	 * @param string $abs Absolute path.
	 * @return bool
	 */
	public static function is_safe( $abs ) {
		if ( self::is_inert_php( $abs ) ) {
			return true;
		}
		return self::is_marked( $abs );
	}

	/**
	 * Has a person marked this exact file — same contents — as reviewed?
	 *
	 * @param string $abs
	 * @return bool
	 */
	public static function is_marked( $abs ) {
		$list = self::all();
		$rel  = self::relative( $abs );

		if ( ! isset( $list[ $rel ] ) ) {
			return false;
		}
		if ( ! is_file( $abs ) ) {
			return false;
		}

		// The mark belongs to the contents that were reviewed, not to the name.
		return isset( $list[ $rel ]['hash'] ) && hash_equals( (string) $list[ $rel ]['hash'], (string) md5_file( $abs ) );
	}

	/**
	 * A PHP file with nothing in it that can run.
	 *
	 * Decided from the token stream rather than by matching the familiar
	 * "Silence is golden" wording, so every variant a plugin author invents —
	 * a different comment, a stray blank line, an empty file — is covered, and
	 * a file that merely *contains* that comment alongside real code is not.
	 *
	 * @param string $abs
	 * @return bool
	 */
	public static function is_inert_php( $abs ) {
		if ( ! is_file( $abs ) ) {
			return false;
		}
		// Anything of consequence is bigger than this; keeps the check cheap.
		if ( filesize( $abs ) > 1024 ) {
			return false;
		}
		if ( 'php' !== strtolower( pathinfo( $abs, PATHINFO_EXTENSION ) ) ) {
			return false;
		}

		$source = @file_get_contents( $abs ); // phpcs:ignore
		if ( false === $source ) {
			return false;
		}

		if ( ! function_exists( 'token_get_all' ) ) {
			// Fall back to the shape rather than guessing.
			return (bool) preg_match( '/\A\s*<\?php\s*(\/\/[^\n]*|#[^\n]*|\/\*.*?\*\/|\s)*\s*\z/s', $source );
		}

		$tokens = @token_get_all( $source ); // phpcs:ignore
		if ( ! is_array( $tokens ) ) {
			return false;
		}

		$harmless = [ T_OPEN_TAG, T_CLOSE_TAG, T_COMMENT, T_DOC_COMMENT, T_WHITESPACE ];

		foreach ( $tokens as $token ) {
			if ( is_string( $token ) ) {
				return false; // Punctuation means a statement.
			}
			if ( in_array( $token[0], $harmless, true ) ) {
				continue;
			}
			// Text outside PHP tags is only harmless when it is blank.
			if ( T_INLINE_HTML === $token[0] && '' === trim( $token[1] ) ) {
				continue;
			}
			return false;
		}

		return true;
	}

	/**
	 * Mark a file as reviewed and safe.
	 *
	 * @param string $abs
	 * @return array|\WP_Error The stored entry.
	 */
	public static function mark( $abs ) {
		$abs = wp_normalize_path( $abs );

		if ( 0 !== strpos( $abs, wp_normalize_path( ABSPATH ) ) ) {
			return new \WP_Error( 'gemsecurity_outside_site', __( 'That file is outside this WordPress installation.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		if ( ! is_file( $abs ) ) {
			return new \WP_Error( 'gemsecurity_missing_file', __( 'That file no longer exists.', 'gemsecurity' ), [ 'status' => 404 ] );
		}

		$rel  = self::relative( $abs );
		$list = self::all();

		$list[ $rel ] = [
			'hash'      => md5_file( $abs ),
			'marked_at' => current_time( 'mysql' ),
			'marked_by' => get_current_user_id(),
		];

		update_option( self::OPTION, $list, false );
		self::$cache = $list;

		Logger::log(
			'file_marked_safe',
			sprintf( 'Marked %s as reviewed and safe.', $rel ),
			Logger::SEVERITY_NOTICE
		);

		return [ 'path' => $rel ] + $list[ $rel ];
	}

	/**
	 * Stop treating a file as safe.
	 *
	 * @param string $rel ABSPATH-relative path.
	 * @return bool
	 */
	public static function unmark( $rel ) {
		$list = self::all();
		if ( ! isset( $list[ $rel ] ) ) {
			return false;
		}
		unset( $list[ $rel ] );
		update_option( self::OPTION, $list, false );
		self::$cache = $list;

		Logger::log( 'file_unmarked_safe', sprintf( 'Removed the safe mark from %s.', $rel ), Logger::SEVERITY_NOTICE );
		return true;
	}

	/**
	 * The list for the UI, with a note where the file has changed since it was
	 * reviewed — that entry no longer suppresses anything and should be either
	 * re-reviewed or removed.
	 *
	 * @return array<int,array>
	 */
	public static function for_js() {
		$out = [];
		foreach ( self::all() as $rel => $entry ) {
			$abs     = ABSPATH . $rel;
			$exists  = is_file( $abs );
			$current = $exists ? md5_file( $abs ) : '';

			$out[] = [
				'path'      => $rel,
				'marked_at' => isset( $entry['marked_at'] ) ? $entry['marked_at'] : '',
				'missing'   => ! $exists,
				'changed'   => $exists && isset( $entry['hash'] ) && ! hash_equals( (string) $entry['hash'], (string) $current ),
			];
		}
		return $out;
	}
}
