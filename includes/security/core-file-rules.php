<?php
namespace GemSecurity\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Server rules from WordPress's own hardening guide, kept in one marked block
 * of the root .htaccess:
 *
 *  - deny wp-config.php to the web (it holds the database password);
 *  - deny error logs — WP_DEBUG_LOG writes wp-content/debug.log, which the web
 *    server hands to anyone who asks for it;
 *  - forbid wp-admin/includes/, which is only ever included by WordPress.
 *
 * Apache and LiteSpeed only: nginx ignores .htaccess, so there the same rules
 * belong in the server config. `<Files>` in the root .htaccess applies to every
 * directory below it, so the log rule covers wp-content/debug.log too.
 */
class CoreFileRules {

	const MARKER = 'GemSecurity Core Files';

	/** @return string[] */
	public static function rules() {
		$deny = [
			'	<IfModule mod_authz_core.c>',
			'		Require all denied',
			'	</IfModule>',
			'	<IfModule !mod_authz_core.c>',
			'		Order allow,deny',
			'		Deny from all',
			'	</IfModule>',
		];
		return array_merge(
			[ '<Files "wp-config.php">' ], $deny, [ '</Files>' ],
			[ '<FilesMatch "^(debug\.log|error_log|php_errorlog|php_error\.log)$">' ], $deny, [ '</FilesMatch>' ],
			[
				'<IfModule mod_rewrite.c>',
				'	RewriteEngine On',
				'	RewriteRule ^wp-admin/includes/ - [F,L]',
				'</IfModule>',
			]
		);
	}

	/**
	 * Write or remove the block.
	 *
	 * @param bool        $enabled
	 * @param string|null $file Defaults to the root .htaccess; overridable for tests.
	 * @return bool Whether the file now matches $enabled.
	 */
	public static function sync( $enabled, $file = null ) {
		$file = $file ?: ABSPATH . '.htaccess';
		if ( ! $enabled && ! file_exists( $file ) ) {
			return true;
		}
		$writable = file_exists( $file ) ? wp_is_writable( $file ) : wp_is_writable( dirname( $file ) );
		if ( ! $writable ) {
			return false;
		}
		if ( ! $enabled ) {
			return self::remove_block( $file, self::MARKER );
		}
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		return (bool) insert_with_markers( $file, self::MARKER, self::rules() );
	}

	/**
	 * Remove a marked block entirely. insert_with_markers() with no lines
	 * leaves the BEGIN/END comments behind.
	 *
	 * @param string $file
	 * @param string $marker
	 * @return bool
	 */
	public static function remove_block( $file, $marker ) {
		$body = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
		$rest = preg_replace( '/\n?# BEGIN ' . preg_quote( $marker, '/' ) . '\n.*?# END ' . preg_quote( $marker, '/' ) . '\n?/s', "\n", $body );
		if ( null === $rest || $rest === $body ) {
			return true; // Nothing of ours in there.
		}
		return false !== file_put_contents( $file, ltrim( $rest, "\n" ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- .htaccess edit, same as insert_with_markers().
	}

	/**
	 * Whether the block is in place.
	 *
	 * @param string|null $file
	 * @return bool
	 */
	public static function installed( $file = null ) {
		$file = $file ?: ABSPATH . '.htaccess';
		return is_readable( $file ) && false !== strpos( (string) file_get_contents( $file ), '# BEGIN ' . self::MARKER ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
	}
}
