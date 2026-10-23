<?php
namespace GemSecurity\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * "Extended protection" must-use plugin loader.
 *
 * Writes a small, self-contained mu-plugin that enforces the IP ban list and a
 * core set of malicious-request rules *before* the rest of WordPress and other
 * plugins load. The generated file is deliberately defensive and fail-open — a
 * problem there must never take the site down.
 */
class MuLoader {

	const FILE = 'gemsecurity-extended-protection.php';

	public static function mu_dir() {
		return defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
	}

	public static function path() {
		return trailingslashit( self::mu_dir() ) . self::FILE;
	}

	public static function is_installed() {
		return file_exists( self::path() );
	}

	/**
	 * Install or remove the mu-plugin to match the desired state.
	 *
	 * @param bool $enabled
	 * @return bool Success.
	 */
	public static function sync( $enabled ) {
		return $enabled ? self::install() : self::uninstall();
	}

	public static function install() {
		$dir = self::mu_dir();
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return false;
		}
		if ( ! wp_is_writable( $dir ) ) {
			return false;
		}
		$source = self::template();
		if ( '' === $source ) {
			return false; // Template missing — never write an empty mu-plugin.
		}
		return false !== file_put_contents( self::path(), $source ); // phpcs:ignore
	}

	public static function uninstall() {
		if ( self::is_installed() ) {
			return unlink( self::path() ); // phpcs:ignore
		}
		return true;
	}

	/**
	 * The generated mu-plugin source.
	 *
	 * @return string
	 */
	private static function template() {
		$bans_table = $GLOBALS['wpdb']->prefix . 'gemsecurity_bans';
		$basename   = defined( 'GEMSECURITY_PLUGIN_BASENAME' ) ? GEMSECURITY_PLUGIN_BASENAME : 'gemsecurity/gemsecurity.php';

		// The source lives in a plain-text template beside this file (a
		// heredoc here fails the WordPress.org Plugin Check). Both values go
		// into PHP code, so they are reduced to what they can legitimately be:
		// a table name is an identifier, a plugin basename a path.
		$template = file_get_contents( __DIR__ . '/mu-loader-template.txt' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
		if ( false === $template ) {
			return '';
		}
		return strtr( $template, [
			'__GEMSEC_BANS_TABLE__' => preg_replace( '/[^A-Za-z0-9_]/', '', $bans_table ),
			'__GEMSEC_BASENAME__'   => preg_replace( '#[^A-Za-z0-9_./-]#', '', $basename ),
		] );
	}
}
