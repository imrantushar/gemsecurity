<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The one place the plugin resolves where WordPress keeps things.
 *
 * Content, plugin, must-use and upload folders can each be moved
 * independently, so every lookup goes through WordPress' own constants and
 * functions here instead of being assembled from the content folder. Paths
 * are normalised (forward slashes) and returned without a trailing slash,
 * except {@see root()}, which keeps it so root-relative paths append cleanly.
 */
class Paths {

	/** WordPress install root (where core lives), normalised, trailing slash. */
	public static function root() {
		return trailingslashit( wp_normalize_path( ABSPATH ) );
	}

	/** The content folder — where WordPress loads drop-ins from. */
	public static function content() {
		return untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );
	}

	/** The plugins folder. */
	public static function plugins() {
		return untrailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) );
	}

	/** The must-use plugins folder. */
	public static function mu() {
		return untrailingslashit( wp_normalize_path( WPMU_PLUGIN_DIR ) );
	}

	/** The uploads base folder (not created if missing). */
	public static function uploads() {
		return untrailingslashit( wp_normalize_path( wp_upload_dir( null, false )['basedir'] ) );
	}

	/**
	 * Root-relative, forward-slashed form of an absolute path.
	 *
	 * @param string $path
	 * @return string
	 */
	public static function relative( $path ) {
		return str_replace( self::root(), '', wp_normalize_path( (string) $path ) );
	}
}
