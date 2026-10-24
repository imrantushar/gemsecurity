<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Grouped backing store for GemSecurity's housekeeping options.
 *
 * The plugin used to spread install flags, schema version, 2FA seal state and
 * runtime snapshots (vulnerability scan, quarantine index) across eight
 * separate `wp_options` rows. Several of those rows were large and still
 * autoloaded, so every request paid for them. This class consolidates them
 * into two rows:
 *
 *   - `gemsecurity_meta`  — tiny flags, autoloaded.
 *   - `gemsecurity_state` — runtime snapshots, NOT autoloaded; hydrated only
 *                           when a module actually reads them.
 *
 * `gemsecurity_settings` is the user-facing config bag and stays as-is.
 */
class OptionStore {

	const META_OPTION  = 'gemsecurity_meta';
	const STATE_OPTION = 'gemsecurity_state';

	/**
	 * @var array|null
	 */
	private static $meta_cache = null;

	/**
	 * @var array|null
	 */
	private static $state_cache = null;

	public static function get_meta( $key, $default = null ) {
		$meta = self::load_meta();
		return array_key_exists( $key, $meta ) ? $meta[ $key ] : $default;
	}

	public static function set_meta( $key, $value ) {
		$meta         = self::load_meta();
		$meta[ $key ] = $value;
		self::$meta_cache = $meta;
		update_option( self::META_OPTION, $meta );
	}

	/**
	 * Set a meta key only if it is not already present. Lets callers record a
	 * one-time timestamp (install time) without clobbering an existing value.
	 *
	 * @return bool True when the key was created, false when it already existed.
	 */
	public static function add_meta( $key, $value ) {
		$meta = self::load_meta();
		if ( array_key_exists( $key, $meta ) ) {
			return false;
		}
		$meta[ $key ]     = $value;
		self::$meta_cache = $meta;
		update_option( self::META_OPTION, $meta );
		return true;
	}

	public static function get_state( $key, $default = null ) {
		$state = self::load_state();
		return array_key_exists( $key, $state ) ? $state[ $key ] : $default;
	}

	public static function set_state( $key, $value ) {
		$state         = self::load_state();
		$state[ $key ] = $value;
		self::$state_cache = $state;
		update_option( self::STATE_OPTION, $state, false );
	}

	public static function delete_state( $key ) {
		$state = self::load_state();
		if ( ! array_key_exists( $key, $state ) ) {
			return;
		}
		unset( $state[ $key ] );
		self::$state_cache = $state;
		update_option( self::STATE_OPTION, $state, false );
	}

	public static function flush_cache() {
		self::$meta_cache  = null;
		self::$state_cache = null;
	}

	private static function load_meta() {
		if ( null === self::$meta_cache ) {
			$meta             = get_option( self::META_OPTION, [] );
			self::$meta_cache = is_array( $meta ) ? $meta : [];
		}
		return self::$meta_cache;
	}

	private static function load_state() {
		if ( null === self::$state_cache ) {
			$state             = get_option( self::STATE_OPTION, [] );
			self::$state_cache = is_array( $state ) ? $state : [];
		}
		return self::$state_cache;
	}
}
