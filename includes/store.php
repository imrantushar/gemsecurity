<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A transient replacement that always survives a broken or misconfigured
 * persistent object cache.
 *
 * WordPress's own transients API is not reliable for this: once a site
 * reports an external object cache (an `object-cache.php` drop-in is
 * present — LiteSpeed Cache, W3 Total Cache, Redis, etc.), `set_transient()`
 * / `get_transient()` store the value ONLY in that cache, with no fallback to
 * the options table. If the cache backend is unreachable or misconfigured —
 * which happens in practice on shared hosting (a stale or half-configured
 * drop-in, a cache plugin pointed at a server that is down) — every write
 * silently goes nowhere and every read comes back empty, with no error.
 *
 * That turns security-critical counters (login lockouts, rate limits, a
 * one-time unlock code) into dead code: the setting looks "on", nothing is
 * ever blocked, and nothing says why. `get_option()` / `update_option()` have
 * no such failure mode — WordPress always keeps the authoritative value in
 * the options table and only uses the object cache as an accelerator in
 * front of it, falling back to the database on a cache miss. Routing these
 * short-lived values through options (with the expiry carried in the value
 * and checked on read) keeps them correct everywhere a transient would have
 * silently failed, at the cost of a few more options-table rows, which
 * {@see prune()} sweeps on the existing daily cron.
 */
class Store {

	/** Option-name prefix; also what prune() matches on. */
	const PREFIX = 'gemsec_kv_';

	/**
	 * @param string $key
	 * @return mixed False if missing or expired.
	 */
	public static function get( $key ) {
		$row = get_option( self::PREFIX . $key, null );
		if ( ! is_array( $row ) || ! array_key_exists( 'v', $row ) || ! isset( $row['x'] ) ) {
			return false;
		}
		if ( $row['x'] > 0 && time() > $row['x'] ) {
			delete_option( self::PREFIX . $key );
			return false;
		}
		return $row['v'];
	}

	/**
	 * @param string $key
	 * @param mixed  $value
	 * @param int    $ttl   Seconds; 0 = never expires.
	 * @return bool
	 */
	public static function set( $key, $value, $ttl = 0 ) {
		$expires = $ttl > 0 ? time() + (int) $ttl : 0;
		// Never autoloaded: these are short-lived and per-key, not something
		// every page load needs.
		return update_option( self::PREFIX . $key, [ 'v' => $value, 'x' => $expires ], false );
	}

	/**
	 * @param string $key
	 * @return bool
	 */
	public static function delete( $key ) {
		return delete_option( self::PREFIX . $key );
	}

	/**
	 * Sweep expired rows. Hooked to the existing daily prune-logs cron so no
	 * new scheduled event is needed.
	 */
	public static function prune() {
		global $wpdb;
		// Our own prefixed rows only, batched so a large table can't time out
		// a single request; direct query because WP has no "delete options
		// matching a pattern" API, and this isn't a per-request path.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$names = $wpdb->get_col( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s LIMIT 500", $wpdb->esc_like( self::PREFIX ) . '%' ) );
		foreach ( $names as $name ) {
			$row = get_option( $name );
			if ( ! is_array( $row ) || ! isset( $row['x'] ) || ( $row['x'] > 0 && time() > $row['x'] ) ) {
				delete_option( $name );
			}
		}
	}
}
