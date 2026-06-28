<?php
namespace GemSecurity\Security;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * IP ban ledger + escalating auto-ban engine.
 *
 * Persistent bans live in {$wpdb->prefix}gemsecurity_bans (temporary, with an
 * expiry, or permanent). Short-term "strikes" are kept in transients; once an
 * IP accumulates enough strikes inside the window it is auto-banned.
 */
class BanList {

	const STRIKE_PREFIX = 'gemsec_strike_';

	private static $cache = [];

	private static function table() {
		global $wpdb;
		return $wpdb->prefix . 'gemsecurity_bans';
	}

	/**
	 * @param string $ip
	 * @return bool
	 */
	public static function is_banned( $ip ) {
		if ( ! $ip || '0.0.0.0' === $ip ) {
			return false;
		}
		if ( isset( self::$cache[ $ip ] ) ) {
			return self::$cache[ $ip ];
		}
		global $wpdb;
		$row = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT id FROM ' . self::table() . ' WHERE ip = %s AND ( expires_at IS NULL OR expires_at > %s ) LIMIT 1',
				$ip,
				current_time( 'mysql' )
			)
		);
		return self::$cache[ $ip ] = (bool) $row;
	}

	/**
	 * Ban an IP.
	 *
	 * @param string $ip
	 * @param string $reason
	 * @param int    $ttl Seconds; 0 = permanent.
	 * @return bool
	 */
	public static function ban( $ip, $reason = '', $ttl = 0 ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		global $wpdb;
		$expires = $ttl > 0 ? gmdate( 'Y-m-d H:i:s', time() + $ttl ) : null;

		$wpdb->query(
			$wpdb->prepare(
				'INSERT INTO ' . self::table() . ' (ip, reason, strikes, expires_at, created_at) VALUES (%s, %s, %d, %s, %s)
				 ON DUPLICATE KEY UPDATE reason = VALUES(reason), strikes = strikes + 1, expires_at = VALUES(expires_at)',
				$ip,
				substr( (string) $reason, 0, 255 ),
				1,
				$expires,
				current_time( 'mysql' )
			)
		);
		unset( self::$cache[ $ip ] );

		Logger::log(
			'ip_banned',
			sprintf( 'IP %s banned (%s)%s.', $ip, $reason ?: 'manual', $expires ? '' : ' permanently' ),
			Logger::SEVERITY_WARNING,
			[ 'user_id' => 0, 'ip_address' => $ip, 'context' => [ 'reason' => $reason, 'ttl' => $ttl ] ]
		);
		return true;
	}

	/**
	 * @param string $ip
	 */
	public static function unban( $ip ) {
		global $wpdb;
		$wpdb->delete( self::table(), [ 'ip' => $ip ], [ '%s' ] );
		unset( self::$cache[ $ip ] );
		delete_transient( self::STRIKE_PREFIX . md5( $ip ) );
	}

	/**
	 * Record a strike; auto-ban once the threshold is reached in the window.
	 *
	 * @param string $ip
	 * @param string $reason
	 * @return bool True if this strike resulted in a ban.
	 */
	public static function record_strike( $ip, $reason = '' ) {
		if ( ! Helper::get_setting( 'autoban_enabled', true ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		if ( self::is_exempt( $ip ) ) {
			return false;
		}

		$threshold = max( 2, (int) Helper::get_setting( 'autoban_threshold', 10 ) );
		$window    = max( 1, (int) Helper::get_setting( 'autoban_window', 60 ) ) * MINUTE_IN_SECONDS;
		$key       = self::STRIKE_PREFIX . md5( $ip );

		$strikes = (int) get_transient( $key ) + 1;
		set_transient( $key, $strikes, $window );

		if ( $strikes >= $threshold ) {
			delete_transient( $key );
			$ttl = (int) Helper::get_setting( 'autoban_duration', 1440 ) * MINUTE_IN_SECONDS; // minutes → seconds
			self::ban( $ip, $reason ?: 'auto-ban: repeated offenses', $ttl );
			return true;
		}
		return false;
	}

	/**
	 * Never auto-ban the current admin's own IP.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_exempt( $ip ) {
		if ( is_user_logged_in() && current_user_can( 'manage_options' ) && $ip === Helper::get_ip_address() ) {
			return true;
		}
		return (bool) apply_filters( 'gemsecurity/ban_exempt', false, $ip );
	}

	/**
	 * @param int $limit
	 * @return array
	 */
	public static function all( $limit = 200 ) {
		global $wpdb;
		$rows = $wpdb->get_results(
			$wpdb->prepare( 'SELECT * FROM ' . self::table() . ' ORDER BY created_at DESC LIMIT %d', $limit ),
			ARRAY_A
		);
		return $rows ? $rows : [];
	}

	public static function count_active() {
		global $wpdb;
		return (int) $wpdb->get_var(
			$wpdb->prepare( 'SELECT COUNT(*) FROM ' . self::table() . ' WHERE expires_at IS NULL OR expires_at > %s', current_time( 'mysql' ) )
		);
	}

	/** Cron: drop expired bans. */
	public static function prune() {
		global $wpdb;
		$wpdb->query(
			$wpdb->prepare( 'DELETE FROM ' . self::table() . ' WHERE expires_at IS NOT NULL AND expires_at < %s', current_time( 'mysql' ) )
		);
	}
}
