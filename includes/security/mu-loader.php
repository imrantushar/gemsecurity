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
		if ( ! is_writable( $dir ) ) {
			return false;
		}
		return false !== file_put_contents( self::path(), self::template() ); // phpcs:ignore
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

		return <<<PHP
<?php
/**
 * Plugin Name: GemSecurity Extended Protection
 * Description: Early request firewall installed by GemSecurity. Do not edit — managed automatically. Delete this file to disable.
 * Version: 1.0
 *
 * Runs before other plugins. Fail-open: any error is swallowed so the site
 * never breaks. Disable from GemSecurity → Threat Defense, or just delete this file.
 */

if ( ! defined( 'ABSPATH' ) ) { return; }

( function () {
	try {
		// Logged-in users bypass the early firewall (full WAF runs later with
		// proper capability checks).
		foreach ( array_keys( \$_COOKIE ) as \$ck ) {
			if ( 0 === strpos( \$ck, 'wordpress_logged_in_' ) ) { return; }
		}

		\$opt = get_option( 'gemsecurity_settings' );
		if ( ! is_array( \$opt ) ) { return; }

		// Resolve client IP (mirror of Helper::get_ip_address).
		\$ip = '';
		foreach ( array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR' ) as \$k ) {
			if ( ! empty( \$_SERVER[ \$k ] ) ) {
				\$cand = trim( explode( ',', (string) \$_SERVER[ \$k ] )[0] );
				if ( filter_var( \$cand, FILTER_VALIDATE_IP ) ) { \$ip = \$cand; break; }
			}
		}
		if ( '' === \$ip || '0.0.0.0' === \$ip ) { return; }

		\$deny = function () {
			if ( ! headers_sent() ) { header( 'HTTP/1.1 403 Forbidden' ); header( 'Cache-Control: no-store' ); }
			exit( 'Access denied.' );
		};

		// 1) Active ban check.
		global \$wpdb;
		if ( isset( \$wpdb ) ) {
			\$row = \$wpdb->get_var( \$wpdb->prepare(
				"SELECT id FROM {$bans_table} WHERE ip = %s AND ( expires_at IS NULL OR expires_at > %s ) LIMIT 1",
				\$ip,
				current_time( 'mysql' )
			) );
			if ( \$row ) { \$deny(); }
		}

		// 2) Bad bots.
		if ( ! empty( \$opt['block_bad_bots'] ) ) {
			\$ua = isset( \$_SERVER['HTTP_USER_AGENT'] ) ? (string) \$_SERVER['HTTP_USER_AGENT'] : '';
			if ( '' === \$ua ) {
				if ( ! isset( \$opt['block_empty_ua'] ) || \$opt['block_empty_ua'] ) { \$deny(); }
			} else {
				if ( preg_match( '#(sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|netsparker|fimap|dirbuster|gobuster|wpscan)#i', \$ua ) ) { \$deny(); }
				foreach ( ( is_array( \$opt['bot_blocklist'] ?? null ) ? \$opt['bot_blocklist'] : array() ) as \$entry ) {
					\$entry = (string) \$entry;
					if ( '' === \$entry ) { continue; }
					if ( false !== strpos( \$entry, '*' ) ) {
						\$regex = '#^' . str_replace( '\*', '.*', preg_quote( \$entry, '#' ) ) . '$#i';
						if ( preg_match( \$regex, \$ua ) ) { \$deny(); }
					} elseif ( false !== stripos( \$ua, \$entry ) ) { \$deny(); }
				}
			}
		}

		// 3) Core malicious-request patterns (URI + query only).
		if ( ! empty( \$opt['waf_enabled'] ) && ! is_admin() ) {
			\$hay = isset( \$_SERVER['REQUEST_URI'] ) ? rawurldecode( (string) \$_SERVER['REQUEST_URI'] ) : '';
			foreach ( (array) \$_GET as \$v ) { if ( is_string( \$v ) ) { \$hay .= ' ' . \$v; } }
			\$rules = array(
				'/(\\bunion\\b.{1,40}\\bselect\\b|information_schema|\\bor\\b\\s+1\\s*=\\s*1|sleep\\s*\\()/i',
				'/(<script\\b|javascript:|onerror\\s*=|document\\.cookie)/i',
				'/(\\.\\.\\/\\.\\.\\/|\\/etc\\/passwd|php:\\/\\/|data:\\/\\/)/i',
			);
			foreach ( \$rules as \$re ) { if ( preg_match( \$re, \$hay ) ) { \$deny(); } }
		}
	} catch ( \Throwable \$e ) {
		// Fail open — never break the site.
	}
} )();
PHP;
	}
}
