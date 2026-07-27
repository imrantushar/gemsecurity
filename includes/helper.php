<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Helper {

	/**
	 * In-request cache of the settings option. The plugin reads settings ~100×
	 * per request across its modules; caching avoids re-resolving the option
	 * each time. Invalidated on save via update_option_/add_option_ hooks.
	 *
	 * @var array|null
	 */
	private static $settings_cache = null;

	public static function get_time() {
		return time() + ( get_option( 'gmt_offset' ) * HOUR_IN_SECONDS );
	}

	/**
	 * Decode a hex-encoded scanner signature / WAF pattern.
	 *
	 * The malware-scanner, file-scanner and WAF rule tables necessarily contain
	 * the same plain-text markers that real malware does (web-shell names,
	 * obfuscation chains, attack regexes). Shipped verbatim, those literals make
	 * the plugin archive itself trip third-party antivirus/heuristic scanners
	 * (e.g. Google Drive, Slack), so we store them hex-encoded and reassemble
	 * the patterns here at runtime. This changes nothing about how the scanners
	 * behave — it only keeps the distributable from self-flagging.
	 *
	 * @param string $hex Hex-encoded literal.
	 * @return string Decoded pattern.
	 */
	public static function sig( $hex ) {
		return (string) hex2bin( $hex );
	}

	/**
	 * The full settings array, resolved once per request.
	 *
	 * @return array
	 */
	public static function get_settings() {
		if ( null === self::$settings_cache ) {
			$settings = get_option( GEMSECURITY_SETTINGS_NAME, [] );
			self::$settings_cache = is_array( $settings ) ? $settings : [];
		}
		return self::$settings_cache;
	}

	/**
	 * Drop the in-request settings cache (hooked on the option update/add).
	 */
	public static function flush_settings_cache() {
		self::$settings_cache = null;
	}

	/**
	 * Whether the GemSecurity Pro addon is active (and, later, licensed).
	 *
	 * The Pro plugin defines GEMSECURITY_PRO_VERSION when it loads; a license
	 * layer can additionally short-circuit the filter to false when expired.
	 *
	 * @return bool
	 */
	public static function is_pro_active() {
		return (bool) apply_filters( 'gemsecurity/is_pro_active', defined( 'GEMSECURITY_PRO_VERSION' ) );
	}

	/**
	 * Canonical registry of Pro-only features, keyed by the page/section key
	 * the UI uses. Single source of truth shared by PHP (menu badges + server
	 * gating) and the React app (nav badges + locked overlays).
	 *
	 * @return array<string,array{title:string,desc:string}>
	 */
	public static function get_pro_features() {
		$features = [
			GEMSECURITY_PLUGIN_SLUG . '-threats'     => [
				'title' => __( 'Threat Defense', 'gemsecurity' ),
				'desc'  => __( 'Escalating auto-bans, the ban ledger and the early-load request firewall.', 'gemsecurity' ),
			],
			GEMSECURITY_PLUGIN_SLUG . '-geolocation' => [
				'title' => __( 'Geolocation', 'gemsecurity' ),
				'desc'  => __( 'Country access control and per-user location lock.', 'gemsecurity' ),
			],
			GEMSECURITY_PLUGIN_SLUG . '-malware'     => [
				'title' => __( 'Malware Scan', 'gemsecurity' ),
				'desc'  => __( 'Signature malware scan, database injection scan, quarantine/restore and the post-hack recovery toolkit.', 'gemsecurity' ),
			],
			GEMSECURITY_PLUGIN_SLUG . '-pro-tools'   => [
				'title' => __( 'Pro Tools', 'gemsecurity' ),
				'desc'  => __( 'Hardening pack, file-change baseline, auto-update enforcement and settings import/export.', 'gemsecurity' ),
			],
		];

		return apply_filters( 'gemsecurity/pro_features', $features );
	}

	/**
	 * Is a given page/section key a Pro feature?
	 *
	 * @param string $key
	 * @return bool
	 */
	public static function is_pro_feature( $key ) {
		return array_key_exists( $key, self::get_pro_features() );
	}

	/**
	 * Whether a Pro feature should be locked for the current install
	 * (i.e. it's a Pro feature AND Pro is not active).
	 *
	 * @param string $key
	 * @return bool
	 */
	public static function is_locked( $key ) {
		return self::is_pro_feature( $key ) && ! self::is_pro_active();
	}

	/**
	 * Upgrade/pricing URL for the Pro upsell.
	 *
	 * @return string
	 */
	public static function upgrade_url() {
		return apply_filters( 'gemsecurity/upgrade_url', 'https://gemsecurity.net/pricing/' );
	}

	/**
	 * Admin menu definition — filterable.
	 */
	public static function get_admin_menu_list() {
		$menu = [];

		$menu[ GEMSECURITY_PLUGIN_SLUG ] = [
			'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
			'title'       => __( 'Dashboard', 'gemsecurity' ),
			'capability'  => 'manage_options',
		];

		$menu[ GEMSECURITY_PLUGIN_SLUG . '-firewall' ] = [
			'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
			'title'       => __( 'Firewall', 'gemsecurity' ),
			'capability'  => 'manage_options',
		];

		$menu[ GEMSECURITY_PLUGIN_SLUG . '-threats' ] = [
			'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
			'title'       => __( 'Threat Defense', 'gemsecurity' ),
			'capability'  => 'manage_options',
			'is_pro'      => true,
		];

		$menu[ GEMSECURITY_PLUGIN_SLUG . '-login-security' ] = [
			'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
			'title'       => __( 'Login Security', 'gemsecurity' ),
			'capability'  => 'manage_options',
		];

		$menu[ GEMSECURITY_PLUGIN_SLUG . '-two-factor' ] = [
			'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
			'title'       => __( 'Two-Factor', 'gemsecurity' ),
			'capability'  => 'manage_options',
		];

		$menu[ GEMSECURITY_PLUGIN_SLUG . '-social-login' ] = [
			'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
			'title'       => __( 'Social Login', 'gemsecurity' ),
			'capability'  => 'manage_options',
		];

		$menu[ GEMSECURITY_PLUGIN_SLUG . '-geolocation' ] = [
			'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
			'title'       => __( 'Geolocation', 'gemsecurity' ),
			'capability'  => 'manage_options',
			'is_pro'      => true,
		];

		$menu[ GEMSECURITY_PLUGIN_SLUG . '-admin-guard' ] = [
			'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
			'title'       => __( 'Admin Guard', 'gemsecurity' ),
			'capability'  => 'manage_options',
		];

		// Scanner hosts every scan surface in one place: the free integrity /
		// file-change tools and the Pro malware + recovery toolkit (as tabs).
		$menu[ GEMSECURITY_PLUGIN_SLUG . '-scanner' ] = [
			'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
			'title'       => __( 'Scanner', 'gemsecurity' ),
			'capability'  => 'manage_options',
		];

		$menu[ GEMSECURITY_PLUGIN_SLUG . '-logs' ] = [
			'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
			'title'       => __( 'Logs', 'gemsecurity' ),
			'capability'  => 'manage_options',
		];

		$menu[ GEMSECURITY_PLUGIN_SLUG . '-backup' ] = [
			'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
			'title'       => __( 'Backup', 'gemsecurity' ),
			'capability'  => 'manage_options',
		];

		$menu[ GEMSECURITY_PLUGIN_SLUG . '-pro-tools' ] = [
			'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
			'title'       => __( 'Pro Tools', 'gemsecurity' ),
			'capability'  => 'manage_options',
			'is_pro'      => true,
		];

		$menu[ GEMSECURITY_PLUGIN_SLUG . '-settings' ] = [
			'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
			'title'       => __( 'Settings', 'gemsecurity' ),
			'capability'  => 'manage_options',
		];

		return apply_filters( 'gemsecurity/admin_menu_list', $menu );
	}

	/**
	 * Returns true for both the top-level page and all subpages.
	 *
	 * @param string $hook
	 * @return bool
	 */
	public static function plugin_page_hook_suffix( $hook ) {
		if ( 'toplevel_page_' . GEMSECURITY_PLUGIN_SLUG === $hook ) {
			return true;
		}

		if ( strpos( $hook, '_page_' . GEMSECURITY_PLUGIN_SLUG ) !== false ) {
			return true;
		}

		return false;
	}

	/**
	 * Get a plugin setting value with optional fallback.
	 *
	 * @param string $key
	 * @param mixed  $default
	 * @return mixed
	 */
	public static function get_setting( $key, $default = null ) {
		$settings = self::get_settings();
		return isset( $settings[ $key ] ) ? $settings[ $key ] : $default;
	}

	/**
	 * Get the visitor's IP address.
	 *
	 * @return string
	 */
	public static function get_ip_address() {
		$keys = [
			'HTTP_CF_CONNECTING_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR',
		];

		foreach ( $keys as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				$ip = trim( explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) )[0] );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		return '0.0.0.0';
	}
}
