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
	 * Sign a short-lived payload for a round trip through the browser.
	 *
	 * Login flows park their state in a transient and read it back on the next
	 * request. That breaks quietly wherever the two requests are not served by
	 * the same cache — a per-process object cache, a second app server, a flush
	 * mid-flow — and the visitor just lands back on the login form with nothing
	 * logged. A signed cookie carries the same payload through the browser so
	 * the flow can complete without shared server-side storage.
	 *
	 * The value is signed, not encrypted: never put anything in it that the
	 * user may not see.
	 *
	 * @param array $data
	 * @return string
	 */
	public static function sign_payload( array $data ) {
		$data['_t'] = time();
		$json       = wp_json_encode( $data );

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		return base64_encode( $json ) . '.' . hash_hmac( 'sha256', $json, wp_salt( 'auth' ) );
	}

	/**
	 * Verify and decode a payload produced by sign_payload().
	 *
	 * @param string $value
	 * @param int    $max_age Seconds the payload stays valid.
	 * @return array|false
	 */
	public static function verify_signed_payload( $value, $max_age = 600 ) {
		$parts = explode( '.', (string) $value );
		if ( 2 !== count( $parts ) ) {
			return false;
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		$json = base64_decode( $parts[0], true );
		if ( false === $json || ! hash_equals( hash_hmac( 'sha256', $json, wp_salt( 'auth' ) ), $parts[1] ) ) {
			return false;
		}

		$data = json_decode( $json, true );
		if ( ! is_array( $data ) || empty( $data['_t'] ) || ( time() - (int) $data['_t'] ) > $max_age ) {
			return false;
		}

		unset( $data['_t'] );
		return $data;
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
	 * Backs the public `gemsecurity/module_active` filter — the integration
	 * surface other plugins (e.g. Academy LMS) use to ask "is GemSecurity
	 * module X active?" without depending on GemSecurity's internal classes
	 * or data storage. Registered unconditionally in gemsecurity.php so it's
	 * queryable any time GemSecurity itself is active, regardless of which
	 * individual modules are on.
	 *
	 * `captcha` is special-cased: it isn't its own Registry module (the
	 * Captcha class boots as part of the `two-factor` module), but "is
	 * CAPTCHA protection active" is the semantic an external caller actually
	 * wants, so this resolves it from the settings that actually govern it.
	 *
	 * @param bool   $default
	 * @param string $id
	 * @return bool
	 */
	public static function is_module_active( $default, $id ) {
		if ( 'captcha' === $id ) {
			return self::get_setting( 'captcha_enabled', false ) && \GemSecurity\Modules\Captcha::is_configured();
		}
		$all = \GemSecurity\Modules\Registry::all();
		if ( ! isset( $all[ $id ] ) ) {
			// Unrecognized id — hand back the caller's own default rather than
			// asserting "inactive", so a caller passing `true` (to fail open)
			// isn't silently overridden.
			return $default;
		}
		return \GemSecurity\Modules\Registry::is_active( (string) $id );
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
	 * Admin menu definition — derived from the module registry so only visible
	 * modules produce a menu item. Core and Pro modules are always visible (Pro
	 * as a locked upsell); other modules appear only when active. Shape is kept
	 * stable (page_slug => [parent_slug,title,capability,is_pro]) for menu.php
	 * and the localized React payload.
	 */
	public static function get_admin_menu_list() {
		$menu = [];

		// Labels are fetched here rather than from the registry itself: the
		// registry is read during plugins_loaded, and translating there loads a
		// text domain before init. This runs on admin_menu, which is safe.
		$labels = \GemSecurity\Modules\Registry::labels();

		foreach ( \GemSecurity\Modules\Registry::all() as $id => $module ) {
			if ( ! \GemSecurity\Modules\Registry::is_visible( $id ) ) {
				continue;
			}
			$menu[ $module['page_slug'] ] = [
				'parent_slug' => GEMSECURITY_PLUGIN_SLUG,
				'title'       => isset( $labels[ $id ]['title'] ) ? $labels[ $id ]['title'] : $id,
				'capability'  => 'manage_options',
				'is_pro'      => $module['is_pro'],
			];
		}

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
	 * Forwarding headers (CF-Connecting-IP, X-Forwarded-For, X-Real-IP) are
	 * trivially spoofable by any client — trusting them unconditionally lets
	 * an attacker rotate their apparent IP on every request, bypassing login
	 * lockouts, IP bans and rate limits. They're only honoured when the
	 * connection is actually arriving from a proxy/CDN the site owner has
	 * explicitly trusted (Cloudflare, or a custom "trusted_proxies" list);
	 * every other request resolves to the raw REMOTE_ADDR, which cannot be
	 * forged without controlling that network hop.
	 *
	 * @return string
	 */
	public static function get_ip_address() {
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( (string) $_SERVER['REMOTE_ADDR'] ) : '';
		$remote_addr = filter_var( $remote_addr, FILTER_VALIDATE_IP ) ? $remote_addr : '0.0.0.0';

		if ( ! self::is_trusted_proxy( $remote_addr ) ) {
			return $remote_addr;
		}

		foreach ( [ 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ] as $key ) {
			if ( empty( $_SERVER[ $key ] ) ) {
				continue;
			}
			$chain = explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) );

			// A forwarding header can carry a multi-hop chain
			// ("client, proxy1, proxy2, ..."). Walk it right-to-left,
			// skipping any entry that is itself a trusted proxy, and take
			// the first one that isn't — never trust the leftmost entry
			// blindly, since a client can prepend a fake IP before the
			// chain reaches your real proxy.
			for ( $i = count( $chain ) - 1; $i >= 0; $i-- ) {
				$candidate = trim( $chain[ $i ] );
				if ( ! filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
					continue;
				}
				if ( self::is_trusted_proxy( $candidate ) ) {
					continue;
				}
				return $candidate;
			}
		}

		// Trusted proxy, but no usable header value — fall back to the
		// connection IP (the proxy's own address) rather than guessing.
		return $remote_addr;
	}

	/**
	 * Whether $ip is a proxy/CDN edge this site has explicitly chosen to
	 * trust for forwarded-IP headers.
	 *
	 * @param string $ip
	 * @return bool
	 */
	private static function is_trusted_proxy( $ip ) {
		if ( '' === $ip || '0.0.0.0' === $ip ) {
			return false;
		}

		if ( self::get_setting( 'trust_cloudflare_ip', false ) ) {
			foreach ( self::cloudflare_ip_ranges() as $cidr ) {
				if ( self::ip_in_cidr( $ip, $cidr ) ) {
					return true;
				}
			}
		}

		foreach ( (array) self::get_setting( 'trusted_proxies', [] ) as $cidr ) {
			$cidr = trim( (string) $cidr );
			if ( '' !== $cidr && self::ip_in_cidr( $ip, $cidr ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Cloudflare's published edge IP ranges (https://www.cloudflare.com/ips/).
	 * Filterable so a site can correct/update the list without waiting on a
	 * plugin release if Cloudflare ever changes it.
	 *
	 * @return string[]
	 */
	private static function cloudflare_ip_ranges() {
		static $ranges = null;
		if ( null === $ranges ) {
			$ranges = apply_filters( 'gemsecurity/cloudflare_ip_ranges', [
				// IPv4.
				'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
				'141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
				'197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
				'104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
				// IPv6.
				'2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
				'2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
			] );
		}
		return $ranges;
	}

	/**
	 * Whether $ip (IPv4 or IPv6) falls inside $cidr. A bare IP (no "/bits")
	 * is treated as an exact match.
	 *
	 * @param string $ip
	 * @param string $cidr
	 * @return bool
	 */
	private static function ip_in_cidr( $ip, $cidr ) {
		$parts  = explode( '/', $cidr, 2 );
		$subnet = $parts[0];

		$ip_bin     = @inet_pton( $ip );
		$subnet_bin = @inet_pton( $subnet );
		// False on invalid input; family mismatch (IPv4 vs IPv6) shows up as
		// different packed lengths — both are simply "no match".
		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$max_bits = strlen( $ip_bin ) * 8;
		$bits     = isset( $parts[1] ) ? (int) $parts[1] : $max_bits;
		if ( $bits < 0 || $bits > $max_bits ) {
			return false;
		}
		if ( 0 === $bits ) {
			return true; // 0.0.0.0/0 or ::/0 — matches everything.
		}

		$full_bytes = intdiv( $bits, 8 );
		if ( $full_bytes > 0 && substr( $ip_bin, 0, $full_bytes ) !== substr( $subnet_bin, 0, $full_bytes ) ) {
			return false;
		}

		$remaining_bits = $bits % 8;
		if ( 0 === $remaining_bits ) {
			return true;
		}

		$mask = chr( ( 0xFF << ( 8 - $remaining_bits ) ) & 0xFF );
		return ( $ip_bin[ $full_bytes ] & $mask ) === ( $subnet_bin[ $full_bytes ] & $mask );
	}
}
