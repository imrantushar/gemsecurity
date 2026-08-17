<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Module registry — the single source of truth for GemSecurity's feature
 * modules.
 *
 * Each module is a page-level feature area. A descriptor ties together
 * everything about that feature: its admin menu entry, its React nav item +
 * page, the PHP class(es) it boots, and the REST route group(s) it registers.
 * Everything downstream (the boot loop in gemsecurity.php, the admin menu, REST
 * registration, and the React nav/router) derives from this registry.
 *
 * Activation is a *coarse* gate stored in the `gemsecurity_active_modules`
 * option. A module that is not active never loads its classes, never registers
 * its menu item, and never registers its REST routes — so it costs nothing.
 * The existing per-feature `*_enabled` settings survive as granular sub-toggles
 * *inside* an active module.
 *
 * Two module kinds bypass the activation toggle:
 *  - `core` modules (Dashboard, Modules, Logs, Settings) are always active.
 *  - `is_pro` modules are always *visible* (as an upsell) but only *boot* when
 *    both their activation flag is on AND Pro is active.
 */
class Registry {

	/** Option holding the per-module activation map: [ id => bool ]. */
	const OPTION = 'gemsecurity_active_modules';

	/** In-request cache of the activation map. */
	private static $state_cache = null;

	/** In-request cache of the resolved descriptor map. */
	private static $descriptors_cache = null;

	/**
	 * All module descriptors, keyed by id, in display order.
	 *
	 * A descriptor:
	 *  - id           string   Stable module id (also the manager key).
	 *  - title        string   Human label (menu + nav + manager card).
	 *  - desc         string   One-line description (manager card).
	 *  - icon         string   Icon name shared with the React nav.
	 *  - category     string   Grouping bucket for the manager UI.
	 *  - core         bool     Always active, cannot be toggled off.
	 *  - is_pro       bool     Requires Pro to boot; always shown as upsell.
	 *  - recommended  bool     Seeded ON for fresh installs.
	 *  - page_slug    string   WP ?page= slug + React route key.
	 *  - classes      string[] Fully-qualified class names booted when active.
	 *  - rest         string[] REST route-group keys registered when active.
	 *  - settings_keys string[] Settings whose truthiness implies "was in use"
	 *                           (used to derive activation on upgrade).
	 *
	 * @return array<string,array>
	 */
	public static function all() {
		if ( null !== self::$descriptors_cache ) {
			return self::$descriptors_cache;
		}

		$slug = GEMSECURITY_PLUGIN_SLUG;

		$modules = [

			// ---- Core (always active) ------------------------------------
			'dashboard' => [
				'title'         => __( 'Dashboard', 'gemsecurity' ),
				'desc'          => __( 'Security overview and at-a-glance status.', 'gemsecurity' ),
				'icon'          => 'grid',
				'category'      => 'core',
				'core'          => true,
				'page_slug'     => $slug,
				'classes'       => [],
				'rest'          => [ 'dashboard', 'search' ],
			],
			'modules' => [
				'title'         => __( 'Modules', 'gemsecurity' ),
				'desc'          => __( 'Turn security modules on or off. Activate only what this site needs.', 'gemsecurity' ),
				'icon'          => 'layers',
				'category'      => 'core',
				'core'          => true,
				'page_slug'     => $slug . '-modules',
				'classes'       => [],
				'rest'          => [ 'modules' ],
			],

			// ---- Firewall & hardening ------------------------------------
			'firewall' => [
				'title'         => __( 'Firewall', 'gemsecurity' ),
				'desc'          => __( 'Request firewall, hardening switches, security headers and comment control.', 'gemsecurity' ),
				'icon'          => 'shield',
				'category'      => 'firewall',
				'recommended'   => true,
				'page_slug'     => $slug . '-firewall',
				'classes'       => [
					Waf::class,
					Firewall::class,
					Comments::class,
					SecurityHeaders::class,
				],
				'rest'          => [],
				'settings_keys' => [
					'firewall_enabled', 'xmlrpc_disabled', 'disable_file_editing',
					'block_author_enumeration', 'disable_user_rest', 'hide_wp_version',
					'comments_disabled', 'security_headers_enabled', 'waf_enabled',
					'rate_limit_enabled', 'throttle_404_enabled', 'block_bad_bots',
					'block_ai_crawlers', 'verify_search_bots',
				],
			],
			'anti-spam' => [
				'title'         => __( 'Anti-Spam', 'gemsecurity' ),
				'desc'          => __( 'Frictionless bot checks on comments and registration, plus heuristic comment filtering.', 'gemsecurity' ),
				'icon'          => 'check',
				'category'      => 'firewall',
				'recommended'   => true,
				'page_slug'     => $slug . '-anti-spam',
				'classes'       => [ AntiSpam::class ],
				'rest'          => [],
				'settings_keys' => [ 'antispam_enabled', 'antispam_heuristics' ],
			],
			'threats' => [
				'title'         => __( 'Threat Defense', 'gemsecurity' ),
				'desc'          => __( 'Escalating auto-bans, the ban ledger and the early-load request firewall.', 'gemsecurity' ),
				'icon'          => 'zap',
				'category'      => 'firewall',
				'is_pro'        => true,
				'page_slug'     => $slug . '-threats',
				'classes'       => [ ThreatIntel::class ], // Auto-ban enforcement lives in Waf; this adds detection.
				'rest'          => [ 'bans', 'bots', 'live-traffic' ],
			],
			'virtual-patch' => [
				'title'         => __( 'Virtual Patch', 'gemsecurity' ),
				'desc'          => __( 'Mitigate known plugin/theme vulnerabilities in place — even before a fix ships.', 'gemsecurity' ),
				'icon'          => 'shield',
				'category'      => 'firewall',
				'is_pro'        => true,
				'page_slug'     => $slug . '-virtual-patch',
				'classes'       => [ VirtualPatch::class ],
				'rest'          => [ 'vpatch' ],
			],

			// ---- Login & access ------------------------------------------
			'login-security' => [
				'title'         => __( 'Login Security', 'gemsecurity' ),
				'desc'          => __( 'Brute-force lockouts, session limits, password policy and custom login URL.', 'gemsecurity' ),
				'icon'          => 'lock',
				'category'      => 'access',
				'recommended'   => true,
				'page_slug'     => $slug . '-login-security',
				'classes'       => [
					LoginSecurity::class,
					Sessions::class,
					PasswordPolicy::class,
					PasswordRotation::class,
					CustomLogin::class,
					Lockdown::class,
					LoginExtras::class,
				],
				'rest'          => [ 'sessions', 'magic-link' ],
				'settings_keys' => [
					'login_attempts_enabled', 'admin_session_timeout_enabled',
					'password_policy_enabled', 'idle_timeout_enabled',
					'custom_login_enabled', 'lockdown_enabled',
				],
			],
			'two-factor' => [
				'title'         => __( 'Two-Factor', 'gemsecurity' ),
				'desc'          => __( 'Time-based OTP / email two-factor and login CAPTCHA.', 'gemsecurity' ),
				'icon'          => 'key',
				'category'      => 'access',
				'page_slug'     => $slug . '-two-factor',
				'classes'       => [
					TwoFactor::class,
					Captcha::class,
				],
				'rest'          => [ '2fa' ],
				'settings_keys' => [ 'two_factor_enabled', 'captcha_enabled' ],
			],
			'social-login' => [
				'title'         => __( 'Social Login', 'gemsecurity' ),
				'desc'          => __( 'Let users sign in with Google, Facebook, GitHub or X.', 'gemsecurity' ),
				'icon'          => 'users',
				'category'      => 'access',
				'page_slug'     => $slug . '-social-login',
				'classes'       => [ SocialLogin::class ],
				'rest'          => [ 'social' ],
				'settings_keys' => [ 'social_login_enabled' ],
			],
			'geolocation' => [
				'title'         => __( 'Geolocation', 'gemsecurity' ),
				'desc'          => __( 'Country access control and per-user location lock.', 'gemsecurity' ),
				'icon'          => 'globe',
				'category'      => 'access',
				'is_pro'        => true,
				'page_slug'     => $slug . '-geolocation',
				'classes'       => [ Geolocation::class ],
				'rest'          => [ 'geo' ],
				'settings_keys' => [ 'geo_enabled' ],
			],
			'admin-guard' => [
				'title'         => __( 'Admin Guard', 'gemsecurity' ),
				'desc'          => __( 'Rogue-admin protection and hidden-administrator detection.', 'gemsecurity' ),
				'icon'          => 'crown',
				'category'      => 'access',
				'recommended'   => true,
				'page_slug'     => $slug . '-admin-guard',
				'classes'       => [
					AdminGuard::class,
					HiddenAdmin::class,
				],
				'rest'          => [ 'admins' ],
				'settings_keys' => [ 'admin_whitelist_enabled', 'hidden_admin_detection' ],
			],
			'api-hardening' => [
				'title'         => __( 'API & Access', 'gemsecurity' ),
				'desc'          => __( 'REST API rate limiting, application-password governance and username-enumeration hardening.', 'gemsecurity' ),
				'icon'          => 'key',
				'category'      => 'access',
				'recommended'   => true,
				'page_slug'     => $slug . '-api-hardening',
				'classes'       => [ ApiHardening::class ],
				'rest'          => [ 'app-passwords' ],
				'settings_keys' => [
					'rest_rate_limit_enabled', 'app_pw_disabled',
					'app_pw_max_age_days', 'login_errors_generic',
				],
			],

			// ---- Scanning ------------------------------------------------
			'scanner' => [
				'title'         => __( 'Scanner', 'gemsecurity' ),
				'desc'          => __( 'Integrity, file-change, link and vulnerability scanning (plus the Pro malware suite).', 'gemsecurity' ),
				'icon'          => 'radar',
				'category'      => 'scanning',
				'recommended'   => true,
				'page_slug'     => $slug . '-scanner',
				// Scanner, Finder, FileWatcher and LinkScanner are on-demand
				// engines (driven by REST + cron) with no init() hooks, so there
				// is nothing to boot here — the module is its page + REST routes.
				'classes'       => [],
				'rest'          => [ 'scan', 'mu-plugins', 'supply-chain' ],
				'settings_keys' => [
					'file_watcher_enabled', 'link_scanner_enabled',
					'scanner_auto_scan', 'vuln_scan_enabled',
				],
			],

			'payment-integrity' => [
				'title'         => __( 'Payment Integrity', 'gemsecurity' ),
				'desc'          => __( 'Monitor checkout-page scripts for Magecart-style tampering (PCI-DSS 4.0 §6.4.3 / §11.6.1).', 'gemsecurity' ),
				'icon'          => 'lock',
				'category'      => 'scanning',
				'is_pro'        => true,
				'page_slug'     => $slug . '-payment-integrity',
				'classes'       => [ PaymentIntegrity::class ],
				'rest'          => [ 'payment-scripts' ],
				'settings_keys' => [ 'payment_integrity_enabled' ],
			],

			'incident-response' => [
				'title'         => __( 'Incident Response', 'gemsecurity' ),
				'desc'          => __( 'Forensic timeline, file quarantine and one-click recovery for after a breach.', 'gemsecurity' ),
				'icon'          => 'alert',
				'category'      => 'scanning',
				'is_pro'        => true,
				'page_slug'     => $slug . '-incident-response',
				'classes'       => [], // On-demand; all work via REST.
				'rest'          => [ 'incident' ],
			],

			// ---- Logging -------------------------------------------------
			'logs' => [
				'title'         => __( 'Logs', 'gemsecurity' ),
				'desc'          => __( 'Activity audit log and real-time alerts.', 'gemsecurity' ),
				'icon'          => 'list',
				'category'      => 'core',
				'core'          => true,
				'page_slug'     => $slug . '-logs',
				'classes'       => [
					AuditLog::class,
					DailyReport::class,
					Alerts::class,
					Compliance::class,
				],
				'rest'          => [ 'logs' ],
			],

			// ---- Maintenance ---------------------------------------------
			'backup' => [
				'title'         => __( 'Backup', 'gemsecurity' ),
				'desc'          => __( 'Scheduled site backups with local (and Pro remote) storage.', 'gemsecurity' ),
				'icon'          => 'refresh',
				'category'      => 'maintenance',
				'recommended'   => true,
				'page_slug'     => $slug . '-backup',
				// The Backup subsystem boots via its own bootstrap (see gemsecurity.php),
				// gated on this module. No plain module class here.
				'classes'       => [],
				'rest'          => [],
			],
			'monitoring' => [
				'title'         => __( 'Monitoring', 'gemsecurity' ),
				'desc'          => __( 'Uptime, TLS-certificate expiry, DNS-change and email-authentication (SPF/DMARC) monitoring.', 'gemsecurity' ),
				'icon'          => 'globe',
				'category'      => 'maintenance',
				'is_pro'        => true,
				'page_slug'     => $slug . '-monitoring',
				'classes'       => [ Monitoring::class ],
				'rest'          => [ 'monitoring' ],
				'settings_keys' => [ 'monitoring_enabled' ],
			],
			'pro-tools' => [
				'title'         => __( 'Pro Tools', 'gemsecurity' ),
				'desc'          => __( 'Hardening pack, file-change baseline, auto-update enforcement and settings import/export.', 'gemsecurity' ),
				'icon'          => 'crown',
				'category'      => 'maintenance',
				'is_pro'        => true,
				'page_slug'     => $slug . '-pro-tools',
				// Backing classes live in the Pro plugin and gate themselves on
				// this module via Registry::is_active( 'pro-tools' ).
				'classes'       => [],
				'rest'          => [],
			],

			// ---- Settings (core) -----------------------------------------
			'settings' => [
				'title'         => __( 'Settings', 'gemsecurity' ),
				'desc'          => __( 'Plugin-wide preferences.', 'gemsecurity' ),
				'icon'          => 'cog',
				'category'      => 'core',
				'core'          => true,
				'page_slug'     => $slug . '-settings',
				'classes'       => [],
				'rest'          => [ 'settings' ],
			],
		];

		// Normalise every descriptor so consumers can rely on all keys existing.
		foreach ( $modules as $id => &$m ) {
			$m['id']            = $id;
			$m['core']          = ! empty( $m['core'] );
			$m['is_pro']        = ! empty( $m['is_pro'] );
			$m['recommended']   = ! empty( $m['recommended'] );
			$m['classes']       = isset( $m['classes'] ) ? (array) $m['classes'] : [];
			$m['rest']          = isset( $m['rest'] ) ? (array) $m['rest'] : [];
			$m['settings_keys'] = isset( $m['settings_keys'] ) ? (array) $m['settings_keys'] : [];
		}
		unset( $m );

		/**
		 * Filter the module registry. Addons (e.g. Pro) can add or amend
		 * descriptors here — a single hook that feeds the menu, REST, boot loop
		 * and React UI at once.
		 *
		 * @param array<string,array> $modules
		 */
		self::$descriptors_cache = apply_filters( 'gemsecurity/modules', $modules );

		return self::$descriptors_cache;
	}

	/**
	 * The persisted activation map, resolved once per request.
	 *
	 * @return array<string,bool>
	 */
	public static function state() {
		if ( null === self::$state_cache ) {
			$state = get_option( self::OPTION, [] );
			self::$state_cache = is_array( $state ) ? $state : [];
		}
		return self::$state_cache;
	}

	/** Drop the in-request activation cache (hooked on option update/add). */
	public static function flush_state_cache() {
		self::$state_cache = null;
	}

	/**
	 * The default activation for a module when nothing is stored yet.
	 * Core, recommended and Pro modules default ON; everything else OFF.
	 *
	 * @param array $descriptor
	 * @return bool
	 */
	private static function default_on( array $descriptor ) {
		return $descriptor['core'] || $descriptor['recommended'] || $descriptor['is_pro'];
	}

	/**
	 * Whether a module should BOOT (load its classes + REST routes).
	 *
	 * @param string $id
	 * @return bool
	 */
	public static function is_active( $id ) {
		$all = self::all();
		if ( ! isset( $all[ $id ] ) ) {
			return false;
		}
		$m = $all[ $id ];

		if ( $m['core'] ) {
			return true;
		}

		$state = self::state();
		$on    = array_key_exists( $id, $state ) ? (bool) $state[ $id ] : self::default_on( $m );

		// Pro modules only boot when Pro is actually active.
		if ( $m['is_pro'] ) {
			return $on && Helper::is_pro_active();
		}

		return $on;
	}

	/**
	 * Whether a module should be VISIBLE in the menu / nav.
	 *
	 * Core modules always show. A Pro module shows as a locked upsell only
	 * while Pro is inactive — there is no toggle to honour yet. Once Pro is
	 * active it obeys its own activation flag exactly like a free module, so
	 * turning any module off removes its menu entry.
	 *
	 * @param string $id
	 * @return bool
	 */
	public static function is_visible( $id ) {
		$all = self::all();
		if ( ! isset( $all[ $id ] ) ) {
			return false;
		}
		$m = $all[ $id ];

		if ( $m['core'] ) {
			return true;
		}

		if ( $m['is_pro'] && ! Helper::is_pro_active() ) {
			return true;
		}

		return self::is_active( $id );
	}

	/**
	 * Descriptors for every module that should boot right now.
	 *
	 * @return array<string,array>
	 */
	public static function active_modules() {
		return array_filter( self::all(), static function ( $m ) {
			return self::is_active( $m['id'] );
		} );
	}

	/**
	 * Compact descriptor list for the React app (localized in Assets).
	 * Includes resolved `active`/`visible` flags per module.
	 *
	 * @return array<int,array>
	 */
	public static function for_js() {
		$out = [];
		foreach ( self::all() as $id => $m ) {
			$out[] = [
				'id'        => $id,
				'title'     => $m['title'],
				'desc'      => $m['desc'],
				'icon'      => $m['icon'],
				'category'  => $m['category'],
				'core'      => $m['core'],
				'is_pro'    => $m['is_pro'],
				'page_slug' => $m['page_slug'],
				'active'    => self::is_active( $id ),
				'visible'   => self::is_visible( $id ),
			];
		}
		return $out;
	}

	/**
	 * Derive an activation map from the current settings — used to seed the
	 * option on install and, crucially, on upgrade so existing sites keep
	 * exactly the behavior they already had (a module is turned ON if any of
	 * its backing `*_enabled` settings is truthy).
	 *
	 * @param array $settings The gemsecurity_settings array.
	 * @return array<string,bool>
	 */
	public static function derive_active_from_settings( array $settings ) {
		$state = [];
		foreach ( self::all() as $id => $m ) {
			if ( $m['core'] ) {
				continue; // Core is implicit; no need to store.
			}

			// Pro modules default ON so unlocking Pro lights them up immediately.
			if ( $m['is_pro'] ) {
				$state[ $id ] = true;
				continue;
			}

			// Modules with no backing settings key fall back to their default.
			if ( empty( $m['settings_keys'] ) ) {
				$state[ $id ] = self::default_on( $m );
				continue;
			}

			$on = false;
			foreach ( $m['settings_keys'] as $key ) {
				if ( ! empty( $settings[ $key ] ) ) {
					$on = true;
					break;
				}
			}
			$state[ $id ] = $on;
		}
		return $state;
	}

	/**
	 * Seed the activation option if it has never been stored. Safe to call on
	 * every activation / upgrade — it only writes when the option is absent so
	 * a user's later choices are never clobbered.
	 *
	 * @return void
	 */
	public static function seed_if_missing() {
		if ( false !== get_option( self::OPTION, false ) ) {
			return;
		}
		$settings = get_option( GEMSECURITY_SETTINGS_NAME, [] );
		if ( ! is_array( $settings ) ) {
			$settings = [];
		}
		add_option( self::OPTION, self::derive_active_from_settings( $settings ) );
		self::flush_state_cache();
	}

	/**
	 * Persist a single module's activation. Core modules cannot be toggled;
	 * Pro modules cannot be turned on while Pro is inactive.
	 *
	 * @param string $id
	 * @param bool   $active
	 * @return bool|\WP_Error True on success.
	 */
	public static function set_active( $id, $active ) {
		$all = self::all();
		if ( ! isset( $all[ $id ] ) ) {
			return new \WP_Error( 'gemsecurity_unknown_module', __( 'Unknown module.', 'gemsecurity' ) );
		}
		$m = $all[ $id ];

		if ( $m['core'] ) {
			return new \WP_Error( 'gemsecurity_core_module', __( 'Core modules cannot be turned off.', 'gemsecurity' ) );
		}
		if ( $active && $m['is_pro'] && ! Helper::is_pro_active() ) {
			return new \WP_Error( 'gemsecurity_pro_required', __( 'This module requires GemSecurity Pro.', 'gemsecurity' ) );
		}

		$state        = self::state();
		$state[ $id ] = (bool) $active;
		update_option( self::OPTION, $state );
		self::flush_state_cache();
		return true;
	}
}
