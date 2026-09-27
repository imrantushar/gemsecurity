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
				'icon'          => 'grid',
				'category'      => 'core',
				'core'          => true,
				'page_slug'     => $slug,
				'classes'       => [],
			],
			'modules' => [
				'icon'          => 'layers',
				'category'      => 'core',
				'core'          => true,
				'page_slug'     => $slug . '-modules',
				'classes'       => [],
			],

			// ---- Firewall & hardening ------------------------------------
			'firewall' => [
				'icon'          => 'shield',
				'category'      => 'firewall',
				'recommended'   => true,
				'page_slug'     => $slug . '-firewall',
				// Waf owns every request-level rule the Firewall page configures:
				// the rule engine, rate limiting, the 404 throttle and bot control.
				// Pro's Hardening pack gates itself on this module too.
				'classes'       => [
					Waf::class,
					Firewall::class,
					SecurityHeaders::class,
				],
				'settings_keys' => [
					'firewall_enabled', 'xmlrpc_disabled', 'disable_file_editing',
					'block_author_enumeration', 'disable_user_rest', 'hide_wp_version',
					'security_headers_enabled', 'waf_enabled',
					'rate_limit_enabled', 'throttle_404_enabled', 'block_bad_bots',
					'block_ai_crawlers', 'verify_search_bots', 'login_errors_generic',
				],
			],
			'anti-spam' => [
				'icon'          => 'check',
				'category'      => 'firewall',
				'recommended'   => true,
				'page_slug'     => $slug . '-anti-spam',
				// Comments belongs here rather than with the firewall: every
				// comment control the UI offers now lives on the Anti-Spam page.
				'classes'       => [ AntiSpam::class, Comments::class ],
				'settings_keys' => [ 'antispam_enabled', 'antispam_heuristics', 'comments_disabled' ],
			],
			'threats' => [
				'icon'          => 'zap',
				'category'      => 'firewall',
				'is_pro'        => true,
				'page_slug'     => $slug . '-threats',
				'classes'       => [ ThreatIntel::class ], // Auto-ban enforcement lives in Waf; this adds detection.
			],
			'virtual-patch' => [
				'icon'          => 'shield',
				'category'      => 'firewall',
				'is_pro'        => true,
				'page_slug'     => $slug . '-virtual-patch',
				'classes'       => [ VirtualPatch::class ],
			],

			// ---- Login & access ------------------------------------------
			'login-security' => [
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
					LoginExtras::class,
				],
				'settings_keys' => [
					'login_attempts_enabled', 'admin_session_timeout_enabled',
					'password_policy_enabled', 'idle_timeout_enabled',
					'custom_login_enabled',
				],
			],
			'captcha' => [
				'icon'          => 'bot',
				'category'      => 'access',
				// On by default, and deliberately without `settings_keys`: the
				// module is the *page*, not the feature. Deriving it from
				// `captcha_enabled` would hide the page on every site that has
				// no CAPTCHA configured yet — which is exactly the site that
				// needs to find it. `captcha_enabled` stays as the granular
				// switch inside the page, and turning the module off from the
				// Modules page still removes the page and stops the class
				// booting. Defaulting on also means sites upgrading from before
				// this module existed (their stored state map has no key for it)
				// keep the CAPTCHA they already had.
				'recommended'   => true,
				'page_slug'     => $slug . '-captcha',
				'classes'       => [ Captcha::class ],
			],
			'two-factor' => [
				'icon'          => 'key',
				'category'      => 'access',
				'page_slug'     => $slug . '-two-factor',
				'classes'       => [ TwoFactor::class ],
				'settings_keys' => [ 'two_factor_enabled' ],
			],
			'social-login' => [
				'icon'          => 'users',
				'category'      => 'access',
				'page_slug'     => $slug . '-social-login',
				'classes'       => [ SocialLogin::class ],
				'settings_keys' => [ 'social_login_enabled' ],
			],
			'geolocation' => [
				'icon'          => 'globe',
				'category'      => 'access',
				'is_pro'        => true,
				'page_slug'     => $slug . '-geolocation',
				'classes'       => [ Geolocation::class ],
				'settings_keys' => [ 'geo_enabled' ],
			],
			'admin-guard' => [
				'icon'          => 'crown',
				'category'      => 'access',
				'recommended'   => true,
				'page_slug'     => $slug . '-admin-guard',
				'classes'       => [
					AdminGuard::class,
					HiddenAdmin::class,
				],
				'settings_keys' => [ 'admin_whitelist_enabled', 'hidden_admin_detection' ],
			],
			'api-hardening' => [
				'icon'          => 'key',
				'category'      => 'access',
				'recommended'   => true,
				'page_slug'     => $slug . '-api-hardening',
				'classes'       => [ ApiHardening::class ],
				'settings_keys' => [
					'rest_rate_limit_enabled', 'app_pw_disabled', 'app_pw_max_age_days',
				],
			],

			// ---- Scanning ------------------------------------------------
			'scanner' => [
				'icon'          => 'radar',
				'category'      => 'scanning',
				'recommended'   => true,
				'page_slug'     => $slug . '-scanner',
				// Scanner, Finder, FileWatcher and LinkScanner are on-demand
				// engines (driven by REST + cron) with no init() hooks, so there
				// is nothing to boot here — the module is its page + REST routes.
				// Pro's malware suite, baseline scopes and auto-update enforcement
				// gate themselves on this module.
				'classes'       => [],
				'settings_keys' => [
					'file_watcher_enabled', 'link_scanner_enabled',
					'scanner_auto_scan', 'vuln_scan_enabled',
				],
			],

			'payment-integrity' => [
				'icon'          => 'lock',
				'category'      => 'scanning',
				'is_pro'        => true,
				'page_slug'     => $slug . '-payment-integrity',
				'classes'       => [ PaymentIntegrity::class ],
				'settings_keys' => [ 'payment_integrity_enabled' ],
			],

			'incident-response' => [
				'icon'          => 'alert',
				'category'      => 'scanning',
				'is_pro'        => true,
				'page_slug'     => $slug . '-incident-response',
				'classes'       => [], // On-demand; all work via REST.
			],

			// ---- Logging -------------------------------------------------
			'logs' => [
				'icon'          => 'list',
				'category'      => 'logging',
				'core'          => true,
				'page_slug'     => $slug . '-logs',
				'classes'       => [ AuditLog::class ],
			],

			// ---- Maintenance ---------------------------------------------
			'backup' => [
				'icon'          => 'refresh',
				'category'      => 'maintenance',
				'recommended'   => true,
				'page_slug'     => $slug . '-backup',
				// The Backup subsystem boots via its own bootstrap (see gemsecurity.php),
				// gated on this module. No plain module class here.
				'classes'       => [],
			],
			'monitoring' => [
				'icon'          => 'globe',
				'category'      => 'maintenance',
				'is_pro'        => true,
				'page_slug'     => $slug . '-monitoring',
				'classes'       => [ Monitoring::class ],
				'settings_keys' => [ 'monitoring_enabled' ],
			],

			// ---- Notifications (core) ------------------------------------
			// Alert delivery and the scheduled sends. Every module raises events;
			// this is the one place that decides who hears about them, so it gets
			// its own page rather than a card buried in Settings. Core, because a
			// security plugin that cannot tell you anything is not one.
			'notifications' => [
				'icon'          => 'mail',
				'category'      => 'core',
				'core'          => true,
				'page_slug'     => $slug . '-notifications',
				'classes'       => [
					Alerts::class,
					DailyReport::class,
				],
			],

			// ---- Settings (core) -----------------------------------------
			// Compliance/SIEM and lockdown are configured on the Settings page,
			// so they boot with it. Settings is core, so these are always
			// available — which is what the page promises.
			'settings' => [
				'icon'          => 'cog',
				'category'      => 'core',
				'core'          => true,
				'page_slug'     => $slug . '-settings',
				'classes'       => [
					Compliance::class,
					Lockdown::class,
				],
			],
		];

		// Normalise every descriptor so consumers can rely on all keys existing.
		foreach ( $modules as $id => &$m ) {
			$m['id']            = $id;
			$m['core']          = ! empty( $m['core'] );
			$m['is_pro']        = ! empty( $m['is_pro'] );
			$m['recommended']   = ! empty( $m['recommended'] );
			$m['classes']       = isset( $m['classes'] ) ? (array) $m['classes'] : [];
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
	 * Human-readable strings for each module, resolved on demand.
	 *
	 * Kept out of all() deliberately. The registry is read during
	 * `plugins_loaded` to decide which modules to boot, and calling __() that
	 * early forces WordPress to load a text domain before `init` — which is
	 * exactly what the "translation loading was triggered too early" notice in
	 * 6.7 is about. Nothing that boots a module needs a label, so the labels
	 * live here and are merged in only by the code that actually displays them,
	 * all of which runs after `init`.
	 *
	 * @return array<string,array{title:string,desc:string}>
	 */
	public static function labels() {
		return [
			'dashboard' => [
				'title' => __( 'Dashboard', 'gemsecurity' ),
				'desc'  => __( 'Security overview and at-a-glance status.', 'gemsecurity' ),
			],
			'modules' => [
				'title' => __( 'Modules', 'gemsecurity' ),
				'desc'  => __( 'Turn security modules on or off. Activate only what this site needs.', 'gemsecurity' ),
			],
			'firewall' => [
				'title' => __( 'Firewall', 'gemsecurity' ),
				'desc'  => __( 'Request firewall and WAF rules, rate limiting, bot control, hardening switches and security headers.', 'gemsecurity' ),
			],
			'anti-spam' => [
				'title' => __( 'Anti-Spam', 'gemsecurity' ),
				'desc'  => __( 'Every comment and registration control in one place: silent bot checks, CAPTCHA on comments, heuristic filtering and the comment kill switch.', 'gemsecurity' ),
			],
			'threats' => [
				'title' => __( 'Threat Defense', 'gemsecurity' ),
				'desc'  => __( 'Live traffic, the ban ledger, escalating auto-bans, the early-load request firewall and behavioural detection.', 'gemsecurity' ),
			],
			'virtual-patch' => [
				'title' => __( 'Virtual Patch', 'gemsecurity' ),
				'desc'  => __( 'Mitigate known plugin/theme vulnerabilities in place — even before a fix ships.', 'gemsecurity' ),
			],
			'login-security' => [
				'title' => __( 'Login Security', 'gemsecurity' ),
				'desc'  => __( 'Brute-force lockouts, session limits, password policy and custom login URL.', 'gemsecurity' ),
			],
			'captcha' => [
				'title' => __( 'CAPTCHA', 'gemsecurity' ),
				'desc'  => __( 'A bot challenge — reCAPTCHA, hCaptcha or Turnstile — on the login, registration, lost-password and comment forms.', 'gemsecurity' ),
			],
			'two-factor' => [
				'title' => __( 'Two-Factor', 'gemsecurity' ),
				'desc'  => __( 'Time-based OTP / email two-factor, backup codes and per-role enforcement.', 'gemsecurity' ),
			],
			'social-login' => [
				'title' => __( 'Social Login', 'gemsecurity' ),
				'desc'  => __( 'Let users sign in with Google, Facebook, GitHub or X.', 'gemsecurity' ),
			],
			'geolocation' => [
				'title' => __( 'Geolocation', 'gemsecurity' ),
				'desc'  => __( 'Country access control and per-user location lock.', 'gemsecurity' ),
			],
			'admin-guard' => [
				'title' => __( 'Admin Guard', 'gemsecurity' ),
				'desc'  => __( 'Rogue-admin protection and hidden-administrator detection.', 'gemsecurity' ),
			],
			'api-hardening' => [
				'title' => __( 'API & Access', 'gemsecurity' ),
				'desc'  => __( 'REST API rate limiting and application-password governance.', 'gemsecurity' ),
			],
			'scanner' => [
				'title' => __( 'Scanner', 'gemsecurity' ),
				'desc'  => __( 'Integrity, file-change, link and vulnerability scanning, auto-update enforcement and the Pro malware suite.', 'gemsecurity' ),
			],
			'payment-integrity' => [
				'title' => __( 'Payment Integrity', 'gemsecurity' ),
				'desc'  => __( 'Monitor checkout-page scripts for Magecart-style tampering (PCI-DSS 4.0 §6.4.3 / §11.6.1).', 'gemsecurity' ),
			],
			'incident-response' => [
				'title' => __( 'Incident Response', 'gemsecurity' ),
				'desc'  => __( 'Forensic timeline, file quarantine and one-click recovery for after a breach.', 'gemsecurity' ),
			],
			'logs' => [
				'title' => __( 'Logs', 'gemsecurity' ),
				'desc'  => __( 'Activity audit log and what gets recorded in it.', 'gemsecurity' ),
			],
			'backup' => [
				'title' => __( 'Backup', 'gemsecurity' ),
				'desc'  => __( 'Scheduled site backups with local (and Pro remote) storage.', 'gemsecurity' ),
			],
			'monitoring' => [
				'title' => __( 'Monitoring', 'gemsecurity' ),
				'desc'  => __( 'Uptime, TLS-certificate expiry, DNS-change and email-authentication (SPF/DMARC) monitoring.', 'gemsecurity' ),
			],
			'notifications' => [
				'title' => __( 'Notifications', 'gemsecurity' ),
				'desc'  => __( 'Where alerts go, what raises one, and the reports sent on a schedule.', 'gemsecurity' ),
			],
			'settings' => [
				'title' => __( 'Settings', 'gemsecurity' ),
				'desc'  => __( 'Plugin-wide preferences: compliance/SIEM, lockdown, log retention and import/export.', 'gemsecurity' ),
			],
		];
	}

	/**
	 * A descriptor with its display strings merged in.
	 *
	 * Use this anywhere a title or description is shown; use all() when only
	 * the structure matters.
	 *
	 * @param string $id
	 * @return array|null
	 */
	public static function describe( $id ) {
		$all = self::all();
		if ( ! isset( $all[ $id ] ) ) {
			return null;
		}
		$labels = self::labels();
		return array_merge(
			$all[ $id ],
			[
				'title' => isset( $labels[ $id ]['title'] ) ? $labels[ $id ]['title'] : $id,
				'desc'  => isset( $labels[ $id ]['desc'] ) ? $labels[ $id ]['desc'] : '',
			]
		);
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
		$out    = [];
		$labels = self::labels();
		foreach ( self::all() as $id => $m ) {
			$out[] = [
				'id'        => $id,
				'title'     => isset( $labels[ $id ]['title'] ) ? $labels[ $id ]['title'] : $id,
				'desc'      => isset( $labels[ $id ]['desc'] ) ? $labels[ $id ]['desc'] : '',
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
