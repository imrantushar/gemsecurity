<?php
namespace GemSecurity\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugin Guard — an allowlist for executable code.
 *
 * Every plugin, must-use plugin and theme is classified as either
 *  - verified: a WordPress.org plugin whose files match the official
 *    checksums for its installed version (a lookalike with the same folder
 *    name but edited code fails this), or
 *  - trusted: explicitly approved by an administrator on the Plugin Guard
 *    page (premium/custom plugins, mu-plugins, pre-approved uploads).
 *
 * With enforcement on, anything else cannot run:
 *  - An untrusted plugin found in `active_plugins` (activated through the
 *    database, or by a hacked account) is filtered out before WordPress loads
 *    it, permanently deactivated, logged and reported by email.
 *  - Activating one from wp-admin or the REST API is refused before its code
 *    is included.
 *  - An untrusted must-use plugin (top-level file, matched by name AND content
 *    hash, so a trusted file that is edited loses its trust) is moved into the
 *    quarantine before WordPress includes it.
 *  - Installing a plugin or theme is refused unless it is on WordPress.org
 *    (plugins: checksum-matched) or was pre-approved by slug.
 *
 * This file is deliberately self-contained: the "0-gemsecurity-plugin-guard"
 * must-use plugin requires it directly and calls {@see early()} before any
 * regular plugin loads — which is the only point where an active plugin can be
 * stopped from running. Anything from the rest of GemSecurity (Logger, Mailer)
 * is used lazily on `init`, and only if it is loaded.
 *
 * Kill switch: define( 'GEMSECURITY_PLUGIN_GUARD_OFF', true ) in wp-config.php.
 */
class PluginGuard {

	/** Guard state: enabled flag + trust list + verification cache (autoloaded: read every request). */
	const OPTION = 'gemsecurity_plugin_guard';

	/** Recent block events, for the UI and for alert rate-limiting. */
	const EVENTS_OPTION = 'gemsecurity_plugin_guard_events';

	/** The early-load must-use file. "0-" so it sorts (and runs) before other mu-plugins. */
	const MU_FILE = '0-gemsecurity-plugin-guard.php';

	const CRON_HOOK = 'gemsecurity_plugin_guard_verify';

	/** Emails held until init (events recorded during mu-plugin load). */
	private static $pending_mail = [];

	/** Plugins blocked during this request, flushed (deactivated + reported) on init. */
	private static $blocked = [];

	/** Mu-plugins quarantined during this request. */
	private static $quarantined = [];

	/** Stub files left in place of quarantined mu-plugins until the mu loop finishes. */
	private static $stubs = [];

	/** When true, the active_plugins filter is bypassed (our own writes). */
	private static $raw = false;

	private static $booted = false;

	/* ------------------------------------------------------------------ */
	/* State                                                              */
	/* ------------------------------------------------------------------ */

	public static function defaults() {
		return [
			'enabled'  => false,
			// key => [ name, at, by, hash? ]. Keys: plugin:<slug>, theme:<slug>, mu:<file>.
			'trusted'  => [],
			// plugin basename => [ status, version, checked_at, note ].
			'verified' => [],
			// Install Lock: off | uploads | installs | full. See install_lock_modes().
			'install_lock' => 'off',
			// Unix time until which the lock is lifted (timed admin unlock).
			'unlock_until' => 0,
			// Upload Shield: refuse executable files on every upload path. On by
			// default — a .php file is never a legitimate upload.
			'upload_shield' => true,
			// Also refuse SVG/HTML (script-capable markup). Off by default: many
			// sites rely on SVG logos.
			'shield_markup' => false,
			// Ban the IP behind a refused upload. Admins' own IP is never banned.
			'shield_autoban' => true,
			// Ban length in hours; 0 = permanent.
			'shield_ban_hours' => 0,
		];
	}

	public static function state() {
		$s = get_option( self::OPTION, [] );
		return array_merge( self::defaults(), is_array( $s ) ? $s : [] );
	}

	public static function save_state( array $s ) {
		update_option( self::OPTION, $s, true );
	}

	public static function is_enabled() {
		if ( defined( 'GEMSECURITY_PLUGIN_GUARD_OFF' ) && GEMSECURITY_PLUGIN_GUARD_OFF ) {
			return false;
		}
		$s = self::state();
		return ! empty( $s['enabled'] );
	}

	/** Plugin folder slug from a basename ("akismet/akismet.php" → "akismet", "hello.php" → "hello"). */
	public static function slug_of( $basename ) {
		return false !== strpos( $basename, '/' ) ? dirname( $basename ) : basename( $basename, '.php' );
	}

	/** GemSecurity's own plugins are always allowed — the guard can never lock itself out. */
	private static function is_own( $basename ) {
		$slug = self::slug_of( $basename );
		return in_array( $slug, [ 'gemsecurity', 'gemsecurity-pro' ], true );
	}

	/** GemSecurity's own must-use files. */
	private static function is_own_mu( $file ) {
		return in_array( $file, [ self::MU_FILE, 'gemsecurity-extended-protection.php' ], true );
	}

	public static function is_plugin_allowed( $basename, $state = null ) {
		if ( self::is_own( $basename ) ) {
			return true;
		}
		$s = $state ? $state : self::state();
		if ( isset( $s['trusted'][ 'plugin:' . self::slug_of( $basename ) ] ) ) {
			return true;
		}
		return isset( $s['verified'][ $basename ]['status'] ) && 'verified' === $s['verified'][ $basename ]['status'];
	}

	public static function is_mu_allowed( $path, $state = null ) {
		$file = basename( $path );
		if ( self::is_own_mu( $file ) ) {
			return true;
		}
		$s   = $state ? $state : self::state();
		$key = 'mu:' . $file;
		if ( empty( $s['trusted'][ $key ]['hash'] ) ) {
			return false;
		}
		$hash = @hash_file( 'sha256', $path ); // phpcs:ignore
		return $hash && hash_equals( $s['trusted'][ $key ]['hash'], $hash );
	}

	/* ------------------------------------------------------------------ */
	/* Boot                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * Register enforcement. Called from the must-use guard (before regular
	 * plugins load) and again, as a fallback, when GemSecurity boots — the
	 * second call is a no-op if the first ran.
	 */
	public static function early() {
		if ( self::$booted || ( defined( 'GEMSECURITY_PLUGIN_GUARD_OFF' ) && GEMSECURITY_PLUGIN_GUARD_OFF ) ) {
			return;
		}
		self::$booted = true;
		$state        = self::state();

		add_action( 'init', [ __CLASS__, 'flush_events' ], 5 );
		add_action( 'shutdown', [ __CLASS__, 'flush_events' ] );

		// Upload Shield runs before anything else so it sees $_FILES before any
		// plugin's own upload handler can move the file into place.
		if ( ! empty( $state['upload_shield'] ) ) {
			require_once __DIR__ . '/upload-shield.php';
			UploadShield::boot( ! empty( $state['shield_markup'] ) );
		}

		if ( 'off' !== self::lock_mode( $state ) ) {
			add_filter( 'map_meta_cap', [ __CLASS__, 'lock_caps' ], 99, 2 );
			add_filter( 'file_mod_allowed', [ __CLASS__, 'lock_file_mods' ], 99, 2 );
			add_action( 'admin_notices', [ __CLASS__, 'lock_notice' ] );
		}

		if ( empty( $state['enabled'] ) ) {
			return;
		}

		try {
			if ( did_action( 'muplugins_loaded' ) === 0 ) {
				self::sweep_mu_plugins();
				add_action( 'muplugins_loaded', [ __CLASS__, 'remove_stubs' ], 0 );
			}
		} catch ( \Throwable $e ) {
			// Fail open — never take the site down.
		}

		add_filter( 'option_active_plugins', [ __CLASS__, 'filter_active' ], 1 );
		add_filter( 'pre_update_option_active_plugins', [ __CLASS__, 'filter_update' ], 1, 2 );
		add_action( 'load-plugins.php', [ __CLASS__, 'guard_activation_request' ], 1 );
		add_filter( 'rest_pre_dispatch', [ __CLASS__, 'guard_rest_activation' ], 1, 3 );
		add_filter( 'upgrader_source_selection', [ __CLASS__, 'gate_install' ], 1, 4 );
		add_action( 'admin_notices', [ __CLASS__, 'admin_notice' ] );
	}

	/** Whether any feature needs the early must-use loader. */
	public static function needs_mu() {
		if ( defined( 'GEMSECURITY_PLUGIN_GUARD_OFF' ) && GEMSECURITY_PLUGIN_GUARD_OFF ) {
			return false;
		}
		$s = self::state();
		return ! empty( $s['enabled'] ) || ! empty( $s['upload_shield'] ) || 'off' !== ( $s['install_lock'] ?? 'off' );
	}

	/* ------------------------------------------------------------------ */
	/* Install Lock                                                       */
	/* ------------------------------------------------------------------ */

	public static function install_lock_modes() {
		return [
			'off'      => __( 'Off', 'gemsecurity' ),
			// Zip uploads are how custom backdoors get in; directory installs
			// still work (and Plugin Guard verifies them).
			'uploads'  => __( 'Block plugin & theme uploads', 'gemsecurity' ),
			'installs' => __( 'Block all new installs (updates still work)', 'gemsecurity' ),
			'full'     => __( 'Freeze: no installs, updates or deletes', 'gemsecurity' ),
		];
	}

	/**
	 * Effective lock mode, honouring a timed unlock.
	 *
	 * @param array|null $state
	 * @return string
	 */
	public static function lock_mode( $state = null ) {
		$s    = $state ? $state : self::state();
		// Plain key list, not install_lock_modes(): this runs before init,
		// where translating the labels would trigger a too-early notice.
		$mode = isset( $s['install_lock'] ) && in_array( $s['install_lock'], [ 'off', 'uploads', 'installs', 'full' ], true ) ? $s['install_lock'] : 'off';
		if ( 'off' !== $mode && ! empty( $s['unlock_until'] ) && (int) $s['unlock_until'] > time() ) {
			return 'off';
		}
		return $mode;
	}

	/**
	 * Deny the capabilities the lock mode covers — for every user, admins
	 * included. map_meta_cap (not user_has_cap) so that blocking uploads does
	 * not also block installing from the directory: core maps both
	 * upload_plugins and install_plugins through here.
	 *
	 * @param string[] $caps
	 * @param string   $cap
	 * @return string[]
	 */
	public static function lock_caps( $caps, $cap ) {
		$mode   = self::lock_mode();
		$denied = [
			'uploads'  => [ 'upload_plugins', 'upload_themes' ],
			'installs' => [ 'upload_plugins', 'upload_themes', 'install_plugins', 'install_themes' ],
			'full'     => [ 'upload_plugins', 'upload_themes', 'install_plugins', 'install_themes', 'update_plugins', 'update_themes', 'delete_plugins', 'delete_themes', 'update_core', 'edit_plugins', 'edit_themes' ],
		];
		if ( isset( $denied[ $mode ] ) && in_array( $cap, $denied[ $mode ], true ) ) {
			return [ 'do_not_allow' ];
		}
		return $caps;
	}

	/**
	 * Freeze mode also stops background (auto) updates and language packs,
	 * the same way DISALLOW_FILE_MODS does.
	 *
	 * @param bool   $allowed
	 * @param string $context
	 * @return bool
	 */
	public static function lock_file_mods( $allowed, $context ) {
		return 'full' === self::lock_mode() ? false : $allowed;
	}

	/**
	 * Lift the lock for a few minutes (one admin, logged and emailed).
	 *
	 * @param int $minutes 0 = relock now.
	 */
	public static function unlock_for( $minutes ) {
		$state                 = self::state();
		$minutes               = max( 0, min( 60, (int) $minutes ) );
		$state['unlock_until'] = $minutes ? time() + $minutes * MINUTE_IN_SECONDS : 0;
		self::save_state( $state );
		if ( $minutes ) {
			/* translators: %d: minutes. */
			self::record_event( 'install_unlocked', 'unlock', sprintf( __( 'Install Lock lifted for %d minutes', 'gemsecurity' ), $minutes ) );
		} else {
			self::log( 'plugin_guard_relock', 'Install Lock re-engaged.', 'notice' );
		}
	}

	/** Explain the lock on the screens it affects. */
	public static function lock_notice() {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || ! in_array( $screen->id, [ 'plugins', 'plugin-install', 'themes', 'theme-install', 'update-core' ], true ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$modes = self::install_lock_modes();
		printf(
			'<div class="notice notice-info"><p><strong>%s</strong> %s <a href="%s">%s</a></p></div>',
			esc_html__( 'GemSecurity Install Lock:', 'gemsecurity' ),
			esc_html( $modes[ self::lock_mode() ] ),
			esc_url( self::page_url() ),
			esc_html__( 'Unlock temporarily', 'gemsecurity' )
		);
	}

	/* ------------------------------------------------------------------ */
	/* Event queue (shared with Upload Shield)                            */
	/* ------------------------------------------------------------------ */

	/** Events queued this request; batched into one email per type on flush. */
	private static $queue = [];

	/**
	 * @param string $type
	 * @param string $key
	 * @param string $label
	 */
	public static function queue_event( $type, $key, $label ) {
		self::$queue[] = [ $type, $key, $label ];
	}

	/** IPs to ban once GemSecurity's BanList is loadable (init), ip => reason. */
	private static $ban_queue = [];

	/** Ban outcome per IP this request, for the alert email: ip => bool. */
	private static $banned = [];

	/**
	 * @param string $ip
	 * @param string $reason
	 */
	public static function queue_ban( $ip, $reason ) {
		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			self::$ban_queue[ $ip ] = $reason;
		}
	}

	/** Ban queued IPs (needs the current user, so after init). */
	private static function flush_bans() {
		$state = self::state();
		foreach ( self::$ban_queue as $ip => $reason ) {
			self::$banned[ $ip ] = false;
			if ( empty( $state['shield_autoban'] ) || ! class_exists( '\GemSecurity\Security\BanList' ) ) {
				continue;
			}
			// Never lock out an administrator (or anyone the ban_exempt filter spares).
			$admin = is_user_logged_in() && current_user_can( 'manage_options' );
			if ( $admin || BanList::is_exempt( $ip ) ) {
				continue;
			}
			self::$banned[ $ip ] = BanList::ban( $ip, $reason, max( 0, (int) $state['shield_ban_hours'] ) * HOUR_IN_SECONDS );
		}
		self::$ban_queue = [];
	}

	/* ------------------------------------------------------------------ */
	/* Regular plugins                                                    */
	/* ------------------------------------------------------------------ */

	/**
	 * Strip untrusted plugins from active_plugins on read, so WordPress never
	 * loads them. Recorded for deactivation + alert on init.
	 *
	 * @param mixed $plugins
	 * @return mixed
	 */
	public static function filter_active( $plugins ) {
		if ( self::$raw || ! is_array( $plugins ) ) {
			return $plugins;
		}
		$state = self::state();
		$keep  = [];
		foreach ( $plugins as $p ) {
			if ( self::is_plugin_allowed( (string) $p, $state ) ) {
				$keep[] = $p;
			} else {
				self::$blocked[ $p ] = 'loaded';
			}
		}
		return $keep;
	}

	/**
	 * Backstop on write: an untrusted plugin added to active_plugins by any
	 * path we did not intercept earlier is dropped (after one verification
	 * attempt, so a freshly installed .org plugin activates normally).
	 *
	 * @param mixed $new
	 * @param mixed $old
	 * @return mixed
	 */
	public static function filter_update( $new, $old ) {
		if ( self::$raw || ! is_array( $new ) ) {
			return $new;
		}
		$old   = is_array( $old ) ? $old : [];
		$added = array_diff( $new, $old );
		if ( ! $added ) {
			return $new;
		}
		foreach ( $added as $p ) {
			if ( self::is_plugin_allowed( $p ) ) {
				continue;
			}
			$res = self::verify_plugin( $p );
			if ( 'verified' !== $res['status'] ) {
				$new                 = array_values( array_diff( $new, [ $p ] ) );
				self::$blocked[ $p ] = 'activation';
			}
		}
		return $new;
	}

	/**
	 * Refuse wp-admin activation of an untrusted plugin BEFORE core includes
	 * its main file (activate_plugin() runs the code first and only then saves
	 * the option, so the write filter alone would let it execute once).
	 */
	public static function guard_activation_request() {
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		if ( '-1' === $action || '' === $action ) {
			$action = isset( $_REQUEST['action2'] ) ? sanitize_key( wp_unslash( $_REQUEST['action2'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		}
		if ( ! in_array( $action, [ 'activate', 'activate-selected' ], true ) ) {
			return;
		}
		$list = [];
		if ( isset( $_REQUEST['plugin'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			$list[] = wp_unslash( $_REQUEST['plugin'] ); // phpcs:ignore
		}
		if ( isset( $_REQUEST['checked'] ) && is_array( $_REQUEST['checked'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			$list = array_merge( $list, wp_unslash( $_REQUEST['checked'] ) ); // phpcs:ignore
		}
		$denied = [];
		foreach ( $list as $p ) {
			$p = (string) $p;
			if ( '' === $p || self::is_plugin_allowed( $p ) ) {
				continue;
			}
			if ( 'verified' !== self::verify_plugin( $p )['status'] ) {
				$denied[]            = $p;
				self::$blocked[ $p ] = 'activation';
			}
		}
		if ( $denied ) {
			self::flush_events();
			wp_die(
				'<h1>' . esc_html__( 'Activation blocked by GemSecurity', 'gemsecurity' ) . '</h1><p>'
				. esc_html( sprintf(
					/* translators: %s: plugin list. */
					__( 'Plugin Guard only allows plugins verified against WordPress.org or marked trusted by an administrator. Not trusted: %s', 'gemsecurity' ),
					implode( ', ', $denied )
				) )
				. '</p><p><a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Review it in GemSecurity → Plugin Guard', 'gemsecurity' ) . '</a></p>',
				esc_html__( 'Activation blocked', 'gemsecurity' ),
				[ 'response' => 403, 'back_link' => true ]
			);
		}
	}

	/**
	 * Same for the REST plugins endpoint (block editor / API clients).
	 *
	 * @param mixed            $result
	 * @param \WP_REST_Server  $server
	 * @param \WP_REST_Request $request
	 * @return mixed
	 */
	public static function guard_rest_activation( $result, $server, $request ) {
		if ( null !== $result || ! ( $request instanceof \WP_REST_Request ) ) {
			return $result;
		}
		if ( 0 !== strpos( $request->get_route(), '/wp/v2/plugins' ) || 'GET' === $request->get_method() ) {
			return $result;
		}
		$status = $request->get_param( 'status' );
		if ( ! in_array( $status, [ 'active', 'network-active' ], true ) ) {
			return $result;
		}
		$plugin = (string) $request->get_param( 'plugin' );
		if ( '' === $plugin ) {
			return $result; // Install-and-activate: the install gate handles the source.
		}
		if ( '.php' !== substr( $plugin, -4 ) ) {
			$plugin .= '.php';
		}
		if ( self::is_plugin_allowed( $plugin ) || 'verified' === self::verify_plugin( $plugin )['status'] ) {
			return $result;
		}
		self::$blocked[ $plugin ] = 'activation';
		return new \WP_Error(
			'gemsecurity_plugin_untrusted',
			__( 'GemSecurity Plugin Guard: this plugin is not verified on WordPress.org and has not been marked trusted.', 'gemsecurity' ),
			[ 'status' => 403 ]
		);
	}

	/* ------------------------------------------------------------------ */
	/* Must-use plugins                                                   */
	/* ------------------------------------------------------------------ */

	/**
	 * Quarantine every untrusted top-level mu-plugin before core includes it.
	 * A harmless stub is left at the original path so core's include of the
	 * (already listed) file does not warn; the stub is removed once the
	 * mu-plugin loop has finished.
	 */
	private static function sweep_mu_plugins() {
		$dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		$files = glob( trailingslashit( $dir ) . '*.php' );
		if ( ! is_array( $files ) || ! $files ) {
			return;
		}
		$state = self::state();
		foreach ( $files as $path ) {
			if ( self::is_mu_allowed( $path, $state ) ) {
				continue;
			}
			$entry = self::quarantine_file( $path );
			if ( $entry ) {
				@file_put_contents( $path, "<?php\n// Quarantined by GemSecurity Plugin Guard. Removed automatically.\n" ); // phpcs:ignore
				self::$stubs[]       = $path;
				self::$quarantined[] = $entry;
			}
		}
	}

	public static function remove_stubs() {
		foreach ( self::$stubs as $path ) {
			@unlink( $path ); // phpcs:ignore
		}
		self::$stubs = [];
	}

	/**
	 * Move a file into the shared quarantine store (same directory + index
	 * shape as {@see Quarantine}, which cannot be autoloaded this early).
	 *
	 * @param string $path
	 * @return array|null Entry.
	 */
	private static function quarantine_file( $path ) {
		$up  = wp_get_upload_dir();
		$dir = trailingslashit( $up['basedir'] ) . 'gemsecurity-quarantine';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
			@file_put_contents( $dir . '/.htaccess', "Require all denied\nDeny from all\n" ); // phpcs:ignore
			@file_put_contents( $dir . '/index.php', "<?php // Silence is golden.\n" ); // phpcs:ignore
		}
		$abs  = wp_normalize_path( $path );
		$id   = md5( $abs . microtime() );
		$hash = @hash_file( 'sha256', $abs ); // phpcs:ignore
		if ( ! @rename( $abs, $dir . '/' . $id . '.quar' ) ) { // phpcs:ignore
			return null;
		}
		$relative = str_replace( wp_normalize_path( ABSPATH ), '', $abs );
		$store    = \GemSecurity\OptionStore::get_state( 'quarantine', [] );
		$store    = is_array( $store ) ? $store : [];
		$store[ $id ] = [
			'id'             => $id,
			'type'           => 'file',
			'original'       => $abs,
			'relative'       => $relative,
			'label'          => $relative,
			'source'         => 'plugin-guard',
			'hash'           => $hash,
			'quarantined_at' => current_time( 'mysql' ),
		];
		\GemSecurity\OptionStore::set_state( 'quarantine', $store );
		return $store[ $id ];
	}

	/**
	 * Restore a mu-plugin this guard quarantined and trust it (by content hash).
	 *
	 * @param string $id Quarantine id.
	 * @return true|\WP_Error
	 */
	public static function restore_and_trust_mu( $id ) {
		$store = \GemSecurity\OptionStore::get_state( 'quarantine', [] );
		if ( ! isset( $store[ $id ] ) || 'plugin-guard' !== ( $store[ $id ]['source'] ?? '' ) ) {
			return new \WP_Error( 'gemsecurity_guard_missing', __( 'Quarantine entry not found.', 'gemsecurity' ), [ 'status' => 404 ] );
		}
		$entry = $store[ $id ];
		$up    = wp_get_upload_dir();
		$src   = trailingslashit( $up['basedir'] ) . 'gemsecurity-quarantine/' . $id . '.quar';
		$hash  = @hash_file( 'sha256', $src ); // phpcs:ignore
		if ( ! $hash ) {
			return new \WP_Error( 'gemsecurity_guard_missing', __( 'The quarantined file is missing.', 'gemsecurity' ), [ 'status' => 404 ] );
		}
		// Trust first, so the restored file is not swept again on the next request.
		self::trust( 'mu:' . basename( $entry['original'] ), basename( $entry['original'] ), $hash );
		if ( ! @rename( $src, $entry['original'] ) ) { // phpcs:ignore
			return new \WP_Error( 'gemsecurity_guard_restore', __( 'Could not restore the file.', 'gemsecurity' ), [ 'status' => 500 ] );
		}
		unset( $store[ $id ] );
		\GemSecurity\OptionStore::set_state( 'quarantine', $store );
		self::log( 'plugin_guard_restore', sprintf( 'Restored and trusted must-use plugin %s.', $entry['label'] ), 'notice' );
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Installs                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Refuse to install a plugin/theme that is neither pre-approved nor from
	 * WordPress.org. Updates of already-installed items pass through (an
	 * untrusted one stays blocked from running anyway).
	 *
	 * @param string|\WP_Error $source
	 * @param string           $remote_source
	 * @param object           $upgrader
	 * @param array            $hook_extra
	 * @return string|\WP_Error
	 */
	public static function gate_install( $source, $remote_source = '', $upgrader = null, $hook_extra = [] ) {
		if ( is_wp_error( $source ) ) {
			return $source;
		}
		$hook_extra = is_array( $hook_extra ) ? $hook_extra : [];
		if ( ! empty( $hook_extra['plugin'] ) || ! empty( $hook_extra['theme'] ) ) {
			return $source; // Update of something already installed.
		}

		$is_theme = ( $upgrader instanceof \Theme_Upgrader ) || ( isset( $hook_extra['type'] ) && 'theme' === $hook_extra['type'] );
		$is_plugin = ( $upgrader instanceof \Plugin_Upgrader ) || ( isset( $hook_extra['type'] ) && 'plugin' === $hook_extra['type'] );
		if ( ! $is_theme && ! $is_plugin ) {
			return $source;
		}

		$slug  = basename( untrailingslashit( $source ) );
		$state = self::state();

		if ( $is_theme ) {
			if ( isset( $state['trusted'][ 'theme:' . $slug ] ) || 'org' === self::theme_status( $slug ) ) {
				return $source;
			}
			self::record_event( 'install_blocked', 'theme:' . $slug, $slug );
			return new \WP_Error( 'gemsecurity_install_untrusted', sprintf(
				/* translators: %s: theme slug. */
				__( 'GemSecurity Plugin Guard blocked this install: the theme "%s" is not on WordPress.org and has not been pre-approved. Add it as trusted under GemSecurity → Plugin Guard, then upload it again.', 'gemsecurity' ),
				$slug
			) );
		}

		if ( isset( $state['trusted'][ 'plugin:' . $slug ] ) ) {
			return $source;
		}
		$check = self::checksum_dir( $slug, untrailingslashit( $source ), self::read_version( untrailingslashit( $source ) ) );
		if ( 'verified' === $check['status'] ) {
			return $source;
		}
		self::record_event( 'install_blocked', 'plugin:' . $slug, $slug . ' — ' . $check['note'] );
		return new \WP_Error( 'gemsecurity_install_untrusted', sprintf(
			/* translators: 1: plugin slug, 2: reason. */
			__( 'GemSecurity Plugin Guard blocked this install: "%1$s" could not be verified against WordPress.org (%2$s). If it is a premium or custom plugin you trust, add it as trusted under GemSecurity → Plugin Guard, then upload it again.', 'gemsecurity' ),
			$slug,
			$check['note']
		) );
	}

	/* ------------------------------------------------------------------ */
	/* Verification                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Verify one installed plugin against WordPress.org checksums and cache
	 * the verdict. A network failure keeps the previous verdict.
	 *
	 * @param string $basename
	 * @return array { status, version, note, checked_at }
	 */
	public static function verify_plugin( $basename ) {
		$basename = (string) $basename;
		$file     = WP_PLUGIN_DIR . '/' . $basename;
		if ( '' === $basename || validate_file( $basename ) || ! is_file( $file ) ) {
			return [ 'status' => 'missing', 'version' => '', 'note' => __( 'Plugin file not found.', 'gemsecurity' ), 'checked_at' => '' ];
		}
		$slug = self::slug_of( $basename );
		$data = get_file_data( $file, [ 'Version' => 'Version' ] );
		$ver  = (string) $data['Version'];

		if ( false === strpos( $basename, '/' ) ) {
			$res = [ 'status' => 'not_org', 'note' => __( 'Single-file plugin — cannot be checksum-verified.', 'gemsecurity' ) ];
		} else {
			$res = self::checksum_dir( $slug, WP_PLUGIN_DIR . '/' . $slug, $ver );
		}
		$res['version']    = $ver;
		$res['checked_at'] = current_time( 'mysql' );

		$state = self::state();
		if ( 'unknown' === $res['status'] && isset( $state['verified'][ $basename ] ) && $state['verified'][ $basename ]['version'] === $ver ) {
			return $state['verified'][ $basename ]; // Offline — keep the last definitive verdict.
		}
		$state['verified'][ $basename ] = $res;
		self::save_state( $state );
		return $res;
	}

	/**
	 * Verify installed plugins (daily cron + "Re-check" button use $force).
	 *
	 * @param bool $force false = only plugins never checked, whose version
	 *                    changed, or whose last check failed to connect.
	 */
	public static function verify_all( $force = true ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$installed = get_plugins();
		$known     = self::state()['verified'];
		foreach ( $installed as $basename => $data ) {
			if ( ! $force && isset( $known[ $basename ] ) && $known[ $basename ]['version'] === $data['Version'] && 'unknown' !== $known[ $basename ]['status'] ) {
				continue;
			}
			self::verify_plugin( $basename );
		}
		// Forget verdicts for plugins that no longer exist.
		$state = self::state();
		$state['verified'] = array_intersect_key( $state['verified'], $installed );
		self::save_state( $state );
	}

	/**
	 * Compare a plugin directory against the official checksums.
	 *
	 * verified       – every file listed by .org matches, no extra PHP files.
	 * modified       – on .org but files differ or extra PHP was added.
	 * not_org        – not in the directory (premium/custom/fake).
	 * unknown        – could not reach WordPress.org.
	 *
	 * @param string $slug
	 * @param string $dir
	 * @param string $version
	 * @return array { status, note }
	 */
	private static function checksum_dir( $slug, $dir, $version ) {
		if ( '' === $version ) {
			return [ 'status' => 'not_org', 'note' => __( 'No version header.', 'gemsecurity' ) ];
		}
		$url  = sprintf( 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json', rawurlencode( $slug ), rawurlencode( $version ) );
		$resp = wp_remote_get( $url, [ 'timeout' => 10 ] );
		if ( is_wp_error( $resp ) ) {
			return [ 'status' => 'unknown', 'note' => __( 'WordPress.org could not be reached.', 'gemsecurity' ) ];
		}
		$code = (int) wp_remote_retrieve_response_code( $resp );
		if ( 404 === $code ) {
			$on_org = self::plugin_on_org( $slug );
			if ( true === $on_org ) {
				return [ 'status' => 'modified', 'note' => sprintf(
					/* translators: %s: version. */
					__( 'The slug is on WordPress.org but version %s was never released there — possibly a lookalike.', 'gemsecurity' ),
					$version
				) ];
			}
			return [ 'status' => 'not_org', 'note' => __( 'Not in the WordPress.org directory (premium, custom or unknown).', 'gemsecurity' ) ];
		}
		if ( 200 !== $code ) {
			return [ 'status' => 'unknown', 'note' => __( 'WordPress.org returned an error.', 'gemsecurity' ) ];
		}
		$json = json_decode( wp_remote_retrieve_body( $resp ), true );
		if ( empty( $json['files'] ) || ! is_array( $json['files'] ) ) {
			return [ 'status' => 'unknown', 'note' => __( 'Unexpected checksum response.', 'gemsecurity' ) ];
		}

		$changed = [];
		foreach ( $json['files'] as $rel => $sums ) {
			$p = $dir . '/' . $rel;
			if ( ! is_file( $p ) ) {
				continue; // Missing files are harmless for code execution.
			}
			$sha = isset( $sums['sha256'] ) ? (array) $sums['sha256'] : [];
			$md5 = isset( $sums['md5'] ) ? (array) $sums['md5'] : [];
			$ok  = $sha ? in_array( hash_file( 'sha256', $p ), $sha, true ) : in_array( md5_file( $p ), $md5, true );
			if ( ! $ok ) {
				$changed[] = $rel;
			}
		}
		$extra = [];
		try {
			// Dev-only trees are never shipped from .org; skipping them keeps a
			// developer checkout from taking minutes to walk.
			$skip = [ 'node_modules', '.git', '.svn' ];
			$it   = new \RecursiveIteratorIterator( new \RecursiveCallbackFilterIterator(
				new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
				static function ( $c ) use ( $skip ) {
					return ! ( $c->isDir() && in_array( $c->getFilename(), $skip, true ) );
				}
			) );
			foreach ( $it as $f ) {
				$rel = ltrim( str_replace( wp_normalize_path( $dir ), '', wp_normalize_path( $f->getPathname() ) ), '/' );
				if ( preg_match( '/\.(php\d?|phtml|phar|inc)$/i', $rel ) && ! isset( $json['files'][ $rel ] ) ) {
					$extra[] = $rel;
				}
			}
		} catch ( \Exception $e ) {
			// Unreadable directory — judged on the listed files only.
		}

		if ( $changed || $extra ) {
			$bits = [];
			if ( $changed ) {
				/* translators: %s: file list. */
				$bits[] = sprintf( __( 'changed: %s', 'gemsecurity' ), implode( ', ', array_slice( $changed, 0, 5 ) ) . ( count( $changed ) > 5 ? '…' : '' ) );
			}
			if ( $extra ) {
				/* translators: %s: file list. */
				$bits[] = sprintf( __( 'added PHP: %s', 'gemsecurity' ), implode( ', ', array_slice( $extra, 0, 5 ) ) . ( count( $extra ) > 5 ? '…' : '' ) );
			}
			return [ 'status' => 'modified', 'note' => __( 'Files differ from WordPress.org', 'gemsecurity' ) . ' — ' . implode( '; ', $bits ) ];
		}
		return [ 'status' => 'verified', 'note' => __( 'Matches the official WordPress.org release.', 'gemsecurity' ) ];
	}

	/** @return bool|null true on .org, false not, null unknown. */
	private static function plugin_on_org( $slug ) {
		$resp = wp_remote_get( 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' . rawurlencode( $slug ), [ 'timeout' => 10 ] );
		if ( is_wp_error( $resp ) ) {
			return null;
		}
		$json = json_decode( wp_remote_retrieve_body( $resp ), true );
		return is_array( $json ) && ! empty( $json['slug'] ) && empty( $json['error'] );
	}

	/**
	 * Theme directory presence (name-based — .org publishes no theme checksums).
	 *
	 * @return string 'org' | 'not_org' | 'unknown'
	 */
	public static function theme_status( $slug ) {
		$key    = 'gemsec_theme_org_' . md5( $slug );
		$cached = get_transient( $key );
		if ( false !== $cached ) {
			return $cached;
		}
		$resp = wp_remote_get( 'https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]=' . rawurlencode( $slug ), [ 'timeout' => 10 ] );
		if ( is_wp_error( $resp ) ) {
			return 'unknown';
		}
		$json   = json_decode( wp_remote_retrieve_body( $resp ), true );
		$status = ( is_array( $json ) && ! empty( $json['slug'] ) && empty( $json['error'] ) ) ? 'org' : 'not_org';
		set_transient( $key, $status, DAY_IN_SECONDS );
		return $status;
	}

	/** Version header of the plugin's main file in a directory. */
	private static function read_version( $dir ) {
		foreach ( (array) glob( $dir . '/*.php' ) as $f ) {
			$d = get_file_data( $f, [ 'Name' => 'Plugin Name', 'Version' => 'Version' ] );
			if ( '' !== $d['Name'] ) {
				return (string) $d['Version'];
			}
		}
		return '';
	}

	/* ------------------------------------------------------------------ */
	/* Trust management                                                   */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string      $key  plugin:<slug> | theme:<slug> | mu:<file>.
	 * @param string      $name Human label.
	 * @param string|null $hash Content hash (mu-plugins).
	 */
	public static function trust( $key, $name = '', $hash = null ) {
		$state = self::state();
		$user  = wp_get_current_user();
		$state['trusted'][ $key ] = array_filter( [
			'name' => (string) $name,
			'at'   => current_time( 'mysql' ),
			'by'   => $user && $user->exists() ? $user->user_login : 'system',
			'hash' => $hash,
		], static function ( $v ) {
			return null !== $v;
		} );
		self::save_state( $state );
		self::log( 'plugin_guard_trust', sprintf( 'Marked %s as trusted.', $key ), 'notice' );
	}

	public static function untrust( $key ) {
		$state = self::state();
		unset( $state['trusted'][ $key ] );
		self::save_state( $state );
		self::log( 'plugin_guard_untrust', sprintf( 'Removed trust from %s.', $key ), 'warning' );
	}

	/* ------------------------------------------------------------------ */
	/* Events, alerts                                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * Persist what this request blocked: deactivate blocked plugins for good,
	 * log, and email (once per item per 12 hours).
	 */
	public static function flush_events() {
		$batch = [];
		if ( self::$blocked ) {
			self::$raw = true;
			$active    = (array) get_option( 'active_plugins', [] );
			$left      = array_values( array_diff( $active, array_keys( self::$blocked ) ) );
			if ( $left !== $active ) {
				update_option( 'active_plugins', $left );
			}
			self::$raw = false;

			foreach ( self::$blocked as $p => $how ) {
				$type = 'loaded' === $how ? 'plugin_deactivated' : 'activation_blocked';
				if ( self::record_event( $type, 'plugin:' . $p, self::plugin_name( $p ), false ) ) {
					$batch[ $type ][] = self::plugin_name( $p );
				}
			}
			self::$blocked = [];
		}
		foreach ( self::$quarantined as $q ) {
			if ( self::record_event( 'mu_quarantined', 'mu:' . basename( $q['original'] ), $q['relative'], false ) ) {
				$batch['mu_quarantined'][] = $q['relative'];
			}
		}
		self::$quarantined = [];
		foreach ( self::$queue as $e ) {
			if ( self::record_event( $e[0], $e[1], $e[2], false ) ) {
				$batch[ $e[0] ][] = $e[2];
			}
		}
		self::$queue = [];
		// Mail needs pluggable functions + the current user: hold until init.
		self::$pending_mail = array_merge_recursive( self::$pending_mail, $batch );
		if ( ! did_action( 'init' ) ) {
			return;
		}
		self::flush_bans();
		if ( ! self::$pending_mail ) {
			return;
		}
		$batch              = self::$pending_mail;
		self::$pending_mail = [];

		// One email per kind of event, listing every item — not one per plugin.
		$user = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		$ip   = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		foreach ( $batch as $type => $labels ) {
			self::email( $type, $labels, $user && $user->exists() ? $user->user_login : '', $ip );
		}
	}

	private static function plugin_name( $basename ) {
		$file = WP_PLUGIN_DIR . '/' . $basename;
		if ( is_file( $file ) ) {
			$d = get_file_data( $file, [ 'Name' => 'Plugin Name' ] );
			if ( '' !== $d['Name'] ) {
				return $d['Name'] . ' (' . $basename . ')';
			}
		}
		return $basename;
	}

	/**
	 * Store an event and send the DANGER email (rate-limited per item).
	 *
	 * @param string $type   plugin_deactivated | activation_blocked | mu_quarantined | install_blocked.
	 * @param string $key    Item key.
	 * @param string $label  Human label.
	 * @param bool   $send   Email now; false = caller batches.
	 * @return bool Whether this item is due an email (12h per item+type).
	 */
	private static function record_event( $type, $key, $label, $send = true ) {
		$events = get_option( self::EVENTS_OPTION, [] );
		$events = is_array( $events ) ? $events : [];

		$last_mail = 0;
		foreach ( $events as $e ) {
			if ( $e['key'] === $key && $e['type'] === $type && ! empty( $e['mailed'] ) ) {
				$last_mail = max( $last_mail, (int) $e['time'] );
			}
		}
		$mail = ( time() - $last_mail ) > 12 * HOUR_IN_SECONDS;

		$user = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		$ip   = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		array_unshift( $events, [
			'type'   => $type,
			'key'    => $key,
			'label'  => $label,
			'time'   => time(),
			'user'   => $user && $user->exists() ? $user->user_login : '',
			'ip'     => $ip,
			'where'  => $ip && class_exists( '\GemSecurity\Security\Geo' ) ? Geo::location_label( $ip ) : '',
			'mailed' => $mail,
		] );
		update_option( self::EVENTS_OPTION, array_slice( $events, 0, 100 ), false );

		$titles = self::event_titles();
		self::log( 'plugin_guard_' . $type, $titles[ $type ] . ': ' . $label, in_array( $type, [ 'install_blocked', 'install_unlocked' ], true ) ? 'warning' : 'critical' );

		if ( $mail && $send ) {
			self::email( $type, [ $label ], $user && $user->exists() ? $user->user_login : '', $ip );
		}
		return $mail;
	}

	private static function event_titles() {
		return [
			'plugin_deactivated' => __( 'Untrusted plugin was active — force-deactivated', 'gemsecurity' ),
			'activation_blocked' => __( 'Untrusted plugin activation blocked', 'gemsecurity' ),
			'mu_quarantined'     => __( 'Unknown must-use plugin quarantined', 'gemsecurity' ),
			'install_blocked'    => __( 'Untrusted plugin/theme install blocked', 'gemsecurity' ),
			'upload_blocked'     => __( 'Executable file upload blocked', 'gemsecurity' ),
			'install_unlocked'   => __( 'Install Lock was temporarily lifted', 'gemsecurity' ),
		];
	}

	/**
	 * @param string   $type
	 * @param string[] $labels
	 * @param string   $user
	 * @param string   $ip
	 */
	private static function email( $type, array $labels, $user, $ip ) {
		$titles = self::event_titles();
		$title  = sprintf( /* translators: %s: event. */ __( 'DANGER: %s', 'gemsecurity' ), $titles[ $type ] );
		$what   = [
			'plugin_deactivated' => __( 'A plugin that is neither verified on WordPress.org nor marked trusted was switched on — most likely written straight into the database. GemSecurity stopped it from loading and deactivated it.', 'gemsecurity' ),
			'activation_blocked' => __( 'Someone tried to activate a plugin that is neither verified on WordPress.org nor marked trusted. The activation was refused before its code ran.', 'gemsecurity' ),
			'mu_quarantined'     => __( 'A must-use plugin you never approved appeared (or a trusted one was edited). Must-use plugins run on every request with no on/off switch, which makes them a favourite backdoor. GemSecurity moved it into quarantine before it could run.', 'gemsecurity' ),
			'install_blocked'    => __( 'Someone tried to install a plugin or theme that is not from WordPress.org and was not pre-approved. The install was refused.', 'gemsecurity' ),
			'upload_blocked'     => __( 'Someone uploaded a file that can run code on the server (for example a .php file, or an image with PHP hidden inside). Upload Shield refused it before any plugin could save it. This is a typical first step of planting a backdoor.', 'gemsecurity' ),
			'install_unlocked'   => __( 'An administrator lifted the Install Lock, so plugins and themes can be uploaded or installed for a few minutes. It re-engages automatically.', 'gemsecurity' ),
		];
		$rows = [
			[ _n( 'Item', 'Items', count( $labels ), 'gemsecurity' ), implode( '<br>', array_map( 'esc_html', $labels ) ) ],
			[ __( 'User', 'gemsecurity' ), esc_html( $user ? $user : __( 'not logged in', 'gemsecurity' ) ) ],
			[ __( 'IP', 'gemsecurity' ), esc_html( $ip ? $ip : '—' ) ],
		];
		if ( $ip && class_exists( '\GemSecurity\Security\Geo' ) ) {
			$where  = Geo::location_label( $ip );
			$rows[] = [ __( 'Location', 'gemsecurity' ), esc_html( $where ? $where : __( 'unknown (private or unresolvable IP)', 'gemsecurity' ) ) ];
		}
		if ( $ip && isset( self::$banned[ $ip ] ) ) {
			$hours  = (int) self::state()['shield_ban_hours'];
			$rows[] = [
				__( 'Action taken', 'gemsecurity' ),
				esc_html( self::$banned[ $ip ]
					/* translators: %d: hours. */
					? ( $hours ? sprintf( __( 'IP blocked for %d hours', 'gemsecurity' ), $hours ) : __( 'IP blocked permanently', 'gemsecurity' ) )
					: __( 'IP not blocked (administrator, exempt, or auto-block off)', 'gemsecurity' ) ),
			];
		}
		$rows = array_merge( $rows, [
			[ __( 'Time', 'gemsecurity' ), esc_html( current_time( 'mysql' ) ) ],
		] );
		$steps = [
			__( 'If you did this yourself, open Plugin Guard and mark the item trusted.', 'gemsecurity' ),
			__( 'If you did not: treat the site as compromised — change every administrator password, end all sessions, and run a full malware scan.', 'gemsecurity' ),
			__( 'Check the administrator list for accounts you do not recognise.', 'gemsecurity' ),
		];

		if ( class_exists( '\GemSecurity\Mailer' ) ) {
			\GemSecurity\Mailer::send( '', '🚨', $title, [
				[ 'type' => 'notice', 'tone' => 'danger', 'text' => esc_html( $what[ $type ] ) ],
				[ 'type' => 'table', 'columns' => [], 'rows' => $rows ],
				[ 'type' => 'list', 'heading' => __( 'What to do now', 'gemsecurity' ), 'items' => array_map( 'esc_html', $steps ) ],
				[ 'type' => 'button', 'url' => self::page_url(), 'label' => __( 'Open Plugin Guard', 'gemsecurity' ) ],
			] );
			return;
		}
		// GemSecurity itself is not loaded (e.g. deactivated outside WordPress) — plain mail.
		$lines = [ $what[ $type ], '' ];
		foreach ( $rows as $r ) {
			$lines[] = $r[0] . ': ' . wp_strip_all_tags( $r[1] );
		}
		$lines = array_merge( $lines, [ '' ], $steps );
		wp_mail( (string) get_option( 'admin_email' ), '🚨 [' . wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES ) . '] ' . $title, implode( "\n", $lines ) );
	}

	private static function log( $type, $message, $severity ) {
		if ( class_exists( '\GemSecurity\Logger' ) ) {
			\GemSecurity\Logger::log( $type, $message, $severity );
		}
	}

	public static function events() {
		$e = get_option( self::EVENTS_OPTION, [] );
		return is_array( $e ) ? $e : [];
	}

	public static function page_url() {
		return admin_url( 'admin.php?page=gemsecurity-plugin-guard' );
	}

	/** Explain blocked activations on the Plugins screen. */
	public static function admin_notice() {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || 'plugins' !== $screen->id || ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		$state = self::state();
		$bad   = [];
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		foreach ( array_keys( get_plugins() ) as $p ) {
			if ( ! self::is_plugin_allowed( $p, $state ) ) {
				$bad[] = $p;
			}
		}
		if ( ! $bad ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p><strong>%s</strong> %s <a href="%s">%s</a></p></div>',
			esc_html__( 'GemSecurity Plugin Guard is on.', 'gemsecurity' ),
			esc_html( sprintf(
				/* translators: %d: count. */
				_n( '%d installed plugin is not verified or trusted and cannot be activated.', '%d installed plugins are not verified or trusted and cannot be activated.', count( $bad ), 'gemsecurity' ),
				count( $bad )
			) ),
			esc_url( self::page_url() ),
			esc_html__( 'Review in Plugin Guard', 'gemsecurity' )
		);
	}

	/* ------------------------------------------------------------------ */
	/* Early must-use loader                                              */
	/* ------------------------------------------------------------------ */

	public static function mu_path() {
		$dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		return trailingslashit( $dir ) . self::MU_FILE;
	}

	public static function mu_installed() {
		return is_file( self::mu_path() );
	}

	public static function install_mu() {
		$dir = dirname( self::mu_path() );
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return false;
		}
		// Relative to WP_PLUGIN_DIR so the loader survives a site move.
		$folder = defined( 'GEMSECURITY_PLUGIN_BASENAME' ) ? dirname( GEMSECURITY_PLUGIN_BASENAME ) : 'gemsecurity';
		$target = $folder . '/includes/security/plugin-guard.php';
		$src    = "<?php\n"
			. "/**\n * Plugin Name: GemSecurity Plugin Guard\n"
			. " * Description: Stops untrusted plugins and must-use plugins from running. Managed by GemSecurity — do not edit. Emergency off: define( 'GEMSECURITY_PLUGIN_GUARD_OFF', true ) in wp-config.php.\n"
			. " */\n"
			. "if ( ! defined( 'ABSPATH' ) ) { return; }\n"
			. "try {\n"
			. "\t\$gemsec_guard = WP_PLUGIN_DIR . '/' . " . wp_json_encode( $target ) . ";\n"
			. "\tif ( is_readable( \$gemsec_guard ) ) {\n"
			. "\t\trequire_once \$gemsec_guard;\n"
			. "\t\t\\GemSecurity\\Security\\PluginGuard::early();\n"
			. "\t}\n"
			. "} catch ( \\Throwable \$e ) {\n"
			. "\t// Fail open — never take the site down.\n"
			. "}\n";
		return false !== @file_put_contents( self::mu_path(), $src ); // phpcs:ignore
	}

	public static function uninstall_mu() {
		if ( self::mu_installed() ) {
			return @unlink( self::mu_path() ); // phpcs:ignore
		}
		return true;
	}
}
