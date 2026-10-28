<?php
namespace GemSecurity\Security;

use GemSecurity\Helper;
use GemSecurity\Logger;
use GemSecurity\Mailer;
use GemSecurity\Rest\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Three small switches that protect the site (and the admin) from themselves:
 *
 *  - IP safelist: addresses that no GemSecurity block, ban or rate limit may
 *    ever apply to, so an administrator cannot lock their own IP out.
 *  - Plugin lock: deactivating or deleting GemSecurity, or switching the lock
 *    off, needs two steps: a separate unlock password, then a one-time code
 *    emailed to the address the lock was set up with. It is not tied to any user
 *    account, so a hacker who logs in as an administrator (even the one who
 *    set the lock) still cannot switch the plugin off.
 *  - File uploads: one switch (also on the admin bar) that stops every upload
 *    path — Media, REST, XML-RPC, and plugin/theme zips.
 *
 * Recovery: define( 'GEMSEC_PLUGIN_LOCK_DISABLE', true ); in wp-config.php
 * lifts the plugin lock (that needs access to the server, not just to wp-admin).
 */
class SiteGuard {

	const TOGGLE_ACTION = 'gemsecurity_toggle_uploads';

	/**
	 * Settings that an attacker with an administrator login would change to
	 * get around protection. While the lock is closed they cannot be changed,
	 * from the settings screen, an import, or the admin bar.
	 */
	const PROTECTED_KEYS = [
		'firewall_enabled', 'waf_enabled', 'ip_blocklist', 'ip_safelist',
		'trust_cloudflare_ip', 'trusted_proxies', 'disable_file_editing',
		'uploads_disabled',
		'two_factor_enabled', 'two_factor_enforced_roles',
		'geo_enabled', 'geo_mode', 'geo_allowed_countries', 'geo_blocked_countries',
		'geo_block_site_enabled', 'geo_block_unknown', 'geo_whitelist_login_enabled',
		'geo_whitelist_block_admins', 'geo_admin_restrict_enabled', 'geo_admin_countries',
		'geo_user_lock_enabled', 'geo_user_lock_action',
	];

	/** Capabilities that let an administrator put new code on the site. */
	const CODE_CAPS = [ 'install_plugins', 'install_themes', 'edit_plugins', 'edit_themes', 'edit_files' ];

	/** Option holding the hashed unlock password (kept out of the settings array, which the UI can read). */
	const LOCK_HASH = 'gemsecurity_lock_hash';

	/** How long a correct password keeps the lock open for that session. */
	const UNLOCK_TTL = 600;

	/** Wrong passwords allowed per user per window. */
	const MAX_TRIES = 5;

	/** Wrong emailed codes allowed per code, and how long a code lives. */
	const MAX_CODE_TRIES = 5;
	const CODE_TTL       = 600;

	/** Codes that can be sent per user per window. */
	const MAX_SENDS = 3;

	public static function init() {
		$self = new self();

		// Plugin lock.
		add_filter( 'map_meta_cap', [ $self, 'lock_caps' ], 10, 4 );
		add_filter( 'plugin_action_links', [ $self, 'lock_action_links' ], 99, 2 );
		add_filter( 'network_admin_plugin_action_links', [ $self, 'lock_action_links' ], 99, 2 );
		add_filter( 'pre_update_option_active_plugins', [ $self, 'keep_active' ], 10, 2 );
		add_filter( 'pre_update_site_option_active_sitewide_plugins', [ $self, 'keep_active_network' ], 10, 2 );

		// wp-admin/options.php lists every option and lets an administrator edit
		// or empty it, so the lock's password hash is closed to writes from
		// anywhere but this class (and stored as an array, which that page
		// shows only as "SERIALIZED DATA" instead of the value).
		add_filter( 'pre_update_option_' . self::LOCK_HASH, [ $self, 'protect_hash_update' ], 10, 2 );
		add_filter( 'pre_delete_option_' . self::LOCK_HASH, [ $self, 'protect_hash_delete' ] );

		// While locked, nobody can install, upload or edit code: that is how an
		// attacker would get past every setting above.
		add_filter( 'user_has_cap', [ $self, 'strip_code_caps' ], 999 );

		// Uploads switch.
		add_action( 'admin_bar_menu', [ $self, 'admin_bar' ], 100 );
		add_action( 'admin_post_' . self::TOGGLE_ACTION, [ $self, 'handle_toggle' ] );
		if ( Helper::get_setting( 'uploads_disabled', false ) ) {
			add_filter( 'upload_mimes', '__return_empty_array', 999 );
			add_filter( 'wp_handle_upload_prefilter', [ $self, 'refuse_upload' ], 0 );
			add_filter( 'wp_handle_sideload_prefilter', [ $self, 'refuse_upload' ], 0 );
			add_filter( 'pre_move_uploaded_file', [ $self, 'refuse_move' ], 0 );
			add_filter( 'user_has_cap', [ $self, 'strip_upload_caps' ], 999 );
		}
	}

	/* --------------------------------------------------------------------- */
	/* IP safelist                                                            */
	/* --------------------------------------------------------------------- */

	/**
	 * Is this IP on the safelist (exact address or CIDR range)?
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function ip_safelisted( $ip ) {
		if ( ! $ip || '0.0.0.0' === $ip ) {
			return false;
		}
		foreach ( (array) Helper::get_setting( 'ip_safelist', [] ) as $entry ) {
			if ( \GemSecurity\Modules\Firewall::ip_matches( $ip, trim( (string) $entry ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Take the requester's own address out of a block list.
	 *
	 * @param array  $list Entries (IPs / CIDR ranges).
	 * @param string $ip   Requester's address.
	 * @return array{0:array,1:bool} The cleaned list, and whether anything was removed.
	 */
	public static function without_ip( array $list, $ip ) {
		if ( ! $ip || '0.0.0.0' === $ip ) {
			return [ $list, false ];
		}
		$kept = [];
		foreach ( $list as $entry ) {
			if ( ! \GemSecurity\Modules\Firewall::ip_matches( $ip, trim( (string) $entry ) ) ) {
				$kept[] = $entry;
			}
		}
		return [ $kept, count( $kept ) !== count( $list ) ];
	}

	/* --------------------------------------------------------------------- */
	/* Plugin lock                                                            */
	/* --------------------------------------------------------------------- */

	/**
	 * Is the lock holding for this request?
	 *
	 * It holds for everybody — owner or not — until the unlock password has
	 * been entered in this login session. Command-line and cron callers are
	 * not restricted: they already have server access, which is the level the
	 * lock exists to protect.
	 *
	 * @return bool
	 */
	public static function locked_for_current_user() {
		if ( ! self::lock_on() || defined( 'GEMSEC_PLUGIN_LOCK_DISABLE' ) ) {
			return false;
		}
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return false;
		}
		return ! self::is_unlocked();
	}

	/**
	 * A lock exists only when it has a password. A switch left on without one
	 * (an older version, a half-finished save) must never become a lock nobody
	 * can open.
	 *
	 * @return bool
	 */
	public static function lock_on() {
		return (bool) Helper::get_setting( 'plugin_lock_enabled', false ) && '' !== self::hash();
	}

	/** @return string Where unlock codes go: the address the lock was set up with. Not a setting, so it cannot be redirected. */
	private static function lock_email() {
		$v = get_option( self::LOCK_HASH, [] );
		return is_array( $v ) && ! empty( $v['email'] ) ? (string) $v['email'] : '';
	}

	/** @return string The stored password hash, or ''. */
	private static function hash() {
		$v = get_option( self::LOCK_HASH, [] );
		return is_array( $v ) && ! empty( $v['h'] ) ? (string) $v['h'] : '';
	}

	/** True only while this class is writing the hash itself. */
	private static $writing = false;

	/**
	 * @param mixed $new
	 * @param mixed $old
	 * @return mixed
	 */
	public function protect_hash_update( $new, $old ) {
		return self::$writing ? $new : $old;
	}

	/**
	 * @param mixed $pre
	 * @return mixed Non-null stops the delete.
	 */
	public function protect_hash_delete( $pre ) {
		return self::$writing ? $pre : false;
	}

	/** @return bool Has this session entered the unlock password recently? */
	public static function is_unlocked() {
		return (bool) Store::get( self::unlock_key() );
	}

	/** @return string Transient key tied to the user and this login session. */
	private static function unlock_key() {
		return 'gemsec_lock_open_' . md5( get_current_user_id() . '|' . wp_get_session_token() );
	}

	/**
	 * @param string $file Plugin basename, e.g. gemsecurity/gemsecurity.php.
	 * @return bool
	 */
	private static function is_ours( $file ) {
		$file = (string) $file;
		return 0 === strpos( $file, 'gemsecurity/' ) || 0 === strpos( $file, 'gemsecurity-pro/' );
	}

	/**
	 * @param string[] $caps
	 * @param string   $cap
	 * @param int      $user_id
	 * @param array    $args
	 * @return string[]
	 */
	public function lock_caps( $caps, $cap, $user_id, $args ) {
		if ( ! in_array( $cap, [ 'deactivate_plugin', 'delete_plugin' ], true ) || empty( $args[0] ) ) {
			return $caps;
		}
		if ( self::is_ours( $args[0] ) && self::locked_for_current_user() ) {
			return [ 'do_not_allow' ];
		}
		return $caps;
	}

	/**
	 * @param array  $links
	 * @param string $file
	 * @return array
	 */
	public function lock_action_links( $links, $file ) {
		if ( self::is_ours( $file ) && self::locked_for_current_user() ) {
			unset( $links['deactivate'], $links['delete'] );
		}
		return $links;
	}

	/**
	 * The bulk "Deactivate" action and a few REST paths call deactivate_plugins()
	 * with no per-plugin capability check, so the option write is the one place
	 * every route has to pass through.
	 *
	 * @param mixed $new
	 * @param mixed $old
	 * @return mixed
	 */
	public function keep_active( $new, $old ) {
		if ( ! is_user_logged_in() || ! self::locked_for_current_user() || ! is_array( $new ) || ! is_array( $old ) ) {
			return $new;
		}
		$dropped = [];
		foreach ( $old as $file ) {
			if ( self::is_ours( $file ) && ! in_array( $file, $new, true ) ) {
				$dropped[] = $file;
			}
		}
		if ( $dropped ) {
			Logger::log(
				'plugin_lock_blocked',
				__( 'Blocked an attempt to deactivate GemSecurity (plugin lock).', 'gemsecurity' ),
				Logger::SEVERITY_WARNING
			);
			$new = array_values( array_unique( array_merge( $new, $dropped ) ) );
		}
		return $new;
	}

	/**
	 * @param mixed $new
	 * @param mixed $old
	 * @return mixed
	 */
	public function keep_active_network( $new, $old ) {
		if ( ! is_user_logged_in() || ! self::locked_for_current_user() || ! is_array( $new ) || ! is_array( $old ) ) {
			return $new;
		}
		foreach ( $old as $file => $time ) {
			if ( self::is_ours( $file ) && ! isset( $new[ $file ] ) ) {
				$new[ $file ] = $time;
			}
		}
		return $new;
	}

	/**
	 * @param array $caps
	 * @return array
	 */
	public function strip_code_caps( $caps ) {
		if ( ! self::locked_for_current_user() ) {
			return $caps;
		}
		foreach ( self::CODE_CAPS as $cap ) {
			unset( $caps[ $cap ] );
		}
		return $caps;
	}

	/**
	 * Keep protected settings as they are while the lock is closed.
	 *
	 * @param array $current Stored settings.
	 * @param array $merged  Settings about to be stored.
	 * @return array{0:array,1:bool} The settings to store, and whether anything was held back.
	 */
	public static function guard_protected( array $current, array $merged ) {
		if ( ! self::locked_for_current_user() ) {
			return [ $merged, false ];
		}
		$held = false;
		foreach ( self::PROTECTED_KEYS as $key ) {
			$old = array_key_exists( $key, $current ) ? $current[ $key ] : null;
			$new = array_key_exists( $key, $merged ) ? $merged[ $key ] : null;
			if ( wp_json_encode( $old ) !== wp_json_encode( $new ) ) {
				$merged[ $key ] = $old;
				$held           = true;
			}
		}
		return [ $merged, $held ];
	}

	/**
	 * The lock switch is not an ordinary setting: the settings form and import
	 * can neither turn it on (no password would exist) nor off (no password
	 * would be asked). Only the lock endpoints below change it.
	 *
	 * @param array $current Stored settings.
	 * @param array $merged  Settings about to be stored.
	 * @return array
	 */
	public static function guard_lock_settings( array $current, array $merged ) {
		$merged['plugin_lock_enabled'] = ! empty( $current['plugin_lock_enabled'] );
		return $merged;
	}

	/* --------------------------------------------------------------------- */
	/* Lock endpoints                                                         */
	/* --------------------------------------------------------------------- */

	/** GET /lock */
	public static function lock_status() {
		return rest_ensure_response( [
			'success'  => true,
			'enabled'  => self::lock_on(),
			'unlocked' => self::is_unlocked(),
			'disabled_by_constant' => defined( 'GEMSEC_PLUGIN_LOCK_DISABLE' ),
		] );
	}

	/** POST /lock/enable { password } — only while no lock exists. */
	public static function lock_enable( $req ) {
		if ( self::lock_on() ) {
			return new \WP_Error( 'gemsecurity_lock', __( 'The lock is already on.', 'gemsecurity' ), [ 'status' => 409 ] );
		}
		$email = (string) wp_get_current_user()->user_email;
		if ( ! is_email( $email ) ) {
			return new \WP_Error( 'gemsecurity_lock', __( 'Your account has no valid email address. Unlock codes are sent by email, so add one to your profile first.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		$password = (string) $req->get_param( 'password' );
		if ( strlen( $password ) < 8 ) {
			return new \WP_Error( 'gemsecurity_lock', __( 'Use at least 8 characters for the unlock password.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		self::$writing = true;
		update_option( self::LOCK_HASH, [ 'h' => wp_hash_password( $password ), 'email' => $email ], false );
		self::$writing = false;
		self::store_flag( true );
		// The person who just set it stays unlocked for this session.
		Store::set( self::unlock_key(), 1, self::UNLOCK_TTL );
		Logger::log( 'plugin_lock_enabled', __( 'GemSecurity plugin lock turned on.', 'gemsecurity' ), Logger::SEVERITY_NOTICE );
		return self::lock_status();
	}

	/**
	 * POST /lock/unlock { password } — step 1 of 2.
	 *
	 * A correct password does not open the lock; it emails a one-time code.
	 * The code (step 2, lock_verify) opens it.
	 */
	public static function lock_unlock( $req ) {
		$hash  = self::hash();
		$email = self::lock_email();
		if ( '' === $hash ) {
			return new \WP_Error( 'gemsecurity_lock', __( 'No lock is set.', 'gemsecurity' ), [ 'status' => 409 ] );
		}
		if ( ! is_email( $email ) ) {
			return new \WP_Error( 'gemsecurity_lock', __( 'This lock has no email address on file. Remove it with the wp-config recovery line and set it up again.', 'gemsecurity' ), [ 'status' => 409 ] );
		}

		$uid       = get_current_user_id();
		$tries_key = 'gemsec_lock_tries_' . $uid;
		$tries     = (int) Store::get( $tries_key );
		if ( $tries >= self::MAX_TRIES ) {
			return new \WP_Error( 'gemsecurity_lock', __( 'Too many wrong passwords. Try again in 15 minutes.', 'gemsecurity' ), [ 'status' => 429 ] );
		}

		if ( ! wp_check_password( (string) $req->get_param( 'password' ), $hash ) ) {
			Store::set( $tries_key, $tries + 1, 15 * MINUTE_IN_SECONDS );
			Logger::log( 'plugin_lock_failed', __( 'Wrong GemSecurity unlock password entered.', 'gemsecurity' ), Logger::SEVERITY_WARNING );
			return new \WP_Error( 'gemsecurity_lock', __( 'Wrong password.', 'gemsecurity' ), [ 'status' => 403 ] );
		}
		Store::delete( $tries_key );

		// Cap how many codes can be requested, so this cannot be used to flood the inbox.
		$sends_key = 'gemsec_lock_sends_' . $uid;
		$sends     = (int) Store::get( $sends_key );
		if ( $sends >= self::MAX_SENDS ) {
			return new \WP_Error( 'gemsecurity_lock', __( 'Too many codes requested. Try again in 15 minutes.', 'gemsecurity' ), [ 'status' => 429 ] );
		}

		$code = (string) random_int( 100000, 999999 );
		$sent = Mailer::send(
			$email,
			'🔐',
			__( 'Your GemSecurity unlock code', 'gemsecurity' ),
			[
				[ 'type' => 'paragraph', 'text' => esc_html__( 'Someone entered the unlock password to open the GemSecurity plugin lock. Use this code to finish:', 'gemsecurity' ) ],
				[ 'type' => 'stats', 'items' => [ __( 'Unlock code', 'gemsecurity' ) => $code ] ],
				[ 'type' => 'notice', 'tone' => 'warning', 'text' => esc_html__( 'The code works for 10 minutes. If this was not you, someone knows your unlock password. Do not share the code.', 'gemsecurity' ) ],
			]
		);
		if ( ! $sent ) {
			return new \WP_Error( 'gemsecurity_lock', __( 'The email with the code could not be sent. Check that your site can send email.', 'gemsecurity' ), [ 'status' => 500 ] );
		}

		Store::set( $sends_key, $sends + 1, 15 * MINUTE_IN_SECONDS );
		Store::set( self::code_key(), [ 'c' => wp_hash( $code ), 'tries' => 0 ], self::CODE_TTL );
		Logger::log( 'plugin_lock_code_sent', __( 'GemSecurity unlock code emailed.', 'gemsecurity' ), Logger::SEVERITY_NOTICE );

		return rest_ensure_response( [ 'success' => true, 'step' => 'code', 'email' => self::mask_email( $email ) ] );
	}

	/** POST /lock/verify { code } — step 2 of 2: the emailed code opens the lock. */
	public static function lock_verify( $req ) {
		$pending = Store::get( self::code_key() );
		if ( ! is_array( $pending ) ) {
			return new \WP_Error( 'gemsecurity_lock', __( 'No code is waiting, or it expired. Enter the password again to get a new one.', 'gemsecurity' ), [ 'status' => 409 ] );
		}
		if ( (int) $pending['tries'] >= self::MAX_CODE_TRIES ) {
			Store::delete( self::code_key() );
			return new \WP_Error( 'gemsecurity_lock', __( 'Too many wrong codes. Enter the password again to get a new one.', 'gemsecurity' ), [ 'status' => 429 ] );
		}

		$code = preg_replace( '/\D/', '', (string) $req->get_param( 'code' ) );
		if ( '' === $code || ! hash_equals( (string) $pending['c'], wp_hash( $code ) ) ) {
			$pending['tries'] = (int) $pending['tries'] + 1;
			Store::set( self::code_key(), $pending, self::CODE_TTL );
			Logger::log( 'plugin_lock_failed', __( 'Wrong GemSecurity unlock code entered.', 'gemsecurity' ), Logger::SEVERITY_WARNING );
			return new \WP_Error( 'gemsecurity_lock', __( 'Wrong code.', 'gemsecurity' ), [ 'status' => 403 ] );
		}

		Store::delete( self::code_key() );
		Store::set( self::unlock_key(), 1, self::UNLOCK_TTL );
		Logger::log( 'plugin_lock_opened', __( 'GemSecurity plugin lock opened for 10 minutes.', 'gemsecurity' ), Logger::SEVERITY_NOTICE );
		return self::lock_status();
	}

	/** @return string Transient key for the pending emailed code (user + login session). */
	private static function code_key() {
		return 'gemsec_lock_code_' . md5( get_current_user_id() . '|' . wp_get_session_token() );
	}

	/** @return string j***@example.com */
	private static function mask_email( $email ) {
		list( $name, $domain ) = array_pad( explode( '@', $email, 2 ), 2, '' );
		return substr( $name, 0, 1 ) . str_repeat( '*', max( 2, strlen( $name ) - 1 ) ) . '@' . $domain;
	}

	/** POST /lock/relock — close it again right away. */
	public static function lock_relock() {
		Store::delete( self::unlock_key() );
		return self::lock_status();
	}

	/** POST /lock/disable — remove the lock (needs it to be open first). */
	public static function lock_disable() {
		if ( self::locked_for_current_user() ) {
			return new \WP_Error( 'gemsecurity_lock', __( 'Enter the unlock password first.', 'gemsecurity' ), [ 'status' => 403 ] );
		}
		self::$writing = true;
		delete_option( self::LOCK_HASH );
		self::$writing = false;
		self::store_flag( false );
		Logger::log( 'plugin_lock_disabled', __( 'GemSecurity plugin lock turned off.', 'gemsecurity' ), Logger::SEVERITY_WARNING );
		return self::lock_status();
	}

	/** Write the on/off flag straight to the option (the settings path refuses to). */
	private static function store_flag( $on ) {
		$settings = get_option( GEMSECURITY_SETTINGS_NAME, [] );
		$settings = is_array( $settings ) ? $settings : [];
		$settings['plugin_lock_enabled'] = (bool) $on;
		update_option( GEMSECURITY_SETTINGS_NAME, $settings );
	}

	/* --------------------------------------------------------------------- */
	/* File uploads                                                           */
	/* --------------------------------------------------------------------- */

	/**
	 * @param array $file
	 * @return array
	 */
	public function refuse_upload( $file ) {
		$file['error'] = __( 'File uploads are turned off on this site.', 'gemsecurity' );
		return $file;
	}

	/**
	 * @return bool False makes WordPress report the upload as failed.
	 */
	public function refuse_move() {
		return false;
	}

	/**
	 * @param array $caps
	 * @return array
	 */
	public function strip_upload_caps( $caps ) {
		unset( $caps['upload_files'], $caps['unfiltered_upload'] );
		return $caps;
	}

	/**
	 * Admin-bar switch for the uploads lock.
	 *
	 * @param \WP_Admin_Bar $bar
	 */
	public function admin_bar( $bar ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$off = (bool) Helper::get_setting( 'uploads_disabled', false );

		$bar->add_node( [
			'id'    => 'gemsecurity',
			'title' => '<span class="ab-icon dashicons dashicons-shield" style="margin-top:2px"></span><span class="ab-label">' . esc_html__( 'GemSecurity', 'gemsecurity' ) . '</span>',
			'href'  => admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG ),
		] );
		$bar->add_node( [
			'id'     => 'gemsecurity-uploads',
			'parent' => 'gemsecurity',
			'title'  => $off
				? esc_html__( 'File uploads: OFF — click to turn on', 'gemsecurity' )
				: esc_html__( 'File uploads: ON — click to turn off', 'gemsecurity' ),
			'href'   => wp_nonce_url( admin_url( 'admin-post.php?action=' . self::TOGGLE_ACTION ), self::TOGGLE_ACTION ),
		] );
	}

	public function handle_toggle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'gemsecurity' ), '', [ 'response' => 403 ] );
		}
		check_admin_referer( self::TOGGLE_ACTION );

		if ( self::locked_for_current_user() ) {
			wp_die(
				esc_html__( 'GemSecurity is locked. Unlock it on the Firewall page (password and emailed code) before changing this.', 'gemsecurity' ),
				'',
				[ 'response' => 403, 'back_link' => true ]
			);
		}

		Settings::apply( [ 'uploads_disabled' => ! Helper::get_setting( 'uploads_disabled', false ) ], 'instant' );

		$back = wp_get_referer();
		wp_safe_redirect( $back ? $back : admin_url() );
		exit;
	}
}
