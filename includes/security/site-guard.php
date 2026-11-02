<?php
namespace GemSecurity\Security;

use GemSecurity\Helper;
use GemSecurity\Logger;
use GemSecurity\Mailer;
use GemSecurity\Rest\Settings;
use GemSecurity\Store;

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
		// delete_plugin (the capability) is never checked by core, so the
		// lock_caps entry for it alone does not stop a deletion; this does.
		add_action( 'delete_plugin', [ $self, 'refuse_delete' ] );
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
		// Styles for the admin-bar count pill (printed inline — a few rules
		// isn't worth a separate stylesheet request on every page).
		add_action( 'wp_head', [ $self, 'admin_bar_css' ], 1000 );
		add_action( 'admin_head', [ $self, 'admin_bar_css' ], 1000 );
		// Any settings change can move the score — bust the admin-bar cache
		// so the next page render shows the current number, not a 5-min-stale one.
		add_action( 'update_option_' . GEMSECURITY_SETTINGS_NAME, static function () {
			delete_transient( 'gemsecurity_score_ab' );
		} );
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

	/** @param string $file Plugin basename about to be deleted. */
	public function refuse_delete( $file ) {
		if ( self::is_ours( $file ) && self::locked_for_current_user() ) {
			wp_die( esc_html__( 'GemSecurity is locked. Unlock it on the Firewall page before deleting it.', 'gemsecurity' ), '', [ 'response' => 403 ] );
		}
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

		// Show badge counts of hardening switches that are currently ON, so
		// an administrator can tell at a glance that the site is locked
		// down (and jump to the setting to turn one off).
		$active = $this->active_hardening_chips();
		$score  = $this->cached_security_score();

		$title = '<span class="ab-icon dashicons dashicons-shield"></span>'
			. '<span class="ab-label">' . esc_html__( 'GemSecurity', 'gemsecurity' ) . '</span>';

		// Score pill: colored by grade so it reads at a glance (green=A/B,
		// amber=C/D, red=F). Clicking the parent still opens the dashboard,
		// where the "boost your score" breakdown explains what to fix.
		if ( null !== $score ) {
			$tone = $score['score'] >= 75 ? 'ok' : ( $score['score'] >= 40 ? 'warn' : 'bad' );
			$title .= '<span class="gemsecurity-ab-score gemsecurity-ab-score--' . esc_attr( $tone ) . '" aria-label="'
				/* translators: 1: numeric score 0-100, 2: letter grade A-F. */
				. esc_attr( sprintf( __( 'Security score %1$d, grade %2$s', 'gemsecurity' ), $score['score'], $score['grade'] ) )
				. '" title="' . esc_attr( sprintf( /* translators: 1: score, 2: grade. */ __( 'Security score %1$d/100 — grade %2$s', 'gemsecurity' ), $score['score'], $score['grade'] ) )
				. '">' . (int) $score['score'] . '</span>';
		}

		if ( $active ) {
			$title .= '<span class="gemsecurity-ab-count" aria-label="'
				/* translators: %d: number of active hardening switches. */
				. esc_attr( sprintf( _n( '%d hardening switch on', '%d hardening switches on', count( $active ), 'gemsecurity' ), count( $active ) ) )
				. '" title="' . esc_attr( sprintf( _n( '%d protection active', '%d protections active', count( $active ), 'gemsecurity' ), count( $active ) ) )
				. '">✓ ' . (int) count( $active ) . '</span>';
		}

		$bar->add_node( [
			'id'    => 'gemsecurity',
			'title' => $title,
			'href'  => admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG ),
		] );

		// Score header inside the dropdown — repeats the badge with its grade
		// and a one-line nudge, so a low score is visible even before the
		// hardening chips. Links to the dashboard where the fix list lives.
		$dashboard = admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG );

		if ( null !== $score ) {
			$tone = $score['score'] >= 75 ? 'ok' : ( $score['score'] >= 40 ? 'warn' : 'bad' );
			$bar->add_node( [
				'id'     => 'gemsecurity-score',
				'parent' => 'gemsecurity',
				'title'  => '<span class="gemsecurity-ab-scorehead">'
					. '<span class="gemsecurity-ab-scorehead__top"><strong>' . esc_html__( 'Security score', 'gemsecurity' ) . '</strong>'
					. '<span class="gemsecurity-ab-score gemsecurity-ab-score--' . esc_attr( $tone ) . '">'
					. (int) $score['score'] . '/100 · ' . esc_html( $score['grade'] ) . '</span></span>'
					. '<span class="gemsecurity-ab-scorehead__note">' . esc_html( $this->score_nudge( $score['score'] ) ) . '</span>'
					. '</span>',
				'href'   => $dashboard,
				'meta'   => [ 'class' => 'gemsecurity-ab-scoreitem' ],
			] );
		}

		// One child per hardening switch currently ON — a quick status
		// readout that doubles as a jump list to each setting's page.
		if ( $active ) {
			$bar->add_node( [
				'id'     => 'gemsecurity-h-protect',
				'parent' => 'gemsecurity',
				'title'  => esc_html__( 'Active protections', 'gemsecurity' ),
				'meta'   => [ 'class' => 'gemsecurity-ab-heading' ],
			] );
			foreach ( $active as $chip ) {
				$bar->add_node( [
					'id'     => 'gemsecurity-chip-' . $chip['id'],
					'parent' => 'gemsecurity',
					'title'  => '<span class="gemsecurity-ab-check">✓</span>' . esc_html( $chip['label'] ),
					'href'   => esc_url( $chip['href'] ),
				] );
			}
		}

		$bar->add_node( [
			'id'     => 'gemsecurity-h-actions',
			'parent' => 'gemsecurity',
			'title'  => esc_html__( 'Quick actions', 'gemsecurity' ),
			'meta'   => [ 'class' => 'gemsecurity-ab-heading' ],
		] );

		// Uploads toggle stays its own node: it is the one chip that
		// toggles in-place from the admin bar rather than linking out.
		$bar->add_node( [
			'id'     => 'gemsecurity-uploads',
			'parent' => 'gemsecurity',
			'title'  => '<span class="gemsecurity-ab-dot gemsecurity-ab-dot--' . ( $off ? 'off' : 'on' ) . '"></span>'
				. ( $off
					? esc_html__( 'File uploads: blocked', 'gemsecurity' )
					: esc_html__( 'File uploads: allowed', 'gemsecurity' ) )
				. '<span class="gemsecurity-ab-action">'
				. ( $off ? esc_html__( 'Allow', 'gemsecurity' ) : esc_html__( 'Block', 'gemsecurity' ) )
				. '</span>',
			'href'   => wp_nonce_url( admin_url( 'admin-post.php?action=' . self::TOGGLE_ACTION ), self::TOGGLE_ACTION ),
		] );

		$bar->add_node( [
			'id'     => 'gemsecurity-open',
			'parent' => 'gemsecurity',
			'title'  => esc_html__( 'Open GemSecurity dashboard', 'gemsecurity' ) . ' →',
			'href'   => $dashboard,
		] );
	}

	/**
	 * The high-impact hardening switches that are currently ON, as admin-bar
	 * chips: [{ id, label, href }, …]. Only switches that materially change
	 * site behaviour are listed here — a long row of "everything's fine" is
	 * noise, so each entry is something an admin should know is active.
	 *
	 * @return array<int,array{id:string,label:string,href:string}>
	 */
	private function active_hardening_chips() {
		$firewall    = admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG . '-firewall' );
		$settings    = admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG . '-settings' );
		$wp_general  = admin_url( 'options-general.php' );

		$candidates = [
			[
				'id'    => 'file-editor',
				'on'    => (bool) Helper::get_setting( 'disable_file_editing', false ),
				'label' => __( 'File editor off', 'gemsecurity' ),
				'href'  => $firewall,
			],
			[
				'id'    => 'xmlrpc',
				'on'    => (bool) Helper::get_setting( 'xmlrpc_disabled', false ),
				'label' => __( 'XML-RPC off', 'gemsecurity' ),
				'href'  => $firewall,
			],
			[
				'id'    => 'plugin-lock',
				'on'    => (bool) Helper::get_setting( 'plugin_lock_enabled', false ),
				'label' => __( 'Plugin lock on', 'gemsecurity' ),
				'href'  => $settings,
			],
			[
				'id'    => 'registration',
				'on'    => ! (bool) get_option( 'users_can_register' ),
				'label' => __( 'User registration off', 'gemsecurity' ),
				'href'  => $wp_general,
			],
		];

		return array_values( array_filter( $candidates, static function ( $c ) {
			return ! empty( $c['on'] );
		} ) );
	}

	/**
	 * Memoised security score for the admin bar. Full assessment runs posture
	 * checks and threat scans, which would be wasted on every page load, so a
	 * five-minute transient keeps the cost bounded. Returns null if the
	 * SecurityScore class is unreachable (e.g. during an upgrade).
	 *
	 * @return array{score:int,grade:string}|null
	 */
	private function cached_security_score() {
		if ( ! class_exists( SecurityScore::class ) ) {
			return null;
		}
		$cached = get_transient( 'gemsecurity_score_ab' );
		if ( is_array( $cached ) && isset( $cached['score'], $cached['grade'] ) ) {
			return $cached;
		}
		$a = SecurityScore::assess();
		$out = [ 'score' => (int) $a['score'], 'grade' => (string) $a['grade'] ];
		set_transient( 'gemsecurity_score_ab', $out, 5 * MINUTE_IN_SECONDS );
		return $out;
	}

	/**
	 * One-line nudge for the admin-bar score header, tuned to the grade range
	 * so the message isn't "fix this" at 95 or "you're set" at 20.
	 *
	 * @param int $score
	 * @return string
	 */
	private function score_nudge( $score ) {
		if ( $score >= 90 ) {
			return __( 'Looking great.', 'gemsecurity' );
		}
		if ( $score >= 75 ) {
			return __( 'A few switches away from an A.', 'gemsecurity' );
		}
		if ( $score >= 60 ) {
			return __( 'Review your to-do list.', 'gemsecurity' );
		}
		if ( $score >= 40 ) {
			return __( 'At risk — fix the warnings.', 'gemsecurity' );
		}
		return __( 'Open the dashboard and start with the critical items.', 'gemsecurity' );
	}

	/**
	 * Inline CSS for the admin-bar count pill. Only prints when the admin
	 * bar is actually showing.
	 */
	public function admin_bar_css() {
		if ( ! is_admin_bar_showing() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		?>
<style id="gemsecurity-ab-css">
#wpadminbar #wp-admin-bar-gemsecurity > .ab-item { display: flex; align-items: center; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-count,
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-score {
	display: inline-flex; align-items: center; justify-content: center;
	min-width: 18px; height: 18px; padding: 0 6px; margin-left: 6px;
	color: #fff;
	border-radius: 9px;
	font-size: 11px; font-weight: 600; line-height: 1;
}
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-count { background: #00AD6B; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-score--ok   { background: #00AD6B; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-score--warn { background: #FDB022; color: #3B2706; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-score--bad  { background: #E2483D; }
#wpadminbar #wp-admin-bar-gemsecurity:hover .gemsecurity-ab-count,
#wpadminbar #wp-admin-bar-gemsecurity.hover .gemsecurity-ab-count,
#wpadminbar #wp-admin-bar-gemsecurity:hover .gemsecurity-ab-score--ok,
#wpadminbar #wp-admin-bar-gemsecurity.hover .gemsecurity-ab-score--ok,
#wpadminbar #wp-admin-bar-gemsecurity:hover .gemsecurity-ab-score--bad,
#wpadminbar #wp-admin-bar-gemsecurity.hover .gemsecurity-ab-score--bad { color: #fff; }
/* Dropdown: roomier rows, a clear score header and labelled sections. */
#wpadminbar #wp-admin-bar-gemsecurity .ab-sub-wrapper { min-width: 260px; }
#wpadminbar #wp-admin-bar-gemsecurity .ab-submenu { padding: 6px 0; }
#wpadminbar #wp-admin-bar-gemsecurity .ab-submenu .ab-item { display: flex; align-items: center; gap: 8px; height: auto; min-height: 30px; line-height: 1.4; padding: 4px 14px; white-space: normal; }
#wpadminbar #wp-admin-bar-gemsecurity .ab-submenu .gemsecurity-ab-score { margin-left: 0; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-scoreitem > .ab-item { padding: 8px 14px 10px; border-bottom: 1px solid rgba(255,255,255,.12); margin-bottom: 4px; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-scorehead { display: flex; flex-direction: column; gap: 4px; width: 100%; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-scorehead__top { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-scorehead__note { font-size: 12px; opacity: .75; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-heading > .ab-item { min-height: 0; padding: 8px 14px 2px; font-size: 10.5px; font-weight: 600; letter-spacing: .6px; text-transform: uppercase; color: #8c8f94 !important; cursor: default; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-check { color: #34d399; font-weight: 700; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-dot { width: 8px; height: 8px; border-radius: 50%; flex: 0 0 auto; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-dot--on { background: #34d399; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-dot--off { background: #f87171; }
#wpadminbar #wp-admin-bar-gemsecurity .gemsecurity-ab-action { margin-left: auto; padding: 1px 8px; border-radius: 10px; background: rgba(255,255,255,.14); font-size: 11px; font-weight: 600; }
#wpadminbar #wp-admin-bar-gemsecurity-open > .ab-item { margin-top: 4px; border-top: 1px solid rgba(255,255,255,.12); color: #72aee6 !important; }
</style>
		<?php
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
