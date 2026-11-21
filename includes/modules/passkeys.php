<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;
use GemSecurity\Security\PasskeyStore;
use GemSecurity\Security\Webauthn;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Passkeys — passwordless sign-in with WebAuthn (Face ID, Touch ID, Windows
 * Hello, security keys, password-manager passkeys).
 *
 * Sign-in is usernameless: the browser offers the passkeys it holds for this
 * site, the server looks the credential up, and a valid signature with user
 * verification signs the user in. Because the passkey already proves
 * possession *and* the user's biometric/PIN, it stands in for the second
 * factor and skips the TOTP/email challenge.
 *
 * Members add and remove their own passkeys on their profile screen.
 * Credentials live in {$wpdb->prefix}gemsecurity_passkeys (public keys only).
 */
class Passkeys {

	const CHALLENGE_PREFIX = 'gemsec_pk_';
	const CHALLENGE_TTL    = 5 * MINUTE_IN_SECONDS;
	const LIMIT_WINDOW     = 15 * MINUTE_IN_SECONDS;
	const MAX_FAILURES     = 10;
	const MAX_OPTIONS      = 40;

	public static function init() {
		if ( ! Helper::get_setting( 'passkeys_enabled', false ) ) {
			return;
		}
		$self = new self();
		add_action( 'rest_api_init', [ $self, 'register_routes' ] );
		add_action( 'login_enqueue_scripts', [ $self, 'login_assets' ] );
		add_action( 'login_form', [ $self, 'render_login_button' ] );
		add_action( 'show_user_profile', [ $self, 'render_profile' ] );
		add_action( 'admin_enqueue_scripts', [ $self, 'profile_assets' ] );
		add_action( 'delete_user', [ PasskeyStore::class, 'delete_all_for_user' ] );
	}

	/* ------------------------------------------------------------------ */
	/* Policy                                                              */
	/* ------------------------------------------------------------------ */

	/** Whether this user's role may use passkeys (no roles selected = everyone). */
	public static function user_allowed( $user ) {
		if ( ! $user instanceof \WP_User ) {
			return false;
		}
		$roles = (array) Helper::get_setting( 'passkeys_roles', [] );
		if ( empty( $roles ) ) {
			return true;
		}
		return (bool) array_intersect( (array) $user->roles, $roles );
	}

	public static function rp_id() {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		/**
		 * Filter the WebAuthn relying-party id (a registrable domain suffix of
		 * the site host). Changing it orphans every registered passkey.
		 */
		return (string) apply_filters( 'gemsecurity/passkeys_rp_id', $host );
	}

	public static function origins() {
		$out = [];
		foreach ( [ home_url(), site_url(), admin_url() ] as $url ) {
			$p = wp_parse_url( $url );
			if ( empty( $p['scheme'] ) || empty( $p['host'] ) ) {
				continue;
			}
			$out[] = $p['scheme'] . '://' . $p['host'] . ( ! empty( $p['port'] ) ? ':' . $p['port'] : '' );
		}
		return array_values( array_unique( (array) apply_filters( 'gemsecurity/passkeys_origins', $out ) ) );
	}

	/** Stable opaque WebAuthn user handle; reveals nothing about the account. */
	private static function user_handle( $user_id ) {
		return hash_hmac( 'sha256', 'gemsec-passkey-' . (int) $user_id, wp_salt( 'auth' ), true );
	}

	/* ------------------------------------------------------------------ */
	/* REST                                                                */
	/* ------------------------------------------------------------------ */

	public function register_routes() {
		$ns   = \GemSecurity\Api::NAMESPACE;
		$auth = [ $this, 'can_manage' ];

		register_rest_route( $ns, '/passkeys', [
			'methods'             => 'GET',
			'callback'            => [ $this, 'rest_list' ],
			'permission_callback' => $auth,
		] );
		register_rest_route( $ns, '/passkeys/register/options', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'rest_register_options' ],
			'permission_callback' => $auth,
		] );
		register_rest_route( $ns, '/passkeys/register/verify', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'rest_register_verify' ],
			'permission_callback' => $auth,
		] );
		register_rest_route( $ns, '/passkeys/(?P<id>\d+)', [
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'rest_rename' ],
				'permission_callback' => $auth,
			],
			[
				'methods'             => 'DELETE',
				'callback'            => [ $this, 'rest_delete' ],
				'permission_callback' => $auth,
			],
		] );

		// Sign-in is, by definition, called by visitors who are not signed in.
		// Both routes authenticate the request themselves: a single-use server
		// challenge plus a signature check against a stored public key.
		register_rest_route( $ns, '/passkeys/login/options', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'rest_login_options' ],
			'permission_callback' => '__return_true',
		] );
		register_rest_route( $ns, '/passkeys/login/verify', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'rest_login_verify' ],
			'permission_callback' => '__return_true',
		] );
	}

	/** Signed-in members manage their own passkeys. */
	public function can_manage() {
		return is_user_logged_in() && self::user_allowed( wp_get_current_user() );
	}

	public function rest_list() {
		$rows = PasskeyStore::for_user( get_current_user_id() );
		return rest_ensure_response( [
			'success'  => true,
			'passkeys' => array_map( [ PasskeyStore::class, 'present' ], $rows ),
		] );
	}

	/* --------------------------- Registration ------------------------- */

	public function rest_register_options() {
		$user = wp_get_current_user();
		if ( PasskeyStore::count_for_user( $user->ID ) >= PasskeyStore::MAX_PER_USER ) {
			return new \WP_Error( 'too_many', __( 'You have reached the passkey limit. Remove one to add another.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		$challenge = Webauthn::random_challenge();
		$token     = $this->store_challenge( $challenge, 'register', $user->ID );

		$exclude = [];
		foreach ( PasskeyStore::for_user( $user->ID ) as $row ) {
			$exclude[] = [ 'type' => 'public-key', 'id' => $row['credential_id'] ];
		}

		$usernameless = (bool) Helper::get_setting( 'passkeys_usernameless', true );

		return rest_ensure_response( [
			'success'   => true,
			'token'     => $token,
			'publicKey' => [
				'rp'                     => [
					'name' => wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ),
					'id'   => self::rp_id(),
				],
				'user'                   => [
					'id'          => Webauthn::b64u_encode( self::user_handle( $user->ID ) ),
					'name'        => $user->user_login,
					'displayName' => $user->display_name ? $user->display_name : $user->user_login,
				],
				'challenge'              => Webauthn::b64u_encode( $challenge ),
				'pubKeyCredParams'       => [
					[ 'type' => 'public-key', 'alg' => Webauthn::ALG_ES256 ],
					[ 'type' => 'public-key', 'alg' => Webauthn::ALG_RS256 ],
				],
				'timeout'                => 120000,
				'attestation'            => 'none',
				'excludeCredentials'     => $exclude,
				'authenticatorSelection' => [
					'residentKey'      => $usernameless ? 'required' : 'preferred',
					'userVerification' => 'required',
				],
			],
		] );
	}

	public function rest_register_verify( $request ) {
		$user  = wp_get_current_user();
		$state = $this->take_challenge( (string) $request->get_param( 'token' ), 'register', $user->ID );
		if ( ! $state ) {
			return new \WP_Error( 'expired', __( 'That request expired. Please try again.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		if ( PasskeyStore::count_for_user( $user->ID ) >= PasskeyStore::MAX_PER_USER ) {
			return new \WP_Error( 'too_many', __( 'You have reached the passkey limit. Remove one to add another.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		$client_data = Webauthn::b64u_decode( $request->get_param( 'clientDataJSON' ) );
		$attestation = Webauthn::b64u_decode( $request->get_param( 'attestationObject' ) );
		if ( false === $client_data || false === $attestation ) {
			return new \WP_Error( 'bad_request', __( 'The passkey response was malformed.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		try {
			$reg = Webauthn::verify_registration( $client_data, $attestation, $state['challenge'], self::origins(), self::rp_id(), true );
		} catch ( \RuntimeException $e ) {
			Logger::log( 'passkey_register_failed', 'Passkey registration was rejected: ' . $e->getMessage(), Logger::SEVERITY_WARNING, [ 'user_id' => $user->ID ] );
			return new \WP_Error( 'verify_failed', __( 'We could not verify that passkey. Please try again.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		$credential_id = Webauthn::b64u_encode( $reg['credential_id'] );
		if ( strlen( $credential_id ) > 191 || PasskeyStore::find_by_credential( $credential_id ) ) {
			return new \WP_Error( 'duplicate', __( 'This passkey is already registered.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		$transports = [];
		foreach ( (array) $request->get_param( 'transports' ) as $t ) {
			if ( is_string( $t ) && preg_match( '/^[a-z-]{2,20}$/', $t ) ) {
				$transports[] = $t;
			}
		}

		$name = sanitize_text_field( (string) $request->get_param( 'name' ) );
		if ( '' === $name ) {
			$name = PasskeyStore::provider_name( $reg['aaguid'] );
		}
		if ( '' === $name ) {
			/* translators: %s: date the passkey was added. */
			$name = sprintf( __( 'Passkey added %s', 'gemsecurity' ), wp_date( get_option( 'date_format' ) ) );
		}

		$id = PasskeyStore::insert( [
			'user_id'       => $user->ID,
			'credential_id' => $credential_id,
			'public_key'    => $reg['public_key_pem'],
			'alg'           => $reg['alg'],
			'sign_count'    => $reg['sign_count'],
			'aaguid'        => $reg['aaguid'],
			'device_type'   => $reg['backup_eligible'] ? 'multi_device' : 'single_device',
			'backed_up'     => $reg['backed_up'],
			'transports'    => substr( implode( ',', array_slice( $transports, 0, 6 ) ), 0, 100 ),
			'name'          => mb_substr( $name, 0, 100 ),
		] );
		if ( ! $id ) {
			return new \WP_Error( 'db', __( 'Could not save the passkey.', 'gemsecurity' ), [ 'status' => 500 ] );
		}

		Logger::log( 'passkey_registered', sprintf( '%s added a passkey.', $user->user_login ), Logger::SEVERITY_NOTICE, [ 'user_id' => $user->ID ] );

		return rest_ensure_response( [
			'success'  => true,
			'passkeys' => array_map( [ PasskeyStore::class, 'present' ], PasskeyStore::for_user( $user->ID ) ),
		] );
	}

	public function rest_rename( $request ) {
		$name = mb_substr( sanitize_text_field( (string) $request->get_param( 'name' ) ), 0, 100 );
		if ( '' === $name ) {
			return new \WP_Error( 'bad_name', __( 'Give the passkey a name.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		$uid = get_current_user_id();
		if ( ! PasskeyStore::find_owned( (int) $request['id'], $uid ) ) {
			return new \WP_Error( 'not_found', __( 'Passkey not found.', 'gemsecurity' ), [ 'status' => 404 ] );
		}
		PasskeyStore::rename( (int) $request['id'], $uid, $name );
		return $this->rest_list();
	}

	public function rest_delete( $request ) {
		$user = wp_get_current_user();
		if ( ! PasskeyStore::find_owned( (int) $request['id'], $user->ID ) ) {
			return new \WP_Error( 'not_found', __( 'Passkey not found.', 'gemsecurity' ), [ 'status' => 404 ] );
		}
		PasskeyStore::delete( (int) $request['id'], $user->ID );
		Logger::log( 'passkey_removed', sprintf( '%s removed a passkey.', $user->user_login ), Logger::SEVERITY_NOTICE, [ 'user_id' => $user->ID ] );
		return $this->rest_list();
	}

	/* ------------------------------ Sign-in --------------------------- */

	public function rest_login_options() {
		if ( $this->bump( 'opts', self::MAX_OPTIONS ) ) {
			return new \WP_Error( 'throttled', __( 'Too many attempts. Please wait a few minutes.', 'gemsecurity' ), [ 'status' => 429 ] );
		}
		$challenge = Webauthn::random_challenge();
		$token     = $this->store_challenge( $challenge, 'login', 0 );

		return rest_ensure_response( [
			'success'   => true,
			'token'     => $token,
			'publicKey' => [
				'challenge'        => Webauthn::b64u_encode( $challenge ),
				'rpId'             => self::rp_id(),
				'timeout'          => 120000,
				'userVerification' => 'required',
				'allowCredentials' => [],
			],
		] );
	}

	public function rest_login_verify( $request ) {
		$generic = new \WP_Error( 'passkey_failed', __( 'Passkey sign-in failed. Try again or use your password.', 'gemsecurity' ), [ 'status' => 401 ] );

		if ( $this->count( 'fail' ) >= self::MAX_FAILURES ) {
			return new \WP_Error( 'throttled', __( 'Too many attempts. Please wait a few minutes.', 'gemsecurity' ), [ 'status' => 429 ] );
		}

		$state = $this->take_challenge( (string) $request->get_param( 'token' ), 'login', 0 );
		if ( ! $state ) {
			return new \WP_Error( 'expired', __( 'That request expired. Please try again.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		$cred_id     = (string) $request->get_param( 'id' );
		$client_data = Webauthn::b64u_decode( $request->get_param( 'clientDataJSON' ) );
		$auth_data   = Webauthn::b64u_decode( $request->get_param( 'authenticatorData' ) );
		$signature   = Webauthn::b64u_decode( $request->get_param( 'signature' ) );
		$handle_raw  = (string) $request->get_param( 'userHandle' );
		$handle      = '' !== $handle_raw ? Webauthn::b64u_decode( $handle_raw ) : '';

		if ( false === $client_data || false === $auth_data || false === $signature || false === $handle || strlen( $cred_id ) > 191 ) {
			$this->bump( 'fail', self::MAX_FAILURES );
			return $generic;
		}

		$row  = PasskeyStore::find_by_credential( $cred_id );
		$user = $row ? get_userdata( (int) $row['user_id'] ) : false;
		if ( ! $row || ! $user ) {
			$this->bump( 'fail', self::MAX_FAILURES );
			Logger::log( 'passkey_login_failed', 'Passkey sign-in used an unknown credential.', Logger::SEVERITY_WARNING, [ 'user_id' => 0 ] );
			return $generic;
		}

		if ( '' !== $handle && ! hash_equals( self::user_handle( $user->ID ), $handle ) ) {
			$this->bump( 'fail', self::MAX_FAILURES );
			Logger::log( 'passkey_login_failed', sprintf( 'Passkey sign-in for "%s" presented the wrong user handle.', $user->user_login ), Logger::SEVERITY_WARNING, [ 'user_id' => $user->ID ] );
			return $generic;
		}

		try {
			$result = Webauthn::verify_assertion( $client_data, $auth_data, $signature, $row['public_key'], (int) $row['alg'], $state['challenge'], self::origins(), self::rp_id(), true );
		} catch ( \RuntimeException $e ) {
			$this->bump( 'fail', self::MAX_FAILURES );
			Logger::log( 'passkey_login_failed', sprintf( 'Passkey sign-in for "%s" was rejected: %s', $user->user_login, $e->getMessage() ), Logger::SEVERITY_WARNING, [ 'user_id' => $user->ID ] );
			return $generic;
		}

		// A counter that does not advance means the credential may have been
		// cloned. Authenticators that do not count (most synced passkeys)
		// report 0 every time, which is fine.
		$stored = (int) $row['sign_count'];
		if ( ( $stored > 0 || $result['sign_count'] > 0 ) && $result['sign_count'] <= $stored ) {
			$this->bump( 'fail', self::MAX_FAILURES );
			Logger::log( 'passkey_clone_suspected', sprintf( 'Passkey for "%s" reported a non-increasing signature counter; sign-in refused.', $user->user_login ), Logger::SEVERITY_CRITICAL, [ 'user_id' => $user->ID ] );
			return $generic;
		}

		if ( ! self::user_allowed( $user ) || is_wp_error( Helper::login_gate( $user ) ) ) {
			Logger::log( 'passkey_login_failed', sprintf( 'Passkey sign-in for "%s" was refused by policy.', $user->user_login ), Logger::SEVERITY_WARNING, [ 'user_id' => $user->ID ] );
			return $generic;
		}
		$check = apply_filters( 'wp_authenticate_user', $user, '' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
		if ( is_wp_error( $check ) ) {
			return $generic;
		}

		PasskeyStore::touch( $row['id'], $result['sign_count'], $result['backed_up'] );

		$remember = (bool) $request->get_param( 'remember' );
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, $remember );
		Logger::log( 'passkey_login', sprintf( '%s signed in with a passkey.', $user->user_login ), Logger::SEVERITY_NOTICE, [ 'user_id' => $user->ID ] );
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound

		$redirect = (string) $request->get_param( 'redirect_to' );
		$redirect = '' !== $redirect ? wp_validate_redirect( esc_url_raw( $redirect ), admin_url() ) : admin_url();
		$redirect = apply_filters( 'login_redirect', $redirect, $redirect, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound

		return rest_ensure_response( [
			'success'  => true,
			'redirect' => $redirect,
		] );
	}

	/* ------------------------- Challenge + limits --------------------- */

	private function store_challenge( $challenge, $purpose, $user_id ) {
		$token = wp_generate_password( 32, false, false );
		set_transient(
			self::CHALLENGE_PREFIX . $token,
			[
				// Raw random bytes do not survive a utf8 options table; keep text.
				'challenge' => Webauthn::b64u_encode( $challenge ),
				'purpose'   => $purpose,
				'user_id'   => (int) $user_id,
			],
			self::CHALLENGE_TTL
		);
		return $token;
	}

	/** Fetch and burn a challenge: each is good for one attempt. */
	private function take_challenge( $token, $purpose, $user_id ) {
		if ( ! preg_match( '/^[A-Za-z0-9]{32}$/', $token ) ) {
			return false;
		}
		$key   = self::CHALLENGE_PREFIX . $token;
		$state = get_transient( $key );
		delete_transient( $key );
		if ( ! is_array( $state ) || $state['purpose'] !== $purpose || (int) $state['user_id'] !== (int) $user_id ) {
			return false;
		}
		$raw = Webauthn::b64u_decode( $state['challenge'] );
		if ( false === $raw ) {
			return false;
		}
		$state['challenge'] = $raw;
		return $state;
	}

	private function limit_key( $what ) {
		return 'gemsec_pk_' . $what . '_' . md5( Helper::get_ip_address() );
	}

	private function count( $what ) {
		return (int) get_transient( $this->limit_key( $what ) );
	}

	/** Count one hit; returns true when the limit was already reached. */
	private function bump( $what, $max ) {
		$n = $this->count( $what );
		if ( $n >= $max ) {
			return true;
		}
		set_transient( $this->limit_key( $what ), $n + 1, self::LIMIT_WINDOW );
		return false;
	}

	/* ------------------------------ Front end ------------------------- */

	private function script_config() {
		return [
			'root'  => esc_url_raw( rest_url( \GemSecurity\Api::NAMESPACE . '/passkeys' ) ),
			'nonce' => wp_create_nonce( 'wp_rest' ),
			'i18n'  => [
				'unsupported' => __( 'This browser does not support passkeys.', 'gemsecurity' ),
				'cancelled'   => __( 'Passkey request was cancelled.', 'gemsecurity' ),
				'failed'      => __( 'Passkey sign-in failed. Try again or use your password.', 'gemsecurity' ),
				'added'       => __( 'Passkey added.', 'gemsecurity' ),
				'none'        => __( 'No passkeys yet.', 'gemsecurity' ),
				'rename'      => __( 'Rename', 'gemsecurity' ),
				'remove'      => __( 'Remove', 'gemsecurity' ),
				'confirm'     => __( 'Remove this passkey? You will no longer be able to sign in with it.', 'gemsecurity' ),
				'namePrompt'  => __( 'Name this passkey', 'gemsecurity' ),
				'synced'      => __( 'Synced', 'gemsecurity' ),
				'device'      => __( 'This device only', 'gemsecurity' ),
				'created'     => __( 'Added', 'gemsecurity' ),
				'lastUsed'    => __( 'Last used', 'gemsecurity' ),
				'never'       => __( 'never', 'gemsecurity' ),
			],
		];
	}

	private function enqueue_script( $handle_config ) {
		wp_enqueue_script(
			'gemsecurity-passkeys',
			GEMSECURITY_ASSETS_URI . 'passkeys/passkeys.js',
			[],
			GEMSECURITY_VERSION,
			true
		);
		wp_add_inline_script( 'gemsecurity-passkeys', 'window.gemsecPasskeys=' . wp_json_encode( array_merge( $this->script_config(), $handle_config ) ) . ';', 'before' );
	}

	public function login_assets() {
		// Only on the plain login form, not on lost-password/2FA/etc.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';
		if ( 'login' !== $action ) {
			return;
		}
		$this->enqueue_script( [ 'mode' => 'login' ] );
		wp_add_inline_style( 'login', '.gemsec-passkey{margin:0 0 16px}.gemsec-passkey button{width:100%;min-height:40px}.gemsec-passkey-msg{margin:8px 0 0;color:#b32d2e;font-size:13px}' );
	}

	public function render_login_button() {
		echo '<div class="gemsec-passkey" id="gemsec-passkey-login" hidden>';
		echo '<button type="button" class="button button-large" data-gemsec-passkey-login>' . esc_html__( 'Sign in with a passkey', 'gemsecurity' ) . '</button>';
		echo '<p class="gemsec-passkey-msg" role="alert" aria-live="polite"></p>';
		echo '</div>';
	}

	public function profile_assets( $hook ) {
		if ( 'profile.php' !== $hook || ! self::user_allowed( wp_get_current_user() ) ) {
			return;
		}
		$this->enqueue_script( [ 'mode' => 'profile' ] );
		wp_add_inline_style( 'common', '#gemsec-passkeys-profile ul{margin:0 0 12px;max-width:640px}#gemsec-passkeys-profile li{display:flex;gap:12px;align-items:center;justify-content:space-between;padding:10px 12px;border:1px solid #c3c4c7;background:#fff;margin:0 0 6px}#gemsec-passkeys-profile .meta{color:#646970;font-size:12px}#gemsec-passkeys-profile .msg{margin:6px 0 0}' );
	}

	public function render_profile( $user ) {
		if ( ! self::user_allowed( $user ) ) {
			return;
		}
		echo '<h2>' . esc_html__( 'Passkeys', 'gemsecurity' ) . '</h2>';
		echo '<table class="form-table" role="presentation"><tr><th>' . esc_html__( 'Sign in without a password', 'gemsecurity' ) . '</th><td>';
		echo '<div id="gemsec-passkeys-profile"><ul></ul>';
		echo '<button type="button" class="button" data-gemsec-passkey-add>' . esc_html__( 'Add a passkey', 'gemsecurity' ) . '</button>';
		echo '<p class="msg" role="status" aria-live="polite"></p>';
		echo '<p class="description">' . esc_html__( 'Use Face ID, Touch ID, Windows Hello, your phone, or a security key instead of typing a password. Passkeys are verified with your fingerprint, face or device PIN, so no second step is needed.', 'gemsecurity' ) . '</p>';
		echo '</div></td></tr></table>';
	}
}
