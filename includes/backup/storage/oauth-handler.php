<?php
namespace GemBackup\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * OAuth handshake for Google Drive, Dropbox, and OneDrive.
 *
 * Endpoints:
 *   GET /gembackup/v1/oauth/{provider}/start    -> returns auth URL
 *   GET /gembackup/v1/oauth/{provider}/callback -> exchanges code for tokens
 *   POST /gembackup/v1/oauth/{provider}/disconnect -> clears stored token
 */
class Oauth_Handler {

	const PROVIDERS = [
		'gdrive' => [
			'auth_url'  => 'https://accounts.google.com/o/oauth2/v2/auth',
			'token_url' => 'https://oauth2.googleapis.com/token',
			'scope'     => 'https://www.googleapis.com/auth/drive.file',
			'extra'     => [ 'access_type' => 'offline', 'prompt' => 'consent' ],
		],
		'dropbox' => [
			'auth_url'  => 'https://www.dropbox.com/oauth2/authorize',
			'token_url' => 'https://api.dropboxapi.com/oauth2/token',
			'scope'     => 'files.content.write files.content.read files.metadata.read account_info.read',
			'extra'     => [ 'token_access_type' => 'offline' ],
		],
		'onedrive' => [
			'auth_url'  => 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
			'token_url' => 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
			'scope'     => 'offline_access Files.ReadWrite',
			'extra'     => [],
		],
	];

	public static function init() {
		add_action( 'rest_api_init', [ __CLASS__, 'register_routes' ] );
	}

	public static function register_routes() {
		register_rest_route( 'gembackup/v1', '/oauth/(?P<provider>[a-z]+)/start', [
			'methods'             => 'GET',
			'callback'            => [ __CLASS__, 'start' ],
			'permission_callback' => function () { return current_user_can( 'manage_options' ); },
		] );

		// Callback is publicly accessible (provider hits it) — security via state token.
		register_rest_route( 'gembackup/v1', '/oauth/(?P<provider>[a-z]+)/callback', [
			'methods'             => 'GET',
			'callback'            => [ __CLASS__, 'callback' ],
			'permission_callback' => '__return_true',
		] );

		register_rest_route( 'gembackup/v1', '/oauth/(?P<provider>[a-z]+)/disconnect', [
			'methods'             => 'POST',
			'callback'            => [ __CLASS__, 'disconnect' ],
			'permission_callback' => function () { return current_user_can( 'manage_options' ); },
		] );
	}

	public static function start( $request ) {
		$provider = sanitize_key( $request['provider'] );
		if ( ! isset( self::PROVIDERS[ $provider ] ) ) {
			return new \WP_Error( 'gembackup_unknown_provider', 'Unknown provider', [ 'status' => 400 ] );
		}
		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		$client_id = $settings[ $provider . '_client_id' ] ?? '';
		if ( ! $client_id ) {
			return new \WP_Error( 'gembackup_no_client', 'OAuth client ID is not configured', [ 'status' => 400 ] );
		}

		$state = wp_generate_password( 32, false );
		set_transient( 'gembackup_oauth_' . $state, $provider, 10 * MINUTE_IN_SECONDS );

		$cfg = self::PROVIDERS[ $provider ];
		$params = array_merge( [
			'client_id'     => $client_id,
			'redirect_uri'  => self::redirect_uri( $provider ),
			'response_type' => 'code',
			'scope'         => $cfg['scope'],
			'state'         => $state,
		], $cfg['extra'] );

		return rest_ensure_response( [
			'url' => $cfg['auth_url'] . '?' . http_build_query( $params ),
		] );
	}

	public static function callback( $request ) {
		$provider = sanitize_key( $request['provider'] );
		$code     = $request->get_param( 'code' );
		$state    = $request->get_param( 'state' );

		$stored = get_transient( 'gembackup_oauth_' . $state );
		delete_transient( 'gembackup_oauth_' . $state );
		if ( $stored !== $provider || ! $code ) {
			return new \WP_Error( 'gembackup_invalid_state', 'Invalid OAuth state', [ 'status' => 400 ] );
		}

		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		$cfg = self::PROVIDERS[ $provider ];

		$response = wp_remote_post( $cfg['token_url'], [
			'body' => [
				'code'          => $code,
				'client_id'     => $settings[ $provider . '_client_id' ] ?? '',
				'client_secret' => $settings[ $provider . '_client_secret' ] ?? '',
				'redirect_uri'  => self::redirect_uri( $provider ),
				'grant_type'    => 'authorization_code',
			],
			'timeout' => 20,
		] );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['access_token'] ) ) {
			return new \WP_Error( 'gembackup_token_exchange', 'Token exchange failed: ' . wp_remote_retrieve_body( $response ), [ 'status' => 400 ] );
		}

		// Store the tokens.
		if ( ! empty( $body['refresh_token'] ) ) {
			$settings[ $provider . '_refresh_token' ] = $body['refresh_token'];
		}
		update_option( GEMBACKUP_SETTINGS_NAME, $settings );

		$ttl = (int) ( $body['expires_in'] ?? 3600 ) - 60;
		set_transient( 'gembackup_' . $provider . '_token', $body['access_token'], $ttl );

		// Redirect back to the GemBackup Storage page with success indicator.
		wp_safe_redirect( admin_url( 'admin.php?page=gembackup-storage&oauth=' . $provider . '&status=success' ) );
		exit;
	}

	public static function disconnect( $request ) {
		$provider = sanitize_key( $request['provider'] );
		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		unset( $settings[ $provider . '_refresh_token' ] );
		update_option( GEMBACKUP_SETTINGS_NAME, $settings );
		delete_transient( 'gembackup_' . $provider . '_token' );
		return rest_ensure_response( [ 'disconnected' => true ] );
	}

	private static function redirect_uri( $provider ) {
		return rest_url( 'gembackup/v1/oauth/' . $provider . '/callback' );
	}
}
