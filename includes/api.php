<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * REST API bootstrap. Registers every plugin route under gemsecurity/v1 and
 * delegates handling to the controllers in includes/rest/.
 */
class Api {

	const NAMESPACE = 'gemsecurity/v1';

	public static function init() {
		$self = new self();
		add_action( 'rest_api_init', [ $self, 'register_routes' ] );
	}

	/**
	 * Shared capability gate for every route.
	 *
	 * @return bool
	 */
	public static function permission() {
		return current_user_can( 'manage_options' );
	}

	public function register_routes() {
		$ns   = self::NAMESPACE;
		$perm = [ __CLASS__, 'permission' ];

		// Settings.
		register_rest_route( $ns, '/settings', [
			[
				'methods'             => 'GET',
				'callback'            => [ Rest\Settings::class, 'get' ],
				'permission_callback' => $perm,
			],
			[
				'methods'             => 'POST',
				'callback'            => [ Rest\Settings::class, 'save' ],
				'permission_callback' => $perm,
			],
		] );

		// Settings export / import.
		register_rest_route( $ns, '/settings/export', [
			'methods'             => 'GET',
			'callback'            => [ Rest\Settings::class, 'export' ],
			'permission_callback' => $perm,
		] );
		register_rest_route( $ns, '/settings/import', [
			'methods'             => 'POST',
			'callback'            => [ Rest\Settings::class, 'import' ],
			'permission_callback' => $perm,
		] );

		// Dashboard overview.
		register_rest_route( $ns, '/dashboard', [
			'methods'             => 'GET',
			'callback'            => [ Rest\Dashboard::class, 'get' ],
			'permission_callback' => $perm,
		] );

		// Logs.
		register_rest_route( $ns, '/logs', [
			[
				'methods'             => 'GET',
				'callback'            => [ Rest\Logs::class, 'get' ],
				'permission_callback' => $perm,
			],
			[
				'methods'             => 'DELETE',
				'callback'            => [ Rest\Logs::class, 'clear' ],
				'permission_callback' => $perm,
			],
		] );
		register_rest_route( $ns, '/logs/export', [
			'methods'             => 'GET',
			'callback'            => [ Rest\Logs::class, 'export' ],
			'permission_callback' => $perm,
		] );

		// Bot stats.
		register_rest_route( $ns, '/bots/stats', [
			'methods'             => 'GET',
			'callback'            => [ Rest\Bots::class, 'stats' ],
			'permission_callback' => $perm,
		] );

		// Add pattern to bot blocklist.
		register_rest_route( $ns, '/bots/blocklist', [
			'methods'             => 'POST',
			'callback'            => [ Rest\Bots::class, 'add_to_blocklist' ],
			'permission_callback' => $perm,
		] );

		// Administrators (whitelist management UI).
		register_rest_route( $ns, '/admins', [
			'methods'             => 'GET',
			'callback'            => [ Rest\Admins::class, 'get' ],
			'permission_callback' => $perm,
		] );

		// Scanner.
		register_rest_route( $ns, '/scan', [
			[
				'methods'             => 'GET',
				'callback'            => [ Rest\Scanner::class, 'last' ],
				'permission_callback' => $perm,
			],
			[
				'methods'             => 'POST',
				'callback'            => [ Rest\Scanner::class, 'run' ],
				'permission_callback' => $perm,
			],
		] );

		// Two-factor (current user enrollment).
		register_rest_route( $ns, '/2fa', [
			'methods'             => 'GET',
			'callback'            => [ Rest\TwoFactor::class, 'status' ],
			'permission_callback' => $perm,
		] );
		register_rest_route( $ns, '/2fa/setup', [
			'methods'             => 'POST',
			'callback'            => [ Rest\TwoFactor::class, 'setup' ],
			'permission_callback' => $perm,
		] );
		register_rest_route( $ns, '/2fa/activate', [
			'methods'             => 'POST',
			'callback'            => [ Rest\TwoFactor::class, 'activate' ],
			'permission_callback' => $perm,
		] );
		register_rest_route( $ns, '/2fa/enable-email', [
			'methods'             => 'POST',
			'callback'            => [ Rest\TwoFactor::class, 'enable_email' ],
			'permission_callback' => $perm,
		] );
		register_rest_route( $ns, '/2fa/disable', [
			'methods'             => 'POST',
			'callback'            => [ Rest\TwoFactor::class, 'disable' ],
			'permission_callback' => $perm,
		] );
		register_rest_route( $ns, '/2fa/backup-codes', [
			'methods'             => 'POST',
			'callback'            => [ Rest\TwoFactor::class, 'backup_codes' ],
			'permission_callback' => $perm,
		] );

		// Social login config (provider list + redirect URI).
		register_rest_route( $ns, '/social', [
			'methods'             => 'GET',
			'callback'            => [ Rest\Social::class, 'config' ],
			'permission_callback' => $perm,
		] );

		// Sessions.
		register_rest_route( $ns, '/sessions', [
			'methods'             => 'GET',
			'callback'            => [ Rest\Sessions::class, 'get' ],
			'permission_callback' => $perm,
		] );
		register_rest_route( $ns, '/sessions/revoke-others', [
			'methods'             => 'POST',
			'callback'            => [ Rest\Sessions::class, 'revoke_others' ],
			'permission_callback' => $perm,
		] );
		register_rest_route( $ns, '/sessions/force-logout', [
			'methods'             => 'POST',
			'callback'            => [ Rest\Sessions::class, 'force_logout' ],
			'permission_callback' => $perm,
		] );

		// Banned IPs.
		register_rest_route( $ns, '/bans', [
			[
				'methods'             => 'GET',
				'callback'            => [ Rest\Bans::class, 'get' ],
				'permission_callback' => $perm,
			],
			[
				'methods'             => 'POST',
				'callback'            => [ Rest\Bans::class, 'add' ],
				'permission_callback' => $perm,
			],
			[
				'methods'             => 'DELETE',
				'callback'            => [ Rest\Bans::class, 'remove' ],
				'permission_callback' => $perm,
			],
		] );

		// Geolocation.
		register_rest_route( $ns, '/geo/test', [
			'methods'             => 'GET',
			'callback'            => [ Rest\Geolocation::class, 'test' ],
			'permission_callback' => $perm,
		] );
		register_rest_route( $ns, '/geo/users', [
			'methods'             => 'GET',
			'callback'            => [ Rest\Geolocation::class, 'users' ],
			'permission_callback' => $perm,
		] );
		register_rest_route( $ns, '/geo/user', [
			'methods'             => 'POST',
			'callback'            => [ Rest\Geolocation::class, 'set_user' ],
			'permission_callback' => $perm,
		] );
	}
}
