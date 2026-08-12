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

	/**
	 * Capability gate for Pro-only routes: manage_options AND Pro active.
	 * Returns a 403 with a machine code the UI can detect.
	 *
	 * @return bool|\WP_Error
	 */
	public static function pro_permission() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return false;
		}
		if ( ! Helper::is_pro_active() ) {
			return new \WP_Error(
				'gemsecurity_pro_required',
				__( 'This feature requires GemSecurity Pro.', 'gemsecurity' ),
				[ 'status' => 403 ]
			);
		}
		return true;
	}

	/**
	 * Whether the module that owns a REST group is currently active. Used to
	 * skip registering routes for deactivated modules.
	 *
	 * @param string $module_id
	 * @return bool
	 */
	private static function module( $module_id ) {
		return Modules\Registry::is_active( $module_id );
	}

	public function register_routes() {
		$ns       = self::NAMESPACE;
		$perm     = [ __CLASS__, 'permission' ];
		$pro_perm = [ __CLASS__, 'pro_permission' ];

		/* -------------------------------------------------------------- */
		/* Core groups — always registered (Dashboard, Modules, Logs,     */
		/* Settings and the global finder are core modules).              */
		/* -------------------------------------------------------------- */

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

		// Module activation manager.
		register_rest_route( $ns, '/modules', [
			[
				'methods'             => 'GET',
				'callback'            => [ Rest\Modules::class, 'get' ],
				'permission_callback' => $perm,
			],
			[
				'methods'             => 'POST',
				'callback'            => [ Rest\Modules::class, 'save' ],
				'permission_callback' => $perm,
			],
		] );

		// Dashboard overview.
		register_rest_route( $ns, '/dashboard', [
			'methods'             => 'GET',
			'callback'            => [ Rest\Dashboard::class, 'get' ],
			'permission_callback' => $perm,
		] );

		// Logs (core "logs" module).
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

		// Code & database finder ("grep from the dashboard") — global tool.
		register_rest_route( $ns, '/search', [
			'methods'             => 'POST',
			'callback'            => [ Rest\Finder::class, 'search' ],
			'permission_callback' => $perm,
		] );

		/* -------------------------------------------------------------- */
		/* Module-owned groups — registered only when their module is on. */
		/* -------------------------------------------------------------- */

		// Threat Defense (Pro): bans ledger + bot stats/blocklist.
		if ( self::module( 'threats' ) ) {
			register_rest_route( $ns, '/bans', [
				[
					'methods'             => 'GET',
					'callback'            => [ Rest\Bans::class, 'get' ],
					'permission_callback' => $perm,
				],
				[
					'methods'             => 'POST',
					'callback'            => [ Rest\Bans::class, 'add' ],
					'permission_callback' => $pro_perm,
				],
				[
					'methods'             => 'DELETE',
					'callback'            => [ Rest\Bans::class, 'remove' ],
					'permission_callback' => $pro_perm,
				],
			] );
			register_rest_route( $ns, '/bots/stats', [
				'methods'             => 'GET',
				'callback'            => [ Rest\Bots::class, 'stats' ],
				'permission_callback' => $pro_perm,
			] );
			register_rest_route( $ns, '/bots/blocklist', [
				'methods'             => 'POST',
				'callback'            => [ Rest\Bots::class, 'add_to_blocklist' ],
				'permission_callback' => $pro_perm,
			] );
		}

		// Admin Guard: administrator whitelist + hidden-admin detection.
		if ( self::module( 'admin-guard' ) ) {
			register_rest_route( $ns, '/admins', [
				'methods'             => 'GET',
				'callback'            => [ Rest\Admins::class, 'get' ],
				'permission_callback' => $perm,
			] );
			register_rest_route( $ns, '/admins/remove', [
				'methods'             => 'POST',
				'callback'            => [ Rest\Admins::class, 'remove' ],
				'permission_callback' => $perm,
			] );
		}

		// Scanner: integrity/malware scan, baseline, MU-plugin inventory.
		if ( self::module( 'scanner' ) ) {
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
			register_rest_route( $ns, '/scan/baseline', [
				'methods'             => 'POST',
				'callback'            => [ Rest\Scanner::class, 'reset_baseline' ],
				'permission_callback' => $perm,
			] );
			register_rest_route( $ns, '/mu-plugins', [
				'methods'             => 'GET',
				'callback'            => [ Rest\MuPlugins::class, 'get' ],
				'permission_callback' => $perm,
			] );
		}

		// Two-Factor (current-user enrollment) + login CAPTCHA module.
		if ( self::module( 'two-factor' ) ) {
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
		}

		// Social login config (provider list + redirect URI).
		if ( self::module( 'social-login' ) ) {
			register_rest_route( $ns, '/social', [
				'methods'             => 'GET',
				'callback'            => [ Rest\Social::class, 'config' ],
				'permission_callback' => $perm,
			] );
		}

		// Sessions (Login Security module).
		if ( self::module( 'login-security' ) ) {
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
		}

		// Geolocation (Pro).
		if ( self::module( 'geolocation' ) ) {
			register_rest_route( $ns, '/geo/test', [
				'methods'             => 'GET',
				'callback'            => [ Rest\Geolocation::class, 'test' ],
				'permission_callback' => $pro_perm,
			] );
			register_rest_route( $ns, '/geo/users', [
				'methods'             => 'GET',
				'callback'            => [ Rest\Geolocation::class, 'users' ],
				'permission_callback' => $pro_perm,
			] );
			register_rest_route( $ns, '/geo/user', [
				'methods'             => 'POST',
				'callback'            => [ Rest\Geolocation::class, 'set_user' ],
				'permission_callback' => $pro_perm,
			] );
		}

		/**
		 * Let the Pro addon (or any extension) register its own routes under
		 * the same namespace without re-hooking rest_api_init.
		 *
		 * @param string $ns Namespace, e.g. "gemsecurity/v1".
		 */
		do_action( 'gemsecurity/register_rest_routes', $ns );
	}
}
