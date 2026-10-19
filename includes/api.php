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

		// Daily report: preview the morning letter or send it on demand.
		register_rest_route( $ns, '/reports/daily', [
			[
				'methods'             => 'GET',
				'callback'            => static function () {
					$data = Modules\DailyReport::collect();
					return rest_ensure_response( [
						'success'      => true,
						'admins'       => count( $data['admins'] ),
						'plugins'      => count( $data['plugins'] ),
						'new_plugins'  => count( $data['new_plugins'] ),
						'new_admins'   => count( $data['new_admins'] ),
						'first_run'    => $data['first_run'],
						'next_run'     => wp_next_scheduled( Modules\DailyReport::CRON_HOOK ),
					] );
				},
				'permission_callback' => $perm,
			],
			[
				'methods'             => 'POST',
				'callback'            => static function () {
					// force: send even while the schedule is off, and leave the
					// "since yesterday" baseline untouched.
					$sent = Modules\DailyReport::send( true );
					return rest_ensure_response( [
						'success' => (bool) $sent,
						'message' => $sent
							? __( 'Report sent.', 'gemsecurity' )
							: __( 'WordPress could not send the email — check the site’s mail setup.', 'gemsecurity' ),
					] );
				},
				'permission_callback' => $perm,
			],
		] );

		// Forced password resets: preview the scope, force it, or clear it.
		register_rest_route( $ns, '/passwords/rotate', [
			[
				'methods'             => 'GET',
				'callback'            => static function ( $req ) {
					$roles = array_filter( array_map( 'sanitize_key', (array) $req->get_param( 'roles' ) ) );
					return rest_ensure_response( [
						'success' => true,
						'targets' => count( Modules\PasswordRotation::targets( [
							'roles'            => $roles,
							'exclude_user_ids' => $req->get_param( 'include_self' ) ? [] : [ get_current_user_id() ],
						] ) ),
						'pending' => Modules\PasswordRotation::pending_count(),
					] );
				},
				'permission_callback' => $perm,
			],
			[
				'methods'             => 'POST',
				'callback'            => static function ( $req ) {
					if ( 'clear' === $req->get_param( 'action' ) ) {
						return rest_ensure_response( [
							'success' => true,
							'cleared' => Modules\PasswordRotation::clear_all(),
							'pending' => Modules\PasswordRotation::pending_count(),
						] );
					}

					$roles = array_filter( array_map( 'sanitize_key', (array) $req->get_param( 'roles' ) ) );
					// The administrator running this is excluded unless they opt
					// in, so a site-wide reset cannot lock its operator out
					// mid-incident.
					$result = Modules\PasswordRotation::force_reset( [
						'roles'            => $roles,
						'exclude_user_ids' => $req->get_param( 'include_self' ) ? [] : [ get_current_user_id() ],
						'notify'           => (bool) $req->get_param( 'notify' ),
						'reason'           => 'manual',
					] );

					return rest_ensure_response( [ 'success' => true, 'pending' => Modules\PasswordRotation::pending_count() ] + $result );
				},
				'permission_callback' => $perm,
			],
		] );

		// Files a person has reviewed and marked safe, so the scanners stop
		// reporting them.
		register_rest_route( $ns, '/safe-files', [
			[
				'methods'             => 'GET',
				'callback'            => static function () {
					return rest_ensure_response( [ 'success' => true, 'files' => Security\SafeFiles::for_js() ] );
				},
				'permission_callback' => $perm,
			],
			[
				'methods'             => 'POST',
				'callback'            => static function ( $req ) {
					$path = (string) $req->get_param( 'path' );
					// Accept either an absolute path or one relative to the
					// install, since findings carry both.
					$abs = ( 0 === strpos( wp_normalize_path( $path ), wp_normalize_path( ABSPATH ) ) )
						? $path
						: ABSPATH . ltrim( $path, '/' );

					$res = Security\SafeFiles::mark( $abs );
					if ( is_wp_error( $res ) ) {
						return $res;
					}
					return rest_ensure_response( [ 'success' => true, 'entry' => $res, 'files' => Security\SafeFiles::for_js() ] );
				},
				'permission_callback' => $perm,
			],
			[
				'methods'             => 'DELETE',
				'callback'            => static function ( $req ) {
					Security\SafeFiles::unmark( (string) $req->get_param( 'path' ) );
					return rest_ensure_response( [ 'success' => true, 'files' => Security\SafeFiles::for_js() ] );
				},
				'permission_callback' => $perm,
			],
		] );

		// Credential tester — check third-party keys against the real provider
		// before a typo reaches the login form. Core: the fields it tests live
		// across several modules.
		register_rest_route( $ns, '/credentials/test', [
			'methods'             => 'POST',
			'callback'            => [ Rest\Credentials::class, 'test' ],
			'permission_callback' => $perm,
		] );

		// In-product documentation for the help drawer, keyed by page slug.
		register_rest_route( $ns, '/docs', [
			'methods'             => 'GET',
			'callback'            => static function () {
				return rest_ensure_response( [
					'success' => true,
					'docs'    => Modules\Docs::for_js(),
					'guides'  => Modules\Docs::guides(),
				] );
			},
			'permission_callback' => $perm,
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
		// Compliance: tamper-evident chain verification + summary report.
		register_rest_route( $ns, '/logs/verify', [
			'methods'             => 'GET',
			'callback'            => static function () {
				return rest_ensure_response( [ 'success' => true ] + Modules\Compliance::verify() );
			},
			'permission_callback' => $perm,
		] );
		register_rest_route( $ns, '/logs/report', [
			'methods'             => 'GET',
			'callback'            => static function ( $req ) {
				return rest_ensure_response( [ 'success' => true, 'report' => Modules\Compliance::report( (int) $req->get_param( 'days' ) ?: 30, sanitize_key( (string) $req->get_param( 'framework' ) ) ?: 'general' ) ] );
			},
			'permission_callback' => $perm,
		] );

		// Code & database finder ("grep from the dashboard") — global tool.
		register_rest_route( $ns, '/search', [
			'methods'             => 'POST',
			'callback'            => [ Rest\Finder::class, 'search' ],
			'permission_callback' => $perm,
		] );

		// CSP violation collector — public (browsers post here directly).
		register_rest_route( $ns, '/csp-report', [
			'methods'             => 'POST',
			'callback'            => [ Rest\Firewall::class, 'csp_report' ],
			'permission_callback' => '__return_true',
		] );
		register_rest_route( $ns, '/csp-violations', [
			'methods'             => 'GET',
			'callback'            => [ Rest\Firewall::class, 'csp_violations' ],
			'permission_callback' => $perm,
		] );
		register_rest_route( $ns, '/file-permissions', [
			'methods'             => 'GET',
			'callback'            => [ Rest\Firewall::class, 'file_permissions' ],
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
			register_rest_route( $ns, '/live-traffic', [
				'methods'             => 'GET',
				'callback'            => [ Modules\ThreatIntel::class, 'rest_traffic' ],
				'permission_callback' => $pro_perm,
			] );
		}

		// Plugin Guard: .org verification, trust list and enforcement.
		if ( self::module( 'plugin-guard' ) ) {
			register_rest_route( $ns, '/plugin-guard', [
				'methods'             => 'GET',
				'callback'            => [ Rest\PluginGuard::class, 'get' ],
				'permission_callback' => $perm,
			] );
			foreach ( [ 'verify', 'enable', 'trust', 'untrust', 'restore', 'lock', 'unlock', 'shield', 'probe' ] as $action ) {
				register_rest_route( $ns, '/plugin-guard/' . $action, [
					'methods'             => 'POST',
					'callback'            => [ Rest\PluginGuard::class, $action ],
					'permission_callback' => $perm,
				] );
			}
		}

		// Virtual patching (Pro) — CVEs currently mitigated on this site.
		if ( self::module( 'virtual-patch' ) ) {
			register_rest_route( $ns, '/vpatch', [
				'methods'             => 'GET',
				'callback'            => [ Rest\Vpatch::class, 'get' ],
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
			// Sweep every existing administrator against the whitelist. GET
			// previews (dry run), POST carries it out.
			register_rest_route( $ns, '/admins/sweep', [
				[
					'methods'             => 'GET',
					'callback'            => [ Rest\Admins::class, 'preview_sweep' ],
					'permission_callback' => $perm,
				],
				[
					'methods'             => 'POST',
					'callback'            => [ Rest\Admins::class, 'sweep' ],
					'permission_callback' => $perm,
				],
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
			register_rest_route( $ns, '/scan/quarantine', [
				'methods'             => 'POST',
				'callback'            => [ Rest\Scanner::class, 'quarantine' ],
				'permission_callback' => $perm,
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
			register_rest_route( $ns, '/supply-chain', [
				'methods'             => 'GET',
				'callback'            => [ Modules\SupplyChain::class, 'rest' ],
				'permission_callback' => $perm,
			] );
		}

		// Payment-page script integrity (Pro). The collector is public (browsers
		// on the checkout page post here); reads/authorise are admin-gated.
		register_rest_route( $ns, '/payment-scripts', [
			[
				'methods'             => 'POST',
				'callback'            => [ Rest\PaymentScripts::class, 'ingest' ],
				'permission_callback' => '__return_true',
			],
			[
				'methods'             => 'GET',
				'callback'            => [ Rest\PaymentScripts::class, 'get' ],
				'permission_callback' => $pro_perm,
			],
		] );
		if ( self::module( 'payment-integrity' ) ) {
			register_rest_route( $ns, '/payment-scripts/authorize', [
				'methods'             => 'POST',
				'callback'            => [ Rest\PaymentScripts::class, 'authorize' ],
				'permission_callback' => $pro_perm,
			] );
		}

		// Incident response (Pro): timeline, quarantine, recovery.
		if ( self::module( 'incident-response' ) ) {
			register_rest_route( $ns, '/incident/timeline', [
				'methods'             => 'GET',
				'callback'            => [ Modules\IncidentResponse::class, 'rest_timeline' ],
				'permission_callback' => $pro_perm,
			] );
			register_rest_route( $ns, '/incident/quarantine', [
				[
					'methods'             => 'GET',
					'callback'            => [ Modules\IncidentResponse::class, 'rest_quarantine_list' ],
					'permission_callback' => $pro_perm,
				],
				[
					'methods'             => 'POST',
					'callback'            => [ Modules\IncidentResponse::class, 'rest_quarantine' ],
					'permission_callback' => $pro_perm,
				],
			] );
			register_rest_route( $ns, '/incident/restore', [
				'methods'             => 'POST',
				'callback'            => [ Modules\IncidentResponse::class, 'rest_restore' ],
				'permission_callback' => $pro_perm,
			] );
			register_rest_route( $ns, '/incident/recover', [
				'methods'             => 'POST',
				'callback'            => [ Modules\IncidentResponse::class, 'rest_recover' ],
				'permission_callback' => $pro_perm,
			] );
		}

		// Two-Factor (current-user enrollment).
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

		// Application-password governance (API & Access module).
		if ( self::module( 'api-hardening' ) ) {
			register_rest_route( $ns, '/app-passwords', [
				'methods'             => 'GET',
				'callback'            => [ Rest\AppPasswords::class, 'get' ],
				'permission_callback' => $perm,
			] );
			register_rest_route( $ns, '/app-passwords/revoke', [
				'methods'             => 'POST',
				'callback'            => [ Rest\AppPasswords::class, 'revoke' ],
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
			// Magic-link recovery (Pro) — issue a one-time login link for a user.
			register_rest_route( $ns, '/magic-link', [
				'methods'             => 'POST',
				'callback'            => [ Rest\MagicLink::class, 'issue' ],
				'permission_callback' => $pro_perm,
			] );
		}

		// Monitoring (Pro).
		if ( self::module( 'monitoring' ) ) {
			register_rest_route( $ns, '/monitoring', [
				'methods'             => 'GET',
				'callback'            => [ Modules\Monitoring::class, 'rest' ],
				'permission_callback' => $pro_perm,
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
