<?php

/**
 * Class SE_License_SDK_Rest_API
 */
final class SE_License_SDK_Rest_API {

	/**
	 * Namespace for the REST API.
	 */
	const NAMESPACE = 'storeengine-sdk/v1';

	/**
	 * @var SE_License_SDK_Client
	 */
	private $client;

	/**
	 * SE_License_SDK_Rest_API constructor.
	 *
	 * @param SE_License_SDK_Client $client The SDK client.
	 */
	public function __construct( SE_License_SDK_Client $client ) {
		$this->client = &$client;
	}

	/**
	 * Initialize the REST API.
	 *
	 * @return void
	 */
	public function init() {
		add_action( 'rest_api_init', [ $this, 'register_routes' ] );
	}

	/**
	 * Register the REST API routes for this client.
	 *
	 * @return void
	 */
	public function register_routes() {
		$slug = $this->client->getSlug();

		register_rest_route( self::NAMESPACE, '/' . $slug . '/license/activate', [
			'methods'             => WP_REST_Server::CREATABLE,
			'callback'            => [ $this, 'activate_license' ],
			'permission_callback' => [ $this, 'permissions_check' ],
			'args'                => [
				'license' => [
					'required'          => true,
					'type'              => 'string',
					'sanitize_callback' => 'sanitize_text_field',
				],
			],
		] );

		register_rest_route( self::NAMESPACE, '/' . $slug . '/license/deactivate', [
			'methods'             => WP_REST_Server::CREATABLE,
			'callback'            => [ $this, 'deactivate_license' ],
			'permission_callback' => [ $this, 'permissions_check' ],
		] );

		register_rest_route( self::NAMESPACE, '/' . $slug . '/license/status', [
			'methods'             => WP_REST_Server::READABLE,
			'callback'            => [ $this, 'check_license_status' ],
			'permission_callback' => [ $this, 'permissions_check' ],
			'args'                => [
				'force' => [ 'type' => 'boolean', 'default' => false ],
			],
		] );

		if ( $this->client->maybe_init_update() ) {
			register_rest_route( self::NAMESPACE, '/' . $slug . '/package-info', [
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => [ $this, 'get_package_info' ],
				'permission_callback' => [ $this, 'permissions_check' ],
				'args'                => [
					'force' => [ 'type' => 'boolean', 'default' => false ],
				],
			] );

			register_rest_route( self::NAMESPACE, '/' . $slug . '/updates/status', [
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => [ $this, 'updates_status' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			] );

			register_rest_route( self::NAMESPACE, '/' . $slug . '/updates/check-now', [
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => [ $this, 'updates_check_now' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			] );

			register_rest_route( self::NAMESPACE, '/' . $slug . '/updates/versions', [
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => [ $this, 'updates_versions' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			] );

			register_rest_route( self::NAMESPACE, '/' . $slug . '/updates/install', [
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => [ $this, 'updates_install' ],
				'permission_callback' => [ $this, 'permissions_check' ],
				'args'                => [
					'version' => [
						'type'              => 'string',
						'required'          => false, // null means "latest"
						'sanitize_callback' => 'sanitize_text_field',
					],
				],
			] );

			register_rest_route( self::NAMESPACE, '/' . $slug . '/updates/rollback', [
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => [ $this, 'updates_rollback' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			] );

			register_rest_route( self::NAMESPACE, '/' . $slug . '/settings/beta-channel', [
				[
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => [ $this, 'get_beta_channel' ],
					'permission_callback' => [ $this, 'permissions_check' ],
				],
				[
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => [ $this, 'set_beta_channel' ],
					'permission_callback' => [ $this, 'permissions_check' ],
					'args'                => [
						'enabled' => [ 'type' => 'boolean', 'required' => true ],
					],
				],
			] );

			register_rest_route( self::NAMESPACE, '/' . $slug . '/settings/auto-update-window', [
				[
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => [ $this, 'get_auto_update_window' ],
					'permission_callback' => [ $this, 'permissions_check' ],
				],
				[
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => [ $this, 'set_auto_update_window' ],
					'permission_callback' => [ $this, 'permissions_check' ],
					'args'                => [
						'window' => [
							'type'              => [ 'string', 'null' ],
							'sanitize_callback' => 'sanitize_text_field',
						],
					],
				],
			] );
		}

		register_rest_route( self::NAMESPACE, '/' . $slug . '/insights/optin', [
			'methods'             => WP_REST_Server::ALLMETHODS,
			'callback'            => [ $this, 'handle_insights_optin' ],
			'permission_callback' => [ $this, 'permissions_check' ],
			'args'                => [
				'opt_in' => [ 'type' => 'boolean' ],
			],
		] );
	}

	/**
	 * Check if the user has permission to manage licenses.
	 *
	 * @return bool|WP_Error
	 */
	public function permissions_check() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'rest_forbidden', __( 'You do not have permission to manage licenses.', 'storeengine-sdk' ), [ 'status' => 403 ] );
		}

		return true;
	}

	/**
	 * Callback for activating a license.
	 *
	 * @param WP_REST_Request $request The request object.
	 *
	 * @return WP_REST_Response|WP_Error
	 */
	public function activate_license( WP_REST_Request $request ) {
		$license = $request->get_param( 'license' );

		$this->client->license()->activate_client_license( [ 'license_key' => $license ] );

		if ( $this->client->license()->get_error() ) {
			return new WP_Error( 'error-activating-license', $this->client->license()->get_error(), [ 'status' => 400 ] );
		}


		return rest_ensure_response( [
			'success' => true,
			'message' => $this->client->license()->get_success(),
			'license' => $this->client->license()->get_public_data(),
		] );
	}

	/**
	 * Callback for deactivating a license.
	 *
	 * @param WP_REST_Request $request The request object.
	 *
	 * @return WP_REST_Response|WP_Error
	 */
	public function deactivate_license() {
		$this->client->license()->deactivate_client_license();

		if ( $this->client->license()->get_error() ) {
			return new WP_Error( 'error-deactivating-license', $this->client->license()->get_error(), [ 'status' => 400 ] );
		}

		return rest_ensure_response( [
			'success' => true,
			'message' => __( 'License deactivated successfully.', 'storeengine-sdk' ),
			'license' => $this->client->license()->get_public_data(),
		] );
	}

	/**
	 * Callback for checking license status.
	 *
	 * @param WP_REST_Request $request The request object.
	 *
	 * @return WP_REST_Response|WP_Error
	 */
	public function check_license_status( WP_REST_Request $request ) {
		if ( $request->get_param( 'force' ) ) {
			$this->client->license()->check_license_status();

			if ( $this->client->license()->get_error() ) {
				return new WP_Error( 'error-checking-license-status', $this->client->license()->get_error(), [ 'status' => 400 ] );
			}
		}

		return rest_ensure_response( $this->client->license()->get_public_data() );
	}

	public function get_package_info( WP_REST_Request $request ) {
		$force = $request->get_param( 'force' );

		if ( 'plugin' === $this->client->getType() ) {
			$update = $this->client->updater()->plugins_api_filter(
				false, 'plugin_information',
				(object) [
					'slug'  => $this->client->getSlug(),
					'force' => $force
				]
			);
		} else {
			$update = $this->client->updater()->themes_api_filter(
				false, 'theme_information',
				(object) [
					'slug'  => $this->client->getSlug(),
					'force' => $force
				]
			);
		}

		return rest_ensure_response( $update );
	}

	/**
	 * GET /updates/status — current state for the React panel hero.
	 */
	public function updates_status() {
		$state    = $this->client->update_state()->all();
		$update   = $this->get_cached_update();
		$current  = $this->client->getProjectVersion();
		$latest   = $update && ! empty( $update->new_version ) ? $update->new_version : $current;
		$available = $latest && version_compare( $current, $latest, '<' );

		return rest_ensure_response( [
			'current_version'      => $current,
			'latest_version'       => $latest,
			'update_available'     => $available,
			'last_checked_at'      => $state['last_checked_at'],
			'previous_version'     => $state['previous_version'],
			'last_install'         => [
				'at'          => $state['last_install_at'],
				'status'      => $state['last_install_status'],
				'target'      => $state['last_install_target'],
				'is_rollback' => $state['last_install_is_rollback'],
			],
			'last_install_log'     => $this->client->new_install_job()->get_last_log(),
			'beta_enabled'         => (bool) $state['beta_enabled'],
			'auto_update_enabled'  => $this->is_auto_update_enabled(),
			'changelog'            => $update && ! empty( $update->upgrade_notice ) ? $update->upgrade_notice : null,
			'package_url'          => $update && ! empty( $update->package ) ? $update->package : null,
		] );
	}

	/**
	 * Whether WordPress will auto-update this plugin/theme. Reads the
	 * real `auto_update_plugins` / `auto_update_themes` site option that
	 * WP-core writes to when the user toggles auto-update from the
	 * Plugins / Themes screen.
	 */
	private function is_auto_update_enabled(): bool {
		if ( $this->client->isPlugin() ) {
			$auto = (array) get_site_option( 'auto_update_plugins', [] );
			return in_array( $this->client->getBasename(), $auto, true );
		}

		$auto = (array) get_site_option( 'auto_update_themes', [] );
		return in_array( $this->client->getSlug(), $auto, true );
	}

	/**
	 * POST /updates/check-now — bust the local cache and re-query the server.
	 */
	public function updates_check_now() {
		$info = $this->client->updater()->force_check();

		if ( ! $info ) {
			return new WP_Error(
				'sdk-check-update-failed',
				__( 'Could not fetch update information from the server.', 'storeengine-sdk' ),
				[ 'status' => 502 ]
			);
		}

		return $this->updates_status();
	}

	/**
	 * GET /updates/versions — proxy the server's version history.
	 */
	public function updates_versions() {
		if ( $this->client->isFree() ) {
			$body = [];
		} else {
			$body = [ 'license' => $this->client->license()->get_key() ];
		}

		$response = $this->client->request( [
			'body'  => $body,
			'route' => 'versions',
		] );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		// Server's /software/* responses come back wrapped in success/data
		// for known routes (Client::request line 1131). /versions isn't in
		// that list yet, so the response is raw wp_remote_request output.
		if ( isset( $response['success'] ) ) {
			if ( ! $response['success'] ) {
				return new WP_Error(
					$response['code'] ?? 'sdk-versions-failed',
					$response['error'] ?? __( 'Could not fetch version history.', 'storeengine-sdk' ),
					[ 'status' => 502 ]
				);
			}

			return rest_ensure_response( $response['data'] );
		}

		// Raw response — decode body + check HTTP status.
		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		// The remote server may be running an older license-management
		// addon that doesn't expose /software/versions. Surface that
		// distinctly so the UI can show a helpful message instead of an
		// ambiguous "no versions available" state.
		if ( 404 === (int) $code || ( is_array( $data ) && 'rest_no_route' === ( $data['code'] ?? '' ) ) ) {
			return new WP_Error(
				'sdk-server-version-list-unsupported',
				__( 'The license server does not yet support listing version history. The vendor needs to update the License Management addon on the server.', 'storeengine-sdk' ),
				[ 'status' => 501 ]
			);
		}

		if ( $code >= 400 ) {
			return new WP_Error(
				$data['code'] ?? 'sdk-versions-failed',
				$data['message'] ?? __( 'Could not fetch version history.', 'storeengine-sdk' ),
				[ 'status' => $code ]
			);
		}

		return rest_ensure_response( is_array( $data ) ? $data : [] );
	}

	/**
	 * POST /updates/install — install a specific version (or "latest" when
	 * no version param is provided). Same code path serves updates and
	 * rollbacks; the server's /software/get-package endpoint enforces the
	 * per-version allow_rollback flag.
	 */
	public function updates_install( WP_REST_Request $request ) {
		$current        = $this->client->getProjectVersion();
		$target_version = $request->get_param( 'version' );

		// "Latest" path: ask the server what the latest released version is.
		if ( ! $target_version ) {
			$info = $this->client->updater()->force_check();

			if ( ! $info || empty( $info->new_version ) ) {
				return new WP_Error(
					'sdk-no-update-available',
					__( 'No update is available right now.', 'storeengine-sdk' ),
					[ 'status' => 409 ]
				);
			}

			$package_url    = ! empty( $info->package ) ? $info->package : null;
			$target_version = $info->new_version;
		} else {
			$package_url = $this->resolve_package_url( $target_version, $current );

			if ( is_wp_error( $package_url ) ) {
				return $package_url;
			}
		}

		if ( ! $package_url ) {
			return new WP_Error(
				'sdk-no-package-url',
				__( 'Server did not return a download URL for the requested version.', 'storeengine-sdk' ),
				[ 'status' => 502 ]
			);
		}

		$job    = $this->client->new_install_job();
		$result = $job->install_from_url( $package_url, $target_version, $current );

		if ( is_wp_error( $result ) ) {
			$this->client->update_state()->record_install( $target_version, $current, 'failed', false );

			return $result;
		}

		$this->client->update_state()->record_install(
			$target_version,
			$current,
			'succeeded',
			(bool) $result['is_rollback']
		);

		return rest_ensure_response( $result );
	}

	/**
	 * POST /updates/rollback — one-click revert to the previously installed
	 * version recorded by the SDK. If no previous_version is recorded the
	 * client should redirect the user to the version-history table instead.
	 */
	public function updates_rollback() {
		$previous = $this->client->update_state()->get( 'previous_version' );

		if ( ! $previous ) {
			return new WP_Error(
				'sdk-no-previous-version',
				__( 'No previous version is recorded for this installation.', 'storeengine-sdk' ),
				[ 'status' => 409 ]
			);
		}

		// Delegate to updates_install with the previous version pre-filled.
		$request = new WP_REST_Request( 'POST', '' );
		$request->set_param( 'version', $previous );

		return $this->updates_install( $request );
	}

	/**
	 * GET /settings/beta-channel — return the local mirror.
	 */
	public function get_beta_channel() {
		return rest_ensure_response( [
			'enabled' => (bool) $this->client->update_state()->get( 'beta_enabled', false ),
		] );
	}

	/**
	 * POST /settings/beta-channel — toggle and sync to the server.
	 */
	public function set_beta_channel( WP_REST_Request $request ) {
		$enabled = (bool) $request->get_param( 'enabled' );

		$response = $this->client->request( [
			'body'  => [ 'enabled' => $enabled ],
			'route' => 'beta-channel',
		] );

		// Mirror locally even if the server is unreachable so the UI stays
		// responsive; the server will reconcile on the next /check-update.
		$this->client->update_state()->set( [ 'beta_enabled' => $enabled ] );

		// Invalidate the cached update info so the next status call hits
		// the right channel.
		$this->client->updater()->delete_cached_version_info();

		return rest_ensure_response( [
			'enabled'        => $enabled,
			'server_synced'  => ! is_wp_error( $response ),
		] );
	}

	public function get_auto_update_window() {
		return rest_ensure_response( [
			'window' => $this->client->update_state()->get( 'auto_update_window' ),
		] );
	}

	public function set_auto_update_window( WP_REST_Request $request ) {
		$window = $request->get_param( 'window' );
		$window = $window ? sanitize_text_field( $window ) : null;

		$response = $this->client->request( [
			'body'  => [ 'window' => $window ],
			'route' => 'schedule-update',
		] );

		$this->client->update_state()->set( [ 'auto_update_window' => $window ] );

		return rest_ensure_response( [
			'window'        => $window,
			'server_synced' => ! is_wp_error( $response ),
		] );
	}

	/**
	 * Read the cached version-info transient so /updates/status doesn't
	 * fire a remote request on every poll. The Updater's check_plugin_update
	 * already populates this on the WP cron path.
	 *
	 * @return object|null
	 */
	private function get_cached_update() {
		$which = $this->client->isPlugin() ? 'plugin_update' : 'theme_update';
		$key   = $this->client->getHookName( 'version_info' ) . $which;
		$info  = get_transient( $key );

		return is_object( $info ) && isset( $info->new_version ) ? $info : null;
	}

	/**
	 * Hit /software/get-package on the license server to resolve a signed
	 * URL for a specific version. The server enforces beta gating and
	 * per-version allow_rollback for downgrades.
	 *
	 * @return string|WP_Error
	 */
	private function resolve_package_url( string $target_version, string $current_version ) {
		$body = [
			'version'         => $target_version,
			'current_version' => $current_version,
		];

		if ( ! $this->client->isFree() ) {
			$body['license'] = $this->client->license()->get_key();
		}

		$response = $this->client->request( [
			'body'  => $body,
			'route' => 'get-package',
		] );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		// /get-package isn't in Client::request's wrapped-route allowlist,
		// so we get back the raw wp_remote_request response.
		$code = wp_remote_retrieve_response_code( $response );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( $code >= 400 ) {
			return new WP_Error(
				$body['code'] ?? 'sdk-get-package-failed',
				$body['message'] ?? __( 'Could not resolve a download URL for the requested version.', 'storeengine-sdk' ),
				[ 'status' => $code ]
			);
		}

		if ( empty( $body['package'] ) ) {
			return new WP_Error(
				'sdk-no-package-url',
				__( 'Server response is missing a package URL.', 'storeengine-sdk' ),
				[ 'status' => 502 ]
			);
		}

		return (string) $body['package'];
	}

	/**
	 * Callback for insights opt-in/opt-out.
	 *
	 * @param WP_REST_Request $request The request object.
	 *
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_insights_optin( WP_REST_Request $request ) {

		$opt_in = $request->get_param( 'opt_in' );

		if ( null !== $opt_in ) {
			if ( $opt_in ) {
				$this->client->insights()->optIn();
			} else {
				$this->client->insights()->optOut();
			}
		}


		return rest_ensure_response( [
			'allowed'   => $this->client->insights()->is_tracking_allowed(),
			'show'      => ! $this->client->insights()->is_notice_dismissed(),
			'last_send' => $this->client->insights()->get_last_send(),
		] );
	}
}
