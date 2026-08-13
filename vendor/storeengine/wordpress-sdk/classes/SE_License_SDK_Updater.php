<?php

/**
 * Class Updater
 * @package AbsolutePluginsServices
 */
final class SE_License_SDK_Updater {

	/**
	 * Client
	 *
	 * @var SE_License_SDK_Client
	 */
	protected $client;

	/**
	 * Flag for checking if the init method is already called.
	 * @var bool
	 */
	private $did_init = false;

	/**
	 * AbsolutePluginsServices\License
	 *
	 * @var SE_License_SDK_License
	 */
	protected $license;

	/**
	 * Cache Key for current App
	 * @var string
	 */
	private $cache_key;

	/**
	 * Flag for disabling cache.
	 *
	 * @var false
	 */
	private $disable_cache = false;

	/**
	 * Initialize the class
	 *
	 * @param SE_License_SDK_Client $client The Client.
	 * @param SE_License_SDK_License $license The license.
	 */
	public function __construct( SE_License_SDK_Client $client ) {
		$this->client        = &$client;
		$this->cache_key     = $this->client->getHookName( 'version_info' );
		$this->disable_cache = apply_filters( $this->client->getHookName( 'disable-updater-cache' ), false );
	}

	/**
	 * Initialize Updater
	 *
	 * @return void
	 */
	public function init() {
		if ( $this->did_init ) {
			return;
		}

		$this->did_init = true;
		$method         = 'run_' . $this->client->getType() . '_hooks'; // run_(plugin/theme)_hooks

		// Run the hooks.
		if ( method_exists( $this, $method ) ) {
			$this->$method();
		}

		add_action( 'init', [ $this, 'clear_package_cache' ], - 1 );

		// Capture upgrades performed by WP itself (cron, plugins.php "update
		// now" link, our own Install_Job) so the SDK can offer a one-click
		// rollback to the previous version.
		add_action( 'upgrader_process_complete', [ $this, 'record_previous_version' ], 10, 2 );
	}

	/**
	 * Load a sibling SDK class file. The SDK ships its own spl_autoload
	 * but in setups where multiple SDK copies coexist (Strauss-prefixed
	 * vendor folders, classmap-authoritative composer dumps, etc.) the
	 * autoloader's `$sdk_init_file` can end up pointing at a different
	 * vendor folder than the one this Updater was loaded from. Falling
	 * back to a relative require_once guarantees the new 1.5.0 classes
	 * load from the same wordpress-sdk/ that contains this Updater.
	 */
	private static function require_sibling( string $class ): void {
		if ( class_exists( $class, false ) ) {
			return;
		}
		$path = __DIR__ . DIRECTORY_SEPARATOR . $class . '.php';
		if ( is_readable( $path ) ) {
			require_once $path;
		}
	}

	/**
	 * Set up WordPress filter hooks to get plugin update.
	 *
	 * @return void
	 */
	private function run_plugin_hooks() {
		add_filter( 'pre_set_site_transient_update_plugins', [ $this, 'check_plugin_update' ], 1, 1 );
		add_filter( 'plugins_api', [ $this, 'plugins_api_filter' ], 10, 3 );

		register_activation_hook( $this->client->getPackageFile(), [ $this, 'delete_cached_version_info' ] );
		register_deactivation_hook( $this->client->getPackageFile(), [ $this, 'delete_cached_version_info' ] );
	}

	/**
	 * Set up WordPress filter hooks to get theme update.
	 *
	 * @return void
	 */
	private function run_theme_hooks() {
		add_filter( 'pre_set_site_transient_update_themes', [ $this, 'check_theme_update' ] );
		add_filter( 'themes_api', [ $this, 'themes_api_filter' ], 10, 3 );
		add_action( 'switch_theme', [ $this, 'delete_cached_version_info' ] );
	}

	/**
	 * Check for Update for this specific project
	 *
	 * @param false|object $transient_data plugin update transient data.
	 *
	 * @return object
	 */
	public function check_plugin_update( $transient_data ) {
		global $pagenow;

		if ( 'plugins.php' === $pagenow && is_multisite() ) {
			return $transient_data;
		}

		if ( ! is_object( $transient_data ) ) {
			$transient_data = new stdClass;
		}

		if ( ! empty( $transient_data->response ) && ! empty( $transient_data->response[ $this->client->getBasename() ] ) ) {
			return $transient_data;
		}

		$project_info = $this->get_information( 'plugin_update' );

		if ( false !== $project_info && is_object( $project_info ) && isset( $project_info->new_version ) ) {
			if ( version_compare( $this->client->getProjectVersion(), $project_info->new_version, '<' ) ) {
				unset( $project_info->sections );
				$transient_data->response[ $this->client->getBasename() ] = $project_info;
			}

			$transient_data->checked[ $this->client->getBasename() ] = $this->client->getProjectVersion();
		}

		return $transient_data;
	}

	/**
	 * Check theme update
	 *
	 * @param false|object $transient_data Theme update transient data.
	 *
	 * @return object
	 */
	public function check_theme_update( $transient_data ) {
		global $pagenow;

		if ( 'themes.php' === $pagenow && is_multisite() ) {
			return $transient_data;
		}

		if ( ! is_object( $transient_data ) ) {
			$transient_data = new stdClass();
		}

		if ( ! empty( $transient_data->response ) && ! empty( $transient_data->response[ $this->client->getSlug() ] ) ) {
			return $transient_data;
		}

		$project_info = $this->get_information( 'theme_update' );

		if ( false !== $project_info && is_object( $project_info ) && isset( $project_info->new_version ) ) {

			if ( version_compare( $this->client->getProjectVersion(), $project_info->new_version, '<' ) ) {
				$transient_data->response[ $this->client->getSlug() ] = (array) $project_info;
			}

			$transient_data->last_checked                        = time();
			$transient_data->checked[ $this->client->getSlug() ] = $this->client->getProjectVersion();
		}

		return $transient_data;
	}

	/**
	 * Get version info from database
	 *
	 * @return object|bool
	 */
	private function get_cached_version_info( $which ) {
		global $pagenow;

		// If updater page then fetch from API now
		if ( 'update-core.php' == $pagenow || $this->disable_cache ) {
			return false; // Force fetching update
		}

		$info = get_transient( $this->cache_key . $which );

		if ( ! $info || ! isset( $info->name ) ) {
			return false; // Cache is expired.
		}

		return $this->__children_to_array( $info, [ 'icons', 'banners', 'sections' ] );
	}

	/**
	 * Set version info to database
	 *
	 * @param mixed $value data (version info) to cache.
	 *
	 * @return void
	 */
	private function set_cached_version_info( $value, $which ) {
		if ( ! $value ) {
			delete_transient( $this->cache_key . $which );

			return;
		}

		set_transient( $this->cache_key . $which, $value, 3 * HOUR_IN_SECONDS );
	}

	/**
	 * Delete cached version info
	 * @return void
	 */
	public function delete_cached_version_info() {
		delete_transient( $this->cache_key );

		if ( $this->client->isPlugin() ) {
			delete_site_transient( 'update_plugins' );
		} else {
			delete_site_transient( 'update_themes' );
		}

		$actions = [ 'plugin_update', 'plugin_information', 'theme_update', 'theme_information' ];

		foreach ( $actions as $which ) {
			delete_transient( $this->cache_key . $which );
		}
	}

	/**
	 * Get plugin info from WC API Manager
	 *
	 * @param string $action
	 * @param bool $force
	 *
	 * @return bool|array
	 */
	private function get_information( string $action, bool $force = false ) {
		$project_info = $this->get_cached_version_info( $action );

		if ( false === $project_info || $force ) {
			$project_info = $this->get_updates( $action );

			$this->set_cached_version_info( $project_info, $action );
		}

		return $project_info;
	}

	private function get_updates( $action ) {
		// Updater doesn't need to care for license.
		// License key will be added to the request body by client (if available).
		// Server will provide update information without package/download link if license not available.
		// For free version response will contain the package/download link.

		$data = $this->client->get_admin_info();

		// Channel
		//$data['channel'] = 'beta';

		// Update -> check-update,
		$response = $this->client->request( [ 'body'  => $data, 'route' => 'check-update' ] );

		if ( isset( $response['success'] ) && $response['success'] ) {
			// Stamp the local "last checked" timestamp so the UI can render
			// "checked 2 minutes ago" without polling the server.
			self::require_sibling( 'SE_License_SDK_Update_State' );
			( new SE_License_SDK_Update_State( $this->client ) )->record_check();

			$data = $response['data'];

			if ( 'plugin_update' !== $action ) {
				// information -> package-info
				$response = $this->client->request( [
					'body'  => $this->client->get_admin_info(),
					'route' => 'package-info',
				] );

				if ( isset( $response['success'] ) && $response['success'] ) {
					$data = array_merge( $data, $response['data'] );
				}
			}

			if ( isset( $data['product_id'] ) ) {
				unset( $data['product_id'] );
			}

			/**
			 * Filter API Response Data
			 *
			 * @param array $data
			 */
			$data = apply_filters( $this->client->getHookName( $action ), $data, $action );

			return $this->__children_to_array( (object) $data, [
				'icons',
				'banners',
				'sections',
				'compatibility',
				'ratings',
				'contributors',
				'screenshots',
				'tags'
			] );
		}

		return false;
	}

	/**
	 * Updates information on the "View version x.x details" page with custom data.
	 *
	 * @param mixed $data Plugin info Data.
	 * @param string $action Request Action.
	 * @param ?object $args API Args.
	 *
	 * @return object $data
	 */
	public function plugins_api_filter( $data, string $action = '', object $args = null ) {
		if ( 'plugin_information' !== $action ) {
			return $data;
		}

		if ( ! isset( $args->slug ) || ( $args->slug !== $this->client->getSlug() ) ) {
			return $data;
		}

		return $this->get_information( 'plugin_information', ! empty( $args->force ) );
	}

	public function themes_api_filter( $data, string $action = '', $args = null ) {
		if ( 'theme_information' !== $action ) {
			return $data;
		}

		if ( ! isset( $args->slug ) || ( $args->slug !== $this->client->getSlug() ) ) {
			return $data;
		}

		return $this->get_information( 'theme_information', ! empty( $args->force ) );
	}

	public function clear_package_cache() {
		add_action( $this->client->getHookName( 'license-activate' ), [ $this, 'delete_cached_version_info' ] );
		add_action( $this->client->getHookName( 'license-deactivate' ), [ $this, 'delete_cached_version_info' ] );
	}

	/**
	 * Force a fresh update check by clearing the local transient and
	 * re-querying the server with the `force` flag. Returns the same
	 * structure as get_information() so callers can use it interchangeably.
	 *
	 * @return object|bool
	 */
	public function force_check() {
		$this->delete_cached_version_info();

		// Tell get_updates() to send `force=true` to the server via the
		// before_client_request_check-update hook. Channel-aware (server
		// also honours the per-installation beta_enabled flag).
		add_filter( $this->client->getHookName( 'before_client_request_check-update' ), [ $this, 'inject_force_param' ], 10, 2 );

		$info = $this->get_information( $this->client->isPlugin() ? 'plugin_update' : 'theme_update', true );

		remove_filter( $this->client->getHookName( 'before_client_request_check-update' ), [ $this, 'inject_force_param' ], 10 );

		return $info;
	}

	/**
	 * Hook callback used by force_check() to flag the outgoing /check-update
	 * request body as a forced refresh. Not used outside force_check().
	 *
	 * @param array $args
	 *
	 * @return array
	 */
	public function inject_force_param( $args ) {
		if ( ! isset( $args['body'] ) || ! is_array( $args['body'] ) ) {
			$args['body'] = [];
		}

		$args['body']['force'] = true;

		return $args;
	}

	/**
	 * Record `previous_version` after WP / our installer upgrades the host
	 * plugin. Powers the "Roll back to v1.9.1" shortcut in the UI.
	 *
	 * @param WP_Upgrader $upgrader
	 * @param array $hook_extra
	 */
	public function record_previous_version( $upgrader, $hook_extra ) {
		if ( empty( $hook_extra['type'] ) || 'plugin' !== $hook_extra['type'] ) {
			return;
		}

		if ( empty( $hook_extra['plugins'] ) && empty( $hook_extra['plugin'] ) ) {
			return;
		}

		$updated = [];
		if ( ! empty( $hook_extra['plugins'] ) && is_array( $hook_extra['plugins'] ) ) {
			$updated = $hook_extra['plugins'];
		} elseif ( ! empty( $hook_extra['plugin'] ) ) {
			$updated = [ $hook_extra['plugin'] ];
		}

		if ( ! in_array( $this->client->getBasename(), $updated, true ) ) {
			return;
		}

		// At this point the new code is already on disk, so reading the
		// header here would return the *new* version. The pre-install
		// version is whatever the SDK booted with on this request.
		$previous = $this->client->getProjectVersion();

		self::require_sibling( 'SE_License_SDK_Update_State' );
		( new SE_License_SDK_Update_State( $this->client ) )->set( [
			'previous_version' => $previous,
			'last_install_at'  => time(),
		] );
	}

	/**
	 * Typecast child element to array or object
	 * Utility method
	 *
	 * @param array|stdClass $input the array or object to convert/typecast.
	 * @param array $children children array.
	 *
	 * @return array|object
	 */
	private function __children_to_array( $input, array $children = [] ) {
		if ( ! empty( $children ) && is_array( $children ) && ( is_object( $input ) || is_array( $input ) ) ) {
			$isObject = is_object( $input );

			foreach ( $children as $child ) {
				if ( call_user_func_array( $isObject ? 'property_exists' : 'array_key_exists', [ $input, $child ] ) ) {
					if ( $isObject ) {
						$input->{$child} = (array) $input->{$child};
					} else {
						$input[ $child ] = (array) $input->{$child};
					}
				}
			}
		}

		return $input;
	}

	final public function __clone() {
		trigger_error( 'Singleton. No cloning allowed!', E_USER_ERROR ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error
	}

	/**
	 * Wakeup.
	 */
	final public function __wakeup() {
		trigger_error( 'Singleton. No serialization allowed!', E_USER_ERROR ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error
	}
}

// End of file SE_License_SDK_Updater.php.
