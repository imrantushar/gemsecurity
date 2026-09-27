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

		// Abort an incomplete update BEFORE WP swaps the live plugin folder.
		// Priority 20 so it runs AFTER the Install_Job folder-normalizer
		// (priority 10) and therefore inspects the final source directory.
		// Covers both the native "Update now" path and the SDK REST installer.
		add_filter( 'upgrader_source_selection', [ $this, 'validate_package_source' ], 20, 4 );

		register_activation_hook( $this->client->getPackageFile(), [ $this, 'delete_cached_version_info' ] );
		register_deactivation_hook( $this->client->getPackageFile(), [ $this, 'delete_cached_version_info' ] );

		// Core/free plugin dependency gate (Points 1+2): never let the pro
		// update out-run the free plugin it depends on. No-op unless the
		// consumer declared `requires_core`.
		if ( $this->client->core_dependency()->is_configured() ) {
			// Abort a native "Update now" / bulk / cron auto-update of the pro
			// plugin while the core plugin is behind — priority 5 so it runs
			// before the package-integrity check and short-circuits early.
			// (The SDK's own installer attempts a core update first; this is
			// the safety net for every other upgrade path.)
			add_filter( 'upgrader_pre_install', [ $this, 'gate_core_dependency' ], 5, 2 );
			add_action( 'admin_notices', [ $this, 'core_dependency_notice' ] );
		}
	}

	/**
	 * Validate the extracted update package before WordPress deletes/swaps the
	 * live plugin folder. If the package is missing its main file or any
	 * declared critical path, return a WP_Error to abort: WP keeps the old
	 * folder (it never reaches `clear_destination`) and, on WP 6.3+, restores
	 * the temp_backup. Net effect — a failed/incomplete update is dismissed and
	 * the user keeps a working plugin instead of a fatal/white-screen.
	 *
	 * Hooked on the core `upgrader_source_selection` filter:
	 *   ($source, $remote_source, $upgrader, $hook_extra)
	 *
	 * @param string|WP_Error $source        Extracted (possibly normalized) source dir.
	 * @param string          $remote_source Working dir the package was unpacked into.
	 * @param WP_Upgrader     $upgrader      The upgrader instance.
	 * @param array           $hook_extra    Context (plugin basename / SDK slug).
	 *
	 * @return string|WP_Error $source unchanged, or WP_Error to abort the install.
	 */
	public function validate_package_source( $source, $remote_source, $upgrader, $hook_extra = [] ) {
		// An upstream filter already errored (e.g. the normalizer) — pass through.
		if ( is_wp_error( $source ) ) {
			return $source;
		}

		// Only ever inspect packages we can prove belong to this plugin.
		if ( ! $this->source_belongs_to_this_plugin( $hook_extra ) ) {
			return $source;
		}

		global $wp_filesystem;

		// Without a usable filesystem we can't validate; don't block the update.
		if ( ! $wp_filesystem || ! is_string( $source ) ) {
			return $source;
		}

		$dir  = trailingslashit( $source );
		$slug = $this->client->getSlug();

		// 1) Main plugin file must be present in the package root.
		$main_file = basename( $this->client->getBasename() );
		if ( $main_file && ! $wp_filesystem->exists( $dir . $main_file ) ) {
			return new WP_Error(
				'sdk-package-incomplete',
				sprintf(
				/* translators: 1: plugin slug, 2: missing main file name. */
					__( 'Update aborted: the downloaded %1$s package is missing its main file (%2$s). Your current version was kept.', 'storeengine-sdk' ),
					$slug,
					$main_file
				)
			);
		}

		// 2) Every declared critical path must exist.
		foreach ( $this->get_critical_paths() as $rel ) {
			if ( ! is_string( $rel ) ) {
				continue;
			}
			$rel = ltrim( $rel, '/' );
			if ( '' === $rel ) {
				continue;
			}
			if ( ! $wp_filesystem->exists( $dir . $rel ) ) {
				return new WP_Error(
					'sdk-package-incomplete',
					sprintf(
					/* translators: 1: plugin slug, 2: missing package-relative path. */
						__( 'Update aborted: the downloaded %1$s package is incomplete (missing %2$s). Your current version was kept.', 'storeengine-sdk' ),
						$slug,
						$rel
					)
				);
			}
		}

		return $source;
	}

	/**
	 * Whether $hook_extra unambiguously identifies the package this Updater
	 * instance manages. `upgrader_source_selection` is a global (non-prefixed)
	 * core hook, so every SDK consumer's callback fires for every install — we
	 * MUST self-scope here and default to false on any ambiguity so we never
	 * validate (or block) a package that isn't provably ours.
	 *
	 * @param array $hook_extra
	 *
	 * @return bool
	 */
	private function source_belongs_to_this_plugin( $hook_extra ): bool {
		if ( empty( $hook_extra ) || ! is_array( $hook_extra ) ) {
			return false;
		}

		// SDK REST Install_Job path — explicit slug tag.
		if ( ! empty( $hook_extra['storeengine_sdk']['slug'] ) ) {
			return $hook_extra['storeengine_sdk']['slug'] === $this->client->getSlug();
		}

		// Native single update (plugins.php "Update now").
		if ( ! empty( $hook_extra['plugin'] ) ) {
			return $hook_extra['plugin'] === $this->client->getBasename();
		}

		// Native bulk update (update-core.php).
		if ( ! empty( $hook_extra['plugins'] ) && is_array( $hook_extra['plugins'] ) ) {
			return in_array( $this->client->getBasename(), $hook_extra['plugins'], true );
		}

		// Native single theme update (themes are keyed by stylesheet == slug).
		if ( ! empty( $hook_extra['theme'] ) ) {
			return $hook_extra['theme'] === $this->client->getSlug();
		}

		// Native bulk theme update.
		if ( ! empty( $hook_extra['themes'] ) && is_array( $hook_extra['themes'] ) ) {
			return in_array( $this->client->getSlug(), $hook_extra['themes'], true );
		}

		return false;
	}

	/**
	 * Effective list of package-relative paths that must exist for an update to
	 * be accepted. Uses the consumer's declared `critical_paths`, falling back
	 * to `vendor/autoload.php` only when the installed build actually ships one.
	 * Filterable so a site can trim/extend without re-vendoring the SDK.
	 *
	 * @return array
	 */
	private function get_critical_paths(): array {
		$paths = $this->client->getCriticalPaths();

		if ( null === $paths ) {
			// Derive the default from the installed copy rather than assuming a
			// layout. Until 1.5.6 this was a blind [ 'vendor/autoload.php' ],
			// which permanently blocked updates for any consumer that ships no
			// vendor/ directory — a pro plugin with no runtime Composer
			// dependencies, or one that vendors somewhere else. Their packages
			// were rejected for a file they never had, with no way to recover:
			// the check runs from the *installed* build, so declaring
			// `critical_paths` in a later release cannot rescue a site already
			// running an older one.
			//
			// Only require the autoloader when the installed build actually has
			// one. That keeps the protection for the consumers it was written
			// for and stops it firing where it was always a false positive. An
			// explicitly declared `critical_paths` is untouched by this.
			$installed = trailingslashit( dirname( $this->client->getPackageFile() ) ) . 'vendor/autoload.php';
			$paths     = file_exists( $installed ) ? [ 'vendor/autoload.php' ] : [];
		}

		/**
		 * Filter the critical paths checked before an update is applied.
		 *
		 * @param array $paths Package-relative paths that must exist.
		 */
		$paths = apply_filters( $this->client->getHookName( 'critical_paths' ), $paths );

		return is_array( $paths ) ? $paths : [];
	}

	/**
	 * Abort a pro update while the core/free plugin it depends on is behind.
	 *
	 * Hooked on core's `upgrader_pre_install` so it covers the native "Update
	 * now" link, bulk updates on update-core.php, and unattended background
	 * auto-updates alike. We only GATE here (never trigger a nested core
	 * upgrade — a re-entrant WP_Upgrader run is unsafe); the SDK's own
	 * installer does the auto-update-the-core-first attempt before it gets here.
	 *
	 * @param bool|WP_Error $response   Whether to proceed. WP_Error to abort.
	 * @param array         $hook_extra Upgrade context.
	 *
	 * @return bool|WP_Error
	 */
	public function gate_core_dependency( $response, $hook_extra = [] ) {
		// An upstream pre-install check already failed — pass it through.
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		// Only ever gate an upgrade we can prove is this pro plugin.
		if ( ! $this->source_belongs_to_this_plugin( $hook_extra ) ) {
			return $response;
		}

		// Never gate a rollback/downgrade — the latest release's core-version
		// requirement doesn't apply to an older pro version.
		if ( ! empty( $hook_extra['storeengine_sdk']['is_rollback'] ) ) {
			return $response;
		}

		$result = $this->client->core_dependency()->ensure_satisfied_or_error( false );

		return is_wp_error( $result ) ? $result : $response;
	}

	/**
	 * Nag the admin to update the core/free plugin first when a pro update is
	 * pending but the dependency isn't satisfied. Only shown while an update is
	 * actually waiting, so a latent version gap that blocks nothing stays quiet.
	 *
	 * @return void
	 */
	public function core_dependency_notice() {
		if ( ! current_user_can( 'update_plugins' ) ) {
			return;
		}

		$dep = $this->client->core_dependency();

		if ( ! $dep->is_configured() || $dep->is_satisfied() ) {
			return;
		}

		// Only nag when a pro update is actually pending.
		$which = $this->client->isPlugin() ? 'plugin_update' : 'theme_update';
		$info  = get_transient( $this->cache_key . $which );

		$update_pending = is_object( $info )
			&& ! empty( $info->new_version )
			&& version_compare( $this->client->getProjectVersion(), $info->new_version, '<' );

		if ( ! $update_pending ) {
			return;
		}

		printf(
			'<div class="notice notice-warning"><p><strong>%1$s:</strong> %2$s</p></div>',
			esc_html( $this->client->getPackageName() ),
			esc_html( $dep->unmet_message() )
		);
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

		// Abort an incomplete theme update BEFORE WP swaps the live theme
		// folder — parity with the plugin path.
		add_filter( 'upgrader_source_selection', [ $this, 'validate_package_source' ], 20, 4 );

		// Core/free plugin dependency gate — no-op unless `requires_core` is set.
		if ( $this->client->core_dependency()->is_configured() ) {
			add_filter( 'upgrader_pre_install', [ $this, 'gate_core_dependency' ], 5, 2 );
			add_action( 'admin_notices', [ $this, 'core_dependency_notice' ] );
		}
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

		// On multisite, skip injection on the per-site plugins.php (a site admin
		// can't update a network plugin anyway) — but DO inject in the Network
		// Admin, where a super admin manages network-activated plugin updates.
		if ( 'plugins.php' === $pagenow && is_multisite() && ! is_network_admin() ) {
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

			// Mirror the license server's per-release core-plugin requirement
			// (if any) so the dependency gate can read it during a later install
			// request. Stored even when empty so a dropped requirement clears.
			$required_core = ( isset( $data['requires_core']['min_version'] ) && is_string( $data['requires_core']['min_version'] ) )
				? $data['requires_core']['min_version']
				: '';
			( new SE_License_SDK_Update_State( $this->client ) )->set( [ 'required_core_version' => $required_core ] );

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
		$type = $hook_extra['type'] ?? '';

		// Only this product's own plugin/theme update.
		if ( ! in_array( $type, [ 'plugin', 'theme' ], true ) ) {
			return;
		}

		if ( ! $this->source_belongs_to_this_plugin( $hook_extra ) ) {
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

		/**
		 * Fires after this product's files have been updated in place (covers the
		 * native "Update now"/bulk/auto-update paths and the SDK installer alike).
		 * Hook name: "{product-hook-prefix}_update_installed".
		 *
		 * @param string                 $previous The version that was running before the swap.
		 * @param SE_License_SDK_Updater $this     The updater instance.
		 */
		$this->client->do_action( 'update_installed', $previous, $this );
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
