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
	 * Results already fetched during this request, keyed by action. WordPress
	 * writes the update transient more than once per check, and each write
	 * re-runs our filter.
	 *
	 * @var array
	 */
	private $runtime_cache = [];

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

		// Background, batched update checks for every SDK product on the site.
		self::require_sibling( 'SE_License_SDK_Update_Batch' );
		SE_License_SDK_Update_Batch::init();

		// Drop the cached version info on every license lifecycle transition,
		// not just the two fired by the PHP license form. `emit_license_event()`
		// is reached from the form, the REST endpoints, WP-CLI and the scheduled
		// re-check alike, so hooking the events here covers every path a license
		// can change through. Registered from init() (plugins_loaded) rather than
		// from clear_package_cache() (`init`) so the listeners are armed for REST
		// and cron requests too.
		$this->client->add_action( 'license_activated', [ $this, 'delete_cached_version_info' ] );
		$this->client->add_action( 'license_deactivated', [ $this, 'delete_cached_version_info' ] );
		$this->client->add_action( 'license_grace_expired', [ $this, 'delete_cached_version_info' ] );

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
		$info  = get_site_transient( $this->cache_key . $which );

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

		$basename = $this->client->getBasename();

		// Cache (or background batch) only — see get_information().
		$project_info = $this->get_information( 'plugin_update' );

		if ( false !== $project_info && is_object( $project_info ) && isset( $project_info->new_version ) ) {
			if ( version_compare( $this->client->getProjectVersion(), $project_info->new_version, '<' ) ) {
				$project_info = clone $project_info;
				unset( $project_info->sections );
				$transient_data->response[ $basename ] = $this->strip_unlicensed_package( $project_info );
			} elseif ( isset( $transient_data->response[ $basename ] ) ) {
				// Up to date now (e.g. updated manually): drop a stale row.
				unset( $transient_data->response[ $basename ] );
			}

			$transient_data->checked[ $basename ] = $this->client->getProjectVersion();
		} elseif ( ! empty( $transient_data->response[ $basename ] ) ) {
			// Nothing fresh to go on: keep the row an earlier check wrote, but
			// re-apply the license gate so a download URL obtained while the
			// license was active cannot outlive the license itself.
			$transient_data->response[ $basename ] = $this->strip_unlicensed_package( $transient_data->response[ $basename ] );
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

		$slug = $this->client->getSlug();

		// Cache (or background batch) only — see check_plugin_update().
		$project_info = $this->get_information( 'theme_update' );

		if ( false !== $project_info && is_object( $project_info ) && isset( $project_info->new_version ) ) {

			if ( version_compare( $this->client->getProjectVersion(), $project_info->new_version, '<' ) ) {
				$transient_data->response[ $slug ] = (array) $this->strip_unlicensed_package( $project_info );
			} elseif ( isset( $transient_data->response[ $slug ] ) ) {
				unset( $transient_data->response[ $slug ] );
			}

			$transient_data->last_checked                        = time();
			$transient_data->checked[ $this->client->getSlug() ] = $this->client->getProjectVersion();
		} elseif ( ! empty( $transient_data->response[ $slug ] ) ) {
			$transient_data->response[ $slug ] = $this->strip_unlicensed_package( $transient_data->response[ $slug ] );
		}

		return $transient_data;
	}

	/**
	 * Remove the download URL from an update payload when this product has no
	 * valid license.
	 *
	 * The license server already omits `package` for an unlicensed site, so
	 * under normal conditions this is a no-op. It matters because the response
	 * is cached — in this SDK's own transient and again in WordPress's
	 * `update_plugins` site transient, which plugins.php renders from directly.
	 * A package URL fetched while the license was active used to survive the
	 * license being deactivated, and WordPress decides between "update now" and
	 * "Automatic update is unavailable" purely on `empty( $response->package )`.
	 * Those signed URLs stay valid on the server for days, so the stale row was
	 * enough to let an unlicensed site pull a paid release from plugins.php.
	 * Invalidating on the license lifecycle events (see init()) closes the
	 * window; this closes it for any payload that predates the fix or reaches
	 * the transient some other way.
	 *
	 * Free products are never gated. A license inside its offline grace period
	 * still counts as valid, so a brief outage doesn't strip working updates.
	 *
	 * @param object|array $info Update payload, as stored in the update transient.
	 *
	 * @return object|array The payload, with `package`/`download_link` blanked
	 *                      when the license doesn't cover it.
	 */
	private function strip_unlicensed_package( $info ) {
		if ( ! $this->client->isPro() ) {
			return $info;
		}

		$is_object = is_object( $info );

		if ( ! $is_object && ! is_array( $info ) ) {
			return $info;
		}

		if ( empty( $is_object ? ( $info->package ?? '' ) : ( $info['package'] ?? '' ) )
		     && empty( $is_object ? ( $info->download_link ?? '' ) : ( $info['download_link'] ?? '' ) ) ) {
			return $info;
		}

		if ( $this->client->license( false )->is_valid() ) {
			return $info;
		}

		// Don't mutate a shared/cached instance — the caller may be handing us
		// the object still held by the version-info transient.
		$info = $is_object ? clone $info : $info;

		foreach ( [ 'package', 'download_link' ] as $field ) {
			if ( $is_object ) {
				if ( property_exists( $info, $field ) ) {
					$info->{$field} = '';
				}
			} elseif ( array_key_exists( $field, $info ) ) {
				$info[ $field ] = '';
			}
		}

		return $info;
	}

	/**
	 * How long a successful update/information payload is cached.
	 *
	 * WordPress itself refreshes the `update_plugins` / `update_themes` site
	 * transient twice a day, so a shorter TTL only adds license-server traffic
	 * without surfacing a release any sooner. Until 1.5.9 this was 3 hours.
	 *
	 * @return int Seconds.
	 */
	private function get_cache_ttl(): int {
		return (int) apply_filters( $this->client->getHookName( 'updater_cache_ttl' ), 12 * HOUR_IN_SECONDS );
	}

	/**
	 * How long to stop asking the license server after a failed check.
	 *
	 * @return int Seconds.
	 */
	private function get_failure_ttl(): int {
		return (int) apply_filters( $this->client->getHookName( 'updater_failure_ttl' ), HOUR_IN_SECONDS );
	}

	/**
	 * Whether a cached value is the "last check failed" marker written by
	 * get_information().
	 *
	 * @param mixed $info Cached value.
	 *
	 * @return bool
	 */
	private function is_failure_marker( $info ): bool {
		return is_object( $info ) && ! empty( $info->se_sdk_check_failed );
	}

	/**
	 * Whether WordPress is running an explicit, user-requested update check
	 * (the "Check again" button on Dashboard → Updates).
	 *
	 * Visiting update-core.php used to bypass the cache on every page view, so
	 * each visit sent one request per SDK product. WordPress only re-checks
	 * wp.org there when `force-check` is present; we now do the same.
	 *
	 * @return bool
	 */
	private function is_forced_update_check(): bool {
		self::require_sibling( 'SE_License_SDK_Update_Batch' );

		return SE_License_SDK_Update_Batch::is_forced_update_check();
	}

	/**
	 * Get version info from database.
	 *
	 * Returns the cached payload, the failure marker when the last check failed
	 * and its back-off hasn't elapsed, or false when there is nothing usable.
	 *
	 * @return object|bool
	 */
	private function get_cached_version_info( $which ) {
		if ( $this->disable_cache || $this->is_forced_update_check() ) {
			return false; // Force fetching update
		}

		$info = get_site_transient( $this->cache_key . $which );

		if ( $this->is_failure_marker( $info ) ) {
			return $info;
		}

		// The two payload shapes carry different identifying fields: the
		// `*_information` routes include `name` (they merge in package-info),
		// while the `*_update` route returns only the version envelope. Testing
		// for `name` alone therefore rejected every cached update payload, so
		// set_cached_version_info() wrote a transient that was never once read
		// back and every update check hit the license server.
		if ( ! is_object( $info ) || ( ! isset( $info->name ) && ! isset( $info->new_version ) ) ) {
			return false; // Cache is expired.
		}

		return $this->__children_to_array( $info, [ 'icons', 'banners', 'sections' ] );
	}

	/**
	 * Set version info to database
	 *
	 * A failed check is cached too (as a marker, for get_failure_ttl()). Until
	 * 1.5.9 a failure *deleted* the transient, so while the license server was
	 * slow or down every admin request that touched update data retried it —
	 * each one blocking the page on the request timeout, and together keeping
	 * the server overloaded.
	 *
	 * @param mixed $value data (version info) to cache.
	 *
	 * @return void
	 */
	private function set_cached_version_info( $value, $which ) {
		if ( ! $value ) {
			set_site_transient(
				$this->cache_key . $which,
				(object) [ 'se_sdk_check_failed' => time() ],
				SE_License_SDK_Client::jitter( max( MINUTE_IN_SECONDS, $this->get_failure_ttl() ) )
			);

			return;
		}

		$ttl = $this->get_cache_ttl();

		// The server may say how long this answer is good for (`next_check_in`),
		// so check frequency can be tuned without shipping a new SDK. Clamped so
		// a bad value can neither hammer the server nor hide updates for long.
		if ( is_object( $value ) && isset( $value->next_check_in ) && is_numeric( $value->next_check_in ) ) {
			$ttl = min( 7 * DAY_IN_SECONDS, max( HOUR_IN_SECONDS, (int) $value->next_check_in ) );
		}

		// ±10 % so sites don't all expire, and ask again, in lockstep.
		set_site_transient( $this->cache_key . $which, $value, SE_License_SDK_Client::jitter( max( MINUTE_IN_SECONDS, $ttl ), 0.1 ) );
	}

	/**
	 * Delete cached version info
	 * @return void
	 */
	public function delete_cached_version_info() {
		$this->runtime_cache = [];

		delete_site_transient( $this->cache_key );

		if ( $this->client->isPlugin() ) {
			delete_site_transient( 'update_plugins' );
		} else {
			delete_site_transient( 'update_themes' );
		}

		$actions = [ 'plugin_update', 'plugin_information', 'theme_update', 'theme_information' ];

		foreach ( $actions as $which ) {
			delete_site_transient( $this->cache_key . $which );
			delete_site_transient( $this->cache_key . $which . '_lock' );
		}

		delete_site_transient( $this->client->getHookName( 'versions_list' ) );
	}

	/**
	 * Get plugin info, cache first.
	 *
	 * Update envelopes (`*_update`) are never fetched by an ordinary request:
	 * a miss either runs the site-wide batch (cron, WP-CLI, "Check again") or
	 * schedules it in the background and returns false for now. The full
	 * `*_information` payload (the "View details" modal, REST package-info) and
	 * forced checks still fetch directly, with a short lock so concurrent
	 * requests don't all refetch the moment the cache expires.
	 *
	 * @param string $action
	 * @param bool $force Explicit user action ("Check for updates", WP-CLI): skip cache and lock.
	 *
	 * @return bool|object
	 */
	private function get_information( string $action, bool $force = false ) {
		if ( ! $force && array_key_exists( $action, $this->runtime_cache ) ) {
			return $this->runtime_cache[ $action ];
		}

		$project_info = $force ? false : $this->get_cached_version_info( $action );

		if ( $this->is_failure_marker( $project_info ) ) {
			return false;
		}

		if ( false !== $project_info ) {
			return $project_info;
		}

		if ( ! $force && $action === $this->get_update_action() ) {
			self::require_sibling( 'SE_License_SDK_Update_Batch' );

			if ( SE_License_SDK_Update_Batch::can_run_inline() ) {
				SE_License_SDK_Update_Batch::run();
				$project_info = $this->read_cache( $action );
			} else {
				SE_License_SDK_Update_Batch::schedule();
				$project_info = false;
			}

			$this->runtime_cache[ $action ] = $project_info;

			return $project_info;
		}

		$lock = $this->cache_key . $action . '_lock';

		if ( ! $force ) {
			if ( get_site_transient( $lock ) ) {
				// Another request is already refreshing this product.
				return false;
			}

			set_site_transient( $lock, 1, MINUTE_IN_SECONDS );
		}

		$project_info = $this->get_updates( $action, $force );

		$this->set_cached_version_info( $project_info, $action );

		delete_site_transient( $lock );

		$this->runtime_cache[ $action ] = $project_info;

		return $project_info;
	}

	/**
	 * `plugin_update` or `theme_update`.
	 *
	 * @return string
	 */
	private function get_update_action(): string {
		return $this->client->isPlugin() ? 'plugin_update' : 'theme_update';
	}

	/**
	 * Cached payload for an action, ignoring the forced-check bypass.
	 *
	 * @param string $action Action.
	 *
	 * @return object|false
	 */
	private function read_cache( string $action ) {
		$info = get_site_transient( $this->cache_key . $action );

		if ( ! is_object( $info ) || $this->is_failure_marker( $info ) || ( ! isset( $info->name ) && ! isset( $info->new_version ) ) ) {
			return false;
		}

		return $this->__children_to_array( $info, [ 'icons', 'banners', 'sections' ] );
	}

	/**
	 * Whether this product's update cache (or failure marker) has expired.
	 * Used by the batch to pick which products to ask about.
	 *
	 * @return bool
	 */
	public function needs_refresh(): bool {
		return false === get_site_transient( $this->cache_key . $this->get_update_action() );
	}

	/**
	 * Store the result of a batched check for this product.
	 *
	 * @param array $response `success` / `data` envelope, as returned by SE_License_SDK_Client::request().
	 *
	 * @return void
	 */
	public function store_update_response( array $response ) {
		$action = $this->get_update_action();

		unset( $this->runtime_cache[ $action ] );

		if ( ! empty( $response['success'] ) && isset( $response['data'] ) && is_array( $response['data'] ) ) {
			$this->set_cached_version_info( $this->process_update_data( $action, $response['data'] ), $action );

			return;
		}

		$this->store_update_failure();
	}

	/**
	 * Record a failed check so this product isn't asked about again until the
	 * failure back-off (or the server's breaker, whichever is longer) elapses.
	 *
	 * @param int $retry_in Seconds the server asked us to wait, if known.
	 *
	 * @return void
	 */
	public function store_update_failure( int $retry_in = 0 ) {
		$action = $this->get_update_action();

		unset( $this->runtime_cache[ $action ] );

		set_site_transient(
			$this->cache_key . $action,
			(object) [ 'se_sdk_check_failed' => time() ],
			max( MINUTE_IN_SECONDS, SE_License_SDK_Client::jitter( $this->get_failure_ttl() ), $retry_in )
		);
	}

	/**
	 * Fallback for servers without the batch route: one request for this product.
	 *
	 * @return void
	 */
	public function refresh_single() {
		$action = $this->get_update_action();

		unset( $this->runtime_cache[ $action ] );

		$this->set_cached_version_info( $this->get_updates( $action ), $action );
	}

	/**
	 * Read whatever update information is already stored locally — never
	 * contacts the license server.
	 *
	 * For code that runs on ordinary admin page loads (localized JS params,
	 * dashboards). Prefers the full `*_information` payload, then the
	 * `*_update` envelope, then the row WordPress keeps in its own update
	 * transient. The license gate is applied to whatever is returned.
	 *
	 * @return object|null
	 */
	public function get_cached_update_info() {
		$type = $this->client->isPlugin() ? 'plugin' : 'theme';

		foreach ( [ $type . '_information', $type . '_update' ] as $which ) {
			$info = get_site_transient( $this->cache_key . $which );

			if ( is_object( $info ) && ! $this->is_failure_marker( $info ) && isset( $info->new_version ) ) {
				return $this->strip_unlicensed_package( $this->__children_to_array( $info, [ 'icons', 'banners', 'sections' ] ) );
			}
		}

		if ( 'plugin' === $type ) {
			$wp  = get_site_transient( 'update_plugins' );
			$row = $wp->response[ $this->client->getBasename() ] ?? null;
		} else {
			$wp  = get_site_transient( 'update_themes' );
			$row = $wp->response[ $this->client->getSlug() ] ?? null;
			$row = is_array( $row ) ? (object) $row : $row;
		}

		if ( is_object( $row ) && isset( $row->new_version ) ) {
			return $this->strip_unlicensed_package( $row );
		}

		return null;
	}

	private function get_updates( $action, bool $force = false ) {
		// Updater doesn't need to care for license.
		// License key will be added to the request body by client (if available).
		// Server will provide update information without package/download link if license not available.
		// For free version response will contain the package/download link.

		$data = $this->client->get_admin_info();

		// Channel
		//$data['channel'] = 'beta';

		// Update -> check-update,
		// Background checks mirror wp_update_plugins(): a short timeout on a
		// page load so a slow license server can't stall wp-admin, a longer one
		// in cron or when the user explicitly asked.
		$timeout = ( $force || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) ? 15 : 5;

		$response = $this->client->request( [ 'body'  => $data, 'route' => 'check-update', 'timeout' => $timeout, 'interactive' => $force ] );

		if ( isset( $response['success'] ) && $response['success'] ) {
			$data = $response['data'];

			$this->client->apply_server_directives( is_array( $data ) ? $data : [] );

			if ( 'plugin_update' !== $action && 'theme_update' !== $action ) {
				// information -> package-info
				$response = $this->client->request( [
					'body'        => $this->client->get_admin_info(),
					'route'       => 'package-info',
					'timeout'     => $timeout,
					'interactive' => $force,
				] );

				if ( isset( $response['success'] ) && $response['success'] ) {
					$data = array_merge( $data, $response['data'] );
				}
			}

			return $this->process_update_data( $action, $data );
		}

		return false;
	}

	/**
	 * Turn a successful `check-update` answer (single or batched) into the
	 * cached payload, recording the check time and core requirement on the way.
	 *
	 * @param string $action Action.
	 * @param array  $data   Response data.
	 *
	 * @return object
	 */
	private function process_update_data( string $action, array $data ) {
		// Stamp the local "last checked" timestamp so the UI can render
		// "checked 2 minutes ago" without polling the server.
		self::require_sibling( 'SE_License_SDK_Update_State' );
		( new SE_License_SDK_Update_State( $this->client ) )->record_check();

		// Mirror the license server's per-release core-plugin requirement
		// (if any) so the dependency gate can read it during a later install
		// request. Stored even when empty so a dropped requirement clears.
		$required_core = ( isset( $data['requires_core']['min_version'] ) && is_string( $data['requires_core']['min_version'] ) )
			? $data['requires_core']['min_version']
			: '';
		( new SE_License_SDK_Update_State( $this->client ) )->set( [ 'required_core_version' => $required_core ] );

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

		return $this->strip_unlicensed_package( $this->get_information( 'plugin_information', ! empty( $args->force ) ) );
	}

	public function themes_api_filter( $data, string $action = '', $args = null ) {
		if ( 'theme_information' !== $action ) {
			return $data;
		}

		if ( ! isset( $args->slug ) || ( $args->slug !== $this->client->getSlug() ) ) {
			return $data;
		}

		return $this->strip_unlicensed_package( $this->get_information( 'theme_information', ! empty( $args->force ) ) );
	}

	/**
	 * Legacy invalidation hooks fired by the SDK's own PHP license form. Kept
	 * for consumers that render that form; every other path (REST, WP-CLI, the
	 * scheduled re-check) is covered by the license lifecycle events wired up in
	 * init(). Both are idempotent, so overlapping is harmless.
	 */
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
						// Was `(array) $input->{$child}` — reading an object
						// property off an array, which warns and yields [].
						$input[ $child ] = (array) $input[ $child ];
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
