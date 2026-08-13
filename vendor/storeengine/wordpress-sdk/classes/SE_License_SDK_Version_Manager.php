<?php
/**
 * SDK Version manager.
 */

declare( strict_types=1 );

final class SE_License_SDK_Version_Manager {
	/**
	 * SE_License_SDK_Version_Manager instance.
	 *
	 * @var SE_License_SDK_Version_Manager
	 */
	private static $instance = null;

	/**
	 * Versions.
	 *
	 * @var array<string, callable>
	 */
	private $versions = [];

	/**
	 * Registered sources.
	 *
	 * @var array<string, string>
	 */
	private $sources = [];

	/**
	 * Register version's callback.
	 *
	 * @param string $version_string Action Scheduler version.
	 * @param callable|string $initialization_callback Callback to initialize the version.
	 */
	public function register( string $version_string, $initialization_callback ): bool {
		if ( isset( $this->versions[ $version_string ] ) ) {
			return false;
		}

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace
		$backtrace = debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS );
		$source    = $backtrace[0]['file'];

		$this->versions[ $version_string ] = $initialization_callback;
		$this->sources[ $source ]          = $version_string;

		return true;
	}

	/**
	 * Get all versions.
	 */
	public function get_versions(): array {
		return $this->versions;
	}

	/**
	 * Get registered sources.
	 *
	 * Use with caution: this method is only available as of Action Scheduler's 3.9.1
	 * release and, owing to the way Action Scheduler is loaded, it's possible that the
	 * class definition used at runtime will belong to an earlier version.
	 *
	 * @return array<string, string>
	 */
	public function get_sources() {
		return $this->sources;
	}

	/**
	 * Get latest version registered.
	 */
	public function latest_version() {
		$keys = array_keys( $this->versions );
		if ( empty( $keys ) ) {
			return false;
		}

		uasort( $keys, 'version_compare' );

		return end( $keys );
	}

	/**
	 * Get callback for latest registered version.
	 */
	public function latest_version_callback() {
		$latest = $this->latest_version();

		if ( empty( $latest ) || ! isset( $this->versions[ $latest ] ) ) {
			return '__return_null';
		}

		return $this->versions[ $latest ];
	}

	/**
	 * Get instance.
	 *
	 * @return SE_License_SDK_Version_Manager
	 * @codeCoverageIgnore
	 */
	public static function instance() {
		if ( empty( self::$instance ) ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Initialize.
	 *
	 * @codeCoverageIgnore
	 */
	public static function initialize_latest_version() {
		$self = self::instance();
		call_user_func( $self->latest_version_callback() );
	}

	/**
	 * Returns information about the plugin or theme which contains the current active version
	 * of Action Scheduler.
	 *
	 * If this cannot be determined, or if Action Scheduler is being loaded via some other
	 * method, then it will return an empty array. Otherwise, if populated, the array will
	 * look like the following:
	 *
	 *     [
	 *         'type' => 'plugin', # or 'theme'
	 *         'name' => 'Name',
	 *     ]
	 *
	 * @return array
	 * @deprecated 3.9.2 Use ActionScheduler_SystemInformation::active_source().
	 *
	 */
	public function active_source(): array {
		_deprecated_function( __METHOD__, '3.9.2', 'ActionScheduler_SystemInformation::active_source()' );

		return ActionScheduler_SystemInformation::active_source();
	}

	/**
	 * Returns the directory path for the currently active installation of Action Scheduler.
	 *
	 * @return string
	 * @deprecated 3.9.2 Use ActionScheduler_SystemInformation::active_source_path().
	 *
	 */
	public function active_source_path(): string {
		_deprecated_function( __METHOD__, '3.9.2', 'ActionScheduler_SystemInformation::active_source_path()' );

		return ActionScheduler_SystemInformation::active_source_path();
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

// End of file SE_License_SDK_Version_Manager.php.