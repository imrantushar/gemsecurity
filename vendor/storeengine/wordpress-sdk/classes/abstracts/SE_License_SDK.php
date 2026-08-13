<?php

/**
 * Class SE_License_SDK
 *
 * @codeCoverageIgnore
 */
abstract class SE_License_SDK {

	/**
	 * SDK init.php file path.
	 *
	 * @var string
	 */
	private static $sdk_init_file;

	/**
	 * SDK installation directory with trailing slash.
	 *
	 * @var string
	 */
	private static $sdk_dir_path;

	/**
	 * SDK Version.
	 *
	 * @var string
	 */
	private static $sdk_version;

	/**
	 * Data store is initialized.
	 *
	 * @var bool
	 */
	private static $sdk_initialized = false;

	/**
	 * @var array<string, SE_License_SDK_Client>
	 */
	private static $registered = [];

	/**
	 * Get the absolute system path to the sdk directory, or a file therein
	 *
	 * @static
	 *
	 * @param ?string $path Path relative to sdk directory.
	 *
	 * @return string
	 */
	public static function sdk_path( ?string $path ): string {
		if ( ! $path ) {
			return self::$sdk_dir_path;
		}

		return self::$sdk_dir_path . ltrim( $path, '/\\' );
	}

	/**
	 * Get the absolute URL to the sdk directory, or a file therein
	 *
	 * @static
	 *
	 * @param string $path Path relative to sdk directory.
	 *
	 * @return string
	 */
	public static function sdk_url( string $path ): string {
		if (
			str_starts_with( self::$sdk_init_file, wp_normalize_path( WPMU_PLUGIN_DIR ) ) ||
			str_starts_with( self::$sdk_init_file, wp_normalize_path( WP_PLUGIN_DIR ) )
		) {
			return trailingslashit( plugin_dir_url( self::$sdk_init_file ) ) . ltrim( $path, '/\\' );
		}

		$theme_root = wp_normalize_path( trailingslashit( get_theme_root() ) );
		$relative_sdk_dir = ltrim( substr( self::$sdk_dir_path, strlen( $theme_root ) ), '/\\' );

		return trailingslashit( get_theme_root_uri() ) . trailingslashit( $relative_sdk_dir ) . ltrim( $path, '/\\' );
	}

	/**
	 * Autoload.
	 *
	 * @param string $class Class name.
	 */
	public static function autoload( string $class ) {
		$ds          = DIRECTORY_SEPARATOR;
		$classes_dir = self::sdk_path( 'classes' . $ds );
		$separator   = strrpos( $class, '\\' );
		if ( false !== $separator ) {
			if ( 0 !== strpos( $class, 'SE_License_SDK' ) ) {
				return;
			}
			$class = substr( $class, $separator + 1 );
		}

		if ( self::is_class_abstract( $class ) ) {
			$dir = $classes_dir . 'abstracts' . $ds;
		} elseif ( strpos( $class, 'SE_License_SDK' ) === 0 ) {
			$segments = explode( '_', $class );
			$type     = $segments[1] ?? '';

			switch ( $type ) {
				case 'WPCLI':
					$dir = $classes_dir . 'WP_CLI' . $ds;
					break;
				default:
					$dir = $classes_dir;
					break;
			}
		} elseif ( self::is_class_cli( $class ) ) {
			$dir = $classes_dir . 'WP_CLI' . $ds;
		} elseif ( strpos( $class, 'WP_Async_Request' ) === 0 ) {
			$dir = self::sdk_path( 'lib' . $ds );
		} else {
			return;
		}

		if ( file_exists( $dir . "{$class}.php" ) ) {
			include $dir . $class . '.php';
		}
	}

	/**
	 * Initialize the plugin
	 *
	 * @static
	 *
	 * @param string $sdk_init_file Plugin file path.
	 */
	public static function init( string $sdk_init_file, string $version ): void {
		self::$sdk_init_file = wp_normalize_path( realpath( $sdk_init_file ) );
		self::$sdk_dir_path  = trailingslashit( dirname( self::$sdk_init_file ) );
		self::$sdk_version   = $version;

		spl_autoload_register( [ __CLASS__, 'autoload' ] );

		/**
		 * Fires in the early stages of Action Scheduler init hook.
		 */
		do_action( 'se_license_sdk_pre_init' );

		require_once self::sdk_path( 'functions.php' );

		// Ensure initialization on plugin activation.
		if ( ! did_action( 'init' ) ) {
			add_action(
				'init',
				/**
				 * Runs after the active store's init() method has been called.
				 *
				 * It would probably be preferable to have $store->init() (or it's parent method) set this itself,
				 * once it has initialized, however that would cause problems in cases where a custom data store is in
				 * use, and it has not yet been updated to follow that same logic.
				 */
				function () {
					self::$sdk_initialized = true;

					/**
					 * Fires when Action Scheduler is ready: it is safe to use the procedural API after this point.
					 */
					do_action( 'se_license_sdk_init' );
				},
				PHP_INT_MIN // As early as possible.
			);
		} else {
			self::$sdk_initialized = true;

			/**
			 * Fires when Action Scheduler is ready: it is safe to use the procedural API after this point.
			 */
			do_action( 'se_license_sdk_init' );
		}
	}

	public static function register( string $file = '', string $name = '', array $args = [] ): SE_License_SDK_Client {
		$registered_file = SE_License_SDK_Client::detect_package_file( $file, $args );

		if ( ! empty( $registered_file ) && ! empty( self::$registered[ $registered_file ] ) ) {
			return self::$registered[ $registered_file ];
		}

		$client = SE_License_SDK_Client::get_instance( $file, $name, self::$sdk_version, $args, );
		$client->set_sdk_version( self::$sdk_version );

		$registered_file = $client->getPackageFile();

		if ( empty( self::$registered[ $registered_file ] ) ) {
			self::$registered[ $registered_file ] = $client;
		}

		return self::$registered[ $registered_file ];
	}

	/**
	 * Get registered client by product slug.
	 *
	 * @param string $file Absolute file path for client.
	 *
	 * @return ?SE_License_SDK_Client
	 */
	public static function get_registered( string $file ): ?SE_License_SDK_Client {
		return $file && array_key_exists( $file, self::$registered ) ? self::$registered[ $file ] : null;
	}

	/**
	 * Check whether the AS data store has been initialized.
	 *
	 * @param ?string $function_name The name of the function being called. Optional. Default `null`.
	 *
	 * @return bool
	 */
	public static function is_initialized( ?string $function_name = null ): bool {
		if ( ! self::$sdk_initialized && ! empty( $function_name ) ) {
			$message = sprintf(
			/* translators: %s function name. */
				__( '%s() was called before the StoreEngine License Manager Client SDK was initialized', 'se-license' ),
				esc_attr( $function_name )
			);
			_doing_it_wrong( esc_html( $function_name ), esc_html( $message ), '1.0.0' );
		}

		return self::$sdk_initialized;
	}

	/**
	 * Determine if the class is one of our abstract classes.
	 *
	 * @param string $class The class name.
	 *
	 * @return bool
	 */
	protected static function is_class_abstract( string $class ): bool {
		static $abstracts = [
			'SE_License_SDK'               => true,
			'SE_License_SDK_WPCLI_Command' => true,
		];

		return isset( $abstracts[ $class ] ) && $abstracts[ $class ] || false !== strpos( $class, 'SE_License_SDK_Abstract_' );
	}

	/**
	 * Determine if the class is one of our WP CLI classes.
	 *
	 * @param string $class The class name.
	 *
	 * @return bool
	 */
	protected static function is_class_cli( string $class ): bool {
		static $cli_segments = array(
			'QueueRunner'                             => true,
			'Command'                                 => true,
			'ProgressBar'                             => true,
			'\Action_Scheduler\WP_CLI\Action_Command' => true,
			'\Action_Scheduler\WP_CLI\System_Command' => true,
		);

		$segments = explode( '_', $class );
		$segment  = $segments[1] ?? $class;

		return isset( $cli_segments[ $segment ] ) && $cli_segments[ $segment ];
	}

	/**
	 * Clone.
	 */
	final public function __clone() {
		trigger_error( 'Singleton. No cloning allowed!', E_USER_ERROR ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error
	}

	/**
	 * Wakeup.
	 */
	final public function __wakeup() {
		trigger_error( 'Singleton. No serialization allowed!', E_USER_ERROR ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error
	}

	/**
	 * Construct.
	 */
	final private function __construct() {
	}
}

// End of file SE_License_SDK.php.
