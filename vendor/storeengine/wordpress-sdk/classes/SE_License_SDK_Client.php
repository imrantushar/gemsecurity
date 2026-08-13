<?php

/**
 * Class Client
 */
final class SE_License_SDK_Client {

	/**
	 * The client/sdk version.
	 *
	 * @var string
	 */
	protected $version = null;

	/**
	 * API EndPoint.
	 *
	 * @var string
	 */
	protected $license_server;

	/**
	 * API NS.
	 *
	 * @var string
	 */
	protected $api_namespace = 'storeengine';

	/**
	 * API version.
	 *
	 * @var string
	 */
	protected $api_version = 'v1';

	/**
	 * Name of the Plugin/Theme.
	 *
	 * @var string
	 */
	protected $package_name;

	/**
	 * Is free package/software.
	 * @var bool
	 */
	protected $is_free = false;

	/**
	 * If initialize update for the plugin.
	 *
	 * @var bool
	 */
	protected $init_update = false;

	/**
	 * Initialize insights api (optin).
	 *
	 * @var bool
	 */
	protected $init_insights = false;

	/**
	 * Initialize promo api.
	 *
	 * @var bool
	 */
	protected $init_promotions = false;

	/**
	 * Initialize rest api.
	 *
	 * @var bool
	 */
	protected $init_restapi = false;

	/**
	 * @var ?string
	 */
	protected $product_logo = null;

	/**
	 * @var ?string
	 */
	protected $primary_color = null;

	/**
	 * The Plugin/Theme file path.
	 * Example ./../wp-content/Plugin/test-slug/test-slug.php.
	 *
	 * @var string
	 */
	protected $package_file;

	/**
	 * MD5 hash of package_file.
	 *
	 * @var string
	 */
	protected $package_file_hash;

	/**
	 * Main Plugin/Theme file.
	 * Example: test-slug/test-slug.php.
	 *
	 * @var string
	 */
	protected $basename;

	/**
	 * Slug of the Plugin/Theme.
	 * Example: test-slug.
	 *
	 * @var string
	 */
	protected $slug;

	/**
	 * The project purchase/checkout URL.
	 *
	 * @var string|null
	 */
	protected $purchase_url = null;

	/**
	 * The project version.
	 *
	 * @var string
	 */
	protected $package_version;

	/**
	 * The project type.
	 *
	 * @var string
	 */
	protected $type;

	/**
	 * Store Product (unique) id for current Product
	 *
	 * @var int
	 */
	protected $product_id = 0;

	/**
	 * Instance of Insights class.
	 *
	 * @var ?SE_License_SDK_Insights
	 */
	private $insights;

	/**
	 * Instance of Promotions class.
	 *
	 * @var ?SE_License_SDK_Promotions
	 */
	private $promotions;

	/**
	 * Instance of License class.
	 *
	 * @var ?SE_License_SDK_License
	 */
	private $license;

	/**
	 * Instance of Updater class.
	 *
	 * @var ?SE_License_SDK_Updater
	 */
	private $updater;

	/**
	 * Instance of Rest API class.
	 *
	 * @var ?SE_License_SDK_Rest_API
	 */
	private $rest_api;

	/**
	 * Per-client update UI state (previous_version, last_install_*, etc.).
	 *
	 * @var ?SE_License_SDK_Update_State
	 */
	private $update_state;

	private $js_param_name;

	/**
	 * Debug Mode Flag.
	 *
	 * @var bool
	 */
	protected $is_debug = false;

	/**
	 * Flag for allowing local request.
	 *
	 * @var bool
	 */
	protected $allow_local = false;

	/**
	 * Current Request IP.
	 * @var ?string
	 */
	protected $request_ip = null;

	protected $is_local_request = null;

	/**
	 * Software data.
	 * This holds all data across different installation under one option.
	 *
	 * @var ?array
	 */
	private $software_data = null;
	private $software_data_option = 'storeengine_sdk_software_data';

	private $is_dirty = false;

	/**
	 * Initialize the class.
	 *
	 * @param string $package_file Main Plugin/Theme file path.
	 * @param string $package_name Name of the Plugin/Theme.
	 * @param array $args {
	 *     Optional Args.
	 *                                    If null license page will show field for product id input.
	 *
	 * @type string $license_server License server URL.
	 * @type int $product_id Store product id for pro product.
	 *                           Default 0.
	 * @type string $slug Theme/Plugin Slug.
	 *                                    Default null (autodetect).
	 * @type string $basename File Basename.
	 *                                    Default null (autodetect).
	 * @type string $package_type Project Type Plugin/Theme.
	 *                                    Default null (autodetect).
	 * @type string $package_version Project Version. Theme/Plugin Version.
	 *                                    Default null (autodetect).
	 * }
	 *
	 * @return void
	 */
	private function __construct( string $package_file = '', string $package_name = '', array $args = [] ) {
		$package_file = $this->resolve_package_file( $package_file, $args );

		if ( ! $package_file || ! file_exists( $package_file ) || ! is_file( $package_file ) ) {
			$message = sprintf(
			/* translators: 1. Current Class Name. */
				esc_html__( 'Invalid argument. SDK could not detect a valid plugin or theme file while initializing %s(). Pass `package_file` explicitly if auto-detection fails.', 'storeengine-sdk' ),
				__CLASS__
			);
			_doing_it_wrong( __METHOD__, $message, '1.0.0' );

			throw new RuntimeException( 'License SDK initialization failed. A valid package file is required or must be auto-detected.' );
		}

		// Required Data.
		$this->package_file = wp_normalize_path( $package_file );
		$this->package_name = is_string( $package_name ) ? trim( $package_name ) : '';

		// Optional Params.
		$args = wp_parse_args( $args, [
			'is_free'         => false,
			'use_update'      => false,
			'license_server'  => null,
			'product_id'      => 0,
			'slug'            => null,
			'basename'        => null,
			'package_type'    => null,
			'package_version' => null,
			'allow_local'     => false,
			'product_logo'    => null,
			'primary_color'   => '#008DFF',
		] );

		if ( ! $args['license_server'] ) {
			throw new RuntimeException( 'License SDK initialization failed. License server must be set.' );
		}

		if ( ! absint( $args['product_id'] ) ) {
			throw new RuntimeException( 'License SDK initialization failed. License product ID must be set.' );
		}

		$this->is_free           = $args['is_free'];
		$this->init_update       = ! $this->is_free || $args['use_update'];
		$this->init_insights     = ! empty( $args['init_insights'] );
		$this->init_promotions   = ! empty( $args['init_promotions'] );
		$this->init_restapi      = ! empty( $args['init_restapi'] );
		$this->product_logo      = $args['product_logo'];
		$this->primary_color     = $args['primary_color'];
		$this->license_server    = $args['license_server'];
		$this->product_id        = absint( $args['product_id'] );
		$this->basename          = $args['basename'];
		$this->slug              = $args['slug'];
		$this->type              = $args['package_type'];
		$this->package_version   = $args['package_version'];

		if ( ! $this->basename || ! $this->slug || ! $this->type || ! $this->package_version ) {
			$this->set_basename_and_slug();
		}

		if ( ! $this->package_name ) {
			$this->package_name = $this->detect_package_name();
		}

		$this->package_file_hash = md5( $this->package_file . $this->slug . $this->product_id . $this->license_server );

		if ( $args['allow_local'] ) {
			$this->allow_local = true;
		}

		$this->js_param_name = 'SE_SDK_' . strtoupper( $this->normalize_key( $this->slug ) );

		if ( ! empty( $args['script_handler'] ) && is_string( $args['script_handler'] ) ) {
			if ( ! empty( $args['script_object'] ) && is_string( $args['script_object'] ) ) {
				$this->js_param_name = $this->normalize_key( $args['script_object'] );
			}
		}

		//http_request_reject_unsafe_urls
		add_filter( 'http_request_host_is_external', [ $this, 'allow_license_server' ], 10, 2 );
		add_action( 'shutdown', [ $this, 'save_software_data' ] );
	}

	public function allow_license_server( $allow, $host ) {
		if ( $this->get_license_server_host() === $host ) {
			return true;
		}

		return $allow;
	}

	/**
	 * Singleton instances.
	 *
	 * @var SE_License_SDK_Client[]
	 */
	private static $instances = [];

	public static function get_instance( string $package_file = '', string $package_name = '', string $sdk_version = null, array $args = [] ): SE_License_SDK_Client {
		$self = new self( $package_file, $package_name, $args );
		$self->set_sdk_version( $sdk_version );

		self::init( $self, $args );

		return $self;
	}

	protected static function init( SE_License_SDK_Client $client, array $args ) {
		$client->purchase_url = $args['purchase_url'] ?? null;

		if ( ! empty( $args['purchase_url'] ) && is_string( $args['purchase_url'] ) ) {
			$client->set_purchase_url(
				add_query_arg(
					[
						'utm_source'   => 'storeengine-sdk',
						'utm_medium'   => 'license-form',
						'utm_campaign' => 'license-activation-upsell',
						'utm_content'  => 'purchase-link',
						'utm_term'     => $client->getSlug(),
						'locale'       => get_locale(),
						'sdk_version'  => $client->getVersion(),
						'version'      => $client->getProjectVersion(),
						'wordpress'    => get_bloginfo( 'version' ),
						'type'         => $client->getType(),
						'instance'     => $client->get_device_id(),
					],
					$args['purchase_url']
				)
			);
		}

		if ( $client->maybe_init_insights() ) {
			// Init insights.
			$client->insights()
			       ->set_data_being_collected( $args['data_being_collected'] ?? null )
			       ->set_terms_url( $args['terms_url'] ?? '' )
			       ->set_privacy_policy_url( $args['privacy_policy_url'] ?? '' )
			       ->set_support_url( $args['support_url'] ?? '' )
			       ->set_support_response( $args['support_ticket_response'] ?? '' )
			       ->set_support_error_response( $args['support_ticket_error_response'] ?? '' )
			       ->set_ticket_template( $args['ticket_template'] ?? '' )
			       ->set_ticket_recipient( $args['ticket_recipient'] ?? '' );

			if ( ! empty( $args['first_install_time'] ) ) {
				$client->insights()->set_first_install_time( $args['first_install_time'] );
			}

			if ( ! empty( $args['optin_notice_delay'] ) ) {
				$client->insights()->set_optin_notice_delay( $args['optin_notice_delay'] );
			}

			if ( array_key_exists( 'should_show_optin', $args ) && ! $args['should_show_optin'] ) {
				$client->insights()->hide_optin_notice();
			}

			// Init insights.
			$client->insights()->init();
		}

		if ( $client->maybe_init_promotions() ) {
			// Init promos.
			$client->promotions()
			       ->set_source( $args['promo_source'] ?? null )
			       ->set_cache_ttl( $args['promo_cache_ttl'] ?? null );
			$client->promotions()->init();
		}

		if ( $client->isPro() ) {
			$client->license( ! empty( $args['redirect_on_activation'] ) )
			       ->set_header_message( $args['activation_prompt'] ?? null )
			       ->set_manage_license_url( $args['store_dashboard_url'] ?? null )
			       ->set_header_icon( $args['product_logo'] ?? null );

			$menu = array_key_exists( 'menu', $args ) ? $args['menu'] : [];

			if ( false !== $menu ) {
				if ( is_array( $menu ) ) {
					$client->license()->set_menu_args( array_filter( $menu ) )->add_settings_page();
				} else {
					$client->license()->set_page_url( $menu );
				}
			}

			$client->license()->init();
		}

		if ( $client->maybe_init_update() ) {
			// Enable updater.
			$client->updater()->init();
		}

		if ( $client->maybe_init_restapi() ) {
			// Init REST API.
			$client->rest_api()->init();
		}

		if ( ! empty( $args['script_handler'] ) && is_string( $args['script_handler'] ) ) {
			add_action( 'admin_enqueue_scripts', function () use ( $client, $args ) {
				wp_localize_script( $args['script_handler'], $client->get_js_param_name(), $client->get_js_params() );
			}, PHP_INT_MAX );
		}
	}

	protected function load_software_data() {
		if ( null === $this->software_data ) {
			// No hooks please...
			remove_all_filters( "pre_option_$this->software_data_option" );
			$this->software_data = get_option( $this->software_data_option );

			if ( ! $this->software_data || ! is_array( $this->software_data ) ) {
				$this->software_data = [];
			}

			$this->is_dirty = false;
		}
	}

	public function get_option( string $key, $default = null ) {
		$this->load_software_data();

		return $this->software_data[ $this->package_file_hash ][ $key ] ?? $default;
	}

	public function set_option( string $key, $value ) {
		$this->load_software_data();
		if ( empty( $this->software_data[ $this->package_file_hash ] ) ) {
			$this->software_data[ $this->package_file_hash ] = [];
		}

		$this->software_data[ $this->package_file_hash ][ $key ] = $value;
		// Flag for update data.
		$this->is_dirty = true;
	}

	public function save_software_data() {
		if ( ! $this->is_dirty ) {
			return;
		}

		$this->is_dirty = false;

		if ( ! is_array( $this->software_data ) ) {
			$this->software_data = [];
		}

		// Force save.
		$this->software_data['last-updated'] = current_time( 'mysql', 1 );

		update_option( $this->software_data_option, $this->software_data );
	}

	public function get_device_id(): string {
		$device_id = $this->get_option( 'device_id' );

		if ( ! $device_id ) {
			$device_id = $this->generate_device_id();
			$this->set_option( 'device_id', $device_id );
		}

		return $device_id;
	}

	/**
	 * Generates a sha256 hash.
	 * @return string
	 */
	private function generate_device_id(): string {
		if ( ! function_exists( 'wp_generate_password' ) ) {
			require_once ABSPATH . WPINC . '/pluggable.php';
		}

		$data = [
			wp_generate_password( 0x80, true, true ),
			site_url(),
			home_url(),
			$this->getPackageHash(),
			$this->getProductId(),
			$this->getProjectVersion(),
			$this->getSlug(),
			microtime(),
		];

		return wp_hash( implode( '||', $data ), 'auth', 'sha256' );
	}

	/**
	 * Set project basename, slug and version.
	 *
	 * @return void
	 */
	protected function set_basename_and_slug() {
		if ( str_starts_with( $this->package_file, wp_normalize_path( WPMU_PLUGIN_DIR ) ) || str_starts_with( $this->package_file, wp_normalize_path( WP_PLUGIN_DIR ) ) ) {
			$this->type     = 'plugin';
			$this->basename = plugin_basename( $this->package_file );
			list( $this->slug, ) = explode( '/', $this->basename );

			// Plugin Data Function
			if ( ! function_exists( 'get_plugin_data' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}

			if ( ! $this->package_version ) {
				$plugin_data           = get_plugin_data( $this->package_file );
				$this->package_version = $plugin_data['Version'];
			}
		} else {
			$this->type = 'theme';
			// SDK can be init from any file within the theme (not only the functions.php).
			// E.g. wp-content/themes/twenty-twenty-five/includes/lib/license.php
			// Extracted basename will be twenty-twenty-five/includes/lib/license.php
			// get_theme_root return theme root `wp-content/themes` without trailing-slash.
			$this->basename = str_replace( trailingslashit( get_theme_root() ), '', $this->package_file );

			// Slug will be the first part (dir-name) of the basename.
			list( $this->slug, ) = explode( '/', $this->basename );

			if ( ! $this->package_version ) {
				$theme                 = wp_get_theme( $this->slug );
				$this->package_version = $theme->get( 'Version' );
			}
		}
	}

	private function resolve_package_file( string $package_file, array $args ): string {
		$candidates = [];

		if ( ! empty( $package_file ) ) {
			$candidates[] = $package_file;
		}

		if ( ! empty( $args['package_file'] ) && is_string( $args['package_file'] ) ) {
			$candidates[] = $args['package_file'];
		}

		foreach ( $candidates as $candidate ) {
			$candidate = wp_normalize_path( $candidate );
			if ( file_exists( $candidate ) && is_file( $candidate ) ) {
				return $candidate;
			}
		}

		return self::detect_package_file_from_backtrace();
	}

	public static function detect_package_file( string $package_file = '', array $args = [] ): string {
		$candidates = [];

		if ( ! empty( $package_file ) ) {
			$candidates[] = $package_file;
		}

		if ( ! empty( $args['package_file'] ) && is_string( $args['package_file'] ) ) {
			$candidates[] = $args['package_file'];
		}

		foreach ( $candidates as $candidate ) {
			$candidate = wp_normalize_path( $candidate );
			if ( file_exists( $candidate ) && is_file( $candidate ) ) {
				return $candidate;
			}
		}

		return self::detect_package_file_from_backtrace();
	}

	private static function detect_package_file_from_backtrace(): string {
		$trace = debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS );
		$sdk_dir = wp_normalize_path( dirname( __DIR__ ) );

		foreach ( $trace as $frame ) {
			if ( empty( $frame['file'] ) || ! is_string( $frame['file'] ) ) {
				continue;
			}

			$file = wp_normalize_path( $frame['file'] );

			if ( str_starts_with( $file, $sdk_dir ) ) {
				continue;
			}

			if ( file_exists( $file ) && is_file( $file ) ) {
				return self::resolve_detected_package_file( $file );
			}
		}

		return '';
	}

	private static function resolve_detected_package_file( string $file ): string {
		$file = wp_normalize_path( $file );

		if ( self::is_plugin_file( $file ) ) {
			return self::detect_plugin_main_file( $file );
		}

		return $file;
	}

	private static function detect_plugin_main_file( string $file ): string {
		$plugin_root = trailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) );
		$mu_plugin_root = trailingslashit( wp_normalize_path( WPMU_PLUGIN_DIR ) );
		$relative_file = '';

		if ( str_starts_with( $file, $plugin_root ) ) {
			$relative_file = ltrim( substr( $file, strlen( $plugin_root ) ), '/' );
		} elseif ( str_starts_with( $file, $mu_plugin_root ) ) {
			$relative_file = ltrim( substr( $file, strlen( $mu_plugin_root ) ), '/' );
		}

		if ( ! $relative_file ) {
			return $file;
		}

		// Plugin Data Function
		if ( ! function_exists( 'get_plugins' ) || ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugin_headers = get_plugin_data( $file, false, false );
		if ( ! empty( $plugin_headers['Name'] ) ) {
			return $file;
		}

		$path_segments = explode( '/', $relative_file );
		$plugin_slug = $path_segments[0];
		$plugins = get_plugins( $plugin_slug );

		if ( empty( $plugins ) ) {
			return $file;
		}

		foreach ( $plugins as $plugin_basename => $plugin_data ) {
			if ( ! empty( $plugin_data['Name'] ) ) {
				return trailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) ) . $plugin_basename;
			}
		}

		return $file;
	}

	private static function is_plugin_file( string $file ): bool {
		$file = wp_normalize_path( $file );

		return str_starts_with( $file, trailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) ) )
			|| str_starts_with( $file, trailingslashit( wp_normalize_path( WPMU_PLUGIN_DIR ) ) );
	}

	private function detect_package_name(): string {
		if ( $this->isPlugin() ) {
			// Plugin Data Function
			if ( ! function_exists( 'get_plugin_data' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}

			$plugin_data = get_plugin_data( $this->package_file );

			if ( ! empty( $plugin_data['Name'] ) ) {
				return $plugin_data['Name'];
			}
		}

		if ( $this->isTheme() ) {
			$theme_name = wp_get_theme( $this->slug )->get( 'Name' );
			if ( $theme_name ) {
				return $theme_name;
			}
		}

		return ucwords( str_replace( [ '-', '_' ], ' ', $this->slug ) );
	}

	/**
	 * Initialize insights class.
	 *
	 * @return SE_License_SDK_Insights
	 */
	public function insights(): SE_License_SDK_Insights {
		if ( ! is_null( $this->insights ) ) {
			return $this->insights;
		}

		$this->insights = new SE_License_SDK_Insights( $this );

		return $this->insights;
	}

	/**
	 * Initialize Promotions class.
	 *
	 * @return SE_License_SDK_Promotions
	 */
	public function promotions(): SE_License_SDK_Promotions {
		if ( ! is_null( $this->promotions ) ) {
			return $this->promotions;
		}

		$this->promotions = new SE_License_SDK_Promotions( $this );

		return $this->promotions;
	}

	/**
	 * Initialize license checker.
	 *
	 * @return SE_License_SDK_License
	 */
	public function license( bool $redirect_on_activation = true ): SE_License_SDK_License {
		if ( $this->isFree() ) {
			throw new RuntimeException( 'Cannot initialize license for free product.' );
		}

		if ( ! is_null( $this->license ) ) {
			return $this->license;
		}

		$this->license = new SE_License_SDK_License( $this, $redirect_on_activation );

		return $this->license;
	}

	/**
	 * Initialize Plugin/Theme updater.
	 *
	 * @return SE_License_SDK_Updater
	 */
	public function updater(): SE_License_SDK_Updater {
		if ( ! is_null( $this->updater ) ) {
			return $this->updater;
		}

		$this->updater = new SE_License_SDK_Updater( $this );

		return $this->updater;
	}

	/**
	 * Per-client update UI state store.
	 */
	public function update_state(): SE_License_SDK_Update_State {
		if ( ! is_null( $this->update_state ) ) {
			return $this->update_state;
		}

		// Defensive load — see require_sibling() in Updater.php for why.
		if ( ! class_exists( 'SE_License_SDK_Update_State', false ) ) {
			$path = __DIR__ . DIRECTORY_SEPARATOR . 'SE_License_SDK_Update_State.php';
			if ( is_readable( $path ) ) {
				require_once $path;
			}
		}

		$this->update_state = new SE_License_SDK_Update_State( $this );

		return $this->update_state;
	}

	/**
	 * Build a fresh Install_Job. A new job is created per install request so
	 * each REST call gets its own job_id + log slot.
	 */
	public function new_install_job(): SE_License_SDK_Install_Job {
		// Defensive load.
		if ( ! class_exists( 'SE_License_SDK_Install_Job', false ) ) {
			$path = __DIR__ . DIRECTORY_SEPARATOR . 'SE_License_SDK_Install_Job.php';
			if ( is_readable( $path ) ) {
				require_once $path;
			}
		}

		return new SE_License_SDK_Install_Job( $this );
	}

	public function get_js_params(): array {
		$data = [
			'device_id' => $this->get_device_id(),
			'version'   => $this->getVersion(),
			'locale'    => get_locale(),
			'wordpress' => get_bloginfo( 'version' ),
		];

		if ( $this->maybe_init_restapi() ) {
			$data['rest_url'] = trailingslashit( rest_url( '/storeengine-sdk/v1/' . $this->getSlug() ) );
			$data['nonce'] = wp_create_nonce( 'wp_rest' );
		}

		if ( $this->isPro() ) {
			$data['license'] = $this->license()->get_public_data();
		}

		if ( $this->maybe_init_update() ) {
			$data['package'] = [
				'version' => $this->getProjectVersion(),
				'type'    => $this->getType(),
			];

			if ( 'plugin' === $this->getType() ) {
				$update = $this->updater()->plugins_api_filter( false, 'plugin_information', (object) [ 'slug' => $this->getSlug(), ] );
			} else {
				$update = $this->updater()->themes_api_filter( false, 'theme_information', (object) [ 'slug' => $this->getSlug(), ] );
			}

			$data['package']['update'] = $update;
			$data['package']['need_update'] = $update ? version_compare( $this->getProjectVersion(), $update->new_version, '<' ): false;
		}

		if ( $this->maybe_init_insights() ) {
			$data['optin'] = [
				'allowed'   => $this->insights()->is_tracking_allowed(),
				'show'      => ! $this->insights()->is_notice_dismissed(),
				'last_send' => $this->insights()->get_last_send(),
			];
		}

		if ( $this->maybe_init_promotions() ) {
			$data['promos'] = $this->promotions()->get_promos();
		}

		return $data;
	}

	public function get_js_param_name(): string {
		return $this->js_param_name;
	}

	/**
	 * Initialize REST API.
	 *
	 * @return SE_License_SDK_Rest_API
	 */
	public function rest_api(): SE_License_SDK_Rest_API {
		if ( ! is_null( $this->rest_api ) ) {
			return $this->rest_api;
		}

		$this->rest_api = new SE_License_SDK_Rest_API( $this );

		return $this->rest_api;
	}

	/**
	 * API Endpoint.
	 *
	 * @param string $route Route to send the request.
	 *
	 * @return string
	 */
	private function endpoint( string $route ): string {
		/**
		 * Filter Request Route string
		 *
		 * @param string $route
		 * @param array $params
		 */
		$route = apply_filters( $this->getHookName( 'client_request_route' ), $route );

		// Server Endpoint.
		$license_server = $this->getLicenseserver();

		// Clean Route Slug.
		$route = rtrim( ltrim( $route, '/\\' ), '/\\' );

		// Backend (license server) admin can change the rest-route prefix (wp-json) via `rest_url_prefix` filter hook.
		// Regardless of permalink settings & rest-route prefix this plain permalink structure always works.
		$endpoint = $license_server . '/index.php?rest_route=/' . $this->getApiNamespace() . '/' . $this->getApiVersion() . '/software/' . $route . '/';

		/**
		 * Filter Final API URL for request
		 *
		 * @param string $endpoint
		 * @param string $route
		 * @param string $apiNamespace
		 * @param string $apiVersion
		 * @param string $sdkVersion
		 */
		return apply_filters(
			$this->getHookName( 'client_request_endpoint' ),
			$endpoint,
			$route,
			$this->getApiNamespace(),
			$this->getApiVersion(),
			$this->version
		);
	}

	public function set_debug_mode( bool $mode = false ) {
		$this->is_debug = $mode;
	}

	public function is_debug() {
		return apply_filters( $this->getHookName( 'client_is_debugging' ), $this->is_debug );
	}

	public function set_allow_local_request( bool $allow = true ): SE_License_SDK_Client {
		$this->allow_local = $allow;

		return $this;
	}

	/**
	 * Get Current Request IP
	 * @return string
	 * @noinspection PhpPregSplitWithoutRegExpInspection
	 * @noinspection RegExpRedundantEscape
	 */
	protected function get_request_ip(): string {
		if ( null === $this->request_ip ) {
			// Return empty string if no valid IP is found
			$this->request_ip = '';

			if ( isset( $_SERVER['HTTP_X_REAL_IP'] ) ) {
				$this->request_ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
			} elseif ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
				// Proxy servers can send through this header like this: X-Forwarded-For: client1, proxy1, proxy2
				// Make sure we always only send through the first IP in the list which should always be the client IP.
				$value = trim( current( preg_split( '/,/', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) ) ) );
				// Account for the '<IPv4 address>:<port>', '[<IPv6>]' and '[<IPv6>]:<port>' cases, removing the port.
				// The regular expression is oversimplified on purpose, later 'rest_is_ip_address' will do the actual IP address validation.
				$value            = preg_replace( '/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\:.*|\[([^]]+)\].*/', '$1$2', $value );
				$this->request_ip = (string) rest_is_ip_address( $value );
			} elseif ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
				// Make sure we always only send through the first IP in the list which should always be the client IP.
				$value            = trim( current( preg_split( '/,/', sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) ) ) );
				$this->request_ip = (string) rest_is_ip_address( $value );
			}
		}

		return $this->request_ip;
	}

	public function get_server_ip_address(): string {
		$response = wp_remote_get( 'https://icanhazip.com/' );
		if ( ! is_wp_error( $response ) ) {
			$ip = trim( wp_remote_retrieve_body( $response ) );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}

		return filter_var( wp_unslash( $_SERVER['SERVER_ADDR'] ), FILTER_VALIDATE_IP );
	}

	/**
	 * Check if the current server is localhost
	 *
	 * @return boolean
	 */
	public function is_local_request(): bool {
		// If local is allowed, then local request should return false in all cases.
		if ( null === $this->is_local_request ) {
			if ( $this->allow_local ) {
				$this->is_local_request = false; // allow all request.
			} else if ( php_sapi_name() === 'phpdbg' || 'development' === wp_get_environment_type() ) {
				$this->is_local_request = true; // local/dev env block request.
			} else if ( 'cli' !== php_sapi_name() ) {
				$this->is_local_request = in_array( $this->get_request_ip(), [
					'127.0.0.1',
					'::1'
				], true ); // is local request
			} else {
				$this->is_local_request = false;
			}
		}

		return $this->is_local_request;
	}

	/**
	 * Client UserAgent String.
	 *
	 * Outputs
	 *
	 * `SE-Client-SDK/1.1.0 (Plugin test-project/2.1.0; WordPress/6.8.3; OS Darwin/arm64; PHP/7.4.33) "Test Blog" https://test-blog.com`
	 *
	 * `SE-Client-SDK/1.1.0 (Theme test-project/2.1.0; WordPress/6.8.3; OS Darwin/arm64; PHP/7.4.33) "Test Blog" https://test-blog.com`
	 *
	 * @return string
	 */
	private function get_user_agent(): string {
		global $wp_version;

		// %1$s: SDK Client Version
		// %2$s: Product/Package Type (Plugin/Theme)
		// %3$s: Product/Package Slug
		// %4$s: Product/Package Version
		// %5$s: WordPress Core Version
		// %6$s: OS Name
		// %7$s: OS Arch
		// %8$s: PHP Version
		// %9$s: Site Name
		// %10$s: Site URL

		return sprintf(
			'SE-Client-SDK/%1$s (%2$s %3$s/%4$s; WordPress/%5$s; OS %6$s/%7$s; PHP/%8$s) "%9$s" %10$s',
			$this->version,
			ucfirst( $this->type ),
			$this->getSlug(),
			$this->package_version,
			$wp_version,
			PHP_OS_FAMILY,
			php_uname( 'm' ) ?: ( PHP_INT_SIZE === 8 ? 'x86_64' : 'x86' ),
			PHP_VERSION,
			get_option( 'blogname' ),
			site_url()
		);
	}

	/**
	 * Send request to remote endpoint.
	 *
	 * @param array $args {
	 * @type array $body Parameters/Data that being sent.
	 * @type string $route Route to send the request to.
	 * }
	 *
	 * @return array|WP_Error   Array of results including HTTP headers or WP_Error if the request failed.
	 */
	public function request( array $args = [] ) {
		$args = wp_parse_args( $args, [
			'route'    => '',
			'body'     => [],
			'method'   => 'POST',
			'timeout'  => 45, // phpcs:ignore WordPressVIPMinimum.Performance.RemoteRequestTimeout.timeout_timeout
			'url'      => false,
		] );

		// Request URL
		$url = $args['route'] ? esc_url_raw( $this->endpoint( $args['route'] ) ) : null;

		if ( ! $url && $args['url'] && str_starts_with( $args['url'], 'https://' ) ) {
			$url = $args['url'];
			unset( $args['url'] );
		}

		if ( ! $url ) {
			return new WP_Error( 'se_srv_invalid_url_or_route', __( 'Invalid URL or route.' ) );
		}

		// Request Headers
		$headers = [
			'User-Agent' => $this->get_user_agent(),
			'Accept'     => 'application/json',
		];

		/**
		 * Before request to api server.
		 *
		 * @param array $params
		 * @param string $route
		 * @param array $headers
		 * @param string $clientVersion
		 * @param string $url
		 */
		do_action( $this->getHookName( 'before_client_request' ), $args, $headers, $this->version, $url );

		/**
		 * Before request to api server to route.
		 *
		 * @param array $params
		 * @param string $route
		 * @param array $headers
		 * @param string $clientVersion
		 * @param string $url
		 */
		do_action( $this->getHookName( 'before_client_request_' . $args['route'] ), $args, $headers, $this->version, $url );

		$timeout  = $this->validate_timeout( $args );

		// Body. Caller-provided fields win over auto-added defaults — this
		// matters for routes like /software/get-package where `version`
		// means "which version's zip to fetch" rather than the SDK's
		// default meaning of "currently installed plugin version". Before
		// 1.5.2 the order was reversed and `version` was always clobbered
		// by getProjectVersion(), so rollback always re-downloaded the
		// currently-installed version's zip.
		$body = array_merge( [
			'is_free'     => $this->is_free,
			'slug'        => $this->getSlug(),
			'site_url'    => site_url(),
			'product_id'  => $this->getProductId(),
			'version'     => $this->getProjectVersion(),
			'sdk_version' => $this->getVersion(),
			'device_id'   => $this->get_device_id(),
			'locale'      => get_locale(),
		], $args['body'] );

		// Add license info for every request, if available.
		if ( ! $this->is_free && $this->license() && $this->license()->get_key() && empty( $body['license'] ) ) {
			$body['license'] = $this->license()->get_key();
		}

		$ssl_verify   = apply_filters( 'https_local_ssl_verify', true ); // phpcs:ignore WordPressVIPMinimum.Performance.RemoteRequestTimeout.timeout_timeout
		$request_args = [
			'method'      => strtoupper( $args['method'] ),
			'timeout'     => $timeout,
			'sslverify'   => $ssl_verify,
			'redirection' => 5,
			'httpversion' => '1.0',
			'blocking'    => true, // always true, as license server unable save data without blocking requests.
			'headers'     => $headers,
			'body'        => $body,
			'cookies'     => [],
		];

		add_filter( 'http_request_reject_unsafe_urls', '__return_false' );

		if ( $this->is_debug() ) {
			$response = wp_remote_request( $url, $request_args ); // phpcs:ignore -- Debugging only.
		} else {
			// Vip doesn't have post method. only _request & _get.
			if ( function_exists( 'vip_safe_wp_remote_request' ) ) {
				// @see https://github.com/Automattic/vip-go-mu-plugins-built/blob/7cc16c7b0006a0d11f8cc402ccbc8b44553aa5e6/vip-helpers/vip-utils.php#L810
				$response = vip_safe_wp_remote_request( $url, '', 10, $timeout, 20, $request_args );
			} else {
				$response = wp_safe_remote_request( $url, $request_args );
			}
		}

		remove_filter( 'http_request_reject_unsafe_urls', '__return_false' );

		/**
		 * After request to api server.
		 *
		 * @param array $response
		 * @param string $route
		 */
		do_action( $this->getHookName( 'after_client_request' ), $response, $args['route'] );

		/**
		 * After request to api server to route.
		 *
		 * @param array $response
		 * @param string $route
		 */
		do_action( $this->getHookName( 'after_client_request_' . $args['route'] ), $response, $args['route'] );

		$routes = [ 'activate-license', 'deactivate-license', 'check-license', 'package-info', 'check-update' ];

		if ( in_array( $args['route'], $routes, true ) ) {
			if ( is_wp_error( $response ) ) {
				return [
					'success' => false,
					'error'   => $response->get_error_message(),
					'code'    => $response->get_error_code(),
					'data'    => $response->get_error_data( $response->get_error_code() ),
				];
			}

			$code = wp_remote_retrieve_response_code( $response );
			$body = wp_remote_retrieve_body( $response );
			$body = json_decode( $body, true );

			if ( 201 === $code && ! $response ) {
				return [
					'success' => true,
					'message' => $body['message'] ?? __( 'Operation successful.', 'storeengine-sdk' ),
					'data'    => []
				];
			}

			if ( $code && $code >= 400 ) {
				return [
					'success' => false,
					'error'   => $body['message'] ?? __( 'Unknown error.', 'storeengine-sdk' ),
					'code'    => $body['code'] ?? 'UNKNOWN_ERROR',
					'data'    => $body['data'] ?? [],
				];
			}

			$message = $body['message'] ?? __( 'Operation successful.', 'storeengine-sdk' );

			unset( $body['message'] );

			return [
				'success' => true,
				'message' => $message,
				'data'    => $body,
			];
		}

		return $response;
	}

	/**
	 * Validate timeout for remote request.
	 * Ensures compatibility with WP-VIP remote-request (suppress triggering _doing_it_wrong)
	 * @see https://github.com/Automattic/vip-go-mu-plugins-built/blob/7cc16c7b0006a0d11f8cc402ccbc8b44553aa5e6/vip-helpers/vip-utils.php#L829-L849
	 *
	 * @param array $args
	 *
	 * @return float|int
	 */
	protected function validate_timeout( array $args ) {
		$is_post_request = 0 === strcasecmp( 'POST', $args['method'] );

		// WP-VipCom default timeout is 1.
		$timeout = isset( $args['timeout'] ) && $args['timeout'] ? abs( $args['timeout'] ) : 1; // phpcs:ignore WordPressVIPMinimum.Performance.RemoteRequestTimeout.timeout_timeout

		if ( defined( 'WP_CLI' ) && WP_CLI && $is_post_request ) {
			if ( 30 < $timeout ) {
				// Remote POST request timeouts are capped at 30 seconds in WP-CLI for performance and stability reasons.
				$timeout = 30;
			}
		} elseif ( is_admin() && $is_post_request ) {
			if ( 15 < $timeout ) {
				// Remote POST request timeouts are capped at 15 seconds for admin requests for performance and stability reasons.
				$timeout = 15;
			}
		} else {
			// Frontend Request.
			if ( $timeout > 5 ) {
				// Remote request timeouts are capped at 5 seconds for performance and stability reasons.
				$timeout = 5;
			}
		}

		return $timeout;
	}

	/**
	 * Get Version of this client.
	 *
	 * @return string
	 */
	public function getVersion(): string {
		return $this->version;
	}

	public function set_sdk_version( string $version ): self {
		$this->version = $version;

		return $this;
	}

	/**
	 * Get API URI.
	 *
	 * @return string
	 */
	public function getLicenseServer(): string {
		return untrailingslashit( $this->license_server );
	}

	/**
	 * Get API URI Host.
	 *
	 * @return string
	 * @see wp_http_validate_url()
	 *
	 */
	public function get_license_server_host(): string {
		return trim( parse_url( $this->getLicenseserver(), PHP_URL_HOST ), '.' );
	}

	/**
	 * Get API Version using by this client.
	 *
	 * @return string
	 */
	public function getApiNamespace(): string {
		return $this->api_namespace;
	}

	/**
	 * Get API Version using by this client.
	 *
	 * @return string
	 */
	public function getApiVersion(): string {
		return $this->api_version;
	}

	/**
	 * Get Plugin/Theme Name.
	 *
	 * @return string
	 */
	public function getPackageName(): string {
		return $this->package_name;
	}

	public function isFree(): bool {
		return $this->is_free;
	}

	public function isPro(): bool {
		return ! $this->isFree();
	}

	public function maybe_init_update(): bool {
		return $this->init_update;
	}

	public function maybe_init_insights(): bool {
		return $this->init_insights;
	}

	public function maybe_init_promotions(): bool {
		return $this->init_promotions;
	}

	public function maybe_init_restapi(): bool {
		return $this->init_restapi;
	}

	/**
	 * Store Product ID.
	 *
	 * @return int
	 */
	public function getProductId(): int {
		return $this->product_id;
	}

	/**
	 * Get Plugin/Theme file.
	 *
	 * @return string
	 */
	public function getPackageFile(): string {
		return $this->package_file;
	}

	/**
	 * Get Plugin/Theme base name.
	 *
	 * @return string
	 */
	public function getBasename(): string {
		return $this->basename;
	}

	/**
	 * Get Plugin/Theme Slug.
	 *
	 * @return string
	 */
	public function getSlug(): string {
		return $this->slug;
	}

	/**
	 * Get Plugin/Theme Slug.
	 *
	 * @return ?string
	 */
	public function getProductLogo() {
		return $this->product_logo;
	}

	public function getPrimaryColor(): string {
		return $this->primary_color;
	}

	public function printPrimaryColor() {
		echo esc_attr( $this->primary_color );
	}

	/**
	 * Get Package Hash
	 *
	 * @return string
	 */
	public function getPackageHash(): string {
		return $this->package_file_hash;
	}

	/**
	 * Get hook name for do_action/apply_filters
	 *
	 * @param string $hook
	 *
	 * @return string returns prefixed hook-name (`se_srv_sdk_(theme|plugin)_*hash*_*(theme|plugin)-slug*_*hook-name*`)
	 */
	public function getHookName( string $hook ): string {
		return 'se_srv_sdk_' . $this->getType() . '_' . $this->getPackageHash() . '_' . $this->getSlug() . '_' . ltrim( rtrim( $hook, '_-' ), '_-' );
	}

	public function do_action( $hook_name, ...$arg ) {
		do_action( $this->getHookName( $hook_name ), ...$arg );
	}

	/**
	 * Adds a callback function to a prefixed action hook.
	 *
	 * @param string $hook_name
	 * @param callable|string $callback
	 * @param int $priority
	 * @param int $accepted_args
	 *
	 * @return true
	 */
	public function add_action( string $hook_name, $callback, int $priority = 10, int $accepted_args = 1 ): bool {
		return add_action( $this->getHookName( $hook_name ), $callback, $priority, $accepted_args );
	}

	public function apply_filters( string $hook_name, $value, ...$args ) {
		return apply_filters( $this->getHookName( $hook_name ), $value, ...$args );
	}

	/**
	 * Adds a callback function to a prefixed filter hook.
	 *
	 * @param string $hook_name
	 * @param callable|string $callback
	 * @param int $priority
	 * @param int $accepted_args
	 *
	 * @return true
	 */
	public function add_filter( string $hook_name, $callback, int $priority = 10, int $accepted_args = 1 ): bool {
		return add_filter( $this->getHookName( $hook_name ), $callback, $priority, $accepted_args );
	}

	public function set_purchase_url( string $purchase_url = null ) {
		$this->purchase_url = $purchase_url;
	}

	public function get_purchase_url() {
		return $this->purchase_url;
	}

	/**
	 * Get Plugin/Theme Project Version.
	 *
	 * @return string
	 */
	public function getProjectVersion(): string {
		return $this->package_version;
	}

	/**
	 * Get Project Type Plugin/Theme.
	 *
	 * @return string plugin or theme
	 */
	public function getType(): string {
		return $this->type;
	}

	public function isPlugin(): bool {
		return 'plugin' === $this->type;
	}

	public function isTheme(): bool {
		return 'theme' === $this->type;
	}

	public function normalize_key( string $input ): string {
		// Replace non-alphanumeric with underscore
		$str = preg_replace( '/[^a-zA-Z0-9]+/', '_', $input );

		// Collapse multiple underscores into one
		$str = preg_replace( '/_+/', '_', $str );

		// Trim leading/trailing underscores
		$str = trim( $str, '_' );

		// Convert to uppercase
		return $str;
	}

	/**
	 * Get Site SuperAdmin
	 * Returns Empty WP_User instance if fails
	 * @return WP_User
	 */
	public function get_admin_data(): WP_User {
		$admins = get_users(
			[
				'role'    => 'administrator',
				'orderby' => 'ID',
				'order'   => 'ASC',
				'number'  => 1,
				'paged'   => 1,
			]
		);

		return ( is_array( $admins ) && ! empty( $admins ) ) ? $admins[0] : new WP_User();
	}

	public function get_admin_info(): array {
		$admin_user   = $this->get_admin_data();
		$admin_emails = array_unique( array_filter( [ get_option( 'admin_email' ), $admin_user->user_email ] ) );
		$admin_emails = implode( ',', $admin_emails );
		$admin_name   = isset( $admin_user->first_name ) && $admin_user->first_name ? trim( $admin_user->first_name . ' ' . $admin_user->last_name ) : $admin_user->display_name;

		return [ 'admin_email' => $admin_emails, 'admin_name' => $admin_name ];
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

// End of file SE_License_SDK_Client.php.
