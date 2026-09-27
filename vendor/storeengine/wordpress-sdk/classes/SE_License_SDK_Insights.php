<?php
/**
 * Class Insights
 */
final class SE_License_SDK_Insights {

	/**
	 * The notice text
	 *
	 * @var string
	 */
	protected $notice;

	/**
	 * Whether to the notice or not
	 *
	 * @var boolean
	 */
	protected $should_show_optin = true;

	protected $first_install_time = null;

	protected $purchase_url = null;

	/**
	 * Delay before OptIn Notice being shown to admin user.
	 * Delay will be calculated relative to first_install_time.
	 * @var float|int
	 */
	protected $optin_notice_delay = 3 * DAY_IN_SECONDS;

	/**
	 * If extra data needs to be sent
	 *
	 * @var ?callable|callable-string
	 */
	protected $usage_log_callback;

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
	 * Email Message Template File (path) For sending Support Ticket
	 * @var string
	 */
	protected $ticketTemplate = '';

	/**
	 * Ticket Email Recipient
	 * @var string
	 */
	protected $ticketRecipient = '';

	/**
	 * Support Page URL
	 * @var string
	 */
	protected $supportURL = '';

	protected $supportResponse = '';

	protected $supportErrorResponse = '';

	protected $data_collection_list = [];

	/**
	 * Initialize the class
	 *
	 * @param SE_License_SDK_Client|string $client The client.
	 */
	final public function __construct( SE_License_SDK_Client $client ) {
		$this->client         = &$client;
		$this->ticketTemplate = __DIR__ . '/../views/insights-support-ticket-email.php';
	}

	/**
	 * Don't show the notice
	 *
	 * @return SE_License_SDK_Insights
	 */
	public function hide_optin_notice() {
		$this->should_show_optin = false;

		return $this;
	}

	/**
	 * Set first installation time of the package.
	 *
	 * @param int $time GMT/UTC-0 Unix Timestamp
	 *
	 * @return SE_License_SDK_Insights
	 */
	public function set_first_install_time( int $time ) {
		if ( $time ) {
			$this->first_install_time = absint( $time );
		}

		return $this;
	}

	/**
	 * Set OptIn notice delay
	 * @param int $delay delay time in seconds.
	 *
	 * @return SE_License_SDK_Insights
	 */
	public function set_optin_notice_delay( int $delay ) {
		if ( $delay ) {
			$this->optin_notice_delay = absint( $delay );
		}

		return $this;
	}

	/**
	 * Set custom notice text
	 *
	 * @param string $text Admin Notice Test.
	 *
	 * @return SE_License_SDK_Insights
	 */
	public function notice( string $text ): SE_License_SDK_Insights {
		$this->notice = $text;

		return $this;
	}

	/**
	 * Initialize insights
	 *
	 * @return void
	 */
	public function init() {

		if ( $this->did_init ) {
			return;
		}

		// Initialize.
		$init_method = 'init_' . $this->client->getType();

		if ( method_exists( $this, $init_method ) ) {
			// init_{plugin/theme}
			$this->$init_method();
		}

		$this->did_init = true;
	}

	/**
	 * Initialize theme hooks
	 *
	 * @return void
	 */
	private function init_theme() {
		$this->init_common();

		add_action( 'switch_theme', [ $this, 'deactivation_cleanup' ] );
		add_action( 'switch_theme', [ $this, 'theme_deactivated' ], 12, 3 );
	}

	/**
	 * Initialize plugin hooks
	 *
	 * @return void
	 */
	private function init_plugin() {

		// Plugin deactivate popup.
		if ( ! $this->client->is_local_request() ) {
			add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_deactivation_assets' ] );
			add_action( 'admin_footer', [ $this, 'deactivate_scripts' ], PHP_INT_MAX );
			//add_action( 'plugin_action_links_' . $this->client->getBasename(), [ $this, 'plugin_action_links' ] );
		}

		$this->init_common();

		register_activation_hook( $this->client->getPackageFile(), [ $this, 'activate_plugin' ] );
		register_deactivation_hook( $this->client->getPackageFile(), [ $this, 'deactivation_cleanup' ] );
	}

	/**
	 * Initialize common hooks
	 *
	 * @return void
	 */
	protected function init_common() {

		add_action( 'admin_init', [ $this, 'handle_optIn_optOut' ] );
		add_action( 'removable_query_args', [ $this, 'add_removable_query_args' ] );

		// Uninstall reason.
		add_action(
				'wp_ajax_' . $this->client->getHookName( 'submit-uninstall-reason' ),
				[ $this, 'uninstall_reason_submission' ]
		);

		// Ticket submission.
		add_action(
				'wp_ajax_' . $this->client->getHookName( 'submit-support-ticket' ),
				[ $this, 'support_ticket_submission' ]
		);

		// cron events.
		add_filter( 'cron_schedules', [ $this, 'add_weekly_schedule' ] );
		add_action( $this->client->getSlug() . '_tracker_send_event', [ $this, 'send_tracking_data' ] );
	}

	public function set_support_url( string $supportURL ): SE_License_SDK_Insights {
		$this->supportURL = $supportURL;

		return $this;
	}

	public function set_support_response( ?string $supportResponse ): SE_License_SDK_Insights {
		$this->supportResponse = $supportResponse;

		return $this;
	}

	public function set_support_error_response( ?string $supportErrorResponse ): SE_License_SDK_Insights {
		$this->supportErrorResponse = $supportErrorResponse;

		return $this;
	}

	public function set_ticket_recipient( string $ticketRecipient ): SE_License_SDK_Insights {
		$this->ticketRecipient = $ticketRecipient;

		return $this;
	}

	public function set_ticket_template( string $ticketTemplate ): SE_License_SDK_Insights {
		if ( $ticketTemplate && is_file( $ticketTemplate ) ) {
			$this->ticketTemplate = realpath( $ticketTemplate );
		}

		return $this;
	}

	/**
	 * Send tracking data to absp_service_api server
	 *
	 * @param boolean $override override current settings.
	 *
	 * @return void
	 */
	public function send_tracking_data( bool $override = false ) {

		// Skip on AJAX Requests.
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return;
		}

		if ( ! $this->is_tracking_allowed() && ! $override ) {
			return;
		}

		// Send a maximum of once per week.
		$last_send = $this->get_last_send();

		/**
		 * Tracking interval
		 *
		 * @param string $interval A valid date/time string
		 */
		$trackingInterval = apply_filters( $this->client->getSlug() . '_tracking_interval', '-1 week' );

		try {
			$intervalCheck = strtotime( $trackingInterval );
		} catch ( Exception $e ) {
			// fallback to default 1 week if filter returned unusable data.
			$intervalCheck = strtotime( '-1 week' );
		}

		if ( $last_send && $last_send > $intervalCheck && ! $override ) {
			return;
		}

		$this->client->request( [ 'body' => $this->get_tracking_data(), 'route' => 'log-usage' ] );

		$this->client->set_option( 'tracking_last_send', time() );
	}

	/**
	 * Get the tracking data points
	 *
	 * @return array
	 */
	protected function get_tracking_data(): array {
		[ 'name' => $name, 'version' => $version ] = $this->get_runtime_info();
		[ 'db_name' => $db_name, 'db_version' => $db_version ] = $this->get_db_info();
		[ 'admin_email' => $admin_emails, 'admin_name' => $admin_name ] = $this->client->get_admin_info();

		$all_plugins = $this->get_plugins_data();
		$theme       = wp_get_theme();
		$theme_data  = [
				'slug'       => $theme->get_stylesheet(),
				'name'       => $theme->get( 'Name' ),
				'version'    => $theme->get( 'Version' ),
				'author'     => $theme->get( 'Author' ),
				'author_url' => $theme->get( 'AuthorURI' ),
				'theme_url'  => $theme->get( 'ThemeURI' ),
				'is_child'   => false,
		];

		if ( $theme->parent() ) {
			$theme_data['is_child']          = true;
			$theme_data['parent_slug']       = $theme->parent()->get_stylesheet();
			$theme_data['parent_name']       = $theme->parent()->get( 'Name' );
			$theme_data['parent_version']    = $theme->parent()->get( 'Version' );
			$theme_data['parent_author']     = $theme->parent()->get( 'Author' );
			$theme_data['parent_author_url'] = $theme->parent()->get( 'AuthorURI' );
			$theme_data['parent_theme_url']  = $theme->parent()->get( 'ThemeURI' );
		}

		$data = [
				'core_name'       => 'WordPress',
				'core_version'    => get_bloginfo( 'version' ),
				'locale'          => get_locale(),
				'server_name'     => $this->get_server_software_name(),
				'server_version'  => $this->get_server_version(),
				'db_name'         => $db_name,
				'db_version'      => $db_version,
				'runtime'         => $name,
				'runtime_version' => $version,
				'os_name'         => php_uname( 's' ),
				'os_arch'         => php_uname( 'm' ),
				'os_version'      => $this->get_os_version(),
				'ip_address'      => $this->client->get_server_ip_address(),
				'usage_log'       => [
						'admin_name'           => $admin_name,
						'admin_email'          => $admin_emails,
						'os_info'              => php_uname(),
						'url'                  => esc_url( home_url() ),
						'site'                 => $this->__get_site_name(),
						'active_plugins'       => $all_plugins['active_plugins'],
						'inactive_plugins'     => $all_plugins['inactive_plugins'],
						'theme'                => $theme_data,
						'wp_memory_limit'      => defined( 'WP_MEMORY_LIMIT' ) ? WP_MEMORY_LIMIT : 'N/A',
						'debug_mode'           => ( defined( 'WP_DEBUG' ) && WP_DEBUG ),
						'multisite'            => is_multisite(),
						'php_execution_time'   => @ini_get( 'max_execution_time' ), // phpcs:ignore
						'php_max_upload_size'  => size_format( wp_max_upload_size() ),
						'php_default_timezone' => date_default_timezone_get(),
						'ext_php_soap'         => class_exists( 'SoapClient' ),
						'ext_php_fsockopen'    => function_exists( 'fsockopen' ),
						'ext_php_curl'         => function_exists( 'curl_init' ),
						'ext_php_ftp'          => function_exists( 'ftp_connect' ),
						'ext_php_sftp'         => function_exists( 'ssh2_connect' ),
				],
		];

		$usage_log = $this->get_usage_log();

		if ( ! empty( $usage_log ) ) {
			$data['usage_log'] = $data['usage_log'] + $usage_log;
		}

		return apply_filters( $this->client->getHookName( 'tracker_data' ), $data );
	}

	protected function set_usage_log_callback( $usage_log_callback): SE_License_SDK_Insights {
		$this->usage_log_callback = $usage_log_callback;

		return $this;
	}

	/**
	 * If a child class wants to send extra data
	 *
	 * @return array
	 */
	protected function get_usage_log(): array {
		if ( is_callable( $this->usage_log_callback ) ) {
			$usage_log = call_user_func( $this->usage_log_callback );

			if ( $usage_log && is_array( $usage_log ) ) {
				return $usage_log;
			}
		}

		return [];
	}

	/**
	 * Explain the user which data we collect
	 *
	 * @return array
	 */
	protected function get_data_collection_list(): array {
		$data = array_merge( [
				'server_env'  => __( 'Server environment details (MySQL version, MySQL version, Server software & version, etc.).', 'storeengine-sdk' ),
				'wp_env'      => __( 'WordPress installation details (version, debug mode, max upload size).', 'storeengine-sdk' ),
				'wp_settings' => __( 'WordPress settings (site language, active and inactive plugins & themes).', 'storeengine-sdk' ),
				'site_meta'   => __( 'Site Name & URL.', 'storeengine-sdk' ),
				'admin_meta'  => __( 'Admin Name & Email.', 'storeengine-sdk' ),
		], $this->data_collection_list );

		return array_unique( array_filter( $data ) );
	}

	public function set_data_being_collected( ?array $items ): SE_License_SDK_Insights {
		$this->data_collection_list = $items ? $items : [];

		return $this;
	}

	/**
	 * Check if the user has opted into tracking
	 *
	 * @return bool
	 */
	public function is_tracking_allowed(): bool {

		// If hide_notice is set (optIn notice is hidden by default), then tracking is also disable.
		// But uninstallation tracking is active.
		return 'yes' === $this->client->get_option( 'allow_tracking', 'no' );
	}

	/**
	 * Get the last time a tracking was sent
	 *
	 * @return false|int
	 */
	public function get_last_send() {
		return $this->client->get_option( 'tracking_last_send', false );
	}

	/**
	 * Check if the notice has been dismissed or enabled
	 *
	 * @return boolean
	 */
	public function is_notice_dismissed(): bool {
		return 'hide' === $this->client->get_option( 'tracking_notice', 'show' );
	}

	/**
	 * Schedule the event weekly
	 *
	 * @return void
	 */
	private function maybe_schedule_event() {
		$hook_name = $this->client->getSlug() . '_tracker_send_event';
		if ( ! wp_next_scheduled( $hook_name ) ) {
			wp_schedule_event( time(), 'weekly', $hook_name );
		}
	}

	/**
	 * Clear any scheduled hook
	 *
	 * @return void
	 */
	private function __clear_schedule_event() {
		wp_clear_scheduled_hook( $this->client->getSlug() . '_tracker_send_event' );
	}

	/**
	 * Tracking Opt In URL
	 * @return string
	 */
	public function get_opt_in_url(): string {
		return add_query_arg( [
				'optAct'   => $this->client->getHookName( 'tracker_optIn' ),
				'_wpnonce' => wp_create_nonce( $this->client->getHookName( 'insight_action' ) ),
		] );
	}

	/**
	 * Tracking Opt Out URL
	 * @return string
	 */
	public function get_opt_out_url(): string {
		return add_query_arg( [
				'optAct'   => $this->client->getHookName( 'tracker_optOut' ),
				'_wpnonce' => wp_create_nonce( $this->client->getHookName( 'insight_action' ) ),
		] );
	}

	public function maybe_show_optin_notice(): bool {
		// Don't show if not configured properly.
		if ( ! $this->should_show_optin || ! $this->first_install_time || ! $this->optin_notice_delay ) {
			return false;
		}

		// Don't show if not admin.
		if ( ! $this->current_user_can() ) {
			return false;
		}

		// Don't show tracking if a local server or already dismissed or already allowed.
		if ( $this->client->is_local_request() || $this->is_notice_dismissed() || $this->is_tracking_allowed() ) {
			return false;
		}

		// Don't show until configured delay after first installation time.
		return current_time( 'timestamp', true ) >= $this->first_install_time + $this->optin_notice_delay;
	}

	/**
	 * Display the admin notice to users that have not opted-in or out
	 *
	 * @return void
	 */
	public function admin_notice() {
		$what_tracked      = $this->get_data_collection_list();
		$terms             = '';
		$privacy_policy    = '';
		$terms_policy_text = '';

		if ( $this->privacy_policy_url ) {
			$privacy_policy = '<a href="' . esc_url( $this->privacy_policy_url ) . '" target="_blank" rel="noopener">' . esc_html__( 'Privacy Policy', 'storeengine-sdk' ) . '</a>';
		}

		if ( $this->terms_url ) {
			$terms = '<a href="' . esc_url( $this->terms_url ) . '" target="_blank" rel="noopener">' . esc_html__( 'Terms of Services', 'storeengine-sdk' ) . '</a>';
		}

		if ( $terms || $privacy_policy ) {
			if ( $terms && $privacy_policy ) {
				$terms_policy_text = sprintf(
				/* translators: 1: Privacy Policy Link, 2: Terms Links */
						__( 'Please read our %1$s and %2$s', 'storeengine-sdk' ),
						$privacy_policy,
						$terms
				);
			} else {
				/* translators: 1: Privacy Policy or Terms Link */
				$terms_policy_text = sprintf( __( 'Please read our %1$s', 'storeengine-sdk' ), ! $privacy_policy ? $terms : $privacy_policy );
			}
		}

		if ( empty( $this->notice ) ) {
			/* translators: 1: plugin name. */
			$this->notice = __( '<h3 class="se-sdk-insights-notice--title">Help Us Improve & Get Exclusive Perks!</h3>', 'storeengine-sdk' );
			/* translators: 1: plugin name, 2: what we collect button. */
			//. What you’ll get if you opt in?
			$this->notice .= __( '<p class="se-sdk-insights-notice--des">We’d love to stay in touch and share useful updates, tips, and special offers to help you get the most from %1$s. Your privacy is our priority. No spam — ever.</p>', 'storeengine-sdk' );
		}

		$this->notice = sprintf( $this->notice, '<strong class="highlight">' . esc_html( $this->client->getPackageName() ) . '</strong>' );

		include __DIR__ . '/../views/insights-opt-in-notice.php';
	}

	protected function current_user_can() {
		return current_user_can( 'manage_options' ) || current_user_can( 'install_plugins' ) || current_user_can( 'install_themes' );
	}

	/**
	 * handle the optIn/optOut
	 *
	 * @return void
	 */
	public function handle_optIn_optOut() {
		if ( $this->maybe_show_optin_notice() && $this->current_user_can() ) {
			// Tracking notice.
			add_action( 'admin_notices', [ $this, 'admin_notice' ] );
		}

		if ( isset( $_REQUEST['_wpnonce'], $_REQUEST['optAct'] ) && $this->current_user_can() ) {
			$items = [
					$this->client->getHookName( 'tracker_optIn' ),
					$this->client->getHookName( 'tracker_optOut' ),
			];
			$opt_act = sanitize_text_field( wp_unslash( $_REQUEST['optAct'] ) );
			if (
					in_array( $opt_act, $items ) &&
					wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['_wpnonce'] ) ), $this->client->getHookName( 'insight_action' ) )
			) {

				if ( $this->client->getHookName( 'tracker_optOut' ) === $_REQUEST['optAct'] ) {
					$this->optOut();
				} else {
					$this->optIn();
				}
				wp_safe_redirect( remove_query_arg( [ 'optAct', '_wpnonce' ] ) );
				exit;
			}
		}
	}

	/**
	 * Add query vars to removable query args array
	 *
	 * @param array $removable_query_args array of removable args.
	 *
	 * @return array
	 */
	public function add_removable_query_args( array $removable_query_args ): array {
		return array_merge( $removable_query_args, [ 'optAct', '_wpnonce' ] );
	}

	/**
	 * Tracking optIn
	 *
	 * @return void
	 * @see Insights::send_tracking_data()
	 */
	public function optIn() {
		$this->client->set_option( 'allow_tracking', 'yes' );
		$this->client->set_option( 'tracking_notice', 'hide' );
		$this->__clear_schedule_event();
		$this->maybe_schedule_event();
		$this->client->request( [ 'body' => [ 'opt_in' => true ], 'route' => 'opt-in' ] );
		$this->send_tracking_data( true );
	}

	/**
	 * optOut from tracking
	 *
	 * @return void
	 */
	public function optOut( $hide_notice = true ) {
		$this->client->set_option( 'allow_tracking', 'no' );
		$this->client->set_option( 'tracking_notice', $hide_notice ? 'hide' : 'show' );
		$this->client->request( [ 'body' => [ 'opt_in' => false ], 'route' => 'opt-in' ] );
		$this->__clear_schedule_event();
		$this->send_tracking_data( true );
	}

	/**
	 * Get the number of post counts
	 *
	 * @param string $post_type PostType name to get count for.
	 *
	 * @return integer
	 */
	public function get_post_count( $post_type ) {
		global $wpdb;

		// phpcs:disable
		return (int) $wpdb->get_var(
				$wpdb->prepare(
						"SELECT count(ID) FROM $wpdb->posts WHERE post_type = %s and post_status = 'publish'",
						$post_type
				)
		);
		// phpcs:enable
	}

	private function get_server_software_name(): ?string {
		if ( PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg' ) {
			return null; // No web server in CLI
		}

		if ( empty( $_SERVER['SERVER_SOFTWARE'] ) ) {
			return null;
		}

		// Example: "Apache/2.4.57 (Unix)" → "Apache"
		// Example: "nginx/1.25.2" → "nginx"
		return preg_split( '/[\/\s]+/', $_SERVER['SERVER_SOFTWARE'] )[0] ?? null;
	}

	private function get_server_version(): ?string {
		if ( PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg' ) {
			return null; // No server software in CLI
		}

		if ( empty( $_SERVER['SERVER_SOFTWARE'] ) ) {
			return null;
		}

		if ( preg_match( '/\d+\.\d+(?:\.\d+)?/', $_SERVER['SERVER_SOFTWARE'], $matches ) ) {
			return $matches[0];
		}

		return null;
	}

	private function get_runtime_info(): array {
		if ( defined( 'HHVM_VERSION' ) ) {
			return [ 'name' => 'HHVM', 'version' => HHVM_VERSION ];
		}
		if ( PHP_SAPI === 'phpdbg' ) {
			return [ 'name' => 'PHPDBG', 'version' => PHP_VERSION ];
		}

		return [ 'name' => 'PHP', 'version' => PHP_VERSION ];
	}

	private function get_db_info(): array {
		global $wpdb;

		$db_name    = null;
		$db_version = null;
		$dbh_class  = get_class( $wpdb->dbh );

		// Try WordPress helper first (MySQL/MariaDB only)
		if ( method_exists( $wpdb, 'db_server_info' ) ) {
			$server_info = $wpdb->db_server_info();
		} elseif ( isset( $wpdb->dbh ) ) {
			if ( $wpdb->dbh instanceof mysqli ) {
				// mysqli
				$server_info = $wpdb->dbh->server_info;
			} elseif ( $wpdb->dbh instanceof \PDO ) {
				// PDO
				$server_info = $wpdb->dbh->getAttribute( \PDO::ATTR_SERVER_VERSION );
				//$driver_name = $wpdb->dbh->getAttribute( \PDO::ATTR_DRIVER_NAME );
			}
		}

		if ( ! empty( $server_info ) ) {
			if ( stripos( $server_info, 'MariaDB' ) !== false ) {
				$db_name    = 'MariaDB';
				$db_version = preg_replace( '/.*MariaDB\s*/i', '', $server_info );
			} elseif ( stripos( $server_info, 'PostgreSQL' ) !== false ) {
				$db_name    = 'PostgreSQL';
				$db_version = preg_replace( '/[^0-9\.].*$/', '', $server_info );
			} elseif ( stripos( $server_info, 'SQLite' ) !== false ) {
				$db_name    = 'SQLite';
				$db_version = preg_replace( '/[^0-9\.].*$/', '', $server_info );
			} else {
				// Default to MySQL
				$db_name    = 'MySQL';
				$db_version = preg_replace( '/[^0-9\.].*$/', '', $server_info );
			}
		}

		return [ 'db_name' => $db_name, 'db_version' => $db_version ];
	}

	private function get_os_version(): ?string {
		if ( php_uname( 's' ) !== 'Darwin' ) {
			return php_uname( 'r' );
		}

		$plistPath = '/System/Library/CoreServices/SystemVersion.plist';
		if ( ! is_readable( $plistPath ) ) {
			return null;
		}

		$plistContent = file_get_contents( $plistPath );
		if ( $plistContent === false ) {
			return null;
		}

		// Match <key>ProductVersion</key> followed by <string>VERSION</string>
		if ( preg_match( '/<key>ProductVersion<\/key>\s*<string>([^<]+)<\/string>/i', $plistContent, $matches ) ) {
			return trim( $matches[1] );
		}

		return null;
	}

	/**
	 * Get the list of active and inactive plugins
	 * @return array
	 */
	private function get_plugins_data(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			include ABSPATH . '/wp-admin/includes/plugin.php';
		}
		$plugins             = get_plugins();
		$active_plugins      = [];
		$active_plugins_keys = get_option( 'active_plugins', [] );
		foreach ( $plugins as $k => $v ) {
			// Take care of formatting the data how we want it.
			$formatted = [
					'name'       => isset( $v['Name'] ) ? wp_strip_all_tags( $v['Name'] ) : '',
					'version'    => isset( $v['Version'] ) ? wp_strip_all_tags( $v['Version'] ) : 'N/A',
					'author'     => isset( $v['Author'] ) ? wp_strip_all_tags( $v['Author'] ) : 'N/A',
					'network'    => isset( $v['Network'] ) ? wp_strip_all_tags( $v['Network'] ) : 'N/A',
					'plugin_uri' => isset( $v['PluginURI'] ) ? wp_strip_all_tags( $v['PluginURI'] ) : 'N/A',
			];
			if ( in_array( $k, $active_plugins_keys ) ) {
				// Remove active plugins from list, so we can show active and inactive separately.
				unset( $plugins[ $k ] );
				$active_plugins[ $k ] = $formatted;
			} else {
				$plugins[ $k ] = $formatted;
			}
		}

		return [
				'active_plugins'   => $active_plugins,
				'inactive_plugins' => $plugins,
		];
	}

	/**
	 * Get user totals based on user role.
	 *
	 * @return array
	 */
	public function get_user_count(): array {
		$user_count          = [];
		$user_count_data     = count_users();
		$user_count['total'] = $user_count_data['total_users'];
		// Get user count based on user role.
		foreach ( $user_count_data['avail_roles'] as $role => $count ) {
			$user_count[ $role ] = $count;
		}

		return $user_count;
	}

	/**
	 * Add weekly cron schedule
	 *
	 * @param array $schedules Cron Schedules.
	 *
	 * @return array
	 */
	public function add_weekly_schedule( $schedules ) {
		$schedules['weekly'] = [
				'interval' => DAY_IN_SECONDS * 7,
				'display'  => __( 'Once Weekly', 'storeengine-sdk' ),
		];

		return $schedules;
	}

	/**
	 * Plugin activation hook
	 *
	 * @return void
	 */
	public function activate_plugin() {
		$allowed = $this->client->get_option( 'allow_tracking', 'no' );
		// if it wasn't allowed before, do nothing.
		if ( 'yes' !== $allowed ) {
			return;
		}

		// Re-schedule and delete the last sent time, so we could force send again.
		wp_schedule_event( time(), 'weekly', $this->client->getSlug() . '_tracker_send_event' );
		$this->send_tracking_data( true );
	}

	/**
	 * Clear our options upon deactivation
	 *
	 * @return void
	 */
	public function deactivation_cleanup() {
		$this->__clear_schedule_event();
	}

	protected $action_links = [];
	protected $action_links_exclude = [ 'deactivate' ];
	protected $action_links_html = [
			'b'      => [ 'class', 'style' ],
			'i'      => [ 'class', 'style' ],
			'span'   => [ 'class', 'style' ],
			'strong' => [ 'class', 'style' ],
	];
	protected $action_links_args = [
			'label'  => '',
			'class'  => '',
			'href'   => '',
			'target' => '',
			'rel'    => '',
	];

	protected $terms_url = '';

	protected $privacy_policy_url = '';


	public function add_action_links( string $id, array $args = [] ) {
		$args = wp_parse_args( $args, $this->action_links_args );

		if ( ! in_array( $id, $this->action_links_exclude ) && ! empty( $args['label'] ) && ! empty( $args['href'] ) ) {
			$this->action_links[ $id ] = sprintf(
					'<a class="%s" href="%s" target="%s" rel="%s">%s</a>',
					esc_attr( $args['class'] ),
					esc_url( $args['href'] ),
					esc_attr( $args['target'] ),
					esc_attr( $args['rel'] ),
					wp_kses( $args['label'], $this->action_links_html )
			);
		}

		return $this;
	}

	public function set_terms_url( string $terms_url ): SE_License_SDK_Insights {
		$this->terms_url = $terms_url;

		return $this;
	}

	public function set_privacy_policy_url( string $privacy_policy_url ): SE_License_SDK_Insights {
		$this->privacy_policy_url = $privacy_policy_url;

		return $this;
	}

	/**
	 * Hook into action links and modify the deactivate link
	 *
	 * @param array $links Plugin Action Links.
	 *
	 * @return array
	 */
	public function plugin_action_links( array $links ): array {

		if ( array_key_exists( 'deactivate', $links ) ) {
			$links['deactivate'] = str_replace( '<a', '<a class="' . $this->client->getSlug() . '-deactivate-link"', $links['deactivate'] );
		}

		if ( ! empty( $this->action_links ) ) {
			$links = $links + $this->action_links;
		}

		return $links;
	}

	/**
	 * Deactivation reasons
	 * @return array
	 */
	private function __get_uninstall_reasons(): array {
		// Five-option list — minimal cognitive load. Only "found-better"
		// and "other" expose an optional text input to capture the
		// follow-up detail that's useful as feedback. All other reasons
		// stand on their own.
		$reasons = [
				[
						'id'          => 'no-longer-needed',
						'text'        => esc_html__( 'I no longer need the plugin', 'storeengine-sdk' ),
						'type'        => '',
						'placeholder' => '',
				],
				[
						'id'          => 'found-better',
						'text'        => esc_html__( 'I found a better plugin', 'storeengine-sdk' ),
						'type'        => 'text',
						'placeholder' => esc_html__( 'Which one?', 'storeengine-sdk' ),
				],
				[
						'id'          => 'how-to-use',
						'text'        => esc_html__( "I couldn't get the plugin to work", 'storeengine-sdk' ),
						'type'        => '',
						'placeholder' => '',
				],
				[
						'id'          => 'debugging',
						'text'        => esc_html__( "It's a temporary deactivation", 'storeengine-sdk' ),
						'type'        => '',
						'placeholder' => '',
				],
				[
						'id'          => 'other',
						'text'        => esc_html__( 'Other', 'storeengine-sdk' ),
						'type'        => 'text',
						'placeholder' => esc_html__( 'Please share the reason', 'storeengine-sdk' ),
				],
		];

		$extra = apply_filters( $this->client->getHookName( 'uninstall_reasons' ), [], $reasons );

		if ( is_array( $extra ) && ! empty( $extra ) ) {
			// extract the last (other) reason and add after extras.
			$other   = array_pop( $reasons );
			$reasons = array_merge( $reasons, $extra, [ $other ] );
		}

		return $reasons;
	}

	/**
	 * Plugin deactivation uninstall reason submission
	 *
	 * @return void
	 */
	public function uninstall_reason_submission() {
		check_ajax_referer( $this->client->getHookName( 'insight_action' ) );

		if ( ! isset( $_POST['reason_id'] ) ) {
			wp_send_json_error( esc_html__( 'Invalid Request', 'storeengine-sdk' ) );
		}

		$reason  = sanitize_text_field( $_REQUEST['reason_id'] );
		$details = isset( $_REQUEST['reason_info'] ) ? trim( sanitize_textarea_field( $_REQUEST['reason_info'] ) ) : '';

		// The deactivation modal shows the admin a clear, plain-language list of
		// every data point below before they click "Submit & Deactivate", and
		// offers "Skip & Deactivate" (which sends nothing) as the cancel path.
		// Submitting is therefore informed consent. See WP.org review
		// "hidden_sensitive_deactivation_payload" and the disclosure in
		// views/insights-deactivation-reasons.php.
		$current_user = wp_get_current_user();

		if ( $current_user->first_name ) {
			$name = trim( $current_user->first_name . ' ' . $current_user->last_name );
		} else {
			$name = $current_user->display_name;
		}

		$data = [
				'reason'      => $reason,
				'message'     => $details,
				'site'        => $this->__get_site_name(),
				'url'         => esc_url( home_url() ),
				'admin_name'  => $name,
				'admin_email' => $current_user->user_email,
				'usage_log'   => $this->get_tracking_data(),
				'type'        => 'uninstall',
		];

		$response = $this->client->request( [ 'body' => $data, 'route' => 'deactivate-license' ] );

		if ( is_wp_error( $response ) ) {
			wp_send_json_error( $response );
		} else {
			wp_send_json_success();
		}
	}

	protected function get_se_url(): string {
		/** @noinspection HttpUrlsUsage */
		return 'http://storeengine.pro/' .
			   '?utm_source=sdk-support-ticket' .
			   '&utm_medium=email-footer' .
			   '&utm_campaign=' . $this->client->getSlug() .
			   '&utm_content=' . $this->client->getLicenseServer();
	}

	protected function getSupportTicketEmailTemplate( $replacements ) {
		ob_start();
		?>
		<!doctype html>
		<html <?php language_attributes(); ?>>
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title><?php esc_html_e( 'Support Ticket Submission', 'storeengine-sdk' ); ?></title>
		</head>
		<body>
		<div class="se-sdk-support-ticket-email-template">
			<?php include $this->ticketTemplate; ?>
			<div style="margin:10px auto">
				<hr style="border-top-color:#008DFF"/>
			</div>
			<div style="margin:50px auto 10px auto">
				<?php // Trick (h3 with &#8203 zero-width-space chars) for dashes before auto generated text version by wp_mail ?>
				<h3 style="display:block;height:0;margin:0;opacity:0;visibility:hidden">&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;&#8203;</h3>
				<p style="font-size: 12px;">
					<?php
					printf(
					// translators: %1$s. StoreEngine Site Link. %2$s. SDK version.
							esc_html__( 'Message Processed via %1$s WordPress License SDK (v.%2$s)', 'storeengine-sdk' ),
							'<a href="' . esc_url( $this->get_se_url() ) . '" target="_blank" style="color:#008DFF">' . esc_html__( 'StoreEngine', 'storeengine-sdk' ) . '</a>',
							esc_html( $this->client->getVersion() )
					);
					?>
				</p>
			</div>
		</div>
		</body>
		</html>
		<?php
		$content = ob_get_clean();

		return str_replace( $replacements['s'], $replacements['r'], $content );
	}

	/**
	 * Handle Support Ticket Submission
	 * @return void
	 */
	public function support_ticket_submission() {
		check_ajax_referer( $this->client->getHookName( 'insight_action' ) );
		if ( empty( $this->ticketTemplate ) || empty( $this->ticketRecipient ) ) {
			wp_send_json_error( __( 'Something Went Wrong.<br>Please try again after sometime.', 'storeengine-sdk' ) );
		}

		if ( ! is_file( $this->ticketTemplate ) ) {
			wp_send_json_error( __( 'Unable to locate support ticket email template file', 'storeengine-sdk') );
		}

		if ( ! empty( $_REQUEST['name'] ) && ! empty( $_REQUEST['email'] ) && sanitize_email( $_REQUEST['email'] ) && is_email( $_REQUEST['email'] ) && ! empty( $_REQUEST['subject'] ) && ! empty( $_REQUEST['message'] ) ) {
			$name  = ucwords( sanitize_text_field( $_REQUEST['name'] ) );
			$email = sanitize_email( $_REQUEST['email'] );

			// Do not translate, as the site's language might not match recipient's preference/language.
			$subject = sprintf( 'Support Request For: %s', $this->client->getPackageName() );
			$headers = [
					'Content-Type: text/html; charset=UTF-8',
					sprintf( 'From: %s <%s>', $name, $email ),
					sprintf( 'Reply-To: %s <%s>', $name, $email ),
			];

			$sanitizers = [
					'email'   => 'sanitize_email',
					'website' => 'esc_url_raw',
					'message' => 'sanitize_textarea_field',
			];

			$data = [ 's' => [], 'r' => [] ];

			foreach ( $_REQUEST as $k => $v ) {
				$sanitizer = $sanitizers[ $k ] ?? 'sanitize_text_field';
				if ( ! function_exists( $sanitizer ) ) {
					continue;
				}

				$v = call_user_func_array( $sanitizer, [ $v ] );

				if ( 'message' === $k ) {
					$v = wp_kses_post( wpautop( ucfirst( $v ) ) );
				} elseif ( 'website' === $k ) {
					$v = esc_url( $v );
				} elseif ( 'subject' === $k ) {
					$v = esc_html( ucfirst( $v ) );
				} else {
					$v = esc_html( $v );
				}

				$data['s'][] = '__' . strtoupper( $k ) . '__';
				$data['r'][] = $v; // phpcs: sanitize ok.
			}



			// phpcs:disable WordPressVIPMinimum.Functions.RestrictedFunctions.wp_mail_wp_mail
			$isSent = wp_mail(
					$this->ticketRecipient,
					$subject,
					$this->getSupportTicketEmailTemplate( $data ),
					$headers
			);
			// phpcs:enable WordPressVIPMinimum.Functions.RestrictedFunctions.wp_mail_wp_mail

			if ( $isSent ) {
				if ( $this->supportResponse ) {
					$message = is_callable( $this->supportResponse ) ? call_user_func_array( $this->supportResponse , [] ) : $this->supportResponse;
				} else {
					$message = '<h3>' . __( 'Thank you -- Support Ticket Submitted.', 'storeengine-sdk' ) . '</h3>';
				}

				wp_send_json_success( wp_kses_post( $message ) );
			} else {
				if ( $this->supportErrorResponse ) {
					$message = is_callable( $this->supportErrorResponse ) ? call_user_func_array( $this->supportErrorResponse , [] ) : $this->supportErrorResponse;
				} else {
					$message = __( 'Something Went Wrong. Please Try Again After Sometime.', 'storeengine-sdk' );
				}

				wp_send_json_error( wp_kses_post( $message ) );
			}
		} else {
			wp_send_json_error( esc_html__( 'Missing Required Fields.', 'storeengine-sdk' ) );
		}
	}

	/**
	 * Handle the plugin deactivation feedback
	 *
	 * @return void
	 */
	public function enqueue_deactivation_assets() {
		global $pagenow;

		if ( 'plugins.php' !== $pagenow ) {
			return;
		}

		wp_enqueue_style(
				'se-sdk-deactivation-modal',
				SE_License_SDK::sdk_url( 'static/deactivation-modal.css' ),
				[],
				$this->client->getVersion()
		);

		wp_enqueue_script(
				'se-sdk-deactivation-modal',
				SE_License_SDK::sdk_url( 'static/deactivation-modal.js' ),
				[ 'jquery' ],
				$this->client->getVersion(),
				true
		);
	}

	/**
	 * Handle the plugin deactivation feedback
	 *
	 * @return void
	 */
	public function deactivate_scripts() {
		global $pagenow;

		if ( 'plugins.php' !== $pagenow ) {
			return;
		}

		$reasons           = $this->__get_uninstall_reasons();
		$admin_user        = $this->client->get_admin_data();
		$displayName       = $admin_user->first_name ? trim( $admin_user->first_name . ' ' . $admin_user->last_name ) : $admin_user->display_name;
		$showSupportTicket = ! empty( $this->supportURL );

		// Plain-language disclosure of every data point sent when the user
		// opts in via the consent checkbox. Kept in sync with the opt-in
		// branch of uninstall_reason_submission(). See WP.org review
		// "hidden_sensitive_deactivation_payload".
		$dataCollectionList = [
			__( 'Your admin name and email address', 'storeengine-sdk' ),
			__( 'Your site name and URL', 'storeengine-sdk' ),
			__( 'Your server IP address and operating-system details', 'storeengine-sdk' ),
			__( 'PHP, database, and web-server names and versions', 'storeengine-sdk' ),
			__( 'WordPress version, locale, and key environment settings', 'storeengine-sdk' ),
			__( 'A list of your active and inactive plugins and active theme', 'storeengine-sdk' ),
		];
		$serverHost       = $this->client->get_license_server_host();
		$privacyPolicyUrl = $this->privacy_policy_url;
		?>
		<div class="se-sdk-product-<?php echo esc_attr( $this->client->getSlug() ); ?> se-sdk-deactivation-modal"
			 id="<?php echo esc_attr( $this->client->getSlug() ); ?>-se-sdk-deactivation-modal"
			 data-slug="<?php echo esc_attr( $this->client->getSlug() ); ?>"
			 data-plugin="<?php echo esc_attr( $this->client->getBasename() ); ?>"
			 data-uninstall-action="<?php echo esc_attr( $this->client->getHookName( 'submit-uninstall-reason' ) ); ?>"
			 data-support-action="<?php echo esc_attr( $this->client->getHookName( 'submit-support-ticket' ) ); ?>"
			 data-nonce="<?php echo esc_attr( wp_create_nonce( $this->client->getHookName( 'insight_action' ) ) ); ?>"
			 data-support-url="<?php echo esc_url( $this->supportURL ); ?>"
			 data-processing-label="<?php esc_attr_e( 'Processing...', 'storeengine-sdk' ); ?>"
			 aria-label="<?php /* translators: 1: Plugin Name */
			 printf( esc_attr__( '&ldquo;%s&rdquo; Uninstall Confirmation', 'storeengine-sdk' ), esc_attr( $this->client->getPackageName() ) ); ?>"
			 role="dialog" aria-modal="true"
			 style="--se-sdk-primary-color: <?php echo esc_attr( $this->client->getPrimaryColor() ); ?>; --se-sdk-danger-color: #f02e5e; --se-sdk-text-color: #141A24; --se-sdk-muted-color: #738496; --se-sdk-border-color: #eeeeee;">
			<?php
			include __DIR__ . '/../views/insights-deactivation-reasons.php';
			?>
		</div>
		<?php
	}

	/**
	 * Run after theme deactivated
	 *
	 * @param string $new_name New Theme Name.
	 * @param WP_Theme $new_theme New Theme WP_Theme Object.
	 * @param WP_Theme $old_theme Old Theme WP_Theme Object.
	 *
	 * @return void
	 */
	public function theme_deactivated( $new_name, $new_theme, $old_theme ) {
		// Make sure this is correct theme to track.
		if ( $old_theme->get_template() == $this->client->getSlug() ) {
			$current_user = wp_get_current_user();

			if ( $current_user->first_name ) {
				$name = trim( $current_user->first_name . ' ' . $current_user->last_name );
			} else {
				$name = $current_user->display_name;
			}

			$data = [
					'reason'      => 'none',
					'message'     => wp_json_encode(
							[
									'new_theme' => [
											'name'          => $new_name,
											'version'       => $new_theme->get( 'Version' ),
											'author'        => $new_theme->get( 'Author' ),
											'parent_theme'  => $new_theme->parent() ? $new_theme->parent()->get( 'Name' ) : '',
											'parent_author' => $new_theme->parent() ? $new_theme->parent()->get( 'Author' ) : '',
									],
							]
					),
					'site'        => $this->__get_site_name(),
					'url'         => esc_url( home_url() ),
					'admin_name'  => $name,
					'admin_email' => $current_user->user_email,
					'usage_log'   => $this->get_tracking_data(),
					'type'        => 'uninstall',
			];

			$this->client->request( [ 'body' => $data, 'route' => 'deactivate-license' ] );
		}
	}

	/**
	 * Get site name
	 * @return string
	 */
	private function __get_site_name(): string {
		$site_name = get_bloginfo( 'name' );
		if ( empty( $site_name ) ) {
			$site_name = get_bloginfo( 'description' );
			$site_name = wp_trim_words( $site_name, 3, '' );
		}
		if ( empty( $site_name ) ) {
			$site_name = get_bloginfo( 'url' );
		}

		return $site_name;
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

// End of file SE_License_SDK_Insights.php.
