<?php
/**
 * Helper Functions.
 */

// ---------------------------------------------------------------------------
// PHP 7.4 polyfills.
//
// WordPress ships these in wp-includes/compat.php from WP 5.9+, but the SDK
// is loaded on `plugins_loaded` priority 1 — which on some boot paths runs
// before WP's compat.php is guaranteed to have been included. Defining safely
// guarded copies here means the SDK never references missing functions when
// running on PHP 7.4 with an older WordPress.
// ---------------------------------------------------------------------------

if ( ! function_exists( 'str_starts_with' ) ) {
	function str_starts_with( string $haystack, string $needle ): bool {
		return 0 === strncmp( $haystack, $needle, strlen( $needle ) );
	}
}

if ( ! function_exists( 'str_ends_with' ) ) {
	function str_ends_with( string $haystack, string $needle ): bool {
		if ( '' === $needle ) {
			return true;
		}
		$len = strlen( $needle );
		return $len <= strlen( $haystack ) && 0 === substr_compare( $haystack, $needle, -$len );
	}
}

if ( ! function_exists( 'str_contains' ) ) {
	function str_contains( string $haystack, string $needle ): bool {
		return '' === $needle || false !== strpos( $haystack, $needle );
	}
}

if ( ! function_exists( 'se_license_init' ) ) {
	/**
	 * Initialize the SDK.
	 *
	 * @param array{
	 * package_file?: string, // Optional product main filepath. If omitted SDK will try to detect it from the calling plugin/theme file.
	 * basename?: string, // Optional plugin/theme basename. Auto-detected from `package_file` when omitted.
	 * package_name?: string, // Optional product name. Auto-detected from plugin/theme metadata when omitted.
	 * package_type?: string, // Optional package type: plugin or theme. Auto-detected when omitted.
	 * is_free?: bool, // Is free or pro. For freemium set true.
	 * product_id: int, // Product ID from the Store/Deployment site.
	 * use_update?: bool, // Should enable updater, For pro/freemium this needs to be enabled, for free version if deployed with StoreEngine this needs to be enabled. If developer just using SDK for uninstall-tracking/analytics this should be false.
	 * slug: string, // Plugin slug (without main file)
	 * package_version?: string, // Optional current package version. Auto-detected from plugin/theme metadata when omitted.
	 * allow_local?: bool, // Should plugin dev allow license activation from local environment. Recommended.
	 * license_server: string, // Store URL (api backend for SDK).
	 * activation_prompt?: null|string, // Custom activation nag (admin-notice) message.
	 * purchase_url?: string, // Plugin store product URL.
	 * store_dashboard_url?: string, // Plugin store user dashboard (where user can find their licenses they purchesed).
	 * product_logo?: string, // Product logo
	 * init_restapi?: bool, // Should initialize rest api for managing license. Useful if plugin developer uses custom 'manage-license' page.
	 * script_handler?:string, // Localize js params on this handler for react/js based custom license managemnt page. Recommended if `init_restapi` is `true`
	 * script_object?:string, // Object name for localized js params. Recommended if  if `script_handler` is being used, must be qnique/prefixed. If not set SDK will set `SE_SDK_{PLUGIN_SLUG}`
	 * menu?: false|string|array{ // False to disable built in 'manage-license' page, url for custom 'manage-license' page or menu config for adding builtin 'manage-license' page UI.
	 *        type: string, // menu type: menu, submenu.
	 *        parent_slug: string, // parent menu slug if type is submenu.
	 *        page_title: string, // Page title for the 'manage-license' page.
	 *        menu_title: string, // Menu title.
	 *        capability: string, // Permission for accessing the 'manage-license' page.
	 *        menu_slug: string, // Menu slug
	 *        icon_url: string, // Icon if type is 'menu'
	 *        position: int, // Menu position
	 * },
	 * redirect_on_activation?:bool, // Should redirect to 'manage-license' page after user activates the plugin. Default is true.
	 * init_insights?: bool,
	 * should_show_optin?: bool, // Show analytics data collection (opt-in) notice.
	 * first_install_time?: int, // Plugin first installation time.
	 * optin_notice_delay?: int, // Opt-in notice delay in seconds (from first installation time).
	 * data_being_collected?: array, // List of extra data being collect. E.g `['num_prod' => __( 'Number of products', 'textdomain' ), 'num_order' => __( 'Number of total orders', 'textdomain' ) ]`
	 * terms_url?: string, // Terms url for the plugin/theme.
	 * privacy_policy_url?: string, // Privacy policy page url for the plugin/theme.
	 * support_url?: string, // Support portal URL for the plugin/theme.
	 * ticket_recipient?: string, // Support recipient email address for sending support message directly from the dashboard.
	 * support_ticket_response?: string, // Support form success response.
	 * support_ticket_error_response?: string, // Support form error response.
	 * init_promotions?: bool,
	 * promo_cache_ttl?: int,
	 * promo_source?: string
	 * } $args
	 *
	 * @return SE_License_SDK_Client
	 */
	function se_license_init( array $args ): SE_License_SDK_Client {
		$args = wp_parse_args( $args, [
			'package_file'                  => '',
			'package_name'                  => '',
			'product_id'                    => 0,
			'is_free'                       => null,
			'use_update'                    => null, // is_org_compliant
			'slug'                          => null,
			'basename'                      => null,
			'package_type'                  => null,
			'package_version'               => null,
			'allow_local'                   => true,
			'license_server'                => null,
			'activation_prompt'             => null,
			'purchase_url'                  => null,
			'store_dashboard_url'           => null,
			'product_logo'                  => '',
			'init_restapi'                  => false,
			'script_handler'                => '',
			'script_object'                 => '',
			'menu'                          => [
				'type'        => '', // Can be: menu, options, submenu. Default to menu.
				'parent_slug' => '', // Parent menu slug if rending as submenu.
				'page_title'  => '', // Default: Manage License
				'menu_title'  => '', // Default: Manage License
				'capability'  => '', // default: manage_options
				'menu_slug'   => '', // Default: [package-slug]-manage-license
				'icon_url'    => '', // Menu icon (icon image/svg url or dashicons).
				'position'    => null, // Menu render priority. Mostly render after the `Settings` menu.
			],
			'redirect_on_activation'        => true,
			// Insight settings
			'init_insights'                 => true,
			'should_show_optin'             => true,
			'first_install_time'            => null,
			'optin_notice_delay'            => null, // Default 3 * DAY_IN_SECONDS
			'data_being_collected'          => [],
			'terms_url'                     => '',
			'privacy_policy_url'            => '',
			'support_url'                   => '',
			'support_ticket_response'       => '',
			'support_ticket_error_response' => '',
			'ticket_template'               => '', // template file path.
			'ticket_recipient'              => '', // ticket recipient email address.
			// Promo settings.
			'init_promotions'               => true,
			'promo_cache_ttl'               => null, // Default 12 * HOUR_IN_SECONDS.
			'promo_source'                  => null, // Default license server `promotions` route/endpoint.
		] );

		return SE_License_SDK::register( $args['package_file'] ?? '', $args['package_name'] ?? '', $args );
	}
}

// End of file functions.php.
