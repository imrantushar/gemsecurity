<?php
/*
 * Plugin Name:		GemSecurity
 * Plugin URI:		http://gemsecurity.net
 * Description:		All-in-one WordPress security dashboard — firewall, login protection, malware scanner, and activity logs.
 * Version:			1.0.0
 * Requires at least:	6.4
 * Requires PHP:		7.4
 * Author:			GemSecurity
 * Author URI:		http://gemsecurity.net
 * License:			GPL-3.0+
 * License URI:		http://www.gnu.org/licenses/gpl-3.0.txt
 * Text Domain:		gemsecurity
 * Domain Path:		/languages/
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class GemSecurity {

	private function __construct() {
		$this->define_constants();
		$this->load_dependency();
		register_activation_hook( __FILE__, [ $this, 'activate' ] );
		register_deactivation_hook( __FILE__, [ $this, 'deactivate' ] );
		add_action( 'plugins_loaded', [ $this, 'on_plugins_loaded' ] );
		// Registered here, not on plugins_loaded: the activation request includes
		// this file after plugins_loaded has already fired.
		add_action( 'activated_plugin', [ GemSecurity\Admin\Setup::class, 'activated_redirect' ], 10, 2 );
		add_action( 'gemsecurity_loaded', [ $this, 'init_plugin' ] );
	}

	public static function init() {
		static $instance = false;

		if ( ! $instance ) {
			$instance = new self();
		}

		return $instance;
	}

	public function define_constants() {
		define( 'GEMSECURITY_VERSION', '1.0.0' );
		define( 'GEMSECURITY_DB_VERSION', '2.1' );
		define( 'GEMSECURITY_SETTINGS_NAME', 'gemsecurity_settings' );
		define( 'GEMSECURITY_PLUGIN_FILE', __FILE__ );
		define( 'GEMSECURITY_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
		define( 'GEMSECURITY_PLUGIN_SLUG', 'gemsecurity' );
		define( 'GEMSECURITY_PLUGIN_ROOT_URI', plugins_url( '/', __FILE__ ) );
		define( 'GEMSECURITY_ROOT_DIR_PATH', plugin_dir_path( __FILE__ ) );
		define( 'GEMSECURITY_INCLUDES_DIR_PATH', GEMSECURITY_ROOT_DIR_PATH . 'includes/' );
		define( 'GEMSECURITY_ASSETS_DIR_PATH', GEMSECURITY_ROOT_DIR_PATH . 'assets/' );
		define( 'GEMSECURITY_ASSETS_URI', GEMSECURITY_PLUGIN_ROOT_URI . 'assets/' );
		define( 'GEMSECURITY_TEMPLATE_DEBUG_MODE', false );
	}

	public function on_plugins_loaded() {
		do_action( 'gemsecurity_loaded' );
	}

	public function init_plugin() {
		do_action( 'gemsecurity_before_init' );
		$this->dispatch_hooks();
		do_action( 'gemsecurity_init' );
	}

	public function dispatch_hooks() {
		// Keep the in-request settings cache fresh when the option changes.
		add_action( 'update_option_' . GEMSECURITY_SETTINGS_NAME, [ GemSecurity\Helper::class, 'flush_settings_cache' ] );
		add_action( 'add_option_' . GEMSECURITY_SETTINGS_NAME, [ GemSecurity\Helper::class, 'flush_settings_cache' ] );

		// Keep the in-request module-activation cache fresh when it changes.
		add_action( 'update_option_' . GemSecurity\Modules\Registry::OPTION, [ GemSecurity\Modules\Registry::class, 'flush_state_cache' ] );
		add_action( 'add_option_' . GemSecurity\Modules\Registry::OPTION, [ GemSecurity\Modules\Registry::class, 'flush_state_cache' ] );

		// Public integration surface for companion plugins (e.g. Academy LMS)
		// to query module state — always registered, independent of any
		// specific module's activation, so it's queryable the moment
		// GemSecurity itself is active.
		add_filter( 'gemsecurity/module_active', [ GemSecurity\Helper::class, 'is_module_active' ], 10, 2 );

		GemSecurity\Database::init();
		GemSecurity\Assets::init();
		GemSecurity\Api::init();

		// Boot only the modules that are active. An inactive module never loads
		// its classes, so it costs nothing (no menu, no REST, no hooks). Each
		// booted class still runs its own granular *_enabled checks internally.
		foreach ( GemSecurity\Modules\Registry::active_modules() as $module ) {
			foreach ( $module['classes'] as $class ) {
				if ( is_callable( [ $class, 'init' ] ) ) {
					$class::init();
				}
			}
		}

		if ( is_admin() ) {
			GemSecurity\Admin::init();
		}
	}

	public function load_dependency() {
		// Composer autoloader — GemSecurity (free) is the sole home of the
		// StoreEngine SDK (vendor/storeengine/wordpress-sdk); GemSecurity Pro
		// no longer bundles its own copy and consumes the global
		// se_license_init() this require makes available. The SDK declares its
		// bootstrap as a composer `files` autoload entry.
		$composer_autoload = GEMSECURITY_ROOT_DIR_PATH . 'vendor/autoload.php';
		if ( file_exists( $composer_autoload ) ) {
			require_once $composer_autoload;
		}

		require_once GEMSECURITY_INCLUDES_DIR_PATH . 'autoload.php';

		// License/insights SDK bootstrap (defers se_license_init to plugins_loaded).
		GemSecurity\StoreLicense::init();
	}

	public function activate() {
		// Feeds the SDK's insights/opt-in "days since install" timing.
		// add_option() is a no-op if it already exists, so re-activation
		// never resets it.
		$first_install = add_option( 'gemsecurity_first_install_time', time(), '', false );

		// Sites that ran GemSecurity before the setup wizard existed are already
		// configured — never push them through it on reactivation.
		if ( ! $first_install ) {
			add_option( GemSecurity\Admin\Setup::STATUS_OPTION, 'legacy', '', false );
		}

		GemSecurity\Installer::activate();
	}

	public function deactivate() {
		GemSecurity\Installer::deactivate();
	}

}

function gemsecurity_start() {
	return GemSecurity::init();
}

gemsecurity_start();
