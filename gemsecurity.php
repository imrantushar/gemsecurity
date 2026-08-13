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
		define( 'GEMSECURITY_DB_VERSION', '2.0' );
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
		GemSecurity\StoreLicense::init();
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

		// Backup subsystem (re-homed GemBackup engine) — gated on its module.
		if ( GemSecurity\Modules\Registry::is_active( 'backup' ) ) {
			GemSecurity\Backup::init();
		}

		if ( is_admin() ) {
			GemSecurity\Admin::init();
		}
	}

	public function load_dependency() {
		// Composer-managed runtime deps (currently just the StoreEngine SDK).
		// Vendored into git since WordPress.org installs never run `composer
		// install`; the check just guards a dev checkout that hasn't run it yet.
		if ( file_exists( GEMSECURITY_ROOT_DIR_PATH . 'vendor/autoload.php' ) ) {
			require_once GEMSECURITY_ROOT_DIR_PATH . 'vendor/autoload.php';
		}

		require_once GEMSECURITY_INCLUDES_DIR_PATH . 'autoload.php';
	}

	public function activate() {
		GemSecurity\Installer::activate();
		GemSecurity\Backup::activate();
	}

	public function deactivate() {
		GemSecurity\Installer::deactivate();
		GemSecurity\Backup::deactivate();
	}

}

function gemsecurity_start() {
	return GemSecurity::init();
}

gemsecurity_start();
