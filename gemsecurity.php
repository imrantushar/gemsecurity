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
		define( 'GEMSECURITY_DB_VERSION', '1.6' );
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

		GemSecurity\Database::init();
		GemSecurity\Assets::init();
		GemSecurity\Api::init();

		// Security modules run on both front-end and admin requests.
		GemSecurity\Modules\Waf::init();
		GemSecurity\Modules\Firewall::init();
		GemSecurity\Modules\LoginSecurity::init();
		GemSecurity\Modules\AdminGuard::init();
		GemSecurity\Modules\SecurityHeaders::init();
		GemSecurity\Modules\Captcha::init();
		GemSecurity\Modules\TwoFactor::init();
		GemSecurity\Modules\AuditLog::init();
		GemSecurity\Modules\SocialLogin::init();
		GemSecurity\Modules\Geolocation::init();
		GemSecurity\Modules\PasswordPolicy::init();
		GemSecurity\Modules\Sessions::init();
		GemSecurity\Modules\CustomLogin::init();
		GemSecurity\Modules\Alerts::init();
		GemSecurity\Modules\Lockdown::init();

		// Backup subsystem (re-homed GemBackup engine).
		GemSecurity\Backup::init();

		if ( is_admin() ) {
			GemSecurity\Admin::init();
		}
	}

	public function load_dependency() {
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
