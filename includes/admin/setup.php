<?php
namespace GemSecurity\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use GemSecurity\Assets;

/**
 * First-run setup wizard.
 *
 * A hidden admin page that prints its own full-screen document (no wp-admin
 * chrome) and mounts the `setup` React bundle. New installs are sent here
 * once after activation; the wizard stays reachable from the app topbar.
 */
class Setup {

	const PAGE_ID = 'gemsecurity-setup';

	/** Option: '' (pending) | 'completed' | 'skipped' | 'legacy'. */
	const STATUS_OPTION = 'gemsecurity_setup_status';

	/** Transient asking the next admin page load to open the wizard. */
	const PENDING_TRANSIENT = 'gemsecurity_open_setup';

	public static function init() {
		$self = new self();
		if ( $self->is_current() ) {
			add_action( 'admin_init', [ $self, 'render_screen' ], 0 );
		}
		add_action( 'admin_menu', [ $self, 'register_page' ] );
		add_action( 'admin_init', [ $self, 'maybe_open_pending' ] );
	}

	/** Registered under a hidden parent so it resolves but never shows in the menu. */
	public function register_page() {
		add_submenu_page(
			'options-writing.php',
			__( 'GemSecurity Setup', 'gemsecurity' ),
			__( 'GemSecurity Setup', 'gemsecurity' ),
			'manage_options',
			self::PAGE_ID,
			'__return_null'
		);
		remove_submenu_page( 'options-writing.php', self::PAGE_ID );
	}

	public function is_current() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return ! empty( $_GET['page'] ) && self::PAGE_ID === $_GET['page'];
	}

	public static function is_pending() {
		return '' === (string) get_option( self::STATUS_OPTION, '' );
	}

	/**
	 * Redirect straight after a single, interactive activation. Bulk, network,
	 * AJAX and CLI activations leave a transient so the next admin page opens
	 * the wizard instead (redirecting mid-bulk would skip the other plugins).
	 *
	 * Hooked from the main plugin file: on the activation request this plugin
	 * is included after plugins_loaded, so nothing registered there runs.
	 *
	 * @param string $plugin       Activated plugin basename.
	 * @param bool   $network_wide Network activation.
	 */
	public static function activated_redirect( $plugin, $network_wide = false ) {
		if ( GEMSECURITY_PLUGIN_BASENAME !== $plugin || ! self::is_pending() ) {
			return;
		}
		$bulk = isset( $_POST['checked'] ) || isset( $_GET['activate-multi'] ); // phpcs:ignore WordPress.Security.NonceVerification -- read only, to tell a bulk action apart.
		if ( $network_wide || $bulk || wp_doing_ajax() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			set_transient( self::PENDING_TRANSIENT, 1, DAY_IN_SECONDS );
			return;
		}
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::PAGE_ID ) );
		exit;
	}

	public function maybe_open_pending() {
		if ( ! get_transient( self::PENDING_TRANSIENT ) || wp_doing_ajax() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		delete_transient( self::PENDING_TRANSIENT );
		if ( self::is_pending() && ! $this->is_current() ) {
			wp_safe_redirect( admin_url( 'admin.php?page=' . self::PAGE_ID ) );
			exit;
		}
	}

	public function render_screen() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$this->enqueue_assets();
		require GEMSECURITY_INCLUDES_DIR_PATH . 'admin/views/setup.php';
		die;
	}

	private function enqueue_assets() {
		$asset_file = GEMSECURITY_ASSETS_DIR_PATH . sprintf( 'build/setup.%s.asset.php', GEMSECURITY_VERSION );
		if ( ! file_exists( $asset_file ) ) {
			return;
		}
		$deps = include $asset_file;

		wp_enqueue_style( 'gemsecurity-setup-style', GEMSECURITY_ASSETS_URI . 'build/setup.css', [ 'wp-components' ], $deps['version'] );
		wp_enqueue_script(
			'gemsecurity-setup-scripts',
			GEMSECURITY_ASSETS_URI . sprintf( 'build/setup.%s.js', GEMSECURITY_VERSION ),
			$deps['dependencies'],
			$deps['version'],
			true
		);

		$data = ( new Assets() )->get_scripts_data();
		$data['admin_url']   = admin_url();
		$data['admin_email'] = get_option( 'admin_email' );
		$data['site_name']   = get_bloginfo( 'name' );
		$data['setup_url']   = admin_url( 'admin.php?page=' . self::PAGE_ID );
		$data['dashboard']   = admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG );

		wp_localize_script( 'gemsecurity-setup-scripts', 'GemSecurityGlobal', $data );
		wp_set_script_translations( 'gemsecurity-setup-scripts', 'gemsecurity', GEMSECURITY_ROOT_DIR_PATH . 'languages' );
	}
}
