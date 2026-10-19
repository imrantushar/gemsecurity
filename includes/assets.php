<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Assets {

	public static function init() {
		$self = new self();
		add_action( 'admin_enqueue_scripts', [ $self, 'backend_scripts' ], 10 );
	}

	/**
	 * Enqueue backend assets on plugin pages only.
	 *
	 * @param string $hook
	 */
	public function backend_scripts( $hook ) {
		if ( ! Helper::plugin_page_hook_suffix( $hook ) ) {
			return;
		}

		remove_all_actions( 'admin_notices' );

		$css_path = GEMSECURITY_ASSETS_DIR_PATH . 'build/backend.css';
		if ( file_exists( $css_path ) ) {
			wp_enqueue_style(
				'gemsecurity-admin-style',
				GEMSECURITY_ASSETS_URI . 'build/backend.css',
				[ 'wp-components' ],
				filemtime( $css_path ),
				'all'
			);
		}

		$asset_file = GEMSECURITY_ASSETS_DIR_PATH . sprintf( 'build/backend.%s.asset.php', GEMSECURITY_VERSION );
		if ( ! file_exists( $asset_file ) ) {
			return;
		}

		$dependencies = include $asset_file;
		wp_enqueue_script(
			'gemsecurity-admin-scripts',
			GEMSECURITY_ASSETS_URI . sprintf( 'build/backend.%s.js', GEMSECURITY_VERSION ),
			$dependencies['dependencies'],
			$dependencies['version'],
			true
		);

		wp_localize_script( 'gemsecurity-admin-scripts', 'GemSecurityGlobal', $this->get_scripts_data() );
		wp_set_script_translations( 'gemsecurity-admin-scripts', 'gemsecurity', GEMSECURITY_ROOT_DIR_PATH . 'languages' );
	}

	public function get_scripts_data() {
		/**
		 * Filters the localized React payload. The StoreEngine SDK bridge
		 * (StoreLicense::add_script_data) hooks this to inject `SeSdk` for the
		 * settings License tab / insights opt-in.
		 *
		 * @param array $data
		 */
		return apply_filters( 'gemsecurity/assets/script_data', [
			'nonce'            => wp_create_nonce( 'wp_rest' ),
			'gemsecurity_nonce'      => wp_create_nonce( 'gemsecurity_nonce' ),
			'rest_url'         => esc_url_raw( rest_url() ),
			'namespace'        => GEMSECURITY_PLUGIN_SLUG . '/v1/',
			'plugin_root_url'  => GEMSECURITY_PLUGIN_ROOT_URI,
			'plugin_root_path' => GEMSECURITY_ROOT_DIR_PATH,
			'ajaxurl'          => esc_url( admin_url( 'admin-ajax.php' ) ),
			'admin_url'        => admin_url(),
			'site_url'         => site_url(),
			'route_path'       => wp_parse_url( admin_url(), PHP_URL_PATH ),
			'menu'             => wp_json_encode( Helper::get_admin_menu_list() ),
			'modules'          => Modules\Registry::for_js(),
			// For page pickers (e.g. where public login links point).
			'pages'            => array_map( static function ( $p ) {
				return [ 'value' => (string) $p->ID, 'label' => $p->post_title ? $p->post_title : sprintf( '#%d', $p->ID ) ];
			}, get_pages( [ 'post_status' => 'publish', 'number' => 300, 'sort_column' => 'post_title' ] ) ),
			'current_user_id'  => get_current_user_id(),
			'is_rtl'           => is_rtl(),
			'is_admin'         => is_admin(),
			'version'          => GEMSECURITY_VERSION,
			'roles'            => $this->get_editable_roles(),
			'is_pro'           => Helper::is_pro_active(),
			'gembackup'        => [
				'active' => Helper::gembackup_active(),
				'url'    => admin_url( 'admin.php?page=gembackup' ),
			],
			'pro_features'     => Helper::get_pro_features(),
			'upgrade_url'      => Helper::upgrade_url(),
		] );
	}

	/**
	 * Role slug => display name, for the 2FA enforce-by-role selector.
	 *
	 * @return array
	 */
	private function get_editable_roles() {
		if ( ! function_exists( 'get_editable_roles' ) ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
		}
		$out = [];
		foreach ( get_editable_roles() as $slug => $role ) {
			$out[ $slug ] = translate_user_role( $role['name'] );
		}
		return $out;
	}
}
