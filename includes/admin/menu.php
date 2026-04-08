<?php
namespace GemSecurity\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use GemSecurity\Helper;

class Menu {

	public static function init() {
		$self = new self();
		add_action( 'admin_menu', [ $self, 'admin_menu' ] );
	}

	public function admin_menu() {
		$page_title = $this->get_toplevel_menu_title();

		add_menu_page(
			$page_title,
			$page_title,
			'manage_options',
			GEMSECURITY_PLUGIN_SLUG,
			[ $this, 'load_main_template' ],
			'dashicons-shield',
			80
		);

		foreach ( Helper::get_admin_menu_list() as $item_key => $item ) {
			add_submenu_page(
				$item['parent_slug'],
				$item['title'],
				$item['title'],
				$item['capability'],
				$item_key,
				[ $this, 'load_main_template' ]
			);
		}
	}

	public function load_main_template() {
		$preloader_html = apply_filters( 'gemsecurity/preloader', 'Loading...' );
		echo '<div id="gemsecuritywrap" class="gemsecuritywrap">' . wp_kses_post( $preloader_html ) . '</div>';
	}

	public function get_toplevel_menu_title() {
		return apply_filters( 'gemsecurity/admin/toplevel_menu_title', __( 'GemSecurity', 'gemsecurity' ) );
	}
}
