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
		add_action( 'admin_head', [ $self, 'menu_badge_styles' ] );
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

		$pro_active = Helper::is_pro_active();

		foreach ( Helper::get_admin_menu_list() as $item_key => $item ) {
			$title = $item['title'];

			// Surface a PRO pill on Pro-gated items while Pro is inactive.
			if ( ! empty( $item['is_pro'] ) && ! $pro_active ) {
				$title .= ' <span class="gemsec-pro-pill">' . esc_html__( 'PRO', 'gemsecurity' ) . '</span>';
			}

			add_submenu_page(
				$item['parent_slug'],
				$item['title'],
				$title,
				$item['capability'],
				$item_key,
				[ $this, 'load_main_template' ]
			);
		}
	}

	/**
	 * Minimal CSS for the PRO pill in the native admin submenu. Printed on
	 * every admin page because the submenu is always present in the DOM.
	 */
	public function menu_badge_styles() {
		echo '<style>#adminmenu .gemsec-pro-pill{display:inline-block;margin-left:6px;padding:0 6px;font-size:9px;font-weight:700;line-height:16px;letter-spacing:.4px;border-radius:9px;background:#f59e0b;color:#1f2937;vertical-align:middle;}</style>';
	}

	public function load_main_template() {
		$preloader_html = apply_filters( 'gemsecurity/preloader', 'Loading...' );
		echo '<div id="gemsecuritywrap" class="gemsecuritywrap">' . wp_kses_post( $preloader_html ) . '</div>';
	}

	public function get_toplevel_menu_title() {
		return apply_filters( 'gemsecurity/admin/toplevel_menu_title', __( 'GemSecurity', 'gemsecurity' ) );
	}
}
