<?php
namespace GemSecurity\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use GemSecurity\Helper;
use GemSecurity\Modules\Registry;

class Menu {

	public static function init() {
		$self = new self();
		add_action( 'admin_menu', [ $self, 'admin_menu' ] );
		add_action( 'admin_enqueue_scripts', [ $self, 'menu_badge_styles' ] );
		add_filter( 'submenu_file', [ $self, 'highlight_group' ], 10, 2 );
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

		$this->collapse_to_groups();
	}

	/**
	 * Show one sidebar entry per navigation group instead of one per module.
	 *
	 * Every module page stays in `$submenu` so WordPress's own page resolver
	 * (`get_admin_page_parent()` iterates `$submenu` to find a module's parent,
	 * which is what makes `?page=<module>` resolve to its real hook) keeps
	 * working. The non-lead entries are given a `gemsec-hidden` CSS class and
	 * hidden from the sidebar; the lead entries are relabelled with the group
	 * title. The app's topbar holds the per-module navigation inside each group.
	 */
	private function collapse_to_groups() {
		global $submenu;

		if ( empty( $submenu[ GEMSECURITY_PLUGIN_SLUG ] ) ) {
			return;
		}

		$leads = [];
		foreach ( Registry::visible_groups() as $group ) {
			$leads[ $group['lead'] ] = $group['title'];
		}

		foreach ( $submenu[ GEMSECURITY_PLUGIN_SLUG ] as $i => $item ) {
			if ( isset( $leads[ $item[2] ] ) ) {
				$submenu[ GEMSECURITY_PLUGIN_SLUG ][ $i ][0] = esc_html( $leads[ $item[2] ] ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
			} else {
				// Keep the entry (so the page still resolves) but hide it from
				// the sidebar via CSS attached to its menu-slug class.
				$submenu[ GEMSECURITY_PLUGIN_SLUG ][ $i ][4] = trim( ( $item[4] ?? '' ) . ' gemsec-hidden' ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
			}
		}
	}

	/**
	 * Highlight the group entry while any of its module pages is open.
	 *
	 * @param string|null $submenu_file Current submenu file.
	 * @param string      $parent_file  Current parent file.
	 * @return string|null
	 */
	public function highlight_group( $submenu_file, $parent_file ) {
		if ( GEMSECURITY_PLUGIN_SLUG !== $parent_file ) {
			return $submenu_file;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		foreach ( Registry::visible_groups() as $group ) {
			if ( in_array( $page, $group['pages'], true ) ) {
				return $group['lead'];
			}
		}
		return $submenu_file;
	}

	/**
	 * Minimal CSS for the PRO pill in the native admin submenu. Printed on
	 * every admin page because the submenu is always present in the DOM.
	 */
	public function menu_badge_styles() {
		wp_register_style( 'gemsecurity-menu', false, [], GEMSECURITY_VERSION );
		wp_enqueue_style( 'gemsecurity-menu' );
		wp_add_inline_style( 'gemsecurity-menu', '#adminmenu .gemsec-pro-pill{display:inline-block;margin-left:6px;padding:0 6px;font-size:9px;font-weight:700;line-height:16px;letter-spacing:.4px;border-radius:9px;background:#f59e0b;color:#1f2937;vertical-align:middle;}#adminmenu .gemsec-hidden{display:none !important;}' );
	}

	public function load_main_template() {
		$preloader_html = apply_filters( 'gemsecurity/preloader', 'Loading...' );
		echo '<div id="gemsecuritywrap" class="gemsecuritywrap">' . wp_kses_post( $preloader_html ) . '</div>';
	}

	public function get_toplevel_menu_title() {
		return apply_filters( 'gemsecurity/admin/toplevel_menu_title', __( 'GemSecurity', 'gemsecurity' ) );
	}
}
