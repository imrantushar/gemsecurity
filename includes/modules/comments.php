<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Fully disable the WordPress comment system.
 *
 * Comments (and pingbacks/trackbacks) are a public, unauthenticated write
 * surface — a favourite channel for spam and injected malicious links/markup.
 * Many sites never use them. When this hardening switch is on the module closes
 * comments everywhere, hides any that already exist, and strips the comment UI
 * from wp-admin so nothing can be posted or displayed.
 */
class Comments {

	public static function init() {
		if ( ! Helper::get_setting( 'comments_disabled', false ) ) {
			return;
		}
		$self = new self();

		// Front-end: nothing is open, and existing comments never render.
		add_filter( 'comments_open', '__return_false', 20 );
		add_filter( 'pings_open', '__return_false', 20 );
		add_filter( 'comments_array', '__return_empty_array', 20 );

		// Drop comment/trackback support from every post type.
		add_action( 'init', [ $self, 'remove_post_type_support' ], 100 );

		// Stop advertising the pingback endpoint.
		add_filter( 'wp_headers', [ $self, 'strip_pingback_header' ] );
		add_action( 'wp_loaded', [ $self, 'strip_feed_comment_links' ] );

		// wp-admin: remove the menu, the dashboard widget, the admin-bar node,
		// and bounce anyone who deep-links to the comments screen.
		add_action( 'admin_menu', [ $self, 'remove_admin_menu' ] );
		add_action( 'admin_init', [ $self, 'redirect_comment_screens' ] );
		add_action( 'wp_dashboard_setup', [ $self, 'remove_dashboard_widget' ] );
		add_action( 'admin_bar_menu', [ $self, 'remove_admin_bar_node' ], 999 );
	}

	/**
	 * Remove comment + trackback support from all registered post types.
	 */
	public function remove_post_type_support() {
		foreach ( get_post_types() as $post_type ) {
			if ( post_type_supports( $post_type, 'comments' ) ) {
				remove_post_type_support( $post_type, 'comments' );
			}
			if ( post_type_supports( $post_type, 'trackbacks' ) ) {
				remove_post_type_support( $post_type, 'trackbacks' );
			}
		}
	}

	/**
	 * @param array $headers
	 * @return array
	 */
	public function strip_pingback_header( $headers ) {
		if ( is_array( $headers ) ) {
			unset( $headers['X-Pingback'] );
		}
		return $headers;
	}

	/**
	 * Remove the comment/trackback feeds' extra <link>s from the head.
	 */
	public function strip_feed_comment_links() {
		remove_action( 'wp_head', 'feed_links_extra', 3 );
	}

	public function remove_admin_menu() {
		remove_menu_page( 'edit-comments.php' );
		remove_submenu_page( 'options-general.php', 'options-discussion.php' );
	}

	/**
	 * Redirect the comments / discussion screens back to the dashboard.
	 */
	public function redirect_comment_screens() {
		global $pagenow;
		if ( in_array( $pagenow, [ 'edit-comments.php', 'options-discussion.php' ], true ) ) {
			wp_safe_redirect( admin_url() );
			exit;
		}
	}

	public function remove_dashboard_widget() {
		remove_meta_box( 'dashboard_recent_comments', 'dashboard', 'normal' );
	}

	/**
	 * @param \WP_Admin_Bar $wp_admin_bar
	 */
	public function remove_admin_bar_node( $wp_admin_bar ) {
		if ( is_object( $wp_admin_bar ) && method_exists( $wp_admin_bar, 'remove_node' ) ) {
			$wp_admin_bar->remove_node( 'comments' );
		}
	}
}
