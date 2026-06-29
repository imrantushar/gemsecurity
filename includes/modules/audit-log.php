<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Expanded audit log.
 *
 * Records meaningful site-management events (content, plugins/themes, users,
 * settings) into the same activity log used by the security modules. Each
 * group can be toggled independently. Security events (logins, firewall,
 * scans, admin guard) are logged by their own modules.
 */
class AuditLog {

	/** Options worth auditing — everything else is too noisy. */
	private static function watched_options() {
		return [
			'siteurl', 'home', 'blogname', 'admin_email', 'users_can_register',
			'default_role', 'template', 'stylesheet', 'permalink_structure',
			'WPLANG', 'timezone_string', 'blog_public',
		];
	}

	public static function init() {
		if ( ! Helper::get_setting( 'audit_log_enabled', true ) ) {
			return;
		}
		$self = new self();

		if ( Helper::get_setting( 'audit_content', true ) ) {
			add_action( 'transition_post_status', [ $self, 'on_post_status' ], 10, 3 );
			add_action( 'before_delete_post', [ $self, 'on_post_delete' ], 10, 1 );
		}

		if ( Helper::get_setting( 'audit_plugins_themes', true ) ) {
			add_action( 'activated_plugin', [ $self, 'on_plugin_activated' ], 10, 1 );
			add_action( 'deactivated_plugin', [ $self, 'on_plugin_deactivated' ], 10, 1 );
			add_action( 'switch_theme', [ $self, 'on_switch_theme' ], 10, 1 );
			add_action( 'upgrader_process_complete', [ $self, 'on_upgrade' ], 10, 2 );
		}

		if ( Helper::get_setting( 'audit_users', true ) ) {
			add_action( 'deleted_user', [ $self, 'on_user_deleted' ], 10, 1 );
			add_action( 'after_password_reset', [ $self, 'on_password_reset' ], 10, 1 );
			add_action( 'wp_logout', [ $self, 'on_logout' ], 10, 1 );
		}

		if ( Helper::get_setting( 'audit_settings', true ) ) {
			foreach ( self::watched_options() as $opt ) {
				add_action( "update_option_{$opt}", [ $self, 'on_option_changed' ], 10, 3 );
			}
		}
	}

	/* ----------------------------- Content ----------------------------- */

	public function on_post_status( $new_status, $old_status, $post ) {
		if ( ! $post instanceof \WP_Post ) {
			return;
		}
		// Ignore autosaves, revisions, and noise post types.
		if ( wp_is_post_revision( $post ) || wp_is_post_autosave( $post ) ) {
			return;
		}
		if ( in_array( $post->post_type, [ 'revision', 'nav_menu_item', 'customize_changeset', 'oembed_cache', 'user_request' ], true ) ) {
			return;
		}
		if ( $new_status === $old_status && 'publish' !== $new_status ) {
			return;
		}
		if ( 'auto-draft' === $new_status || ( 'auto-draft' === $old_status && 'draft' === $new_status ) ) {
			return;
		}

		if ( 'publish' === $new_status && 'publish' !== $old_status ) {
			$verb = 'published';
		} elseif ( 'trash' === $new_status ) {
			$verb = 'trashed';
		} elseif ( 'publish' === $new_status ) {
			$verb = 'updated';
		} else {
			$verb = 'saved (' . $new_status . ')';
		}

		Logger::log(
			'content_' . ( 'published' === $verb ? 'published' : ( 'trashed' === $verb ? 'trashed' : 'updated' ) ),
			sprintf( '%s "%s" %s.', self::post_type_label( $post ), get_the_title( $post ) ?: '(no title)', $verb ),
			Logger::SEVERITY_INFO,
			[ 'context' => [ 'post_id' => $post->ID, 'post_type' => $post->post_type, 'status' => $new_status ] ]
		);
	}

	public function on_post_delete( $post_id ) {
		$post = get_post( $post_id );
		if ( ! $post instanceof \WP_Post || wp_is_post_revision( $post ) ) {
			return;
		}
		if ( in_array( $post->post_type, [ 'revision', 'nav_menu_item', 'customize_changeset', 'oembed_cache' ], true ) ) {
			return;
		}
		Logger::log(
			'content_deleted',
			sprintf( '%s "%s" permanently deleted.', self::post_type_label( $post ), get_the_title( $post ) ?: '#' . $post_id ),
			Logger::SEVERITY_NOTICE,
			[ 'context' => [ 'post_id' => $post_id, 'post_type' => $post->post_type ] ]
		);
	}

	/* ------------------------- Plugins & themes ------------------------ */

	public function on_plugin_activated( $plugin ) {
		Logger::log( 'plugin_activated', sprintf( 'Plugin activated: %s', $plugin ), Logger::SEVERITY_NOTICE, [ 'context' => [ 'plugin' => $plugin ] ] );
	}

	public function on_plugin_deactivated( $plugin ) {
		Logger::log( 'plugin_deactivated', sprintf( 'Plugin deactivated: %s', $plugin ), Logger::SEVERITY_NOTICE, [ 'context' => [ 'plugin' => $plugin ] ] );
	}

	public function on_switch_theme( $new_name ) {
		Logger::log( 'theme_switched', sprintf( 'Active theme switched to: %s', $new_name ), Logger::SEVERITY_NOTICE, [ 'context' => [ 'theme' => $new_name ] ] );
	}

	public function on_upgrade( $upgrader, $data ) {
		if ( ! is_array( $data ) || empty( $data['type'] ) || empty( $data['action'] ) ) {
			return;
		}
		$items = [];
		if ( ! empty( $data['plugins'] ) ) {
			$items = (array) $data['plugins'];
		} elseif ( ! empty( $data['themes'] ) ) {
			$items = (array) $data['themes'];
		}
		$label = $items ? implode( ', ', $items ) : $data['type'];
		Logger::log(
			'software_' . $data['action'],
			sprintf( '%s %s: %s', ucfirst( $data['type'] ), $data['action'] === 'update' ? 'updated' : $data['action'] . 'ed', $label ),
			Logger::SEVERITY_NOTICE,
			[ 'context' => [ 'type' => $data['type'], 'action' => $data['action'], 'items' => $items ] ]
		);
	}

	/* ------------------------------ Users ------------------------------ */

	public function on_user_deleted( $user_id ) {
		Logger::log( 'user_deleted', sprintf( 'User account #%d deleted.', $user_id ), Logger::SEVERITY_WARNING, [ 'context' => [ 'target_user_id' => $user_id ] ] );
	}

	public function on_password_reset( $user ) {
		$login = $user instanceof \WP_User ? $user->user_login : '';
		Logger::log( 'password_reset', sprintf( 'Password reset completed for "%s".', $login ), Logger::SEVERITY_NOTICE, [ 'context' => [ 'target' => $login ] ] );
	}

	public function on_logout( $user_id ) {
		$user = get_userdata( $user_id );
		Logger::log( 'user_logout', sprintf( '%s logged out.', $user ? $user->user_login : '#' . $user_id ), Logger::SEVERITY_INFO, [ 'user_id' => $user_id ] );
	}

	/* ---------------------------- Settings ----------------------------- */

	public function on_option_changed( $old_value, $new_value, $option ) {
		if ( $old_value === $new_value ) {
			return;
		}
		Logger::log(
			'option_changed',
			sprintf( 'Site setting "%s" was changed.', $option ),
			Logger::SEVERITY_NOTICE,
			[ 'context' => [ 'option' => $option, 'old' => self::scalar( $old_value ), 'new' => self::scalar( $new_value ) ] ]
		);
	}

	/* ----------------------------- Helpers ----------------------------- */

	private static function post_type_label( $post ) {
		$obj = get_post_type_object( $post->post_type );
		return $obj && isset( $obj->labels->singular_name ) ? $obj->labels->singular_name : ucfirst( $post->post_type );
	}

	private static function scalar( $value ) {
		if ( is_scalar( $value ) ) {
			return (string) $value;
		}
		return '[' . gettype( $value ) . ']';
	}

	/** Event-type → category map, shared with the Logs REST filter. */
	public static function category_map() {
		return [
			'login'           => [ 'admin_login', 'user_login', 'login_failed', 'login_lockout', 'admin_session_expired', 'user_logout', '2fa_challenge', '2fa_failed', '2fa_success' ],
			'firewall'        => [ 'firewall_block', 'author_enumeration_blocked', 'captcha_failed', 'waf_block', 'waf_bad_bot', 'waf_rate_limited', 'waf_404_flood', 'ip_banned' ],
			'bots'            => [ 'waf_bad_bot' ],
			'vulnerability'   => [ 'vuln_found' ],
			'admin_guard'     => [ 'rogue_admin_deleted', 'rogue_admin_demoted' ],
			'scanner'         => [ 'scan_completed' ],
			'content'         => [ 'content_published', 'content_updated', 'content_trashed', 'content_deleted' ],
			'plugins_themes'  => [ 'plugin_activated', 'plugin_deactivated', 'theme_switched', 'software_update', 'software_install' ],
			'users'           => [ 'user_deleted', 'password_reset', 'user_registered', 'user_role_changed' ],
			'settings'        => [ 'option_changed' ],
			'geolocation'     => [ 'geo_login_blocked', 'geo_site_blocked', 'geo_new_location', 'geo_verified', 'geo_verify_failed' ],
		];
	}
}
