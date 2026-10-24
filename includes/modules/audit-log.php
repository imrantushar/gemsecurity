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

		// Stamp every logged event with who/how: channel, user agent, session.
		add_action( 'set_logged_in_cookie', [ $self, 'remember_login_token' ], 10, 6 );
		add_filter( 'gemsecurity/log_args', [ $self, 'add_actor_context' ], 10, 2 );

		if ( Helper::get_setting( 'audit_content', true ) ) {
			add_action( 'transition_post_status', [ $self, 'on_post_status' ], 10, 3 );
			add_action( 'before_delete_post', [ $self, 'on_post_delete' ], 10, 1 );
			// After core's revision save (post_updated @10) so the revision id is known.
			add_action( 'post_updated', [ $self, 'on_post_updated' ], 20, 3 );
			add_action( 'added_post_meta', [ $self, 'on_post_meta' ], 10, 4 );
			add_action( 'updated_post_meta', [ $self, 'on_post_meta' ], 10, 4 );
			add_action( 'deleted_post_meta', [ $self, 'on_post_meta_deleted' ], 10, 4 );
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
			add_action( 'user_register', [ $self, 'on_user_registered' ], 10, 1 );
			add_action( 'set_user_role', [ $self, 'on_user_role_changed' ], 10, 3 );
			add_action( 'profile_update', [ $self, 'on_profile_update' ], 10, 2 );
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

		if ( $new_status === $old_status ) {
			return; // Same-status edits are logged by on_post_updated() with a diff.
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

	/**
	 * Edits to live content: what changed, with a before/after snippet, any
	 * newly added outbound links, and the revision to compare or restore.
	 * Status changes are left to on_post_status().
	 *
	 * @param int      $post_id
	 * @param \WP_Post $after
	 * @param \WP_Post $before
	 */
	public function on_post_updated( $post_id, $after, $before ) {
		if ( ! $after instanceof \WP_Post || ! $before instanceof \WP_Post || ! self::is_tracked_post( $after ) ) {
			return;
		}
		if ( $after->post_status !== $before->post_status || ! in_array( $after->post_status, [ 'publish', 'private', 'future' ], true ) ) {
			return;
		}

		$fields  = [
			'post_title'     => 'title',
			'post_name'      => 'slug',
			'post_content'   => 'content',
			'post_excerpt'   => 'excerpt',
			'post_author'    => 'author',
			'post_date'      => 'date',
			'post_parent'    => 'parent',
			'post_password'  => 'password',
			'comment_status' => 'comments',
		];
		$changes = [];
		foreach ( $fields as $field => $label ) {
			if ( (string) $before->$field === (string) $after->$field ) {
				continue;
			}
			if ( 'post_content' === $field ) {
				$changes[ $label ] = self::text_diff( $before->post_content, $after->post_content );
			} elseif ( 'post_password' === $field ) {
				$changes[ $label ] = [ 'old' => '' !== $before->post_password ? 'set' : 'none', 'new' => '' !== $after->post_password ? 'set' : 'none' ];
			} else {
				$changes[ $label ] = [ 'old' => self::clip( $before->$field ), 'new' => self::clip( $after->$field ) ];
			}
		}
		if ( ! $changes ) {
			return;
		}

		$new_links = array_values( array_diff( self::external_links( $after->post_content ), self::external_links( $before->post_content ) ) );

		if ( $new_links ) {
			$severity = Logger::SEVERITY_WARNING;
		} elseif ( isset( $changes['slug'] ) || isset( $changes['author'] ) || isset( $changes['password'] ) ) {
			$severity = Logger::SEVERITY_NOTICE;
		} else {
			$severity = Logger::SEVERITY_INFO;
		}

		$message = sprintf(
			'%s "%s" edited: %s.',
			self::post_type_label( $after ),
			get_the_title( $after ) ?: '(no title)',
			implode( ', ', array_keys( $changes ) )
		);
		if ( $new_links ) {
			$message .= sprintf( ' %d new outbound link(s) added.', count( $new_links ) );
		}

		$context = [
			'post_id'   => $post_id,
			'post_type' => $after->post_type,
			'url'       => get_permalink( $after ),
			'changes'   => $changes,
			'new_links' => array_slice( $new_links, 0, 20 ),
		];

		// Core saves the revision on wp_after_insert_post (priority 9); log just
		// after it so the entry can link to that revision.
		$log = static function ( $inserted_id ) use ( &$log, $post_id, $message, $severity, $context ) {
			if ( (int) $inserted_id !== (int) $post_id ) {
				return;
			}
			remove_action( 'wp_after_insert_post', $log, 20 );
			$revisions           = wp_get_post_revisions( $post_id, [ 'numberposts' => 1, 'fields' => 'ids' ] );
			$context['revision'] = $revisions ? (int) reset( $revisions ) : 0;
			Logger::log( 'content_updated', $message, $severity, [ 'context' => $context ] );
		};
		add_action( 'wp_after_insert_post', $log, 20, 1 );
	}

	/**
	 * Search-visibility meta (SEO title/description, canonical, robots,
	 * redirects, focus keyword), the page template and featured image.
	 * Matched by key pattern so any SEO plugin's fields are covered.
	 */
	public static function is_watched_meta( $meta_key ) {
		if ( in_array( $meta_key, [ '_wp_page_template', '_thumbnail_id' ], true ) ) {
			return true;
		}
		if ( 0 === strpos( $meta_key, '_edit_' ) || 0 === strpos( $meta_key, '_wp_' ) ) {
			return false;
		}
		$pattern = apply_filters(
			'gemsecurity/audit_meta_pattern',
			'/(seo|meta_?desc|metadesc|_description$|_title$|canonical|robots|noindex|nofollow|focus_?(kw|keyword)|redirect)/i'
		);
		return (bool) preg_match( $pattern, $meta_key );
	}

	public function on_post_meta( $meta_id, $post_id, $meta_key, $meta_value ) {
		if ( ! self::is_watched_meta( $meta_key ) ) {
			return;
		}
		$post = get_post( $post_id );
		// Live content only — drafts churn meta on every autosave.
		if ( ! $post || ! self::is_tracked_post( $post ) || ! in_array( $post->post_status, [ 'publish', 'private', 'future' ], true ) ) {
			return;
		}
		// Old value isn't passed; the previous revision of the post holds the
		// content, but meta history isn't kept, so record the new value.
		Logger::log(
			'content_meta_changed',
			sprintf( '%s "%s": "%s" set to "%s".', self::post_type_label( $post ), get_the_title( $post ) ?: '(no title)', $meta_key, self::clip( self::scalar( $meta_value ), 120 ) ),
			Logger::SEVERITY_NOTICE,
			// Context field, not a query — meta_key here is the name of the
			// post meta that changed, recorded alongside the event.
			[ 'context' => [ 'post_id' => $post_id, 'post_type' => $post->post_type, 'url' => get_permalink( $post ), 'meta_key' => $meta_key, 'new' => self::clip( self::scalar( $meta_value ) ) ] ] // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
		);
	}

	public function on_post_meta_deleted( $meta_ids, $post_id, $meta_key, $meta_value ) {
		if ( ! self::is_watched_meta( $meta_key ) ) {
			return;
		}
		$post = get_post( $post_id );
		if ( ! $post || ! self::is_tracked_post( $post ) ) {
			return;
		}
		Logger::log(
			'content_meta_changed',
			sprintf( '%s "%s": "%s" removed.', self::post_type_label( $post ), get_the_title( $post ) ?: '(no title)', $meta_key ),
			Logger::SEVERITY_NOTICE,
			// Context field, not a query.
			[ 'context' => [ 'post_id' => $post_id, 'post_type' => $post->post_type, 'meta_key' => $meta_key, 'new' => null ] ] // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
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

	public function on_user_registered( $user_id ) {
		$user = get_userdata( $user_id );
		Logger::log(
			'user_registered',
			sprintf( 'New user "%s" created (%s).', $user ? $user->user_login : '#' . $user_id, $user ? implode( ', ', $user->roles ) : '' ),
			Logger::SEVERITY_NOTICE,
			[ 'context' => [ 'target_user_id' => $user_id ] ]
		);
	}

	public function on_user_role_changed( $user_id, $role, $old_roles ) {
		if ( ! $old_roles ) {
			return; // Initial role on registration — logged by on_user_registered().
		}
		$user = get_userdata( $user_id );
		Logger::log(
			'user_role_changed',
			sprintf( 'Role of "%s" changed from %s to %s.', $user ? $user->user_login : '#' . $user_id, implode( ', ', (array) $old_roles ), $role ),
			'administrator' === $role ? Logger::SEVERITY_WARNING : Logger::SEVERITY_NOTICE,
			[ 'context' => [ 'target_user_id' => $user_id, 'old' => array_values( (array) $old_roles ), 'new' => $role ] ]
		);
	}

	public function on_profile_update( $user_id, $old_user ) {
		$user = get_userdata( $user_id );
		if ( ! $user || ! $old_user instanceof \WP_User ) {
			return;
		}
		$what = [];
		if ( $user->user_email !== $old_user->user_email ) {
			$what[] = 'email';
		}
		if ( $user->user_pass !== $old_user->user_pass ) {
			$what[] = 'password';
		}
		if ( ! $what ) {
			return;
		}
		Logger::log(
			'user_credentials_changed',
			sprintf( '%s of "%s" changed.', ucfirst( implode( ' and ', $what ) ), $user->user_login ),
			Logger::SEVERITY_NOTICE,
			[ 'context' => [ 'target_user_id' => $user_id, 'changed' => $what, 'old_email' => in_array( 'email', $what, true ) ? $old_user->user_email : null ] ]
		);
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

	/* -------------------------- Actor context -------------------------- */

	/** Session token of a login happening in this request (cookie not readable yet). */
	private static $login_token = '';

	public function remember_login_token( $cookie, $expire, $expiration, $user_id, $scheme, $token = '' ) {
		self::$login_token = (string) $token;
	}

	/**
	 * Add channel, user agent and a short login-session id to every event, so
	 * a content change can be traced to the exact login (and IP) that made it.
	 *
	 * @param array  $args
	 * @param string $event_type
	 * @return array
	 */
	public function add_actor_context( $args, $event_type ) {
		$context = isset( $args['context'] ) && is_array( $args['context'] ) ? $args['context'] : [];
		$token   = self::$login_token ?: ( function_exists( 'wp_get_session_token' ) ? wp_get_session_token() : '' );

		$context += array_filter( [
			'via'     => self::channel(),
			'ua'      => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 255 ) : '',
			'session' => $token ? substr( hash( 'sha256', $token ), 0, 12 ) : '',
		] );
		$args['context'] = $context;
		return $args;
	}

	/** How the request reached WordPress. */
	private static function channel() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'wp-cli';
		}
		if ( wp_doing_cron() ) {
			return 'cron';
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return 'xml-rpc';
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return did_action( 'application_password_did_authenticate' ) ? 'rest (app password)' : 'rest';
		}
		if ( wp_doing_ajax() ) {
			return 'ajax';
		}
		return is_admin() ? 'admin' : 'web';
	}

	/* ----------------------------- Helpers ----------------------------- */

	private static function is_tracked_post( $post ) {
		if ( wp_is_post_revision( $post ) || wp_is_post_autosave( $post ) ) {
			return false;
		}
		return ! in_array( $post->post_type, [ 'revision', 'nav_menu_item', 'customize_changeset', 'oembed_cache', 'user_request', 'wp_global_styles' ], true );
	}

	private static function clip( $text, $max = 300 ) {
		$text = (string) $text;
		return strlen( $text ) > $max ? substr( $text, 0, $max ) . '…' : $text;
	}

	/**
	 * Compact content diff: trims the shared prefix/suffix and keeps the
	 * changed middle of each side, with a little surrounding context.
	 */
	private static function text_diff( $old, $new ) {
		$old = (string) $old;
		$new = (string) $new;
		$max = min( strlen( $old ), strlen( $new ) );

		$start = 0;
		while ( $start < $max && $old[ $start ] === $new[ $start ] ) {
			$start++;
		}
		$end = 0;
		while ( $end < $max - $start && $old[ strlen( $old ) - 1 - $end ] === $new[ strlen( $new ) - 1 - $end ] ) {
			$end++;
		}

		$from = max( 0, $start - 40 );
		return [
			'old'        => self::clip( substr( $old, $from, strlen( $old ) - $end - $from + 40 ), 500 ),
			'new'        => self::clip( substr( $new, $from, strlen( $new ) - $end - $from + 40 ), 500 ),
			'old_length' => strlen( $old ),
			'new_length' => strlen( $new ),
		];
	}

	/** Unique off-site link targets in a block of HTML. */
	private static function external_links( $html ) {
		if ( ! preg_match_all( '/href\s*=\s*["\']([^"\']+)["\']/i', (string) $html, $m ) ) {
			return [];
		}
		$home  = wp_parse_url( home_url(), PHP_URL_HOST );
		$links = [];
		foreach ( $m[1] as $url ) {
			$host = wp_parse_url( $url, PHP_URL_HOST );
			if ( $host && strcasecmp( $host, (string) $home ) !== 0 ) {
				$links[] = $url;
			}
		}
		return array_values( array_unique( $links ) );
	}


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
			'bots'            => [ 'waf_bad_bot', 'seems_bot' ],
			'vulnerability'   => [ 'vuln_found' ],
			'admin_guard'     => [ 'rogue_admin_deleted', 'rogue_admin_demoted' ],
			'scanner'         => [ 'scan_completed' ],
			'content'         => [ 'content_published', 'content_updated', 'content_trashed', 'content_deleted', 'content_meta_changed' ],
			'plugins_themes'  => [ 'plugin_activated', 'plugin_deactivated', 'theme_switched', 'software_update', 'software_install' ],
			'users'           => [ 'user_deleted', 'password_reset', 'user_registered', 'user_role_changed', 'user_credentials_changed' ],
			'settings'        => [ 'option_changed' ],
			'geolocation'     => [ 'geo_login_blocked', 'geo_site_blocked', 'geo_new_location', 'geo_verified', 'geo_verify_failed' ],
			'academy'         => [ 'academy_login_blocked', 'academy_captcha_failed', 'academy_registration', 'academy_instructor_status', 'academy_content_blocked', 'academy_geo_blocked', 'academy_enrollment_abuse', 'academy_ajax_rate_limited' ],
		];
	}
}
