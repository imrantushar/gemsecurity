<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Session management + idle timeout.
 *
 * Idle timeout logs a user out after a period of inactivity (distinct from the
 * absolute admin-session timeout in Login Security). Session listing/revocation
 * is handled by the REST controller using WordPress session tokens.
 */
class Sessions {

	const ACTIVITY_META = '_gemsec_last_activity';

	public static function init() {
		if ( ! Helper::get_setting( 'idle_timeout_enabled', false ) ) {
			return;
		}
		$self = new self();
		add_action( 'init', [ $self, 'enforce_idle_timeout' ], 2 );
	}

	public function enforce_idle_timeout() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) || ! is_user_logged_in() ) {
			return;
		}
		// Don't count REST/AJAX heartbeats as activity-resetting in a way that hides idleness,
		// but also don't log out background requests.
		$idle = max( 1, (int) Helper::get_setting( 'idle_timeout_minutes', 30 ) ) * MINUTE_IN_SECONDS;
		$uid  = get_current_user_id();
		$last = (int) get_user_meta( $uid, self::ACTIVITY_META, true );
		$now  = time();

		if ( $last && ( $now - $last ) > $idle ) {
			delete_user_meta( $uid, self::ACTIVITY_META );
			Logger::log( 'idle_logout', sprintf( 'User "%s" logged out after inactivity.', wp_get_current_user()->user_login ), Logger::SEVERITY_INFO, [ 'user_id' => $uid ] );
			wp_logout();
			if ( ! wp_doing_ajax() && ! ( defined( 'REST_REQUEST' ) && REST_REQUEST ) && ! headers_sent() ) {
				wp_safe_redirect( wp_login_url() );
				exit;
			}
			return;
		}

		// Throttle activity writes to once per minute.
		if ( ! $last || ( $now - $last ) > MINUTE_IN_SECONDS ) {
			update_user_meta( $uid, self::ACTIVITY_META, $now );
		}
	}

	/**
	 * Active sessions for a user, normalised for display.
	 *
	 * @param int $user_id
	 * @return array
	 */
	public static function list_for( $user_id ) {
		$manager  = \WP_Session_Tokens::get_instance( $user_id );
		$sessions = $manager->get_all();
		$current  = wp_get_session_token();

		$out = [];
		foreach ( $sessions as $s ) {
			$out[] = [
				'ip'         => $s['ip'] ?? '',
				'ua'         => $s['ua'] ?? '',
				'login'      => isset( $s['login'] ) ? gmdate( 'Y-m-d H:i', (int) $s['login'] ) : '',
				'expiration' => isset( $s['expiration'] ) ? gmdate( 'Y-m-d H:i', (int) $s['expiration'] ) : '',
				// We can flag the current session by matching token hash isn't exposed; approximate by IP+UA.
				'is_current' => ( ( $s['ip'] ?? '' ) === Helper::get_ip_address() ),
			];
		}
		return $out;
	}
}
