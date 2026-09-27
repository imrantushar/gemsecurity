<?php
namespace GemSecurity\Security;

use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Containment actions taken after a suspected compromise.
 *
 * Free ships the one action that needs no file access. Pro adds
 * key/salt regeneration (which rewrites wp-config.php) and rolling back to the
 * last clean backup; both are surfaced alongside this on the Incident Response
 * page rather than in a second place.
 */
class Recovery {

	/**
	 * Force-logout every user by clearing all session tokens.
	 *
	 * Done as a single DELETE rather than by walking users and calling
	 * WP_Session_Tokens: an incident is exactly when the user list may be
	 * large or partly hidden, and a per-user loop with a query cap would
	 * silently leave the tail of it still logged in.
	 *
	 * @return int Number of session records cleared.
	 */
	public static function logout_all_users() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$count = (int) $wpdb->query(
			$wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s", 'session_tokens' )
		);

		Logger::log(
			'recovery_logout_all',
			sprintf( 'Forced logout of all users (%d session record(s) cleared).', $count ),
			Logger::SEVERITY_CRITICAL
		);

		return $count;
	}
}
