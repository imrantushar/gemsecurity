<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Central activity / security event logger.
 *
 * Writes to the {$wpdb->prefix}gemsecurity_logs table. Every security-relevant
 * event in the plugin should flow through Logger::log() so the Logs screen and
 * Dashboard can surface a single source of truth.
 */
class Logger {

	const SEVERITY_INFO     = 'info';
	const SEVERITY_NOTICE   = 'notice';
	const SEVERITY_WARNING  = 'warning';
	const SEVERITY_CRITICAL = 'critical';

	/**
	 * Record a security event.
	 *
	 * @param string $event_type Machine slug, e.g. "admin_login", "rogue_admin_deleted".
	 * @param string $message    Human readable message.
	 * @param string $severity   One of the SEVERITY_* constants.
	 * @param array  $args       Optional { user_id, ip_address, context (array) }.
	 * @return int|false Inserted row id or false on failure.
	 */
	public static function log( $event_type, $message, $severity = self::SEVERITY_INFO, $args = [] ) {
		global $wpdb;

		$table = $wpdb->prefix . 'gemsecurity_logs';

		$user_id    = isset( $args['user_id'] ) ? absint( $args['user_id'] ) : get_current_user_id();
		$ip_address = isset( $args['ip_address'] ) ? $args['ip_address'] : Helper::get_ip_address();
		$context    = isset( $args['context'] ) && ! empty( $args['context'] ) ? wp_json_encode( $args['context'] ) : null;

		$inserted = $wpdb->insert(
			$table,
			[
				'event_type' => substr( (string) $event_type, 0, 50 ),
				'severity'   => in_array( $severity, self::severities(), true ) ? $severity : self::SEVERITY_INFO,
				'message'    => (string) $message,
				'ip_address' => $ip_address ? substr( $ip_address, 0, 45 ) : null,
				'user_id'    => $user_id ? $user_id : null,
				'context'    => $context,
				'created_at' => current_time( 'mysql' ),
			],
			[ '%s', '%s', '%s', '%s', '%d', '%s', '%s' ]
		);

		$row_id = $inserted ? (int) $wpdb->insert_id : false;

		/**
		 * Fires after a security event is logged.
		 *
		 * @param string   $event_type
		 * @param string   $message
		 * @param string   $severity
		 * @param array    $args
		 * @param int|false $row_id
		 */
		do_action( 'gemsecurity/event_logged', $event_type, $message, $severity, $args, $row_id );

		return $row_id;
	}

	/**
	 * Valid severities.
	 *
	 * @return string[]
	 */
	public static function severities() {
		return [
			self::SEVERITY_INFO,
			self::SEVERITY_NOTICE,
			self::SEVERITY_WARNING,
			self::SEVERITY_CRITICAL,
		];
	}

	/**
	 * Delete log rows older than the configured retention window.
	 * Hooked to a daily cron event.
	 */
	public static function prune() {
		global $wpdb;

		$days = (int) Helper::get_setting( 'logs_retention_days', 30 );
		if ( $days <= 0 ) {
			return;
		}

		$table = $wpdb->prefix . 'gemsecurity_logs';
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE created_at < %s",
				gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) )
			)
		);
	}
}
