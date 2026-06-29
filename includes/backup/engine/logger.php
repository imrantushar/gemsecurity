<?php
namespace GemBackup\Engine;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Logger {

	public static function info( $message, $backup_id = null, $context = null ) {
		self::write( 'info', $message, $backup_id, $context );
	}

	public static function success( $message, $backup_id = null, $context = null ) {
		self::write( 'success', $message, $backup_id, $context );
	}

	public static function warning( $message, $backup_id = null, $context = null ) {
		self::write( 'warning', $message, $backup_id, $context );
	}

	public static function error( $message, $backup_id = null, $context = null ) {
		self::write( 'error', $message, $backup_id, $context );
	}

	public static function write( $level, $message, $backup_id = null, $context = null ) {
		global $wpdb;
		$wpdb->insert( $wpdb->gembackup_logs, [
			'backup_id' => $backup_id,
			'level'     => $level,
			'message'   => $message,
			'context'   => $context ? wp_json_encode( $context ) : null,
			'user_id'   => get_current_user_id(),
		] );
	}
}
