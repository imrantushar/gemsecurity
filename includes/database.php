<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Database {

	public static function init() {
		$self = new self();
		add_action( 'init', [ $self, 'register_tables' ], 5 );
	}

	/**
	 * Register custom table names on the $wpdb object so they
	 * can be referenced as $wpdb->gemsecurity_logs anywhere.
	 */
	public function register_tables() {
		global $wpdb;
		$wpdb->gemsecurity_logs = $wpdb->prefix . 'gemsecurity_logs';
	}
}
