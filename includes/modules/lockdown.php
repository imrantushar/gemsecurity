<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Recovery / lockdown mode + pre-update backup.
 *
 * Lockdown: when enabled, the public site is closed to everyone except logged-in
 * administrators (a 503 maintenance page is shown) — useful during an incident.
 * Login still works so admins can get in and manage the site.
 *
 * Backup: optionally trigger the sibling GemBackup plugin before any plugin /
 * theme / core update via its `gembackup/run_backup` action.
 */
class Lockdown {

	public static function init() {
		$self = new self();

		if ( Helper::get_setting( 'lockdown_enabled', false ) ) {
			add_action( 'template_redirect', [ $self, 'enforce' ], 0 );
		}
		if ( Helper::get_setting( 'backup_before_updates', false ) ) {
			add_filter( 'upgrader_pre_install', [ $self, 'pre_update_backup' ], 10, 1 );
		}
	}

	public function enforce() {
		if ( current_user_can( 'manage_options' ) ) {
			return; // Admins keep full access.
		}
		$message = trim( (string) Helper::get_setting( 'lockdown_message', '' ) )
			?: __( 'This site is temporarily unavailable for scheduled maintenance. Please check back soon.', 'gemsecurity' );

		nocache_headers();
		wp_die(
			esc_html( $message ),
			esc_html__( 'Temporarily unavailable', 'gemsecurity' ),
			[ 'response' => 503 ]
		);
	}

	/**
	 * @param mixed $response
	 * @return mixed
	 */
	public function pre_update_backup( $response ) {
		// Only attempt once per request, and only if GemBackup is present.
		static $done = false;
		if ( $done ) {
			return $response;
		}
		$done = true;

		if ( has_action( 'gembackup/run_backup' ) ) {
			Logger::log( 'pre_update_backup', 'Triggered a backup via GemBackup before an update.', Logger::SEVERITY_INFO );
			// Public hook into GemBackup's own API — not one of ours to prefix.
			do_action( 'gembackup/run_backup' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
		}
		/**
		 * Always fire a generic seam so any backup solution can hook in.
		 */
		do_action( 'gemsecurity/pre_update_backup' );

		return $response;
	}
}
