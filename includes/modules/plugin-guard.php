<?php
namespace GemSecurity\Modules;

use GemSecurity\Security\PluginGuard as Guard;
use GemSecurity\Security\UploadShield;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugin Guard module boot: keeps the early must-use loader in sync,
 * re-verifies plugins after installs/updates and daily, and registers the
 * enforcement hooks as a fallback when the loader could not be written.
 */
class PluginGuard {

	public static function init() {
		// Fallback: no-op when the must-use loader already registered everything.
		Guard::early();

		add_action( Guard::CRON_HOOK, [ Guard::class, 'verify_all' ] );
		add_action( 'admin_init', [ __CLASS__, 'maintain' ] );
		add_action( 'upgrader_process_complete', [ __CLASS__, 'after_upgrade' ], 10, 2 );
	}

	/** Keep the cron and the loader file matching the enabled flag. */
	public static function maintain() {
		$on = Guard::is_enabled();
		if ( $on && ! wp_next_scheduled( Guard::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', Guard::CRON_HOOK );
		} elseif ( ! $on && wp_next_scheduled( Guard::CRON_HOOK ) ) {
			wp_clear_scheduled_hook( Guard::CRON_HOOK );
		}
		$mu = Guard::needs_mu();
		if ( $mu !== Guard::mu_installed() ) {
			$mu ? Guard::install_mu() : Guard::uninstall_mu();
		}
		self::sync_htaccess();
	}

	/** Keep the uploads/.htaccess deny block matching the Upload Shield toggle. */
	public static function sync_htaccess() {
		require_once GEMSECURITY_INCLUDES_DIR_PATH . 'security/upload-shield.php';
		$state = Guard::state();
		$want  = ! empty( $state['upload_shield'] );
		if ( $want !== UploadShield::htaccess_installed() ) {
			$want ? UploadShield::install_htaccess() : UploadShield::remove_htaccess();
		}
	}

	/**
	 * Re-verify plugins that were just installed or updated so a fresh .org
	 * plugin is recognised before anyone clicks Activate.
	 *
	 * @param object $upgrader
	 * @param array  $extra
	 */
	public static function after_upgrade( $upgrader, $extra ) {
		if ( ! Guard::is_enabled() || empty( $extra['type'] ) || 'plugin' !== $extra['type'] ) {
			return;
		}
		$list = [];
		if ( ! empty( $extra['plugins'] ) ) {
			$list = (array) $extra['plugins'];
		} elseif ( ! empty( $extra['plugin'] ) ) {
			$list = [ $extra['plugin'] ];
		} elseif ( $upgrader instanceof \Plugin_Upgrader && method_exists( $upgrader, 'plugin_info' ) ) {
			$info = $upgrader->plugin_info();
			if ( $info ) {
				$list = [ $info ];
			}
		}
		foreach ( $list as $p ) {
			Guard::verify_plugin( $p );
		}
	}
}
