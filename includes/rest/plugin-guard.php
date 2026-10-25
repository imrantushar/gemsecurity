<?php
namespace GemSecurity\Rest;

use GemSecurity\Security\PluginGuard as Guard;
use GemSecurity\Security\UploadShield;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugin Guard endpoints: inventory, enable/disable, trust management.
 */
class PluginGuard {

	/** GET /plugin-guard */
	public static function get() {
		return rest_ensure_response( [ 'success' => true ] + self::inventory() );
	}

	/** POST /plugin-guard/verify — re-check every plugin against WordPress.org. */
	public static function verify() {
		Guard::verify_all();
		return self::get();
	}

	/**
	 * POST /plugin-guard/enable { enabled: bool, trust: string[] }
	 *
	 * Turning enforcement on trusts exactly the items the admin ticked first,
	 * so nothing they rely on is switched off by surprise.
	 */
	public static function enable( \WP_REST_Request $request ) {
		$enabled = (bool) $request->get_param( 'enabled' );
		if ( $enabled ) {
			Guard::verify_all( false );
			$inv = self::inventory();
			foreach ( (array) $request->get_param( 'trust' ) as $key ) {
				self::trust_key( sanitize_text_field( (string) $key ), $inv );
			}
		}
		$state            = Guard::state();
		$state['enabled'] = $enabled;
		Guard::save_state( $state );
		\GemSecurity\Modules\PluginGuard::maintain();
		\GemSecurity\Logger::log( 'plugin_guard_toggle', $enabled ? 'Plugin Guard enforcement turned on.' : 'Plugin Guard enforcement turned off.', $enabled ? 'notice' : 'warning' );
		return self::get();
	}

	/** POST /plugin-guard/lock { mode } — Install Lock mode. */
	public static function lock( \WP_REST_Request $request ) {
		$mode = sanitize_key( (string) $request->get_param( 'mode' ) );
		if ( ! isset( Guard::install_lock_modes()[ $mode ] ) ) {
			return new \WP_Error( 'gemsecurity_guard_mode', __( 'Unknown lock mode.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		$state                 = Guard::state();
		$state['install_lock'] = $mode;
		$state['unlock_until'] = 0;
		Guard::save_state( $state );
		\GemSecurity\Modules\PluginGuard::maintain();
		\GemSecurity\Logger::log( 'plugin_guard_lock', sprintf( 'Install Lock set to "%s".', $mode ), 'off' === $mode ? 'warning' : 'notice' );
		return self::get();
	}

	/** POST /plugin-guard/unlock { minutes } — timed unlock; 0 relocks. */
	public static function unlock( \WP_REST_Request $request ) {
		Guard::unlock_for( (int) $request->get_param( 'minutes' ) );
		return self::get();
	}

	/** POST /plugin-guard/shield { upload_shield, shield_markup } */
	public static function shield( \WP_REST_Request $request ) {
		$state = Guard::state();
		foreach ( [ 'upload_shield', 'shield_markup', 'shield_autoban' ] as $k ) {
			if ( null !== $request->get_param( $k ) ) {
				$state[ $k ] = (bool) $request->get_param( $k );
			}
		}
		if ( null !== $request->get_param( 'shield_ban_hours' ) ) {
			$state['shield_ban_hours'] = max( 0, min( 87600, (int) $request->get_param( 'shield_ban_hours' ) ) );
		}
		Guard::save_state( $state );
		\GemSecurity\Modules\PluginGuard::maintain();
		\GemSecurity\Logger::log( 'plugin_guard_shield', $state['upload_shield'] ? 'Upload Shield on.' : 'Upload Shield turned off.', $state['upload_shield'] ? 'notice' : 'warning' );
		return self::get();
	}

	/** POST /plugin-guard/probe — does PHP execute inside uploads? */
	public static function probe() {
		require_once GEMSECURITY_INCLUDES_DIR_PATH . 'security/upload-shield.php';
		$state          = Guard::state();
		$state['probe'] = UploadShield::probe();
		Guard::save_state( $state );
		return self::get();
	}

	/** POST /plugin-guard/trust { key, name? } — key: plugin:<slug> | theme:<slug> | mu:<file>. */
	public static function trust( \WP_REST_Request $request ) {
		$key = sanitize_text_field( (string) $request->get_param( 'key' ) );
		if ( ! preg_match( '/^(plugin|theme):[a-z0-9._-]+$|^mu:[A-Za-z0-9._-]+\.php$/', $key ) ) {
			return new \WP_Error( 'gemsecurity_guard_key', __( 'Enter a plugin or theme folder slug, e.g. my-pro-plugin.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		if ( ! self::trust_key( $key, self::inventory(), sanitize_text_field( (string) $request->get_param( 'name' ) ) ) ) {
			return new \WP_Error( 'gemsecurity_guard_mu', __( 'That must-use plugin file was not found.', 'gemsecurity' ), [ 'status' => 404 ] );
		}
		return self::get();
	}

	/** POST /plugin-guard/untrust { key } */
	public static function untrust( \WP_REST_Request $request ) {
		Guard::untrust( sanitize_text_field( (string) $request->get_param( 'key' ) ) );
		return self::get();
	}

	/** POST /plugin-guard/restore { id } — restore a quarantined mu-plugin and trust it. */
	public static function restore( \WP_REST_Request $request ) {
		$res = Guard::restore_and_trust_mu( sanitize_key( (string) $request->get_param( 'id' ) ) );
		return is_wp_error( $res ) ? $res : self::get();
	}

	/**
	 * @param string $key
	 * @param array  $inv
	 * @param string $name
	 * @return bool
	 */
	private static function trust_key( $key, array $inv, $name = '' ) {
		if ( 0 === strpos( $key, 'mu:' ) ) {
			foreach ( $inv['mu_plugins'] as $m ) {
				if ( $m['key'] === $key ) {
					Guard::trust( $key, $m['file'], $m['hash'] );
					return true;
				}
			}
			return false;
		}
		foreach ( array_merge( $inv['plugins'], $inv['themes'] ) as $row ) {
			if ( $row['key'] === $key ) {
				$name = $row['name'];
				break;
			}
		}
		Guard::trust( $key, $name ? $name : substr( $key, strpos( $key, ':' ) + 1 ) );
		return true;
	}

	private static function inventory() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$state  = Guard::state();
		$active = (array) get_option( 'active_plugins', [] );

		$plugins = [];
		foreach ( get_plugins() as $file => $data ) {
			$slug = Guard::slug_of( $file );
			$key  = 'plugin:' . $slug;
			$ver  = isset( $state['verified'][ $file ] ) ? $state['verified'][ $file ] : null;
			$own  = in_array( $slug, [ 'gemsecurity', 'gemsecurity-pro' ], true );
			$plugins[] = [
				'key'        => $key,
				'file'       => $file,
				'slug'       => $slug,
				'name'       => $data['Name'],
				'version'    => $data['Version'],
				'author'     => wp_strip_all_tags( $data['Author'] ),
				'active'     => in_array( $file, $active, true ),
				'status'     => $own ? 'own' : ( $ver ? $ver['status'] : 'unchecked' ),
				'note'       => $ver ? $ver['note'] : '',
				'checked_at' => $ver ? $ver['checked_at'] : '',
				'trusted'    => isset( $state['trusted'][ $key ] ) ? $state['trusted'][ $key ] : null,
				'allowed'    => Guard::is_plugin_allowed( $file, $state ),
			];
		}

		$mu  = [];
		$dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		foreach ( (array) glob( trailingslashit( $dir ) . '*.php' ) as $path ) {
			$f    = basename( $path );
			$key  = 'mu:' . $f;
			$d    = get_file_data( $path, [ 'Name' => 'Plugin Name' ] );
			$own  = in_array( $f, [ Guard::MU_FILE, 'gemsecurity-extended-protection.php' ], true );
			$hash = (string) @hash_file( 'sha256', $path ); // phpcs:ignore
			$tr   = isset( $state['trusted'][ $key ] ) ? $state['trusted'][ $key ] : null;
			$mu[] = [
				'key'      => $key,
				'file'     => $f,
				'name'     => $d['Name'] ? $d['Name'] : $f,
				'hash'     => $hash,
				'size'     => (int) @filesize( $path ), // phpcs:ignore
				'modified' => gmdate( 'Y-m-d H:i', (int) @filemtime( $path ) ), // phpcs:ignore
				'status'   => $own ? 'own' : ( $tr ? ( hash_equals( (string) $tr['hash'], $hash ) ? 'trusted' : 'changed' ) : 'untrusted' ),
				'trusted'  => $tr,
				'allowed'  => Guard::is_mu_allowed( $path, $state ),
			];
		}

		$themes = [];
		$current = get_stylesheet();
		foreach ( wp_get_themes() as $slug => $theme ) {
			$key      = 'theme:' . $slug;
			$themes[] = [
				'key'     => $key,
				'slug'    => $slug,
				'name'    => $theme->get( 'Name' ),
				'version' => $theme->get( 'Version' ),
				'active'  => $slug === $current || $slug === get_template(),
				'status'  => Guard::theme_status( $slug ),
				'trusted' => isset( $state['trusted'][ $key ] ) ? $state['trusted'][ $key ] : null,
			];
		}

		// Trusted slugs with nothing installed yet = pre-approved uploads.
		$installed = array_merge( wp_list_pluck( $plugins, 'key' ), wp_list_pluck( $themes, 'key' ), wp_list_pluck( $mu, 'key' ) );
		$pre       = [];
		foreach ( $state['trusted'] as $key => $t ) {
			if ( ! in_array( $key, $installed, true ) ) {
				$pre[] = [ 'key' => $key ] + $t;
			}
		}

		$quarantined = [];
		foreach ( (array) \GemSecurity\OptionStore::get_state( 'quarantine', [] ) as $q ) {
			if ( 'plugin-guard' === ( $q['source'] ?? '' ) ) {
				$quarantined[] = $q;
			}
		}

		require_once GEMSECURITY_INCLUDES_DIR_PATH . 'security/upload-shield.php';
		$server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';

		return [
			'lock'         => [
				'mode'         => isset( $state['install_lock'] ) ? $state['install_lock'] : 'off',
				'effective'    => Guard::lock_mode( $state ),
				'unlock_until' => (int) $state['unlock_until'] > time() ? (int) $state['unlock_until'] : 0,
				'modes'        => Guard::install_lock_modes(),
				'file_mods_constant' => defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS,
			],
			'shield'       => [
				'enabled'   => ! empty( $state['upload_shield'] ),
				'markup'    => ! empty( $state['shield_markup'] ),
				'autoban'   => ! empty( $state['shield_autoban'] ),
				'ban_hours' => (int) $state['shield_ban_hours'],
				'htaccess'  => UploadShield::htaccess_installed(),
				'dirs'      => UploadShield::htaccess_dirs(),
				'server'    => false !== strpos( $server, 'nginx' ) ? 'nginx' : ( preg_match( '/apache|litespeed/', $server ) ? 'apache' : ( $server ? $server : 'unknown' ) ),
				'probe'     => isset( $state['probe'] ) ? $state['probe'] : null,
				'nginx'     => UploadShield::nginx_snippet(),
				'exec_exts' => UploadShield::exec_extensions(),
			],
			'enabled'      => ! empty( $state['enabled'] ),
			'kill_switch'  => defined( 'GEMSECURITY_PLUGIN_GUARD_OFF' ) && GEMSECURITY_PLUGIN_GUARD_OFF,
			'mu_installed' => Guard::mu_installed(),
			'plugins'      => $plugins,
			'mu_plugins'   => $mu,
			'themes'       => $themes,
			'preapproved'  => $pre,
			'quarantined'  => $quarantined,
			'events'       => array_slice( Guard::events(), 0, 30 ),
		];
	}
}
