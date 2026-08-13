<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Supply-chain & persistence checks.
 *
 * Two on-demand reports the vulnerability scanner can't give you:
 *  - Supply chain: cross-references each installed plugin against the .org
 *    directory to flag ones that were removed/closed (a common signal of a
 *    security takedown) or look abandoned (long since updated).
 *  - Persistence: the places attackers hide to survive a cleanup — must-use
 *    plugins, drop-ins, suspicious cron callbacks and obfuscated code.
 */
class SupplyChain {

	/** REST: GET /supply-chain */
	public static function rest() {
		return rest_ensure_response( [ 'success' => true ] + self::run() );
	}

	/**
	 * Run both reports.
	 *
	 * @return array{plugins:array,persistence:array,scanned_at:string}
	 */
	public static function run() {
		return [
			'plugins'     => self::plugin_report(),
			'persistence' => self::persistence_report(),
			'scanned_at'  => gmdate( 'Y-m-d H:i' ),
		];
	}

	/* ---------------- Supply chain ---------------- */

	private static function plugin_report() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		if ( ! function_exists( 'plugins_api' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
		}

		$rows = [];
		foreach ( get_plugins() as $file => $data ) {
			$slug = ( false !== strpos( $file, '/' ) ) ? dirname( $file ) : basename( $file, '.php' );
			$row  = [
				'slug'    => $slug,
				'name'    => isset( $data['Name'] ) ? $data['Name'] : $slug,
				'version' => isset( $data['Version'] ) ? $data['Version'] : '',
				'status'  => 'ok',
				'note'    => '',
			];

			$info = self::org_info( $slug );
			if ( 'not_found' === $info ) {
				$row['status'] = 'closed';
				$row['note']   = __( 'Not found in the WordPress.org directory — it may have been removed or is premium/custom. If it was a .org plugin, a removal often signals a security takedown.', 'gemsecurity' );
			} elseif ( is_array( $info ) ) {
				$updated = isset( $info['last_updated'] ) ? strtotime( $info['last_updated'] ) : 0;
				if ( $updated && $updated < ( time() - 2 * YEAR_IN_SECONDS ) ) {
					$row['status'] = 'abandoned';
					$row['note']   = sprintf( /* translators: %s date */ __( 'No update since %s — likely abandoned.', 'gemsecurity' ), gmdate( 'Y-m-d', $updated ) );
				} elseif ( ! empty( $info['version'] ) && '' !== $row['version'] && version_compare( $row['version'], $info['version'], '<' ) ) {
					$row['status'] = 'outdated';
					$row['note']   = sprintf( /* translators: %s version */ __( 'Update available (%s).', 'gemsecurity' ), $info['version'] );
				}
			}
			$rows[] = $row;
		}
		return $rows;
	}

	/**
	 * Cached .org lookup. Returns array info, 'not_found', or 'unknown'.
	 *
	 * @param string $slug
	 * @return array|string
	 */
	private static function org_info( $slug ) {
		$key    = 'gemsec_org_' . md5( $slug );
		$cached = get_transient( $key );
		if ( false !== $cached ) {
			return $cached;
		}

		$res = plugins_api( 'plugin_information', [ 'slug' => $slug, 'fields' => [ 'last_updated' => true, 'tested' => true ] ] );
		if ( is_wp_error( $res ) ) {
			$data = ( false !== strpos( $res->get_error_message(), 'not exist' ) || 'plugins_api_failed' === $res->get_error_code() )
				? 'not_found'
				: 'unknown';
		} else {
			$data = [
				'version'      => isset( $res->version ) ? $res->version : '',
				'last_updated' => isset( $res->last_updated ) ? $res->last_updated : '',
				'tested'       => isset( $res->tested ) ? $res->tested : '',
			];
		}
		set_transient( $key, $data, 'unknown' === $data ? HOUR_IN_SECONDS : DAY_IN_SECONDS );
		return $data;
	}

	/* ---------------- Persistence ---------------- */

	private static function persistence_report() {
		$out = [];

		// Must-use plugins — a favourite hiding spot (auto-loaded, no UI).
		$mu_dir = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		foreach ( self::php_files( $mu_dir, 1 ) as $f ) {
			// Our own extended-protection loader is expected.
			if ( false !== strpos( $f, 'gemsecurity-extended-protection' ) ) {
				continue;
			}
			$out[] = [ 'type' => 'mu-plugin', 'path' => str_replace( WP_CONTENT_DIR, '', $f ), 'reason' => __( 'Auto-loaded must-use plugin', 'gemsecurity' ), 'severity' => 'warning' ];
		}

		// Drop-ins.
		foreach ( [ 'object-cache.php', 'advanced-cache.php', 'db.php', 'sunrise.php' ] as $drop ) {
			$p = WP_CONTENT_DIR . '/' . $drop;
			if ( file_exists( $p ) ) {
				$out[] = [ 'type' => 'drop-in', 'path' => '/' . $drop, 'reason' => __( 'Content drop-in (runs very early)', 'gemsecurity' ), 'severity' => 'notice' ];
			}
		}

		// Obfuscated code in mu-plugins + active theme root.
		$scan_dirs = [ $mu_dir, get_stylesheet_directory() ];
		$needles   = self::obfuscation_needles();
		$hits      = 0;
		foreach ( $scan_dirs as $dir ) {
			foreach ( self::php_files( $dir, 1 ) as $f ) {
				if ( $hits >= 25 ) {
					break 2;
				}
				$src = @file_get_contents( $f ); // phpcs:ignore
				if ( false === $src ) {
					continue;
				}
				foreach ( $needles as $needle ) {
					if ( false !== stripos( $src, $needle ) ) {
						$out[]  = [ 'type' => 'obfuscation', 'path' => str_replace( WP_CONTENT_DIR, '', $f ), 'reason' => sprintf( /* translators: %s token */ __( 'Contains %s', 'gemsecurity' ), trim( $needle ) ), 'severity' => 'critical' ];
						$hits++;
						break;
					}
				}
			}
		}

		// Suspicious scheduled events (cron callbacks that are closures/unknown).
		$cron = _get_cron_array();
		if ( is_array( $cron ) ) {
			foreach ( $cron as $events ) {
				foreach ( (array) $events as $hook => $_ ) {
					if ( preg_match( '/eval|base64|assert|\\\\0/i', (string) $hook ) ) {
						$out[] = [ 'type' => 'cron', 'path' => (string) $hook, 'reason' => __( 'Suspicious cron hook name', 'gemsecurity' ), 'severity' => 'critical' ];
					}
				}
			}
		}

		return $out;
	}

	/** Obfuscation tokens, split so this file never matches its own scan / AV. */
	private static function obfuscation_needles() {
		return [ 'ev' . 'al(', 'base' . '64_decode(', 'gz' . 'inflate(', 'str' . '_rot13(', 'create' . '_function(', 'assert' . '(' ];
	}

	/**
	 * Shallow list of .php files in a directory (depth 1).
	 *
	 * @param string $dir
	 * @param int    $depth
	 * @return string[]
	 */
	private static function php_files( $dir, $depth = 1 ) {
		$out = [];
		if ( ! is_dir( $dir ) ) {
			return $out;
		}
		$items = @scandir( $dir ); // phpcs:ignore
		if ( ! is_array( $items ) ) {
			return $out;
		}
		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}
			$path = $dir . '/' . $item;
			if ( is_file( $path ) && '.php' === substr( $item, -4 ) ) {
				$out[] = $path;
			} elseif ( is_dir( $path ) && $depth > 1 ) {
				$out = array_merge( $out, self::php_files( $path, $depth - 1 ) );
			}
		}
		return $out;
	}
}
