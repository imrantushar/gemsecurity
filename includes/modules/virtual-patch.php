<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;
use GemSecurity\Security\BanList;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Virtual patching — CVE-targeted request mitigation.
 *
 * Unlike the generic WAF, each vPatch rule is tied to a specific plugin/theme
 * and version range. Only rules that apply to *this* site's installed, still-
 * vulnerable software are enforced, so a known CVE is neutralised in place even
 * when no fix has been released — with minimal false-positive risk and overhead.
 *
 * The rule set is small in the free plugin (illustrative examples); the Pro
 * add-on supplies the live, curated feed via the `gemsecurity/vpatch_rules`
 * filter.
 */
class VirtualPatch {

	const CACHE_KEY = 'gemsecurity_vpatch_applicable';

	public static function init() {
		if ( ! Helper::get_setting( 'virtual_patch_enabled', true ) ) {
			return;
		}
		$self = new self();
		// Run early, before plugins process the request.
		add_action( 'init', [ $self, 'protect' ], 1 );
		// Invalidate the applicable-rule cache when the plugin inventory changes.
		add_action( 'activated_plugin', [ __CLASS__, 'flush_cache' ] );
		add_action( 'deactivated_plugin', [ __CLASS__, 'flush_cache' ] );
		add_action( 'upgrader_process_complete', [ __CLASS__, 'flush_cache' ] );
	}

	/**
	 * The full rule set (bundled examples + the Pro feed via filter).
	 *
	 * A rule: {
	 *   id, cve, title, plugin (slug or '*'), max_version (inclusive; '' = any),
	 *   pattern (PCRE tested against URI + query + body), severity
	 * }
	 *
	 * @return array<int,array>
	 */
	public static function rules() {
		$bundled = [
			[
				'id'          => 'gs-generic-sqli-union',
				'cve'         => '',
				'title'       => __( 'Generic SQL injection (UNION SELECT) in query', 'gemsecurity' ),
				'plugin'      => '*',
				'max_version' => '',
				'pattern'     => '/union[\s\/*]+select/i',
				'severity'    => 'critical',
			],
			[
				'id'          => 'gs-generic-traversal',
				'cve'         => '',
				'title'       => __( 'Path traversal in a file parameter', 'gemsecurity' ),
				'plugin'      => '*',
				'max_version' => '',
				'pattern'     => '/(?:\.\.\/){2,}/',
				'severity'    => 'high',
			],
		];

		/**
		 * Filter the virtual-patch rule set. The Pro feed hooks here to add
		 * CVE-specific, plugin/version-targeted mitigation rules.
		 *
		 * @param array $bundled
		 */
		$rules = apply_filters( 'gemsecurity/vpatch_rules', $bundled );
		return is_array( $rules ) ? $rules : $bundled;
	}

	/** Slug => version map of every installed plugin. */
	private static function installed_versions() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$out = [];
		foreach ( get_plugins() as $file => $data ) {
			$slug         = ( false !== strpos( $file, '/' ) ) ? dirname( $file ) : basename( $file, '.php' );
			$out[ $slug ] = isset( $data['Version'] ) ? $data['Version'] : '0';
		}
		return $out;
	}

	/**
	 * Rules that apply to this site right now (installed + still in range),
	 * cached until the plugin inventory changes.
	 *
	 * @return array<int,array>
	 */
	public static function applicable_rules() {
		$cached = get_transient( self::CACHE_KEY );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$versions = self::installed_versions();
		$out      = [];
		foreach ( self::rules() as $r ) {
			$plugin = isset( $r['plugin'] ) ? $r['plugin'] : '*';
			if ( '*' === $plugin ) {
				$out[] = $r;
				continue;
			}
			if ( ! isset( $versions[ $plugin ] ) ) {
				continue; // not installed → not exposed.
			}
			$max = isset( $r['max_version'] ) ? $r['max_version'] : '';
			if ( '' === $max || version_compare( $versions[ $plugin ], $max, '<=' ) ) {
				$r['installed_version'] = $versions[ $plugin ];
				$out[]                  = $r;
			}
		}

		set_transient( self::CACHE_KEY, $out, HOUR_IN_SECONDS );
		return $out;
	}

	public static function flush_cache() {
		delete_transient( self::CACHE_KEY );
	}

	public function protect() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}
		if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
			return;
		}
		$rules = self::applicable_rules();
		if ( empty( $rules ) ) {
			return;
		}

		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? rawurldecode( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$hay  = $uri . ' ' . wp_json_encode( wp_unslash( $_GET ) ) . ' ' . wp_json_encode( wp_unslash( $_POST ) ); // phpcs:ignore
		$ip   = Helper::get_ip_address();

		foreach ( $rules as $r ) {
			if ( empty( $r['pattern'] ) ) {
				continue;
			}
			if ( @preg_match( $r['pattern'], $hay ) ) { // phpcs:ignore -- rule patterns are trusted.
				Logger::log(
					'vpatch_block',
					sprintf(
						/* translators: 1: CVE or rule id, 2: ip */
						__( 'Virtual patch %1$s blocked a request from %2$s.', 'gemsecurity' ),
						! empty( $r['cve'] ) ? $r['cve'] : $r['id'],
						$ip
					),
					Logger::SEVERITY_CRITICAL,
					[ 'user_id' => 0, 'ip_address' => $ip, 'context' => [ 'rule' => $r['id'], 'cve' => $r['cve'] ?? '' ] ]
				);
				if ( class_exists( '\GemSecurity\Security\BanList' ) ) {
					BanList::record_strike( $ip, 'vpatch:' . $r['id'] );
				}
				status_header( 403 );
				nocache_headers();
				wp_die(
					esc_html__( 'Your request was blocked for security reasons.', 'gemsecurity' ),
					esc_html__( 'Blocked', 'gemsecurity' ),
					[ 'response' => 403 ]
				);
			}
		}
	}
}
