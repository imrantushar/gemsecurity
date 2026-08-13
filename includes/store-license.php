<?php
namespace GemSecurity;

use SE_License_SDK_Client;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * StoreEngine SDK bootstrap for GemSecurity.
 *
 * The SDK is composer-managed (`storeengine/wordpress-sdk`) and its init.php
 * is auto-loaded by composer's files autoload (see load_dependency() in the
 * main plugin file), so we don't need to require it manually here. We defer
 * `se_license_init()` until plugins_loaded and bridge the SDK's frontend
 * params into GemSecurity's existing `gemsecurity/assets/script_data` filter
 * so the React dashboard can read `SeSdk` from the localized
 * `GemSecurityGlobal` data.
 *
 * Mirrors ZenCommunity's `ZenCommunity\StoreLicense` integration.
 */
final class StoreLicense {

	protected static ?SE_License_SDK_Client $sdk_client = null;

	private function __construct() {}

	public static function init(): void {
		if ( ! did_action( 'plugins_loaded' ) ) {
			add_action( 'plugins_loaded', [ __CLASS__, 'load_sdk' ] );
		} else {
			self::load_sdk();
		}
	}

	public static function load_sdk(): void {
		if ( null !== self::$sdk_client ) {
			return;
		}

		if ( ! function_exists( 'se_license_init' ) ) {
			_doing_it_wrong(
				__METHOD__,
				'StoreEngine SDK is missing. Run `composer install` in the gemsecurity plugin directory.',
				'1.0.0'
			);
			return;
		}

		self::$sdk_client = se_license_init( [
			'package_file'        => GEMSECURITY_PLUGIN_FILE,
			'package_name'        => 'GemSecurity', // translation removed due to load too early
			// TODO: replace with the real StoreEngine product id once the
			// GemSecurity product is created on the store. The SDK hard-fails
			// (RuntimeException) on a falsy product_id even for free
			// packages, so this is a non-zero placeholder, not a real id —
			// it only affects usage-tracking attribution, since `is_free`
			// keeps license()/update checks from ever calling the server.
			'product_id'          => 999999,
			'is_free'             => true,
			'slug'                => 'gemsecurity',
			'basename'            => GEMSECURITY_PLUGIN_BASENAME,
			'package_type'        => 'plugin',
			'package_version'     => GEMSECURITY_VERSION,
			'allow_local'         => true,
			// Free is distributed on WordPress.org, so WP core owns updates —
			// we deliberately leave `use_update` off (no store-served update
			// channel). What we DO want from the SDK is the anonymous,
			// opt-in usage tracking + deactivation feedback popup, which is
			// what `init_insights` boots. Without this flag the whole insights
			// subsystem (opt-in notice, deactivation form, reporting cron) never
			// registers — and `includes/rest/license.php` exists solely to expose
			// that opt-in to the settings UI. We intentionally do NOT set
			// `init_restapi`: the SDK's own license routes call `license()`,
			// which throws for free products; the opt-in is proxied through our
			// own `gemsecurity/v1` namespace instead.
			'init_insights'       => true,
			// TODO: replace with the real StoreEngine store domain + URLs
			// once the GemSecurity product is live.
			'license_server'      => 'https://store.gemsecurity.net/',
			'purchase_url'        => Helper::upgrade_url(),
			'product_logo'        => defined( 'GEMSECURITY_ASSETS_URI' ) ? GEMSECURITY_ASSETS_URI . 'images/icon_logo.png' : '',
			'store_dashboard_url' => 'https://store.gemsecurity.net/dashboard/license-keys/',
			'terms_url'           => 'https://gemsecurity.net/terms-and-conditions/',
			'privacy_policy_url'  => 'https://gemsecurity.net/privacy-policy/',
			'ticket_recipient'    => 'support@gemsecurity.net',
			'primary_color'       => '#2A3BEE',
			'first_install_time'  => get_option( 'gemsecurity_first_install_time' ),
			'optin_notice_delay'  => 3 * DAY_IN_SECONDS,
		] );

		add_filter( 'gemsecurity/assets/script_data', [ __CLASS__, 'add_script_data' ] );
	}

	public static function add_script_data( array $data ): array {
		// When GemSecurity Pro is active, its SDK client owns the `SeSdk`
		// payload: it carries `is_free = false`, the REST `rest_url`/`nonce`,
		// and the real license object the settings "License" tab needs to
		// activate a key. Both free and pro hook this same filter and the run
		// order is not guaranteed — so the free client must explicitly yield to
		// Pro instead of clobbering Pro's payload with free (`is_free = true`)
		// data, which would force the read-only "Free Edition" UI even on a Pro
		// site and hide the activation form.
		if (
			class_exists( '\GemSecurityPro\StoreLicense' ) &&
			method_exists( '\GemSecurityPro\StoreLicense', 'get_client' ) &&
			\GemSecurityPro\StoreLicense::get_client()
		) {
			return $data;
		}

		if ( self::$sdk_client && method_exists( self::$sdk_client, 'get_js_params' ) ) {
			$params = self::$sdk_client->get_js_params();
			$params['is_free'] = self::$sdk_client->isFree();

			if ( empty( $params['license'] ) || ! is_array( $params['license'] ) ) {
				$params['license'] = [
					'license'     => '',
					'status'      => self::$sdk_client->isFree() ? 'free' : 'inactive',
					'device_id'   => self::$sdk_client->get_device_id(),
					'slug'        => self::$sdk_client->getSlug(),
					'product_id'  => self::$sdk_client->getProductId(),
					'remaining'   => 0,
					'activations' => 0,
					'limit'       => 1,
					'unlimited'   => self::$sdk_client->isFree(),
					'expires'     => 0,
					'updated_at'  => '',
				];
			}

			$data['SeSdk'] = $params;
		}
		return $data;
	}

	public static function get_client(): ?SE_License_SDK_Client {
		return self::$sdk_client;
	}
}
