# StoreEngine License Management Client SDK For WordPress

This *StoreEngine License Management Client SDK for WordPress* is a lightweight, developer-friendly toolkit that helps
WordPress plugin and theme authors securely manage licensing, updates, and insights for their premium products.

## Features

By integrating this SDK, you can:

1.	Automate license activation and deactivation for customers who purchase through your own eCommerce site powered by the StoreEngine plugin.
2.	Deliver secure and seamless automatic updates to premium plugins and themes directly within WordPress.
3.	Track and monitor license usage with detailed activation and deactivation logs, ensuring better compliance visibility.
4.	Gain actionable insights with usage analytics, showing how your products are used in real-world environments.
5.	Run in-product promotions and marketing campaigns to cross-sell or upsell your other free or premium offerings.
6.	Integrated Isolated per-client REST API for license and insights management.
7.	Full support for theme license management and automatic updates.

Whether you’re an independent developer or managing a portfolio of WordPress products, this SDK is designed to simplify
license enforcement, streamline product updates, and provide valuable insights—all while reducing your development overhead.

## Installation

There are two ways to install this SDK.

1. Download the latest release version and include it in your project like you would with any other third-party library.
2. Install via composer.

### Download and use as 3rd Party library

Download the latest [release file](https://github.com/imrantushar/storeengine-sdk-for-wordpress/releases/latest) and extract in a folder (e.g `library/storeengine`) of your plugin/theme.
Now include the `init.php` file in your plugin/theme. This file must be loaded before the `plugins_loaded` hook.

```php
require_once __DIR__ . '/library/storeengine/init.php'
```

### Install via Composer

To install via `composer` please add this repository in your project's `composer.json` file. Then require `storeengine/wordpress-sdk`.
_This SDK is not yet available in [packagist.org](https://packagist.org/) (will be available soon)._

```json
{
	"repositories": [
		{
			"type": "vcs",
			"url": "https://github.com/imrantushar/storeengine-sdk-for-wordpress.git"
		}
	],
	"require": {
		"storeengine/wordpress-sdk": "^1.3"
	}
}
```

Then run composer update command from the terminal.

```bash
composer update
```

Include the Composer autoloader in your plugin/theme.

```php
require_once __DIR__ . '/vendor/autoload.php'
```

> **PS:** Don’t worry about “class/function already exists” errors or version conflicts when other plugins or themes use this SDK.
> <br>
> The SDK is designed with a fail-safe mechanism that always loads the latest available version if multiple copies are found within a WordPress installation.

## Usage

Integrating the SDK into your plugin or theme is designed to be drop-in simple.
The core entry point is a single helper function: `se_license_init()`, which wires up licensing, updates, and insights
automatically for your product.

This function should be called as early as possible within the WordPress load order — typically on the `plugins_loaded` hook.

```php
add_action( 'plugins_loaded', function () {
	se_license_init( [
		'package_file'        => __FILE__,
		'package_name'        => __( 'Your Amazing Plugin', 'textdomain' ),
		'product_id'          => 27870,
		'is_free'             => false,
		'slug'                => 'your-amazing-plugin',
		'basename'            => plugin_basename( __FILE__ ),
		'package_type'        => 'plugin',
		'package_version'     => '1.0.0',
		'license_server'      => 'https://your-website.com',
		'product_logo'        => plugins_url( 'assets/images/logo.svg', __FILE__ ),
		'store_dashboard_url' => 'https://your-website.com/dashboard/license-keys/',
		'terms_url'           => 'https://your-website.com/terms-and-conditions/',
		'privacy_policy_url'  => 'https://your-website.com/privacy-policy/',
		'ticket_recipient'    => 'support@your-website.com',
		'first_install_time'  => get_option( 'your-amazing-plugin-first-installation-time' ),
		'optin_notice_delay'  => 3 * DAY_IN_SECONDS, # Optional, Default is 3 days from installation.
		'init_restapi'        => true, # Enable isolated REST API for this product.
	] );
} );
```

### Deploy Free Plugins

Free WordPress plugin can be deployed with StoreEngine, and SDK will now can auto-update the plugin directly from the deployed server.
This can be achieved by setting `is_free` to `true` and setting `use_update` to true. Updater will fetch package information without any active license.

```php
add_action( 'plugins_loaded', function () {
	se_license_init( [
		'package_file'        => __FILE__,
		'package_name'        => __( 'Your Amazing Plugin', 'textdomain' ),
		'product_id'          => 27870,
		'is_free'             => true,
		'use_update'          => true,
		'slug'                => 'your-amazing-plugin',
		'basename'            => plugin_basename( __FILE__ ),
		'package_type'        => 'plugin',
		'package_version'     => '1.0.0',
		'license_server'      => 'https://your-website.com',
		'product_logo'        => plugins_url( 'assets/images/logo.svg', __FILE__ ),
		'store_dashboard_url' => 'https://your-website.com/dashboard/license-keys/',
		'terms_url'           => 'https://your-website.com/terms-and-conditions/',
		'privacy_policy_url'  => 'https://your-website.com/privacy-policy/',
		'ticket_recipient'    => 'support@your-website.com',
		'first_install_time'  => get_option( 'your-amazing-plugin-first-installation-time' ),
		'optin_notice_delay'  => 3 * DAY_IN_SECONDS, # Optional, Default is 3 days from installation.
		'init_restapi'        => true, # Enable isolated REST API for this product.
	] );
} );
```

### How it works
- Automatic versioning & failsafe loading: If multiple plugins or themes bundle this SDK, WordPress will always load the
latest version automatically, preventing conflicts or duplicate class errors.
- Seamless UI integration: A “Manage License” menu item is automatically created for your users, with customizable branding (logo).
- Secure API communication: All license activations, deactivations, and update checks are routed securely through your
StoreEngine-powered server.
- Future extensibility: Once enabled, upcoming features like usage analytics and in-product promotions (upcoming) can be
toggled on with minimal additional code.


> **For Plugin:** Call `se_license_init()` from the main plugin file (`your-plugin-slug/your-plugin-slug.php`).
> <br>
> **For Theme:** Instructions coming soon.

## Isolated REST API

The SDK includes a built-in REST API namespace (`storeengine-sdk/v1`) that is isolated for each plugin instance. This feature is disabled by default and can be enabled by setting `init_restapi` to `true` in the `se_license_init` call.

### Endpoints
Endpoints are prefixed with your plugin slug: `/wp-json/storeengine-sdk/v1/{slug}/`

- **License Activation**: `POST /license/activate` (requires `license` parameter).
- **License Deactivation**: `POST /license/deactivate`.
- **License Status**: `GET /license/status` (use `?force=true` to skip cache).
- **Insights Opt-in/Out**: `POST /insights/optin` (use `?opt_in=true/false`).

All endpoints require the `manage_options` capability.

## Learn More

Visit our official website [storeengine.pro](https://storeengine.pro) for more details on selling WordPress plugins and themes online.

* [Software Management Guide](https://storeengine.pro/docs/storeengine-license-management/): Detailed instructions on how to sell software (WordPress plugin/theme) and deployment.
* API Reference (coming soon): For handling other software/app license activation and automatic updates. 

## License and Attribution

This project, **StoreEngine License Management Client SDK For WordPress**, is licensed under the GNU General Public License v3.0.

This project includes code derived from **Action Scheduler** by Automattic, Inc., also licensed under the GNU GPL v3.0.

See [license.txt](./license.txt) for license details.

## Credits

*StoreEngine License Management Client SDK for WordPress* is developed and maintained by [Kodezen](http://kodezen.com/).

Collaboration is welcome! We’d love to work with you to improve this SDK. [Pull Requests](http://github.com/imrantushar/storeengine-license-management-client-sdk/pulls) are highly appreciated.

The versioned loading and initializer system of this SDK is based on and derived from [Action Scheduler](https://actionscheduler.org/), developed and maintained by [Automattic](https://automattic.com/), with significant early development contributed by [Flightless](https://flightless.us/).
