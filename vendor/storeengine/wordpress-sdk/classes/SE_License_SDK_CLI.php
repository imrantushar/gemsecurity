<?php
/**
 * WP-CLI commands for SDK-managed products.
 *
 * Registered as `wp se-license` when WP-CLI is available. Every command targets
 * a single product by its slug (see `wp se-license list`).
 *
 * @package StoreEngine\LicenseManagementClientSDK
 */

declare( strict_types=1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage StoreEngine-SDK product licenses and updates from the command line.
 */
class SE_License_SDK_CLI {

	/**
	 * Resolve a client by slug or stop with an error.
	 *
	 * @param array $args Positional args; first is the slug.
	 *
	 * @return SE_License_SDK_Client
	 */
	protected function client_or_die( array $args ): SE_License_SDK_Client {
		$slug = $args[0] ?? '';

		if ( ! $slug ) {
			WP_CLI::error( 'Product slug is required. Run `wp se-license list` to see available products.' );
		}

		$client = SE_License_SDK::get_registered_by_slug( $slug );

		if ( ! $client ) {
			WP_CLI::error( sprintf( 'No SDK-registered product found for slug "%s". Run `wp se-license list`.', $slug ) );
		}

		return $client;
	}

	/**
	 * List all products registered with the SDK on this site.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp se-license list
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Associative args.
	 */
	public function list( $args, $assoc_args ) {
		$rows = [];

		foreach ( SE_License_SDK::get_all_registered() as $client ) {
			$rows[] = [
				'slug'    => $client->getSlug(),
				'name'    => $client->getPackageName(),
				'type'    => $client->getType(),
				'version' => $client->getProjectVersion(),
				'free'    => $client->isFree() ? 'yes' : 'no',
			];
		}

		if ( ! $rows ) {
			WP_CLI::warning( 'No SDK-registered products found.' );

			return;
		}

		WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $rows, [ 'slug', 'name', 'type', 'version', 'free' ] );
	}

	/**
	 * Show the license + update status for a product.
	 *
	 * ## OPTIONS
	 *
	 * <slug>
	 * : The product slug.
	 *
	 * [--format=<format>]
	 * : Output format (table, json, yaml).
	 *
	 * ## EXAMPLES
	 *
	 *     wp se-license status storeengine-pro
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Associative args.
	 */
	public function status( $args, $assoc_args ) {
		$client  = $this->client_or_die( $args );
		$license = $client->license( false );
		$data    = $license->get_license();

		$rows = [
			[ 'field' => 'slug', 'value' => $client->getSlug() ],
			[ 'field' => 'name', 'value' => $client->getPackageName() ],
			[ 'field' => 'installed_version', 'value' => $client->getProjectVersion() ],
			[ 'field' => 'license_status', 'value' => $data['status'] ?? 'inactive' ],
			[ 'field' => 'license_valid', 'value' => $license->is_valid() ? 'yes' : 'no' ],
			[ 'field' => 'in_offline_grace', 'value' => $license->is_in_grace() ? 'yes' : 'no' ],
			[ 'field' => 'expires', 'value' => ! empty( $data['expires'] ) ? gmdate( 'Y-m-d H:i:s', (int) $data['expires'] ) . ' UTC' : '—' ],
			[ 'field' => 'activations', 'value' => sprintf( '%s / %s', $data['activations'] ?? 0, ! empty( $data['unlimited'] ) ? '∞' : ( $data['limit'] ?? 0 ) ) ],
		];

		WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $rows, [ 'field', 'value' ] );
	}

	/**
	 * Activate a license key for a product.
	 *
	 * ## OPTIONS
	 *
	 * <slug>
	 * : The product slug.
	 *
	 * --license=<key>
	 * : The license key to activate.
	 *
	 * ## EXAMPLES
	 *
	 *     wp se-license activate storeengine-pro --license=XXXX-XXXX-XXXX
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Associative args.
	 */
	public function activate( $args, $assoc_args ) {
		$client = $this->client_or_die( $args );
		$key    = $assoc_args['license'] ?? '';

		if ( ! $key ) {
			WP_CLI::error( 'The --license=<key> option is required.' );
		}

		$license = $client->license( false );
		$license->activate_client_license( [ 'license_key' => $key ] );

		if ( $license->get_error() ) {
			WP_CLI::error( $license->get_error() );
		}

		WP_CLI::success( $license->get_success() ?: 'License activated.' );
	}

	/**
	 * Deactivate the license for a product on this site.
	 *
	 * ## OPTIONS
	 *
	 * <slug>
	 * : The product slug.
	 *
	 * ## EXAMPLES
	 *
	 *     wp se-license deactivate storeengine-pro
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Associative args.
	 */
	public function deactivate( $args, $assoc_args ) {
		$client  = $this->client_or_die( $args );
		$license = $client->license( false );
		$license->deactivate_client_license();

		if ( $license->get_error() ) {
			WP_CLI::error( $license->get_error() );
		}

		WP_CLI::success( $license->get_success() ?: 'License deactivated.' );
	}

	/**
	 * Check whether an update is available for a product.
	 *
	 * ## OPTIONS
	 *
	 * <slug>
	 * : The product slug.
	 *
	 * ## EXAMPLES
	 *
	 *     wp se-license check-update storeengine-pro
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Associative args.
	 */
	public function check_update( $args, $assoc_args ) {
		$client = $this->client_or_die( $args );

		if ( ! $client->maybe_init_update() ) {
			WP_CLI::warning( 'Updates are not enabled for this product.' );

			return;
		}

		$info    = $client->updater()->force_check();
		$current = $client->getProjectVersion();

		if ( ! $info || empty( $info->new_version ) ) {
			WP_CLI::success( sprintf( 'Up to date (v%s).', $current ) );

			return;
		}

		if ( version_compare( $current, $info->new_version, '<' ) ) {
			WP_CLI::log( sprintf( 'Update available: v%s → v%s', $current, $info->new_version ) );
		} else {
			WP_CLI::success( sprintf( 'Up to date (v%s).', $current ) );
		}
	}

	/**
	 * Install the latest (or a specific) version of a product via the SDK.
	 *
	 * Honours the core-dependency gate: for a pro product with `requires_core`
	 * it updates the free/core plugin first and aborts with a message if it
	 * still can't be satisfied.
	 *
	 * ## OPTIONS
	 *
	 * <slug>
	 * : The product slug.
	 *
	 * [--version=<version>]
	 * : Specific version to install/roll back to. Defaults to latest.
	 *
	 * [--yes]
	 * : Skip the confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     wp se-license install storeengine-pro
	 *     wp se-license install storeengine-pro --version=2.1.0
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Associative args.
	 */
	public function install( $args, $assoc_args ) {
		$client = $this->client_or_die( $args );

		if ( ! $client->maybe_init_update() ) {
			WP_CLI::error( 'Updates are not enabled for this product.' );
		}

		$version = $assoc_args['version'] ?? '';
		$current = $client->getProjectVersion();

		WP_CLI::confirm(
			$version
				? sprintf( 'Install %s v%s (currently v%s)?', $client->getSlug(), $version, $current )
				: sprintf( 'Install the latest %s (currently v%s)?', $client->getSlug(), $current ),
			$assoc_args
		);

		// Delegate to the same handler the REST installer uses — this applies
		// the core-dependency gate, resolves the (signed) package URL, runs the
		// install job and records update-state, so CLI and UI stay identical.
		$request = new WP_REST_Request( 'POST', '' );
		if ( $version ) {
			$request->set_param( 'version', $version );
		}

		$result = $client->rest_api()->updates_install( $request );

		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() );
		}

		$data = $result->get_data();
		WP_CLI::success( sprintf(
			'%s %s v%s.',
			$client->getSlug(),
			! empty( $data['is_rollback'] ) ? 'rolled back to' : 'installed',
			$data['target_version'] ?? $version
		) );
	}
}
