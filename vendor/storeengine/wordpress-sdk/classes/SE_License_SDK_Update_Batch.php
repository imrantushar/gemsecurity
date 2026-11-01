<?php
/**
 * Batched, background update checks for every SDK product on the site.
 *
 * Before 1.5.9 each product asked the license server for its own update
 * information from inside the request that happened to find its cache empty,
 * usually an admin page load. A site running five Kodezen plugins made five
 * blocking requests, and while the server was slow every one of them waited
 * for its timeout.
 *
 * Now:
 * - an ordinary request never contacts the server for update data: it reads
 *   the cache and, when a product is due, schedules one cron event;
 * - that event (and WordPress's own twice-daily update check, which already
 *   runs in cron) sends ONE `check-updates` request carrying every due product
 *   that shares a license server;
 * - a server that doesn't know the batch route yet is asked per product, as
 *   before, and the shared circuit breaker in SE_License_SDK_Client stops the
 *   remaining products from waiting on a server that just failed.
 *
 * Only one copy of this class is loaded (the elected SDK version), so it sees
 * every product registered by every plugin, whatever SDK copy they bundle.
 */
final class SE_License_SDK_Update_Batch {

	/**
	 * Cron hook that runs the background refresh.
	 */
	const HOOK = 'se_license_sdk_refresh_updates';

	/**
	 * Site transient used as a run lock.
	 */
	const LOCK = 'se_sdk_update_batch_lock';

	/**
	 * Most products sent in one request.
	 */
	const MAX_ITEMS = 50;

	/**
	 * Whether a batch already ran during this request.
	 *
	 * @var bool
	 */
	private static $ran = false;

	/**
	 * Register the cron handler (once, whichever product calls first).
	 *
	 * @return void
	 */
	public static function init() {
		if ( ! has_action( self::HOOK, [ __CLASS__, 'run_scheduled' ] ) ) {
			add_action( self::HOOK, [ __CLASS__, 'run_scheduled' ] );
		}
	}

	/**
	 * Whether this request may contact the license server for update data:
	 * cron, WP-CLI, or the "Check again" button on Dashboard → Updates.
	 *
	 * @return bool
	 */
	public static function can_run_inline(): bool {
		$inline = wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) || self::is_forced_update_check();

		/**
		 * Whether the current request may contact the license server for
		 * background data (update checks, promotions). False means "read the
		 * cache and schedule a background refresh".
		 *
		 * @param bool $inline
		 */
		return (bool) apply_filters( 'se_license_sdk_can_fetch_inline', $inline );
	}

	/**
	 * Whether WordPress is running an explicit, user-requested update check.
	 *
	 * @return bool
	 */
	public static function is_forced_update_check(): bool {
		global $pagenow;

		return 'update-core.php' === $pagenow && ! empty( $_GET['force-check'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	}

	/**
	 * Queue a background refresh when any product is due. Costs nothing on the
	 * request that calls it: WordPress runs the event through a non-blocking
	 * loopback (or the system cron when WP-Cron is disabled).
	 *
	 * @return void
	 */
	public static function schedule() {
		if ( wp_installing() || ! self::get_due_clients() ) {
			return;
		}

		if ( ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_single_event( time(), self::HOOK );
		}
	}

	/**
	 * Cron callback: refresh, then push the results into WordPress's update
	 * transients so the plugins/themes screens show them without waiting for
	 * WordPress's next scheduled check.
	 *
	 * @return void
	 */
	public static function run_scheduled() {
		self::run( false, true );
	}

	/**
	 * Refresh update data for every due product.
	 *
	 * @param bool $all      Refresh every product, not only those whose cache expired.
	 * @param bool $reinject Re-save WordPress's update transients afterwards. Must
	 *                       stay false when called from inside those filters.
	 *
	 * @return void
	 */
	public static function run( bool $all = false, bool $reinject = false ) {
		if ( self::$ran ) {
			return;
		}

		self::$ran = true;

		$clients = $all || self::is_forced_update_check() ? self::get_update_clients() : self::get_due_clients();

		if ( ! $clients || get_site_transient( self::LOCK ) ) {
			return;
		}

		set_site_transient( self::LOCK, 1, 2 * MINUTE_IN_SECONDS );

		$groups = [];
		foreach ( $clients as $client ) {
			$groups[ $client->get_server_key() ][] = $client;
		}

		foreach ( $groups as $group ) {
			foreach ( array_chunk( $group, self::MAX_ITEMS ) as $chunk ) {
				self::refresh_chunk( $chunk );
			}
		}

		delete_site_transient( self::LOCK );

		if ( $reinject ) {
			self::reinject( $clients );
		}
	}

	/**
	 * Send one batched request for products sharing a server.
	 *
	 * @param SE_License_SDK_Client[] $clients Clients.
	 *
	 * @return void
	 */
	private static function refresh_chunk( array $clients ) {
		$sender = reset( $clients );

		// Server known to be down: don't even try, and don't let any product
		// retry before the breaker closes.
		$retry_in = $sender->get_server_retry_in();
		if ( $retry_in > 0 ) {
			foreach ( $clients as $client ) {
				$client->updater()->store_update_failure( $retry_in );
			}

			return;
		}

		// This server told us recently it has no batch route: go straight to
		// per-product requests instead of wasting one on the batch every time.
		$no_batch_key = 'se_sdk_nobatch_' . $sender->get_server_key();
		if ( get_site_transient( $no_batch_key ) ) {
			foreach ( $clients as $client ) {
				$client->updater()->refresh_single();
			}

			return;
		}

		$items = [];
		foreach ( $clients as $client ) {
			$items[ self::item_key( $client ) ] = $client->get_request_identity();
		}

		$response = $sender->request( [
			'route'   => 'check-updates',
			'body'    => array_merge( $sender->get_admin_info(), [ 'items' => $items ] ),
			'timeout' => 15,
		] );

		if ( ! empty( $response['success'] ) && isset( $response['data']['results'] ) && is_array( $response['data']['results'] ) ) {
			$results = $response['data']['results'];

			// Site-wide instructions (pause_background) from the server.
			$sender->apply_server_directives( $response['data'] );

			foreach ( $clients as $client ) {
				$result = $results[ self::item_key( $client ) ] ?? null;

				if ( is_array( $result ) && ! empty( $result['success'] ) && isset( $result['data'] ) && is_array( $result['data'] ) ) {
					$data = $result['data'];

					// A batch-level next_check_in applies to items that don't set their own.
					if ( ! isset( $data['next_check_in'] ) && isset( $response['data']['next_check_in'] ) ) {
						$data['next_check_in'] = $response['data']['next_check_in'];
					}

					$client->updater()->store_update_response( [ 'success' => true, 'data' => $data ] );
				} else {
					$client->updater()->store_update_response( [ 'success' => false ] );
				}
			}

			return;
		}

		if ( ! empty( $response['transport_error'] ) ) {
			// The breaker is open now; wait it out.
			$retry_in = $sender->get_server_retry_in();

			foreach ( $clients as $client ) {
				$client->updater()->store_update_failure( $retry_in );
			}

			return;
		}

		// The server answered but has no batch route (older license-management
		// addon): fall back to one request per product. If one of those fails
		// at transport level the breaker opens and the rest return at once.
		if ( 'rest_no_route' === ( $response['code'] ?? '' ) ) {
			set_site_transient( $no_batch_key, 1, DAY_IN_SECONDS );
		}

		foreach ( $clients as $client ) {
			$client->updater()->refresh_single();
		}
	}

	/**
	 * Re-save WordPress's update transients so our (now cached) rows are
	 * injected by the pre_set filters.
	 *
	 * @param SE_License_SDK_Client[] $clients Refreshed clients.
	 *
	 * @return void
	 */
	private static function reinject( array $clients ) {
		$types = [];
		foreach ( $clients as $client ) {
			$types[ $client->isPlugin() ? 'update_plugins' : 'update_themes' ] = true;
		}

		foreach ( array_keys( $types ) as $transient ) {
			$value = get_site_transient( $transient );

			// When WordPress has no transient yet it builds one on its next check,
			// and our filter reads the fresh cache then.
			if ( is_object( $value ) ) {
				set_site_transient( $transient, $value );
			}
		}
	}

	/**
	 * Every registered product with updates enabled.
	 *
	 * @return SE_License_SDK_Client[]
	 */
	private static function get_update_clients(): array {
		if ( ! class_exists( 'SE_License_SDK', false ) ) {
			return [];
		}

		$clients = [];
		foreach ( SE_License_SDK::get_all_registered() as $client ) {
			if ( $client instanceof SE_License_SDK_Client && $client->maybe_init_update() ) {
				$clients[] = $client;
			}
		}

		return $clients;
	}

	/**
	 * Products whose update cache (including a failure marker) has expired.
	 *
	 * @return SE_License_SDK_Client[]
	 */
	private static function get_due_clients(): array {
		return array_values( array_filter( self::get_update_clients(), function ( SE_License_SDK_Client $client ) {
			return $client->updater()->needs_refresh();
		} ) );
	}

	/**
	 * Key a product by inside the batch payload.
	 *
	 * @param SE_License_SDK_Client $client Client.
	 *
	 * @return string
	 */
	private static function item_key( SE_License_SDK_Client $client ): string {
		return sanitize_key( $client->getSlug() );
	}
}

// End of file SE_License_SDK_Update_Batch.php.
