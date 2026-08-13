<?php

/**
 * Drives an install / update / rollback of the host plugin from a signed
 * package URL returned by the StoreEngine license server.
 *
 * Synchronous: the REST request blocks until the upgrader returns. The
 * captured log is also persisted to a transient so the UI can re-read it
 * later (e.g. after a hard reload while debugging a failed install).
 */
final class SE_License_SDK_Install_Job {

	const LOG_TTL = HOUR_IN_SECONDS;

	/**
	 * @var SE_License_SDK_Client
	 */
	private $client;

	/**
	 * @var string
	 */
	private $job_id;

	public function __construct( SE_License_SDK_Client $client ) {
		$this->client = $client;
		$this->job_id = wp_generate_password( 12, false );
	}

	public function get_job_id(): string {
		return $this->job_id;
	}

	/**
	 * Install or upgrade the host plugin from a signed package URL.
	 *
	 * @param string $package_url      Signed URL (from /software/get-package).
	 * @param string $target_version   The version the URL is expected to deliver.
	 * @param string|null $current_version Currently installed version, used to
	 *                                     distinguish update vs. rollback in
	 *                                     the log and audit metadata.
	 *
	 * @return array|WP_Error On success, an array with the captured log,
	 *                       status, and version metadata. WP_Error on failure.
	 */
	public function install_from_url( string $package_url, string $target_version, ?string $current_version = null ) {
		if ( ! $this->client->isPlugin() ) {
			return new WP_Error(
				'sdk-only-plugins-supported',
				__( 'Only plugin packages can be installed via the SDK installer.', 'storeengine-sdk' ),
				[ 'status' => 400 ]
			);
		}

		if ( ! current_user_can( 'install_plugins' ) || ! current_user_can( 'activate_plugins' ) ) {
			return new WP_Error(
				'sdk-insufficient-capabilities',
				__( 'You do not have permission to install plugins.', 'storeengine-sdk' ),
				[ 'status' => 403 ]
			);
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		require_once ABSPATH . 'wp-admin/includes/class-plugin-upgrader.php';

		// Force-load the filesystem. If FS_METHOD isn't 'direct', this fails
		// without prompting (the skin's request_filesystem_credentials always
		// returns true).
		if ( ! WP_Filesystem() ) {
			return new WP_Error(
				'sdk-fs-unavailable',
				__( 'WordPress could not initialize the filesystem. Set FS_METHOD to "direct" or ensure the web server can write to wp-content/plugins.', 'storeengine-sdk' ),
				[ 'status' => 500 ]
			);
		}

		$basename   = $this->client->getBasename();
		$slug       = $this->client->getSlug();
		$was_active = is_plugin_active( $basename );

		$is_rollback = $current_version && version_compare( $target_version, $current_version, '<' );

		// Suspend the cache and bump time limits while we work — install can
		// take 10–30s on slow hosts and PHP-FPM default is often 30s.
		wp_suspend_cache_addition( true );
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 300 ); // phpcs:ignore
		}

		// Defensive load — see Updater.php::require_sibling() for context.
		if ( ! class_exists( 'SE_License_SDK_Upgrader_Skin', false ) ) {
			$skin_path = __DIR__ . DIRECTORY_SEPARATOR . 'SE_License_SDK_Upgrader_Skin.php';
			if ( is_readable( $skin_path ) ) {
				require_once $skin_path;
			}
		}

		$skin     = new SE_License_SDK_Upgrader_Skin();
		$upgrader = new Plugin_Upgrader( $skin );

		// Tag the run so other plugins (and our own previous_version
		// recorder) can see what kind of operation this is.
		$hook_extra = [
			'type'                  => 'plugin',
			'action'                => $is_rollback ? 'install' : 'update',
			'plugin'                => $basename,
			'temp_backup'           => [
				'slug' => $slug,
				'src'  => WP_PLUGIN_DIR,
				'dir'  => 'plugins',
			],
			'storeengine_sdk'       => [
				'job_id'          => $this->job_id,
				'target_version'  => $target_version,
				'current_version' => $current_version,
				'is_rollback'     => $is_rollback,
				'slug'            => $slug,
			],
		];

		/**
		 * Lets the consumer pre-validate or veto the install.
		 *
		 * @param true|WP_Error $proceed Return WP_Error to abort.
		 * @param array $hook_extra
		 */
		$proceed = apply_filters(
			$this->client->getHookName( 'pre_install' ),
			true,
			$hook_extra
		);

		if ( is_wp_error( $proceed ) ) {
			wp_suspend_cache_addition( false );

			return $proceed;
		}

		$run_args = [
			'package'                     => $package_url,
			'destination'                 => WP_PLUGIN_DIR,
			'clear_destination'           => true,
			'clear_working'               => true,
			'abort_if_destination_exists' => false,
			'hook_extra'                  => $hook_extra,
		];

		// Mirror `Plugin_Upgrader::deactivate_plugin_before_upgrade()` — but
		// only when we already know the plugin is active. Touching an
		// actively-loaded plugin file on Windows fails silently (the file is
		// open and cannot be replaced), which leaks as "install reported
		// success but nothing actually changed". The post-install
		// reactivation step below restores it.
		if ( $was_active && ! is_plugin_inactive( $basename ) ) {
			deactivate_plugins( [ $basename ], true );
		}

		// Pin the install destination to this plugin's slug regardless of
		// what the zip's top folder is named. Older deployment uploads
		// (predating the upload-time normalization in license-management's
		// versions-controller.php) can contain a top folder like
		// "{slug}-{version}/" instead of "{slug}/". WP_Upgrader builds the
		// destination from that top-folder basename, so without this fix a
		// rollback to one of those older zips installs into a NEW sibling
		// folder (e.g. wp-content/plugins/{slug}-1.0/) and leaves the
		// currently-installed plugin folder untouched — install reports
		// success but the user sees no change on disk.
		//
		// The filter is scoped via $hook_extra['storeengine_sdk']['slug']
		// so concurrent SDK consumers don't normalize each other's installs.
		$expected_slug    = $slug;
		$normalize_filter = static function ( $source, $remote_source, $upgrader_inst, $hook_extra_passed ) use ( $expected_slug, $skin ) {
			global $wp_filesystem;

			if ( empty( $hook_extra_passed['storeengine_sdk']['slug'] ) ) {
				return $source;
			}
			if ( $hook_extra_passed['storeengine_sdk']['slug'] !== $expected_slug ) {
				return $source;
			}

			$source        = trailingslashit( $source );
			$actual        = trim( basename( untrailingslashit( $source ) ), '/' );
			$expected_path = trailingslashit( $remote_source ) . $expected_slug;

			if ( $actual === $expected_slug ) {
				return $source;
			}

			// Old leftovers from a previous failed install could exist at
			// the target path inside the working dir; clear before move.
			if ( $wp_filesystem->exists( $expected_path ) ) {
				$wp_filesystem->delete( $expected_path, true );
			}

			if ( ! $wp_filesystem->move( untrailingslashit( $source ), $expected_path ) ) {
				return new WP_Error(
					'sdk-rename-source-failed',
					sprintf(
						/* translators: 1: actual folder name in zip, 2: expected plugin slug */
						__( 'Could not normalize package folder from "%1$s" to "%2$s".', 'storeengine-sdk' ),
						$actual,
						$expected_slug
					)
				);
			}

			if ( method_exists( $skin, 'feedback' ) ) {
				$skin->feedback( sprintf(
					/* translators: 1: actual folder name in zip, 2: expected plugin slug */
					__( 'Renamed package folder "%1$s" → "%2$s" to match installed plugin.', 'storeengine-sdk' ),
					$actual,
					$expected_slug
				) );
			}

			return trailingslashit( $expected_path );
		};

		add_filter( 'upgrader_source_selection', $normalize_filter, 10, 4 );

		try {
			$result = $upgrader->run( $run_args );
		} finally {
			remove_filter( 'upgrader_source_selection', $normalize_filter, 10 );
		}

		// Restore caching.
		wp_suspend_cache_addition( false );

		$messages = $skin->get_messages();

		if ( is_wp_error( $result ) ) {
			$this->persist_log( 'failed', $messages, $target_version, $current_version, $is_rollback );

			return new WP_Error(
				'sdk-install-failed',
				$result->get_error_message() ?: __( 'Plugin installer reported an error.', 'storeengine-sdk' ),
				[ 'status' => 500, 'log' => $messages ]
			);
		}

		if ( false === $result || null === $result ) {
			$err = $skin->get_last_error() ?: __( 'Installer returned no result.', 'storeengine-sdk' );
			$this->persist_log( 'failed', $messages, $target_version, $current_version, $is_rollback );

			return new WP_Error(
				'sdk-install-failed',
				$err,
				[ 'status' => 500, 'log' => $messages ]
			);
		}

		// Reactivate the plugin if it was active before the install. The
		// upgrader leaves it deactivated by default to avoid running new
		// activation hooks against the old database state — that's fine
		// because we're either upgrading our own code or putting it back.
		$reactivated = true;
		if ( $was_active && is_plugin_inactive( $basename ) ) {
			$activated = activate_plugin( $basename );
			if ( is_wp_error( $activated ) ) {
				$reactivated = false;
				$messages[]  = [
					'level'   => 'warning',
					'message' => sprintf(
					/* translators: %s: WP error message */
						__( 'Installed but could not reactivate the plugin: %s', 'storeengine-sdk' ),
						$activated->get_error_message()
					),
					'time'    => time(),
				];
			}
		}

		$this->persist_log( 'succeeded', $messages, $target_version, $current_version, $is_rollback );

		/**
		 * Fires after a successful SDK-driven install/update/rollback.
		 *
		 * @param string $target_version
		 * @param string|null $current_version
		 * @param bool $is_rollback
		 * @param array $messages
		 */
		do_action(
			$this->client->getHookName( 'post_install' ),
			$target_version,
			$current_version,
			$is_rollback,
			$messages
		);

		return [
			'job_id'          => $this->job_id,
			'status'          => 'succeeded',
			'target_version'  => $target_version,
			'current_version' => $current_version,
			'is_rollback'     => $is_rollback,
			'reactivated'     => $reactivated,
			'log'             => $messages,
		];
	}

	/**
	 * Persist the captured log so the UI can re-read it later (esp. for
	 * post-mortem on a failed install where the React state was lost).
	 */
	private function persist_log( string $status, array $messages, string $target_version, ?string $current_version, bool $is_rollback ): void {
		set_transient(
			$this->log_transient_key(),
			[
				'job_id'          => $this->job_id,
				'status'          => $status,
				'target_version'  => $target_version,
				'current_version' => $current_version,
				'is_rollback'     => $is_rollback,
				'finished_at'     => time(),
				'messages'        => $messages,
			],
			self::LOG_TTL
		);
	}

	private function log_transient_key(): string {
		return $this->client->getHookName( 'last_install_log' );
	}

	/**
	 * Look up the most recent install log written by any job for this client.
	 */
	public function get_last_log(): ?array {
		$value = get_transient( $this->log_transient_key() );

		return is_array( $value ) ? $value : null;
	}
}

// End of file SE_License_SDK_Install_Job.php.
