<?php

/**
 * Core / free-plugin dependency gate.
 *
 * A pro product can declare (via the `requires_core` init arg) that it depends
 * on a free/core plugin and must not be updated ahead of it. This matters
 * because pro packages ship instantly from the vendor's own license server,
 * while the matching free release is hosted on wordpress.org — where, since
 * 2024, plugin updates are held for ~24 hours of moderator/security review.
 * Applying the pro update during that window would leave a site running new
 * pro against old free.
 *
 * The required version is resolved from (in order of precedence):
 *   1. the license server's per-release answer (`requires_core.min_version` in
 *      the /check-update response, mirrored into Update_State), then
 *   2. the static `min_version` declared in the `requires_core` init arg.
 *
 * When a required version is known and the installed core plugin doesn't meet
 * it, the SDK first tries to update the core plugin, and — if it still can't
 * be satisfied (update not yet available, or not installed) — refuses the pro
 * update with an actionable "update the free plugin first / manually" message.
 *
 * The whole gate is a no-op unless the consumer declared `requires_core`.
 */
final class SE_License_SDK_Core_Dependency {

	/**
	 * @var SE_License_SDK_Client
	 */
	private $client;

	public function __construct( SE_License_SDK_Client $client ) {
		$this->client = $client;
	}

	/**
	 * Whether the consumer declared a core dependency at all.
	 */
	public function is_configured(): bool {
		return null !== $this->client->getRequiresCore();
	}

	/**
	 * Core plugin basename (e.g. "ablocks/ablocks.php"), or '' when unset.
	 */
	public function basename(): string {
		$core = $this->client->getRequiresCore();

		return ( $core && ! empty( $core['basename'] ) ) ? (string) $core['basename'] : '';
	}

	/**
	 * Human-readable core plugin name for notices/messages.
	 */
	public function name(): string {
		$core = $this->client->getRequiresCore();

		if ( $core && ! empty( $core['name'] ) ) {
			return (string) $core['name'];
		}

		// Fall back to the installed plugin's own name, then a title-cased slug.
		$basename = $this->basename();
		if ( $basename ) {
			$file = trailingslashit( WP_PLUGIN_DIR ) . $basename;
			if ( file_exists( $file ) ) {
				if ( ! function_exists( 'get_plugin_data' ) ) {
					require_once ABSPATH . 'wp-admin/includes/plugin.php';
				}
				$data = get_plugin_data( $file, false, false );
				if ( ! empty( $data['Name'] ) ) {
					return (string) $data['Name'];
				}
			}
		}

		$slug = $core && ! empty( $core['slug'] ) ? (string) $core['slug'] : '';

		return $slug ? ucwords( str_replace( [ '-', '_' ], ' ', $slug ) ) : __( 'the required plugin', 'storeengine-sdk' );
	}

	/**
	 * Whether the core plugin folder/file exists on disk.
	 */
	public function is_installed(): bool {
		$basename = $this->basename();

		return $basename && file_exists( trailingslashit( WP_PLUGIN_DIR ) . $basename );
	}

	/**
	 * Currently installed core version, read fresh from the plugin header (not
	 * the request-cached get_plugins() list, so it's correct right after an
	 * in-request core update). '' when not installed.
	 */
	public function installed_version(): string {
		$basename = $this->basename();
		if ( ! $basename ) {
			return '';
		}

		$file = trailingslashit( WP_PLUGIN_DIR ) . $basename;
		if ( ! file_exists( $file ) ) {
			return '';
		}

		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$data = get_plugin_data( $file, false, false );

		return isset( $data['Version'] ) ? (string) $data['Version'] : '';
	}

	/**
	 * The required core version — server answer wins over the static arg.
	 * '' means "no requirement declared" → the gate does not block.
	 */
	public function required_version(): string {
		// Per-release requirement supplied by the license server (if any).
		$server = $this->client->update_state()->get( 'required_core_version' );
		if ( is_string( $server ) && '' !== $server ) {
			return $server;
		}

		$core = $this->client->getRequiresCore();

		return ( $core && ! empty( $core['min_version'] ) ) ? (string) $core['min_version'] : '';
	}

	/**
	 * Is the dependency satisfied? True when there's no declared requirement,
	 * or when the installed core meets the required version.
	 */
	public function is_satisfied(): bool {
		if ( ! $this->is_configured() ) {
			return true;
		}

		$required = $this->required_version();

		// No concrete version requirement → never block on this gate.
		if ( '' === $required ) {
			return true;
		}

		$installed = $this->installed_version();
		if ( '' === $installed ) {
			return false; // required version known but core not installed.
		}

		return version_compare( $installed, $required, '>=' );
	}

	/**
	 * Try to bring the core plugin up to the required version via WordPress's
	 * own plugin updater. Only attempts when the core is already installed and
	 * an update that actually meets the requirement is available — so it won't
	 * churn while the matching free release is still held in wp.org review.
	 *
	 * @return bool True if the dependency is satisfied after the attempt.
	 */
	public function try_update_core(): bool {
		if ( ! $this->is_configured() || $this->is_satisfied() ) {
			return $this->is_satisfied();
		}

		$basename = $this->basename();

		// We can't safely auto-install a completely missing plugin here; leave
		// that to the actionable "install & update" message.
		if ( ! $basename || ! $this->is_installed() ) {
			return false;
		}

		if ( ! current_user_can( 'update_plugins' ) ) {
			return false;
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/update.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		require_once ABSPATH . 'wp-admin/includes/class-plugin-upgrader.php';

		// Refresh available-update info (hits wp.org / the core plugin's own
		// update source).
		if ( function_exists( 'wp_update_plugins' ) ) {
			wp_update_plugins();
		}

		$updates   = get_site_transient( 'update_plugins' );
		$available = ( isset( $updates->response[ $basename ]->new_version ) )
			? (string) $updates->response[ $basename ]->new_version
			: '';

		$required = $this->required_version();

		// Nothing newer offered, or what's offered still doesn't satisfy the
		// requirement (e.g. free 3.8.4 is still in wp.org's review queue).
		if ( '' === $available ) {
			return false;
		}
		if ( '' !== $required && version_compare( $available, $required, '<' ) ) {
			return false;
		}

		if ( ! WP_Filesystem() ) {
			return false;
		}

		// Defensive load — see Updater::require_sibling().
		if ( ! class_exists( 'SE_License_SDK_Upgrader_Skin', false ) ) {
			$skin_path = __DIR__ . DIRECTORY_SEPARATOR . 'SE_License_SDK_Upgrader_Skin.php';
			if ( is_readable( $skin_path ) ) {
				require_once $skin_path;
			}
		}

		$was_active = is_plugin_active( $basename );

		$skin     = class_exists( 'SE_License_SDK_Upgrader_Skin', false ) ? new SE_License_SDK_Upgrader_Skin() : null;
		$upgrader = $skin ? new Plugin_Upgrader( $skin ) : new Plugin_Upgrader();

		$result = $upgrader->upgrade( $basename );

		// Keep the core plugin active across the upgrade (the upgrader can leave
		// it deactivated). Only when it was active before.
		if ( true === $result && $was_active && is_plugin_inactive( $basename ) ) {
			activate_plugin( $basename );
		}

		return $this->is_satisfied();
	}

	/**
	 * Ensure the dependency is satisfied, optionally attempting a core update
	 * first. Returns true when satisfied, or a WP_Error the caller can surface.
	 *
	 * @param bool $attempt_update Whether to try updating the core plugin.
	 *
	 * @return true|WP_Error
	 */
	public function ensure_satisfied_or_error( bool $attempt_update = true ) {
		if ( ! $this->is_configured() || $this->is_satisfied() ) {
			return true;
		}

		if ( $attempt_update && $this->try_update_core() && $this->is_satisfied() ) {
			return true;
		}

		return new WP_Error( 'sdk-core-dependency-unmet', $this->unmet_message(), [ 'status' => 409 ] );
	}

	/**
	 * Actionable message shown when the core dependency can't be satisfied.
	 */
	public function unmet_message(): string {
		$product   = $this->client->getPackageName();
		$core_name = $this->name();
		$required  = $this->required_version();
		$installed = $this->installed_version();

		if ( ! $this->is_installed() ) {
			return sprintf(
			/* translators: 1: pro product name, 2: core/free plugin name, 3: required version. */
				__( '%1$s requires %2$s version %3$s or newer to be installed and active first. Please install and update %2$s, then update %1$s.', 'storeengine-sdk' ),
				$product,
				$core_name,
				$required
			);
		}

		return sprintf(
		/* translators: 1: pro product name, 2: core/free plugin name, 3: required version, 4: installed version. */
			__( '%1$s needs %2$s version %3$s or newer, but %4$s is installed. Update %2$s first — the matching release can take up to 24 hours to appear from WordPress.org, or you can update %2$s manually — then update %1$s.', 'storeengine-sdk' ),
			$product,
			$core_name,
			$required,
			$installed ?: __( 'an older version', 'storeengine-sdk' )
		);
	}

	final public function __clone() {
		trigger_error( 'Singleton. No cloning allowed!', E_USER_ERROR ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error
	}

	final public function __wakeup() {
		trigger_error( 'Singleton. No serialization allowed!', E_USER_ERROR ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error
	}
}

// End of file SE_License_SDK_Core_Dependency.php.
