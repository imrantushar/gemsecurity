<?php

/**
 * Tiny wp_options-backed store for per-client update UI state.
 *
 * Keeps update-related state out of the license transient (which gets
 * cleared on every license toggle) and out of the cached version info
 * transient (which the SDK already clobbers on a 3h TTL). This is where
 * we record:
 *
 * - previous_version: what we were on before the last successful install
 *                     so the React panel can offer one-click rollback
 *                     without making the user pick from the history list.
 * - last_install_*:   audit trail of the most recent install attempt.
 * - last_checked_at:  user-visible "checked X minutes ago" timestamp.
 * - beta_enabled / auto_update_window: local mirror of the server flags;
 *                     server is still source of truth, but mirroring
 *                     means /updates/status can answer without a remote
 *                     round-trip.
 */
final class SE_License_SDK_Update_State {

	/**
	 * @var SE_License_SDK_Client
	 */
	private $client;

	/**
	 * @var string
	 */
	private $option_key;

	public function __construct( SE_License_SDK_Client $client ) {
		$this->client     = $client;
		$this->option_key = $this->client->getHookName( 'update_state' );
	}

	public function all(): array {
		$value = get_option( $this->option_key, [] );

		if ( ! is_array( $value ) ) {
			$value = [];
		}

		return wp_parse_args( $value, [
			'previous_version'    => null,
			'last_install_at'     => null,
			'last_install_status' => null,
			'last_install_target' => null,
			'last_install_is_rollback' => false,
			'last_checked_at'     => null,
			'beta_enabled'        => false,
			'auto_update_window'  => null,
		] );
	}

	public function get( string $key, $default = null ) {
		$all = $this->all();

		return array_key_exists( $key, $all ) ? $all[ $key ] : $default;
	}

	public function set( array $changes ): void {
		$current = $this->all();
		$next    = array_merge( $current, $changes );

		update_option( $this->option_key, $next, false );
	}

	public function delete(): void {
		delete_option( $this->option_key );
	}

	public function record_install( string $target_version, ?string $current_version, string $status, bool $is_rollback ): void {
		$changes = [
			'last_install_at'          => time(),
			'last_install_status'      => $status,
			'last_install_target'      => $target_version,
			'last_install_is_rollback' => $is_rollback,
		];

		// On a successful update or rollback, remember where we came from
		// so the UI can offer a one-click reverse without making the user
		// pick from the version-history table.
		if ( 'succeeded' === $status && $current_version && $current_version !== $target_version ) {
			$changes['previous_version'] = $current_version;
		}

		$this->set( $changes );
	}

	public function record_check( int $time = null ): void {
		$this->set( [ 'last_checked_at' => $time ?: time() ] );
	}
}

// End of file SE_License_SDK_Update_State.php.
