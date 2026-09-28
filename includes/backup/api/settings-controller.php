<?php
namespace GemBackup\Api;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Settings_Controller extends Rest_Controller {

	protected $rest_base = 'settings';

	public function register_routes() {
		register_rest_route( $this->namespace, '/' . $this->rest_base, [
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'get_settings' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
			[
				'methods'             => 'PUT',
				'callback'            => [ $this, 'update_settings' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
		] );
	}

	public function get_settings() {
		return $this->ok( self::for_client( self::effective() ) );
	}

	/**
	 * What the settings screen may see.
	 *
	 * The option row also holds every storage driver's credentials (written
	 * by the storage controller under `<driver>_*` keys) and the encryption
	 * passphrase. None of that belongs in a settings payload: only the keys
	 * this screen owns go out, and the passphrase is reduced to whether one
	 * is set.
	 *
	 * @param array $settings
	 * @return array
	 */
	private static function for_client( $settings ) {
		$out = array_intersect_key( $settings, \GemBackup\Installer::defaults() );
		$out['encryption_passphrase_set'] = '' !== (string) ( $settings['encryption_passphrase'] ?? '' );
		$out['encryption_passphrase']     = '';
		return $out;
	}

	/**
	 * Stored settings over the defaults.
	 *
	 * A site that has never saved backup settings has no option row, so the
	 * raw value is an empty array. Returning that made the UI show every
	 * default-ON switch as OFF, and a save from that screen would have written
	 * those falses back — quietly turning off the pre-restore safety snapshot
	 * and the transient-table skip.
	 *
	 * @return array
	 */
	private static function effective() {
		$stored = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		$stored = is_array( $stored ) ? $stored : [];
		return array_merge( \GemBackup\Installer::defaults(), $stored );
	}

	public function update_settings( $request ) {
		$current = self::effective();
		$incoming = $request->get_json_params();
		if ( ! is_array( $incoming ) ) {
			return $this->fail( 'gembackup_invalid_payload', __( 'Invalid payload.', 'gembackup' ) );
		}

		// Only the keys this screen owns; driver credentials are the storage
		// controller's business and must not be writable from here.
		$incoming = array_intersect_key( $incoming, \GemBackup\Installer::defaults() );
		unset( $incoming['local_path'], $incoming['enabled_drivers'], $incoming['active_storage'] );

		// The passphrase is never sent to the client, so a blank one means
		// "unchanged", not "clear it".
		if ( isset( $incoming['encryption_passphrase'] ) && '' === (string) $incoming['encryption_passphrase'] ) {
			unset( $incoming['encryption_passphrase'] );
		}

		$merged = array_merge( $current, $incoming );

		// Sanitize known keys. The notification recipient and webhook are
		// plugin-wide (the Notifications page), so they are deliberately not
		// accepted here.
		$merged['backup_retention']           = max( 1, (int) ( $merged['backup_retention'] ?? 10 ) );
		$merged['backup_logs_retention_days'] = max( 1, (int) ( $merged['backup_logs_retention_days'] ?? 30 ) );
		$merged['health_alert_days']          = max( 1, (int) ( $merged['health_alert_days'] ?? 7 ) );
		$merged['notify_on_failure']          = ! empty( $merged['notify_on_failure'] );
		$merged['encryption_enabled']         = ! empty( $merged['encryption_enabled'] );
		$merged['encryption_passphrase']      = (string) ( $merged['encryption_passphrase'] ?? '' );
		$merged['exclude_paths']              = sanitize_textarea_field( (string) ( $merged['exclude_paths'] ?? '' ) );
		$merged['exclude_tables_smart']       = ! empty( $merged['exclude_tables_smart'] );
		$merged['exclude_tables_extra']       = sanitize_textarea_field( (string) ( $merged['exclude_tables_extra'] ?? '' ) );
		$merged['restore_safety_snapshot']    = ! empty( $merged['restore_safety_snapshot'] );

		unset( $merged['notify_email'], $merged['webhook_url'], $merged['logs_retention_days'] );

		update_option( GEMBACKUP_SETTINGS_NAME, $merged );
		do_action( 'gembackup/settings_updated', $merged );

		return $this->ok( self::for_client( $merged ) );
	}
}
