<?php
namespace GemSecurity\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Storage for passkey (WebAuthn) credentials: one row per credential in
 * {$wpdb->prefix}gemsecurity_passkeys. Only the public key is stored, so the
 * table holds nothing an attacker could sign in with.
 */
class PasskeyStore {

	/** Credentials one account may register. */
	const MAX_PER_USER = 10;

	/** Best-effort names for well-known authenticators, by AAGUID. */
	private static function providers() {
		return [
			'fbfc3007-154e-4ecc-8c0b-6e020557d7bd' => 'iCloud Keychain',
			'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' => 'Google Password Manager',
			'adce0002-35bc-c60a-648b-0b25f1f05503' => 'Chrome on Mac',
			'08987058-cadc-4b81-b6e1-30de50dcbe96' => 'Windows Hello',
			'9ddd1817-af5a-4672-a2b9-3e3dd95000a9' => 'Windows Hello',
			'6028b017-b1d4-4c02-b4b3-afcdafc96bb2' => 'Windows Hello',
			'bada5566-a7aa-401f-bd96-45619a55120d' => '1Password',
			'531126d6-e717-415c-9320-3d9aa6981239' => 'Dashlane',
			'd548826e-79b4-db40-a3d8-11116f7e8349' => 'Bitwarden',
			'ee882879-721c-4913-9775-3dfcce97072a' => 'YubiKey',
		];
	}

	public static function provider_name( $aaguid ) {
		$map = self::providers();
		return isset( $map[ $aaguid ] ) ? $map[ $aaguid ] : '';
	}

	private static function table() {
		global $wpdb;
		return $wpdb->prefix . 'gemsecurity_passkeys';
	}

	/**
	 * @param int $user_id
	 * @return array[] Rows, newest first.
	 */
	public static function for_user( $user_id ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE user_id = %d ORDER BY id DESC", $user_id ), ARRAY_A );
		return is_array( $rows ) ? $rows : [];
	}

	public static function count_for_user( $user_id ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE user_id = %d", $user_id ) );
	}

	/**
	 * @param string $credential_id base64url credential id.
	 * @return array|null
	 */
	public static function find_by_credential( $credential_id ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE credential_id = %s", $credential_id ), ARRAY_A );
		return $row ? $row : null;
	}

	/**
	 * @param int    $id
	 * @param int    $user_id Owner; a row is only returned for its owner.
	 * @return array|null
	 */
	public static function find_owned( $id, $user_id ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d AND user_id = %d", $id, $user_id ), ARRAY_A );
		return $row ? $row : null;
	}

	/**
	 * @param array $row Column => value (credential_id, public_key, etc.).
	 * @return int|false Insert id.
	 */
	public static function insert( array $row ) {
		global $wpdb;
		$ok = $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			self::table(),
			[
				'user_id'       => (int) $row['user_id'],
				'credential_id' => $row['credential_id'],
				'public_key'    => $row['public_key'],
				'alg'           => (int) $row['alg'],
				'sign_count'    => (int) $row['sign_count'],
				'aaguid'        => $row['aaguid'],
				'device_type'   => $row['device_type'],
				'backed_up'     => empty( $row['backed_up'] ) ? 0 : 1,
				'transports'    => $row['transports'],
				'name'          => $row['name'],
				'created_at'    => current_time( 'mysql', true ),
			],
			[ '%d', '%s', '%s', '%d', '%d', '%s', '%s', '%d', '%s', '%s', '%s' ]
		);
		return $ok ? (int) $wpdb->insert_id : false;
	}

	public static function touch( $id, $sign_count, $backed_up ) {
		global $wpdb;
		$wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			self::table(),
			[
				'sign_count'   => (int) $sign_count,
				'backed_up'    => $backed_up ? 1 : 0,
				'last_used_at' => current_time( 'mysql', true ),
			],
			[ 'id' => (int) $id ],
			[ '%d', '%d', '%s' ],
			[ '%d' ]
		);
	}

	public static function rename( $id, $user_id, $name ) {
		global $wpdb;
		return false !== $wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			self::table(),
			[ 'name' => $name ],
			[ 'id' => (int) $id, 'user_id' => (int) $user_id ],
			[ '%s' ],
			[ '%d', '%d' ]
		);
	}

	public static function delete( $id, $user_id ) {
		global $wpdb;
		return (bool) $wpdb->delete( self::table(), [ 'id' => (int) $id, 'user_id' => (int) $user_id ], [ '%d', '%d' ] ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	public static function delete_all_for_user( $user_id ) {
		global $wpdb;
		$wpdb->delete( self::table(), [ 'user_id' => (int) $user_id ], [ '%d' ] ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Shape a row for the browser: never includes the key material.
	 */
	public static function present( array $row ) {
		$provider = self::provider_name( (string) $row['aaguid'] );
		return [
			'id'           => (int) $row['id'],
			'name'         => $row['name'],
			'provider'     => $provider,
			'synced'       => 'multi_device' === $row['device_type'],
			'created_at'   => mysql2date( 'c', $row['created_at'], false ),
			'last_used_at' => $row['last_used_at'] ? mysql2date( 'c', $row['last_used_at'], false ) : null,
		];
	}
}
