<?php
namespace GemSecurity\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Encrypt small secrets (2FA seeds) before they are written to the database.
 *
 * A TOTP seed stored in plain text means a database leak — an SQL injection,
 * a backup left on a public bucket, a staging copy — hands an attacker every
 * user's second factor. Sealed values are useless without the key, and the
 * key comes from, in order:
 *
 *  1. GEMSECURITY_SECRET_KEY in wp-config.php, when defined (recommended:
 *     keeps the key out of the database entirely);
 *  2. a key file an earlier release wrote (read only, never created now), so
 *     secrets it sealed keep opening;
 *  3. a random key in a non-autoloaded option, created on first use. Kept
 *     separate from the WordPress salts on purpose: rotating salts after an
 *     incident must not lock every user out of 2FA.
 *  4. Only if none of those is available: a key derived from the salts.
 *
 * Format: "gsx1<k>:" + base64( iv[12] | tag[16] | ciphertext ), AES-256-GCM,
 * where <k> is f (constant/legacy file key), o (option key) or s (salt-derived
 * key). A value without
 * the prefix is legacy plain text and is returned as-is by open().
 */
class SecretBox {

	const PREFIX   = 'gsx1';
	const KEY_FILE = 'gemsecurity-secret-key.php';
	const OPTION   = 'gemsecurity_secret_key';

	/** @var array<string,string> In-request key cache. */
	private static $keys = [];

	/**
	 * Key file an earlier release created, if one is still on disk.
	 *
	 * @return string|null
	 */
	public static function key_file() {
		$candidates = [
			trailingslashit( wp_upload_dir( null, false )['basedir'] ) . 'gemsecurity/' . self::KEY_FILE,
			trailingslashit( dirname( get_theme_root() ) ) . self::KEY_FILE, // Pre-1.x releases kept it in the content folder.
		];
		foreach ( $candidates as $file ) {
			if ( is_readable( $file ) ) {
				return $file;
			}
		}
		return null;
	}

	/**
	 * @param string $kind 'f', 'o' or 's'.
	 * @return string|null 32-byte key.
	 */
	private static function key( $kind ) {
		if ( isset( self::$keys[ $kind ] ) ) {
			return self::$keys[ $kind ];
		}
		if ( 's' === $kind ) {
			return self::$keys['s'] = hash( 'sha256', wp_salt( 'secure_auth' ) . '|gemsecurity-secretbox', true );
		}
		if ( 'o' === $kind ) {
			$raw = base64_decode( (string) get_option( self::OPTION, '' ), true );
			return $raw && 32 === strlen( $raw ) ? self::$keys['o'] = $raw : null;
		}
		if ( defined( 'GEMSECURITY_SECRET_KEY' ) && '' !== (string) GEMSECURITY_SECRET_KEY ) {
			return self::$keys['f'] = hash( 'sha256', (string) GEMSECURITY_SECRET_KEY, true );
		}
		$file = self::key_file();
		if ( $file && preg_match( '/KEY:([A-Za-z0-9+\/=]{40,})/', (string) file_get_contents( $file ), $m ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			$raw = base64_decode( $m[1], true );
			if ( $raw && 32 === strlen( $raw ) ) {
				return self::$keys['f'] = $raw;
			}
		}
		return null;
	}

	/**
	 * Which key new values are sealed with, creating the option key if needed.
	 *
	 * @return string 'f', 'o' or 's'.
	 */
	private static function seal_kind() {
		if ( null !== self::key( 'f' ) ) {
			return 'f';
		}
		if ( null === self::key( 'o' ) ) {
			// add_option() never overwrites an existing key.
			add_option( self::OPTION, base64_encode( random_bytes( 32 ) ), '', false );
			unset( self::$keys['o'] );
		}
		return null !== self::key( 'o' ) ? 'o' : 's';
	}

	public static function available() {
		return function_exists( 'openssl_encrypt' ) && in_array( 'aes-256-gcm', openssl_get_cipher_methods(), true );
	}

	/** Whether a stored value is already sealed. */
	public static function is_sealed( $value ) {
		return is_string( $value ) && 0 === strpos( $value, self::PREFIX );
	}

	/**
	 * @param string $plain
	 * @return string Sealed value (or the plain value if encryption is unavailable).
	 */
	public static function seal( $plain ) {
		$plain = (string) $plain;
		if ( '' === $plain || self::is_sealed( $plain ) || ! self::available() ) {
			return $plain;
		}
		$kind = self::seal_kind();
		$iv   = random_bytes( 12 );
		$tag  = '';
		$ct   = openssl_encrypt( $plain, 'aes-256-gcm', self::key( $kind ), OPENSSL_RAW_DATA, $iv, $tag );
		if ( false === $ct ) {
			return $plain;
		}
		return self::PREFIX . $kind . ':' . base64_encode( $iv . $tag . $ct );
	}

	/**
	 * @param string $stored
	 * @return string Plain value; '' if it cannot be decrypted (key missing).
	 */
	public static function open( $stored ) {
		$stored = (string) $stored;
		if ( ! self::is_sealed( $stored ) ) {
			return $stored; // Legacy plain text.
		}
		$kind = substr( $stored, strlen( self::PREFIX ), 1 );
		$raw  = base64_decode( substr( $stored, strlen( self::PREFIX ) + 2 ), true );
		$key  = in_array( $kind, [ 'f', 'o', 's' ], true ) ? self::key( $kind ) : null;
		if ( ! $raw || strlen( $raw ) < 29 || ! $key || ! self::available() ) {
			return '';
		}
		$plain = openssl_decrypt( substr( $raw, 28 ), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr( $raw, 0, 12 ), substr( $raw, 12, 16 ) );
		return false === $plain ? '' : $plain;
	}
}
