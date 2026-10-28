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
 * key deliberately does NOT live in the database:
 *
 *  1. GEMSECURITY_SECRET_KEY in wp-config.php, when defined; else
 *  2. a key file in wp-content (PHP that exits before printing anything),
 *     created on first use. Kept separate from the WordPress salts on
 *     purpose: rotating salts after an incident must not lock every user out
 *     of 2FA.
 *  3. Only if that file cannot be written: a key derived from the salts
 *     (marked in the ciphertext, so a later key file does not break it).
 *
 * Format: "gsx1<k>:" + base64( iv[12] | tag[16] | ciphertext ), AES-256-GCM,
 * where <k> is f (file/constant key) or s (salt-derived key). A value without
 * the prefix is legacy plain text and is returned as-is by open().
 */
class SecretBox {

	const PREFIX   = 'gsx1';
	const KEY_FILE = 'gemsecurity-secret-key.php';

	/** @var array<string,string> In-request key cache. */
	private static $keys = [];

	public static function key_file() {
		// A key an earlier release put in wp-content stays where it is, so the
		// secrets it sealed keep opening. New keys go to the uploads folder.
		$legacy = WP_CONTENT_DIR . '/' . self::KEY_FILE;
		if ( is_file( $legacy ) ) {
			return $legacy;
		}
		$up = wp_get_upload_dir();
		return trailingslashit( $up['basedir'] ) . 'gemsecurity/' . self::KEY_FILE;
	}

	/**
	 * @param string $kind 'f' or 's'.
	 * @return string|null 32-byte key.
	 */
	private static function key( $kind ) {
		if ( isset( self::$keys[ $kind ] ) ) {
			return self::$keys[ $kind ];
		}
		if ( 's' === $kind ) {
			return self::$keys['s'] = hash( 'sha256', wp_salt( 'secure_auth' ) . '|gemsecurity-secretbox', true );
		}
		if ( defined( 'GEMSECURITY_SECRET_KEY' ) && '' !== (string) GEMSECURITY_SECRET_KEY ) {
			return self::$keys['f'] = hash( 'sha256', (string) GEMSECURITY_SECRET_KEY, true );
		}
		$file = self::key_file();
		if ( is_readable( $file ) && preg_match( '/KEY:([A-Za-z0-9+\/=]{40,})/', (string) file_get_contents( $file ), $m ) ) { // phpcs:ignore
			$raw = base64_decode( $m[1], true );
			if ( $raw && 32 === strlen( $raw ) ) {
				return self::$keys['f'] = $raw;
			}
		}
		return null;
	}

	/** Create the key file if it does not exist yet. @return bool */
	private static function ensure_key_file() {
		if ( null !== self::key( 'f' ) ) {
			return true;
		}
		$file = self::key_file();
		$dir  = dirname( $file );
		if ( ! is_dir( $dir ) && wp_mkdir_p( $dir ) ) {
			file_put_contents( $dir . '/index.php', "<?php // Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- own uploads subfolder.
			file_put_contents( $dir . '/.htaccess', "Require all denied\nDeny from all\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- own uploads subfolder.
		}
		if ( file_exists( $file ) || ! is_writable( $dir ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
			return false; // Never overwrite an existing (unreadable/garbled) key.
		}
		$body = "<?php\n"
			. "// GemSecurity encryption key for 2FA secrets. Do not delete or edit:\n"
			. "// without it, authenticator-app codes stop working (backup codes still do).\n"
			. "// Move it into wp-config.php as GEMSECURITY_SECRET_KEY if you prefer.\n"
			. "exit;\n"
			. '// KEY:' . base64_encode( random_bytes( 32 ) ) . "\n";
		if ( false === @file_put_contents( $file, $body, LOCK_EX ) ) { // phpcs:ignore
			return false;
		}
		@chmod( $file, 0640 ); // phpcs:ignore
		self::$keys = [];
		return null !== self::key( 'f' );
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
		$kind = self::ensure_key_file() ? 'f' : 's';
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
		$key  = in_array( $kind, [ 'f', 's' ], true ) ? self::key( $kind ) : null;
		if ( ! $raw || strlen( $raw ) < 29 || ! $key || ! self::available() ) {
			return '';
		}
		$plain = openssl_decrypt( substr( $raw, 28 ), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr( $raw, 0, 12 ), substr( $raw, 12, 16 ) );
		return false === $plain ? '' : $plain;
	}
}
