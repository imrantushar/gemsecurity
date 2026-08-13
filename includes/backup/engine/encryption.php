<?php
namespace GemBackup\Engine;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * AES-256-CBC streaming encryption helper, with an encrypt-then-MAC
 * integrity layer (HMAC-SHA256) so a tampered backup is detected and
 * rejected before anything is decrypted to disk.
 *
 * Current format (v2): magic "GBK2" (4) | salt (16) | iv (16) | ciphertext
 * (streamed in 1MB chunks, CBC-chained across chunk boundaries) | HMAC-SHA256
 * of the ciphertext (32 bytes). The MAC key is independently derived from
 * the same passphrase via domain separation on the PBKDF2 salt, so one
 * passphrase never reuses identical key material for two different
 * purposes.
 *
 * Backups made before this fix used the legacy format (magic "GBKE": no
 * trailing MAC) and remain restorable — refusing to restore an existing
 * backup would defeat the point of a disaster-recovery feature — but a
 * legacy-format restore carries no integrity guarantee, same as before
 * this fix. That code path is unchanged from the original implementation.
 */
class Encryption {

	const MAGIC        = 'GBK2';
	const MAGIC_LEGACY = 'GBKE';
	const MAC_LEN      = 32; // SHA-256 digest length.

	public static function is_enabled() {
		$s = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		return ! empty( $s['encryption_enabled'] ) && ! empty( $s['encryption_passphrase'] );
	}

	public static function get_passphrase() {
		$s = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		return $s['encryption_passphrase'] ?? '';
	}

	/**
	 * Derive the encryption and MAC keys from one passphrase. Domain
	 * separation via a suffix on the PBKDF2 salt keeps the two keys
	 * cryptographically independent without needing a second secret.
	 *
	 * @param string $passphrase
	 * @param string $salt Raw 16-byte salt.
	 * @return array{0:string,1:string} [ $enc_key, $mac_key ]
	 */
	private static function derive_keys( $passphrase, $salt ) {
		return [
			hash_pbkdf2( 'sha256', $passphrase, $salt . 'enc', 100000, 32, true ),
			hash_pbkdf2( 'sha256', $passphrase, $salt . 'mac', 100000, 32, true ),
		];
	}

	public static function encrypt_file( $source, $destination, $passphrase ) {
		if ( ! function_exists( 'openssl_encrypt' ) ) {
			return new \WP_Error( 'gembackup_no_openssl', __( 'OpenSSL extension is required for encryption.', 'gembackup' ) );
		}

		$salt = random_bytes( 16 );
		$iv   = random_bytes( 16 );
		list( $enc_key, $mac_key ) = self::derive_keys( $passphrase, $salt );
		$hmac_ctx = hash_init( 'sha256', HASH_HMAC, $mac_key );

		$in  = @fopen( $source, 'rb' );
		$out = @fopen( $destination, 'wb' );
		if ( ! $in || ! $out ) {
			return new \WP_Error( 'gembackup_encrypt_io', __( 'Failed to open files for encryption.', 'gembackup' ) );
		}

		fwrite( $out, self::MAGIC );
		fwrite( $out, $salt );
		fwrite( $out, $iv );

		$prev_block = $iv;
		while ( ! feof( $in ) ) {
			$chunk = fread( $in, 1024 * 1024 );
			// The final chunk (feof now true, having just consumed the rest
			// of the input) always gets real PKCS7 padding, even if it
			// happens to already be block-aligned — standard PKCS7 semantics,
			// chosen deliberately so decrypt never has to guess whether a
			// given chunk was padded (see decrypt_v2()). Every earlier chunk
			// is exactly 1MB, itself always block-aligned, and needs none.
			$flags     = feof( $in ) ? OPENSSL_RAW_DATA : ( OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING );
			$encrypted = openssl_encrypt( $chunk, 'aes-256-cbc', $enc_key, $flags, $prev_block );
			fwrite( $out, $encrypted );
			hash_update( $hmac_ctx, $encrypted );
			$prev_block = substr( $encrypted, -16 );
		}

		fclose( $in );
		fwrite( $out, hash_final( $hmac_ctx, true ) );
		fclose( $out );
		return true;
	}

	/**
	 * @param string $source
	 * @param string $destination
	 * @param string $passphrase
	 * @return true|\WP_Error
	 */
	public static function decrypt_file( $source, $destination, $passphrase ) {
		if ( ! function_exists( 'openssl_decrypt' ) ) {
			return new \WP_Error( 'gembackup_no_openssl', __( 'OpenSSL extension is required for decryption.', 'gembackup' ) );
		}

		$in = @fopen( $source, 'rb' );
		if ( ! $in ) {
			return new \WP_Error( 'gembackup_decrypt_io', __( 'Failed to open files for decryption.', 'gembackup' ) );
		}

		$magic = fread( $in, 4 );
		if ( self::MAGIC === $magic ) {
			return self::decrypt_v2( $in, $source, $destination, $passphrase );
		}
		if ( self::MAGIC_LEGACY === $magic ) {
			return self::decrypt_legacy( $in, $source, $destination, $passphrase );
		}

		fclose( $in );
		return new \WP_Error( 'gembackup_bad_magic', __( 'Backup file is not encrypted or is corrupt.', 'gembackup' ) );
	}

	/**
	 * Authenticated (v2) decryption. Single pass over the source: decrypts
	 * to a temp file while simultaneously re-computing the HMAC over the
	 * ciphertext. The temp file is only renamed into place if the stored
	 * MAC matches; on any mismatch it's deleted and the real destination
	 * path is never created, so tampered ciphertext can never produce
	 * output the restore engine goes on to read.
	 *
	 * @param resource $in   Open handle, positioned right after the magic.
	 * @param string   $source
	 * @param string   $destination
	 * @param string   $passphrase
	 * @return true|\WP_Error
	 */
	private static function decrypt_v2( $in, $source, $destination, $passphrase ) {
		$salt = fread( $in, 16 );
		$iv   = fread( $in, 16 );
		list( $enc_key, $mac_key ) = self::derive_keys( $passphrase, $salt );
		$hmac_ctx = hash_init( 'sha256', HASH_HMAC, $mac_key );

		$header_len     = 4 + 16 + 16;
		$ciphertext_len = filesize( $source ) - $header_len - self::MAC_LEN;
		if ( false === $ciphertext_len || $ciphertext_len < 0 ) {
			fclose( $in );
			return new \WP_Error( 'gembackup_bad_magic', __( 'Backup file is not encrypted or is corrupt.', 'gembackup' ) );
		}

		$tmp = $destination . '.decrypting-' . wp_generate_password( 12, false );
		$out = @fopen( $tmp, 'wb' );
		if ( ! $out ) {
			fclose( $in );
			return new \WP_Error( 'gembackup_decrypt_io', __( 'Failed to open files for decryption.', 'gembackup' ) );
		}

		$prev_block = $iv;
		$remaining  = $ciphertext_len;
		while ( $remaining > 0 ) {
			$chunk = fread( $in, min( 1024 * 1024, $remaining ) );
			if ( false === $chunk || '' === $chunk ) {
				break; // truncated file — the MAC check below will catch it.
			}
			$remaining -= strlen( $chunk );
			hash_update( $hmac_ctx, $chunk );

			// Only the final ciphertext chunk can carry real PKCS7 padding —
			// every earlier chunk is, by construction, a full block-aligned
			// 1MB read. Decrypt each chunk the way it was actually encrypted
			// rather than guessing from the ciphertext: a block-aligned,
			// really-padded chunk decrypts "successfully" but wrong under
			// zero-padding mode instead of failing, so openssl_decrypt's own
			// false-on-failure can't be used to detect this (unlike on the
			// encrypt side, where zero-padding mode reliably fails for
			// non-aligned input).
			$flags     = ( 0 === $remaining ) ? OPENSSL_RAW_DATA : ( OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING );
			$decrypted = openssl_decrypt( $chunk, 'aes-256-cbc', $enc_key, $flags, $prev_block );
			// $decrypted can still legitimately be false here (e.g. a
			// tampered final block failing PKCS7 unpadding) — write what we
			// have; the MAC comparison below is the authoritative check,
			// not this per-chunk decrypt result.
			fwrite( $out, false === $decrypted ? '' : $decrypted );
			$prev_block = substr( $chunk, -16 );
		}
		fclose( $out );

		$stored_mac = fread( $in, self::MAC_LEN );
		fclose( $in );

		$computed_mac = hash_final( $hmac_ctx, true );
		if ( ! is_string( $stored_mac ) || ! hash_equals( $computed_mac, $stored_mac ) ) {
			@unlink( $tmp );
			return new \WP_Error( 'gembackup_decrypt_tamper', __( 'This backup failed integrity verification and was not restored. The file may be corrupted or tampered with.', 'gembackup' ) );
		}

		if ( ! @rename( $tmp, $destination ) ) {
			@unlink( $tmp );
			return new \WP_Error( 'gembackup_decrypt_io', __( 'Could not finalise the decrypted file.', 'gembackup' ) );
		}

		return true;
	}

	/**
	 * Legacy (pre-fix) decryption — no integrity check, kept so backups made
	 * before this fix stay restorable. Flagged via the backup log so that's
	 * visible rather than silent.
	 *
	 * The padding-detection logic here is fixed relative to the original
	 * implementation. The original always tried zero-padding first and only
	 * fell back to real-padding decryption on failure — but decrypt-side
	 * zero-padding mode never actually fails for block-aligned ciphertext,
	 * real-padded or not, so that fallback effectively never triggered: any
	 * legacy backup whose final chunk needed real PKCS7 padding (i.e. most
	 * backups whose total size isn't a multiple of 16 bytes) was being
	 * silently restored with trailing garbage bytes.
	 *
	 * The original encryptor only applied real padding to the final chunk
	 * when that chunk genuinely wasn't already block-aligned — so unlike
	 * the v2 format (always padded, unconditionally, see encrypt_file()),
	 * whether a legacy backup's last chunk was padded is genuinely
	 * ambiguous from the ciphertext alone: the bytes on disk from
	 * encrypt_file() are correctly formed either way, only how they're
	 * interpreted here was wrong. The fix is to try the checks in the
	 * opposite order: real-padding-mode decrypt validates PKCS7 padding
	 * and reliably fails when a block wasn't actually padded, so trying it
	 * first and falling back to zero-padding only on that failure correctly
	 * resolves the ambiguity in the overwhelming majority of cases (the
	 * residual risk is a same-order-of-magnitude-as-1-in-16 chance of a
	 * false-positive padding match on an unpadded final block that
	 * coincidentally looks like valid padding — inherent to the old
	 * format's ambiguity, not fixable without rewriting bytes already on
	 * disk in existing backups).
	 *
	 * @param resource $in     Open handle, positioned right after the magic.
	 * @param string   $source
	 * @param string   $destination
	 * @param string   $passphrase
	 * @return true|\WP_Error
	 */
	private static function decrypt_legacy( $in, $source, $destination, $passphrase ) {
		$salt = fread( $in, 16 );
		$iv   = fread( $in, 16 );
		$key  = hash_pbkdf2( 'sha256', $passphrase, $salt, 100000, 32, true );

		$ciphertext_len = filesize( $source ) - 4 - 16 - 16;
		if ( false === $ciphertext_len || $ciphertext_len < 0 ) {
			fclose( $in );
			return new \WP_Error( 'gembackup_bad_magic', __( 'Backup file is not encrypted or is corrupt.', 'gembackup' ) );
		}

		$out = @fopen( $destination, 'wb' );
		if ( ! $out ) {
			fclose( $in );
			return new \WP_Error( 'gembackup_decrypt_io', __( 'Failed to open files for decryption.', 'gembackup' ) );
		}

		$prev_block = $iv;
		$remaining  = $ciphertext_len;
		while ( $remaining > 0 ) {
			$chunk = fread( $in, min( 1024 * 1024, $remaining ) );
			if ( false === $chunk || '' === $chunk ) {
				break;
			}
			$remaining -= strlen( $chunk );

			if ( 0 === $remaining ) {
				// Final chunk: try real-padding mode first — it validates
				// PKCS7 padding and fails when there isn't any, unlike
				// zero-padding mode, which never fails either way. Only
				// fall back to treating it as unpadded if that validation
				// fails (see docblock for the residual ambiguity this
				// can't fully resolve).
				$decrypted = openssl_decrypt( $chunk, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $prev_block );
				if ( false === $decrypted ) {
					$decrypted = openssl_decrypt( $chunk, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $prev_block );
				}
			} else {
				$decrypted = openssl_decrypt( $chunk, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $prev_block );
			}
			fwrite( $out, false === $decrypted ? '' : $decrypted );
			$prev_block = substr( $chunk, -16 );
		}

		fclose( $in );
		fclose( $out );

		Logger::warning( __( 'Restored from a pre-upgrade backup with no integrity protection (legacy encryption format). Consider making a fresh backup.', 'gembackup' ) );

		return true;
	}
}
