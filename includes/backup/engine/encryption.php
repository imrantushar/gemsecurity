<?php
namespace GemBackup\Engine;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * AES-256-CBC streaming encryption helper.
 * Key is derived from the passphrase via PBKDF2.
 * Output file format: magic (4) | salt (16) | iv (16) | ciphertext.
 */
class Encryption {

	const MAGIC = "GBKE";

	public static function is_enabled() {
		$s = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		return ! empty( $s['encryption_enabled'] ) && ! empty( $s['encryption_passphrase'] );
	}

	public static function get_passphrase() {
		$s = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		return $s['encryption_passphrase'] ?? '';
	}

	public static function encrypt_file( $source, $destination, $passphrase ) {
		if ( ! function_exists( 'openssl_encrypt' ) ) {
			return new \WP_Error( 'gembackup_no_openssl', __( 'OpenSSL extension is required for encryption.', 'gembackup' ) );
		}

		$salt = random_bytes( 16 );
		$iv   = random_bytes( 16 );
		$key  = hash_pbkdf2( 'sha256', $passphrase, $salt, 100000, 32, true );

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
			$encrypted = openssl_encrypt( $chunk, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $prev_block );
			if ( $encrypted === false ) {
				// final chunk — allow padding.
				$encrypted = openssl_encrypt( $chunk, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $prev_block );
				fwrite( $out, $encrypted );
				break;
			}
			fwrite( $out, $encrypted );
			$prev_block = substr( $encrypted, -16 );
		}

		fclose( $in );
		fclose( $out );
		return true;
	}

	public static function decrypt_file( $source, $destination, $passphrase ) {
		if ( ! function_exists( 'openssl_decrypt' ) ) {
			return new \WP_Error( 'gembackup_no_openssl', __( 'OpenSSL extension is required for decryption.', 'gembackup' ) );
		}

		$in  = @fopen( $source, 'rb' );
		$out = @fopen( $destination, 'wb' );
		if ( ! $in || ! $out ) {
			return new \WP_Error( 'gembackup_decrypt_io', __( 'Failed to open files for decryption.', 'gembackup' ) );
		}

		$magic = fread( $in, 4 );
		if ( $magic !== self::MAGIC ) {
			fclose( $in );
			fclose( $out );
			return new \WP_Error( 'gembackup_bad_magic', __( 'Backup file is not encrypted or is corrupt.', 'gembackup' ) );
		}

		$salt = fread( $in, 16 );
		$iv   = fread( $in, 16 );
		$key  = hash_pbkdf2( 'sha256', $passphrase, $salt, 100000, 32, true );

		$prev_block = $iv;
		while ( ! feof( $in ) ) {
			$chunk = fread( $in, 1024 * 1024 );
			if ( $chunk === '' ) break;
			$decrypted = openssl_decrypt( $chunk, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $prev_block );
			if ( $decrypted === false ) {
				$decrypted = openssl_decrypt( $chunk, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $prev_block );
			}
			fwrite( $out, $decrypted );
			$prev_block = substr( $chunk, -16 );
		}

		fclose( $in );
		fclose( $out );
		return true;
	}
}
