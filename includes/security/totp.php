<?php
namespace GemSecurity\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * RFC 6238 (TOTP) / RFC 4648 (Base32) implementation — no external libraries.
 *
 * Used for app-based two-factor authentication (Google Authenticator, Authy,
 * 1Password, etc.).
 */
class Totp {

	const PERIOD = 30;
	const DIGITS = 6;
	const ALGO   = 'sha1';

	private static $base32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Generate a new Base32-encoded shared secret.
	 *
	 * @param int $length Number of Base32 characters (default 32 ≈ 160 bits).
	 * @return string
	 */
	public static function generate_secret( $length = 32 ) {
		$secret = '';
		$bytes  = random_bytes( $length );
		for ( $i = 0; $i < $length; $i++ ) {
			$secret .= self::$base32[ ord( $bytes[ $i ] ) & 31 ];
		}
		return $secret;
	}

	/**
	 * Compute the TOTP code for a given secret and time.
	 *
	 * @param string   $secret    Base32 secret.
	 * @param int|null $timestamp Defaults to now.
	 * @return string Zero-padded 6-digit code.
	 */
	public static function get_code( $secret, $timestamp = null ) {
		$timestamp = null === $timestamp ? time() : $timestamp;
		$counter   = (int) floor( $timestamp / self::PERIOD );

		$key = self::base32_decode( $secret );
		if ( '' === $key ) {
			return '';
		}

		$binary = pack( 'N*', 0 ) . pack( 'N*', $counter );
		$hash   = hash_hmac( self::ALGO, $binary, $key, true );

		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;
		$value  = (
			( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 ) |
			( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 ) |
			( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 ) |
			( ord( $hash[ $offset + 3 ] ) & 0xFF )
		);

		$code = $value % ( 10 ** self::DIGITS );
		return str_pad( (string) $code, self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify a user-supplied code, allowing for clock drift.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $code   Submitted code.
	 * @param int    $window Number of ±30s steps to allow (default 1).
	 * @return bool
	 */
	public static function verify( $secret, $code, $window = 1 ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}
		$now = time();
		for ( $i = -$window; $i <= $window; $i++ ) {
			$candidate = self::get_code( $secret, $now + ( $i * self::PERIOD ) );
			if ( '' !== $candidate && hash_equals( $candidate, $code ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Build an otpauth:// provisioning URI for QR codes.
	 *
	 * @param string $secret
	 * @param string $label  Usually the user email / login.
	 * @param string $issuer Site name.
	 * @return string
	 */
	public static function provisioning_uri( $secret, $label, $issuer ) {
		return sprintf(
			'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d',
			rawurlencode( $issuer . ':' . $label ),
			$secret,
			rawurlencode( $issuer ),
			strtoupper( self::ALGO ),
			self::DIGITS,
			self::PERIOD
		);
	}

	/* ------------------------------------------------------------------ */

	private static function base32_decode( $b32 ) {
		$b32 = strtoupper( $b32 );
		$buffer = 0;
		$bits   = 0;
		$output = '';
		$len    = strlen( $b32 );
		for ( $i = 0; $i < $len; $i++ ) {
			$char = $b32[ $i ];
			if ( '=' === $char ) {
				continue;
			}
			$val = strpos( self::$base32, $char );
			if ( false === $val ) {
				continue;
			}
			$buffer = ( $buffer << 5 ) | $val;
			$bits  += 5;
			if ( $bits >= 8 ) {
				$bits  -= 8;
				$output .= chr( ( $buffer >> $bits ) & 0xFF );
			}
		}
		return $output;
	}
}
