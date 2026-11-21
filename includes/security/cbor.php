<?php
namespace GemSecurity\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Minimal CBOR decoder (RFC 8949) — just enough for WebAuthn attestation
 * objects and COSE public keys. Written in plain PHP so passkeys work on
 * PHP 7.4 hosts without GMP or a third-party library.
 *
 * Supported: unsigned/negative integers, byte/text strings, arrays, maps,
 * tags (the tag is dropped), booleans, null/undefined. Indefinite lengths
 * and floats are refused: WebAuthn never uses them.
 */
class Cbor {

	const MAX_DEPTH = 8;

	/**
	 * Decode one CBOR item from the start of $data.
	 *
	 * @param string $data Binary CBOR.
	 * @param int    $offset Start offset; advanced past the decoded item.
	 * @return mixed
	 * @throws \RuntimeException On malformed or unsupported input.
	 */
	public static function decode( $data, &$offset = 0 ) {
		return self::item( $data, $offset, 0 );
	}

	private static function item( $data, &$offset, $depth ) {
		if ( $depth > self::MAX_DEPTH ) {
			throw new \RuntimeException( 'CBOR nested too deeply.' );
		}
		$total = strlen( $data );
		if ( $offset >= $total ) {
			throw new \RuntimeException( 'CBOR truncated.' );
		}
		$initial = ord( $data[ $offset++ ] );
		$major   = $initial >> 5;
		$info    = $initial & 31;

		if ( 7 === $major ) {
			switch ( $info ) {
				case 20:
					return false;
				case 21:
					return true;
				case 22:
				case 23:
					return null;
			}
			throw new \RuntimeException( 'Unsupported CBOR simple value.' );
		}

		$arg = self::argument( $data, $offset, $info );

		switch ( $major ) {
			case 0:
				return $arg;
			case 1:
				return -1 - $arg;
			case 2:
			case 3:
				if ( $arg > $total - $offset ) {
					throw new \RuntimeException( 'CBOR string overruns input.' );
				}
				$str     = substr( $data, $offset, $arg );
				$offset += $arg;
				return $str;
			case 4:
				if ( $arg > $total - $offset ) {
					throw new \RuntimeException( 'CBOR array overruns input.' );
				}
				$out = [];
				for ( $i = 0; $i < $arg; $i++ ) {
					$out[] = self::item( $data, $offset, $depth + 1 );
				}
				return $out;
			case 5:
				if ( $arg > $total - $offset ) {
					throw new \RuntimeException( 'CBOR map overruns input.' );
				}
				$out = [];
				for ( $i = 0; $i < $arg; $i++ ) {
					$key = self::item( $data, $offset, $depth + 1 );
					if ( ! is_int( $key ) && ! is_string( $key ) ) {
						throw new \RuntimeException( 'Unsupported CBOR map key.' );
					}
					$out[ $key ] = self::item( $data, $offset, $depth + 1 );
				}
				return $out;
			case 6:
				return self::item( $data, $offset, $depth + 1 );
		}
		throw new \RuntimeException( 'Unsupported CBOR item.' );
	}

	private static function argument( $data, &$offset, $info ) {
		if ( $info < 24 ) {
			return $info;
		}
		$sizes = [
			24 => 1,
			25 => 2,
			26 => 4,
			27 => 8,
		];
		if ( ! isset( $sizes[ $info ] ) ) {
			throw new \RuntimeException( 'Unsupported CBOR length encoding.' );
		}
		$size = $sizes[ $info ];
		if ( $offset + $size > strlen( $data ) ) {
			throw new \RuntimeException( 'CBOR truncated.' );
		}
		$raw     = substr( $data, $offset, $size );
		$offset += $size;
		switch ( $size ) {
			case 1:
				return ord( $raw );
			case 2:
				return unpack( 'n', $raw )[1];
			case 4:
				return unpack( 'N', $raw )[1];
		}
		$hi = unpack( 'N', substr( $raw, 0, 4 ) )[1];
		$lo = unpack( 'N', substr( $raw, 4, 4 ) )[1];
		if ( $hi > 0x7FFFFFFF ) {
			throw new \RuntimeException( 'CBOR integer too large.' );
		}
		return ( $hi << 32 ) | $lo;
	}
}
