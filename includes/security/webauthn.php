<?php
namespace GemSecurity\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WebAuthn / passkey ceremony verification.
 *
 * Pure verification logic with no WordPress state, so it can be unit-tested
 * against known vectors. Supports ES256 (-7) and RS256 (-257) credentials via
 * OpenSSL. Attestation is accepted as "none": passkeys are verified by the
 * signatures they produce at sign-in, not by who made the authenticator.
 *
 * Every failure throws \RuntimeException with a message safe to log (never
 * shown to the visitor verbatim).
 */
class Webauthn {

	const FLAG_UP = 0x01;
	const FLAG_UV = 0x04;
	const FLAG_BE = 0x08;
	const FLAG_BS = 0x10;
	const FLAG_AT = 0x40;

	const ALG_ES256 = -7;
	const ALG_RS256 = -257;

	/* ---------------------------- Encoding ---------------------------- */

	public static function b64u_encode( $bin ) {
		return rtrim( strtr( base64_encode( $bin ), '+/', '-_' ), '=' );
	}

	public static function b64u_decode( $str ) {
		$str = (string) $str;
		if ( '' === $str || ! preg_match( '/^[A-Za-z0-9_-]+$/', $str ) ) {
			return false;
		}
		$pad = strlen( $str ) % 4;
		if ( $pad ) {
			$str .= str_repeat( '=', 4 - $pad );
		}
		return base64_decode( strtr( $str, '-_', '+/' ), true );
	}

	public static function random_challenge() {
		return random_bytes( 32 );
	}

	/* --------------------------- Registration ------------------------- */

	/**
	 * Verify a navigator.credentials.create() response.
	 *
	 * @param string $client_data_json Raw clientDataJSON bytes.
	 * @param string $attestation_object Raw attestationObject bytes.
	 * @param string $challenge Raw challenge issued for this ceremony.
	 * @param array  $origins Allowed origins.
	 * @param string $rp_id Relying party id.
	 * @param bool   $require_uv Whether user verification must have happened.
	 * @return array { credential_id (raw), public_key_pem, alg, sign_count, aaguid, flags, backup_eligible, backed_up, user_verified }
	 */
	public static function verify_registration( $client_data_json, $attestation_object, $challenge, array $origins, $rp_id, $require_uv = false ) {
		self::check_client_data( $client_data_json, 'webauthn.create', $challenge, $origins );

		try {
			$att = Cbor::decode( $attestation_object );
		} catch ( \RuntimeException $e ) {
			throw new \RuntimeException( 'Attestation object is not valid CBOR: ' . $e->getMessage() );
		}
		if ( ! is_array( $att ) || empty( $att['authData'] ) || ! is_string( $att['authData'] ) ) {
			throw new \RuntimeException( 'Attestation object has no authData.' );
		}

		$auth = self::parse_auth_data( $att['authData'], true );
		self::check_rp( $auth, $rp_id );
		if ( ! ( $auth['flags'] & self::FLAG_UP ) ) {
			throw new \RuntimeException( 'User presence flag not set.' );
		}
		if ( $require_uv && ! ( $auth['flags'] & self::FLAG_UV ) ) {
			throw new \RuntimeException( 'User verification required but not performed.' );
		}
		if ( empty( $auth['credential_id'] ) ) {
			throw new \RuntimeException( 'No credential in authData.' );
		}

		$cose = $auth['cose'];
		$alg  = isset( $cose[3] ) ? (int) $cose[3] : 0;
		$pem  = self::cose_to_pem( $cose );

		return [
			'credential_id'   => $auth['credential_id'],
			'public_key_pem'  => $pem,
			'alg'             => $alg,
			'sign_count'      => $auth['sign_count'],
			'aaguid'          => $auth['aaguid'],
			'flags'           => $auth['flags'],
			'backup_eligible' => (bool) ( $auth['flags'] & self::FLAG_BE ),
			'backed_up'       => (bool) ( $auth['flags'] & self::FLAG_BS ),
			'user_verified'   => (bool) ( $auth['flags'] & self::FLAG_UV ),
		];
	}

	/* ---------------------------- Assertion --------------------------- */

	/**
	 * Verify a navigator.credentials.get() response.
	 *
	 * @param string $client_data_json Raw clientDataJSON bytes.
	 * @param string $auth_data Raw authenticatorData bytes.
	 * @param string $signature Raw signature bytes.
	 * @param string $public_key_pem Stored public key.
	 * @param int    $alg COSE algorithm.
	 * @param string $challenge Raw challenge issued for this ceremony.
	 * @param array  $origins Allowed origins.
	 * @param string $rp_id Relying party id.
	 * @param bool   $require_uv Whether user verification must have happened.
	 * @return array { flags, sign_count, user_verified, backed_up }
	 */
	public static function verify_assertion( $client_data_json, $auth_data, $signature, $public_key_pem, $alg, $challenge, array $origins, $rp_id, $require_uv = true ) {
		self::check_client_data( $client_data_json, 'webauthn.get', $challenge, $origins );

		$auth = self::parse_auth_data( $auth_data, false );
		self::check_rp( $auth, $rp_id );
		if ( ! ( $auth['flags'] & self::FLAG_UP ) ) {
			throw new \RuntimeException( 'User presence flag not set.' );
		}
		if ( $require_uv && ! ( $auth['flags'] & self::FLAG_UV ) ) {
			throw new \RuntimeException( 'User verification required but not performed.' );
		}

		if ( self::ALG_ES256 !== (int) $alg && self::ALG_RS256 !== (int) $alg ) {
			throw new \RuntimeException( 'Unsupported credential algorithm.' );
		}
		$key = openssl_pkey_get_public( $public_key_pem );
		if ( ! $key ) {
			throw new \RuntimeException( 'Stored public key is unreadable.' );
		}
		$signed = $auth_data . hash( 'sha256', $client_data_json, true );
		if ( 1 !== openssl_verify( $signed, $signature, $key, OPENSSL_ALGO_SHA256 ) ) {
			throw new \RuntimeException( 'Signature check failed.' );
		}

		return [
			'flags'         => $auth['flags'],
			'sign_count'    => $auth['sign_count'],
			'user_verified' => (bool) ( $auth['flags'] & self::FLAG_UV ),
			'backed_up'     => (bool) ( $auth['flags'] & self::FLAG_BS ),
		];
	}

	/* ----------------------------- Internals -------------------------- */

	private static function check_client_data( $client_data_json, $type, $challenge, array $origins ) {
		$data = json_decode( $client_data_json, true );
		if ( ! is_array( $data ) ) {
			throw new \RuntimeException( 'clientDataJSON is not valid JSON.' );
		}
		if ( ! isset( $data['type'] ) || $type !== $data['type'] ) {
			throw new \RuntimeException( 'Wrong ceremony type.' );
		}
		if ( ! isset( $data['challenge'] ) || ! is_string( $data['challenge'] ) || ! hash_equals( self::b64u_encode( $challenge ), $data['challenge'] ) ) {
			throw new \RuntimeException( 'Challenge mismatch.' );
		}
		if ( ! isset( $data['origin'] ) || ! in_array( $data['origin'], $origins, true ) ) {
			throw new \RuntimeException( 'Origin not allowed: ' . ( isset( $data['origin'] ) && is_string( $data['origin'] ) ? substr( $data['origin'], 0, 100 ) : '' ) );
		}
		if ( ! empty( $data['crossOrigin'] ) ) {
			throw new \RuntimeException( 'Cross-origin ceremonies are not allowed.' );
		}
	}

	private static function check_rp( array $auth, $rp_id ) {
		if ( ! hash_equals( hash( 'sha256', $rp_id, true ), $auth['rp_id_hash'] ) ) {
			throw new \RuntimeException( 'RP ID hash mismatch.' );
		}
	}

	/**
	 * Parse authenticator data.
	 *
	 * @param string $bin Raw authData.
	 * @param bool   $expect_credential Whether attested credential data must be present.
	 * @return array
	 */
	public static function parse_auth_data( $bin, $expect_credential ) {
		if ( strlen( $bin ) < 37 ) {
			throw new \RuntimeException( 'authData too short.' );
		}
		$flags = ord( $bin[32] );
		$out   = [
			'rp_id_hash'    => substr( $bin, 0, 32 ),
			'flags'         => $flags,
			'sign_count'    => unpack( 'N', substr( $bin, 33, 4 ) )[1],
			'aaguid'        => '',
			'credential_id' => '',
			'cose'          => [],
		];

		if ( $flags & self::FLAG_AT ) {
			if ( strlen( $bin ) < 55 ) {
				throw new \RuntimeException( 'Attested credential data truncated.' );
			}
			$aaguid_hex      = bin2hex( substr( $bin, 37, 16 ) );
			$out['aaguid']   = sprintf(
				'%s-%s-%s-%s-%s',
				substr( $aaguid_hex, 0, 8 ),
				substr( $aaguid_hex, 8, 4 ),
				substr( $aaguid_hex, 12, 4 ),
				substr( $aaguid_hex, 16, 4 ),
				substr( $aaguid_hex, 20, 12 )
			);
			$id_len = unpack( 'n', substr( $bin, 53, 2 ) )[1];
			if ( $id_len < 1 || $id_len > 1023 || strlen( $bin ) < 55 + $id_len ) {
				throw new \RuntimeException( 'Credential id length invalid.' );
			}
			$out['credential_id'] = substr( $bin, 55, $id_len );
			$offset               = 55 + $id_len;
			try {
				$cose = Cbor::decode( $bin, $offset );
			} catch ( \RuntimeException $e ) {
				throw new \RuntimeException( 'Credential public key is not valid CBOR.' );
			}
			if ( ! is_array( $cose ) ) {
				throw new \RuntimeException( 'Credential public key malformed.' );
			}
			$out['cose'] = $cose;
		} elseif ( $expect_credential ) {
			throw new \RuntimeException( 'No attested credential data.' );
		}
		return $out;
	}

	/**
	 * Convert a COSE_Key (EC2 P-256 or RSA) to a PEM SubjectPublicKeyInfo.
	 *
	 * @param array $cose Decoded COSE key map.
	 * @return string
	 */
	public static function cose_to_pem( array $cose ) {
		$kty = isset( $cose[1] ) ? (int) $cose[1] : 0;
		$alg = isset( $cose[3] ) ? (int) $cose[3] : 0;

		if ( 2 === $kty && self::ALG_ES256 === $alg ) {
			if ( ! isset( $cose[-1], $cose[-2], $cose[-3] ) || 1 !== (int) $cose[-1] ) {
				throw new \RuntimeException( 'Only P-256 EC keys are supported.' );
			}
			$x = $cose[-2];
			$y = $cose[-3];
			if ( ! is_string( $x ) || ! is_string( $y ) || 32 !== strlen( $x ) || 32 !== strlen( $y ) ) {
				throw new \RuntimeException( 'EC key coordinates malformed.' );
			}
			$der = hex2bin( '3059301306072a8648ce3d020106082a8648ce3d030107034200' ) . "\x04" . $x . $y;
			return self::pem( $der );
		}

		if ( 3 === $kty && self::ALG_RS256 === $alg ) {
			if ( ! isset( $cose[-1], $cose[-2] ) || ! is_string( $cose[-1] ) || ! is_string( $cose[-2] ) ) {
				throw new \RuntimeException( 'RSA key malformed.' );
			}
			if ( strlen( $cose[-1] ) < 256 ) {
				throw new \RuntimeException( 'RSA key too small.' );
			}
			$rsa_key = self::der( 0x30, self::der_int( $cose[-1] ) . self::der_int( $cose[-2] ) );
			$bits    = self::der( 0x03, "\x00" . $rsa_key );
			$algid   = hex2bin( '300d06092a864886f70d0101010500' );
			return self::pem( self::der( 0x30, $algid . $bits ) );
		}

		throw new \RuntimeException( 'Unsupported credential algorithm.' );
	}

	private static function der( $tag, $content ) {
		$len = strlen( $content );
		if ( $len < 128 ) {
			$l = chr( $len );
		} else {
			$bytes = ltrim( pack( 'N', $len ), "\x00" );
			$l     = chr( 0x80 | strlen( $bytes ) ) . $bytes;
		}
		return chr( $tag ) . $l . $content;
	}

	private static function der_int( $bin ) {
		$bin = ltrim( $bin, "\x00" );
		if ( '' === $bin || ord( $bin[0] ) > 0x7F ) {
			$bin = "\x00" . $bin;
		}
		return self::der( 0x02, $bin );
	}

	private static function pem( $der ) {
		return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
	}
}
