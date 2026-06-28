<?php
namespace GemSecurity\Security;

use GemSecurity\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * IP → country resolver.
 *
 * Self-contained, no external libraries and no dependency on other plugins:
 *   1. CDN / proxy country headers (free, instant).
 *   2. 24h per-IP transient cache.
 *   3. Free IP-geolocation API (fail-open — never blocks login on an outage).
 *
 * Returns uppercase ISO-3166-1 alpha-2 codes, or '' when the country is
 * unknown (private/reserved IP, localhost, or lookup failure).
 */
class Geo {

	const CACHE_PREFIX = 'gemsec_geo_';
	const CACHE_TTL    = DAY_IN_SECONDS;

	/** Country headers injected by common CDNs / reverse proxies. */
	private static function country_headers() {
		return [
			'HTTP_CF_IPCOUNTRY',              // Cloudflare
			'HTTP_CLOUDFRONT_VIEWER_COUNTRY', // AWS CloudFront
			'HTTP_X_COUNTRY_CODE',
			'HTTP_GEOIP_COUNTRY_CODE',
			'GEOIP_COUNTRY_CODE',
			'MM_COUNTRY_CODE',
		];
	}

	/**
	 * Country for the current visitor.
	 *
	 * @return string Uppercase ISO code, or '' if unknown.
	 */
	public static function current_country() {
		return self::country_for_ip( Helper::get_ip_address() );
	}

	/**
	 * Resolve a country code for an IP address.
	 *
	 * @param string $ip
	 * @return string
	 */
	public static function country_for_ip( $ip ) {
		// Headers can be present even for otherwise un-geolocatable setups.
		$header = self::from_headers();
		if ( '' !== $header ) {
			return $header;
		}

		if ( ! $ip || '0.0.0.0' === $ip || self::is_private_ip( $ip ) ) {
			return '';
		}

		$key    = self::CACHE_PREFIX . md5( $ip );
		$cached = get_transient( $key );
		if ( false !== $cached ) {
			return is_string( $cached ) ? $cached : '';
		}

		$country = self::from_api( $ip );

		// Cache successes for 24h; cache misses briefly to avoid hammering.
		set_transient( $key, $country, '' !== $country ? self::CACHE_TTL : 10 * MINUTE_IN_SECONDS );

		return $country;
	}

	/**
	 * @return string Country from a CDN/proxy header, or ''.
	 */
	private static function from_headers() {
		foreach ( self::country_headers() as $key ) {
			if ( empty( $_SERVER[ $key ] ) ) {
				continue;
			}
			$code = strtoupper( substr( trim( sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) ), 0, 2 ) );
			if ( self::is_valid_code( $code ) ) {
				return $code;
			}
		}
		return '';
	}

	/**
	 * Query a free IP-geolocation API. Fail-open (returns '' on any error).
	 *
	 * @param string $ip
	 * @return string
	 */
	private static function from_api( $ip ) {
		$endpoints = [
			'http://ip-api.com/json/' . rawurlencode( $ip ) . '?fields=status,countryCode',
			'https://ipapi.co/' . rawurlencode( $ip ) . '/country/',
		];

		/**
		 * Filter the geolocation API endpoints (allows pointing at a paid/self-hosted service).
		 *
		 * @param string[] $endpoints
		 * @param string   $ip
		 */
		$endpoints = apply_filters( 'gemsecurity/geo_api_endpoints', $endpoints, $ip );

		foreach ( $endpoints as $url ) {
			$response = wp_remote_get( $url, [ 'timeout' => 3, 'headers' => [ 'Accept' => 'application/json' ] ] );
			if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
				continue;
			}
			$body = trim( wp_remote_retrieve_body( $response ) );
			$code = '';

			$json = json_decode( $body, true );
			if ( is_array( $json ) ) {
				if ( isset( $json['status'] ) && 'success' !== $json['status'] ) {
					continue;
				}
				$code = $json['countryCode'] ?? ( $json['country_code'] ?? ( $json['country'] ?? '' ) );
			} else {
				// Plain-text "US" style response (ipapi.co/{ip}/country/).
				$code = $body;
			}

			$code = strtoupper( substr( trim( (string) $code ), 0, 2 ) );
			if ( self::is_valid_code( $code ) ) {
				return $code;
			}
		}

		return '';
	}

	/**
	 * @param string $code
	 * @return bool
	 */
	public static function is_valid_code( $code ) {
		return (bool) preg_match( '/^[A-Z]{2}$/', $code ) && ! in_array( $code, [ 'XX', 'T1', 'ZZ' ], true );
	}

	/**
	 * @param string $ip
	 * @return bool True for private / reserved ranges (no public geolocation).
	 */
	public static function is_private_ip( $ip ) {
		return ! filter_var(
			$ip,
			FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
		);
	}

	/**
	 * Emergency kill-switch: define('GEMSEC_GEO_DISABLE', true) in wp-config.php.
	 *
	 * @return bool
	 */
	public static function is_bypassed() {
		return defined( 'GEMSEC_GEO_DISABLE' ) && GEMSEC_GEO_DISABLE;
	}
}
