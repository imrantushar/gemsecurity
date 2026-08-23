<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Mailer;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Monitoring (Pro): early-warning signals that live outside the plugin's normal
 * request path — TLS certificate expiry, DNS record changes (a hijack/defacement
 * signal), site reachability, and email-authentication (SPF/DKIM/DMARC) health.
 */
class Monitoring {

	const RESULT_OPTION = 'gemsecurity_monitoring';
	const DNS_OPTION    = 'gemsecurity_monitoring_dns';

	public static function init() {
		add_action( \GemSecurity\Installer::CRON_DAILY_SCAN, [ __CLASS__, 'run_and_alert' ] );
	}

	/** Host of the site. */
	private static function host() {
		return (string) wp_parse_url( home_url(), PHP_URL_HOST );
	}

	/**
	 * Run all checks (cached ~1h for the UI).
	 *
	 * @param bool $fresh
	 * @return array
	 */
	public static function run( $fresh = false ) {
		if ( ! $fresh ) {
			$cached = get_transient( self::RESULT_OPTION );
			if ( is_array( $cached ) ) {
				return $cached;
			}
		}

		$result = [
			'checked' => gmdate( 'Y-m-d H:i:s' ),
			'health'  => self::check_health(),
			'ssl'     => self::check_ssl(),
			'dns'     => self::check_dns(),
			'email'   => self::check_email(),
		];
		set_transient( self::RESULT_OPTION, $result, HOUR_IN_SECONDS );
		update_option( self::RESULT_OPTION, $result, false );
		return $result;
	}

	/** Reachability of the home URL. */
	private static function check_health() {
		$res = wp_remote_get( home_url( '/' ), [ 'timeout' => 5, 'sslverify' => false, 'redirection' => 2 ] );
		if ( is_wp_error( $res ) ) {
			return [ 'up' => false, 'code' => 0, 'note' => $res->get_error_message() ];
		}
		$code = (int) wp_remote_retrieve_response_code( $res );
		return [ 'up' => ( $code >= 200 && $code < 500 ), 'code' => $code, 'note' => '' ];
	}

	/** TLS certificate expiry. */
	private static function check_ssl() {
		$host = self::host();
		if ( ! function_exists( 'stream_socket_client' ) || ! function_exists( 'openssl_x509_parse' ) ) {
			return [ 'supported' => false ];
		}
		$ctx    = stream_context_create( [ 'ssl' => [ 'capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false ] ] );
		$client = @stream_socket_client( "ssl://{$host}:443", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ctx ); // phpcs:ignore
		if ( ! $client ) {
			return [ 'supported' => true, 'valid' => false, 'note' => $errstr ?: __( 'Could not connect over TLS.', 'gemsecurity' ) ];
		}
		$params = stream_context_get_params( $client );
		fclose( $client );
		if ( empty( $params['options']['ssl']['peer_certificate'] ) ) {
			return [ 'supported' => true, 'valid' => false, 'note' => __( 'No certificate presented.', 'gemsecurity' ) ];
		}
		$cert = openssl_x509_parse( $params['options']['ssl']['peer_certificate'] );
		$exp  = isset( $cert['validTo_time_t'] ) ? (int) $cert['validTo_time_t'] : 0;
		$days = $exp ? (int) floor( ( $exp - time() ) / DAY_IN_SECONDS ) : null;
		return [
			'supported'   => true,
			'valid'       => true,
			'expires'     => $exp ? gmdate( 'Y-m-d', $exp ) : '',
			'days_left'   => $days,
			'issuer'      => isset( $cert['issuer']['O'] ) ? $cert['issuer']['O'] : '',
		];
	}

	/** Detect changes to the domain's A record. */
	private static function check_dns() {
		$host = self::host();
		$ip   = @gethostbyname( $host ); // phpcs:ignore
		if ( $ip === $host ) {
			return [ 'supported' => false ];
		}
		$baseline = get_option( self::DNS_OPTION, '' );
		$changed  = ( '' !== $baseline && $baseline !== $ip );
		if ( '' === $baseline ) {
			update_option( self::DNS_OPTION, $ip, false );
		}
		return [ 'supported' => true, 'ip' => $ip, 'baseline' => $baseline ?: $ip, 'changed' => $changed ];
	}

	/** SPF / DMARC presence (DKIM is selector-specific, so noted only). */
	private static function check_email() {
		$host = self::host();
		// Strip a leading www for the organisational domain.
		$domain = preg_replace( '/^www\./', '', $host );
		if ( ! function_exists( 'dns_get_record' ) ) {
			return [ 'supported' => false ];
		}
		$spf = false;
		foreach ( (array) @dns_get_record( $domain, DNS_TXT ) as $rec ) { // phpcs:ignore
			if ( isset( $rec['txt'] ) && 0 === stripos( $rec['txt'], 'v=spf1' ) ) {
				$spf = true;
				break;
			}
		}
		$dmarc = '';
		foreach ( (array) @dns_get_record( '_dmarc.' . $domain, DNS_TXT ) as $rec ) { // phpcs:ignore
			if ( isset( $rec['txt'] ) && false !== stripos( $rec['txt'], 'v=DMARC1' ) ) {
				$dmarc = $rec['txt'];
				break;
			}
		}
		$policy = '';
		if ( $dmarc && preg_match( '/p=(\w+)/i', $dmarc, $m ) ) {
			$policy = strtolower( $m[1] );
		}
		return [ 'supported' => true, 'domain' => $domain, 'spf' => $spf, 'dmarc' => (bool) $dmarc, 'dmarc_policy' => $policy ];
	}

	/** Daily cron: run checks and alert on the important negatives. */
	public static function run_and_alert() {
		if ( ! Helper::get_setting( 'monitoring_enabled', false ) ) {
			return;
		}
		$r = self::run( true );

		$alerts = [];
		if ( isset( $r['ssl']['days_left'] ) && null !== $r['ssl']['days_left'] && $r['ssl']['days_left'] <= 14 ) {
			$alerts[] = sprintf( /* translators: %d days */ __( 'TLS certificate expires in %d days.', 'gemsecurity' ), $r['ssl']['days_left'] );
		}
		if ( ! empty( $r['dns']['changed'] ) ) {
			$alerts[] = __( 'The site’s DNS A record changed.', 'gemsecurity' );
		}
		if ( ! empty( $r['health'] ) && empty( $r['health']['up'] ) ) {
			$alerts[] = __( 'The site appears to be down.', 'gemsecurity' );
		}

		foreach ( $alerts as $a ) {
			Logger::log( 'monitoring_alert', $a, Logger::SEVERITY_WARNING, [ 'user_id' => 0 ] );
		}
		if ( $alerts ) {
			$to = \GemSecurity\Mailer::recipient();
			Mailer::send(
				$to,
				'📡',
				__( 'Monitoring alert', 'gemsecurity' ),
				[
					[
						'type'    => 'list',
						'heading' => __( 'What changed', 'gemsecurity' ),
						'items'   => array_map( 'esc_html', $alerts ),
					],
					[
						'type'  => 'button',
						'url'   => admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG . '-monitoring' ),
						'label' => __( 'Open Monitoring', 'gemsecurity' ),
					],
				]
			);
		}
	}

	/** REST: GET /monitoring */
	public static function rest( $req ) {
		$fresh = rest_sanitize_boolean( $req->get_param( 'fresh' ) );
		return rest_ensure_response( [ 'success' => true, 'data' => self::run( $fresh ) ] );
	}
}
