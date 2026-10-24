<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;
use GemSecurity\Security\BanList;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Advanced threat detection layered on top of the auto-ban engine (Pro):
 *  - Behavioral anomaly scoring — heuristic request scoring that flags
 *    zero-day-shaped traffic signature rules miss.
 *  - Credential-stuffing detection — one IP trying many different usernames.
 *  - Live Traffic — a rolling, real-time view of recent requests.
 */
class ThreatIntel {

	const TRAFFIC_OPTION = 'gemsecurity_live_traffic';
	const TRAFFIC_MAX    = 150;

	public static function init() {
		$self = new self();

		if ( Helper::get_setting( 'credential_stuffing_enabled', false ) ) {
			add_action( 'wp_login_failed', [ $self, 'on_login_failed' ], 10, 1 );
		}
		if ( Helper::get_setting( 'anomaly_detection_enabled', false ) ) {
			add_action( 'init', [ $self, 'score_request' ], 2 );
		}
		if ( Helper::get_setting( 'live_traffic_enabled', false ) ) {
			add_action( 'init', [ $self, 'record_traffic' ], 3 );
		}
	}

	private function skip() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) || wp_doing_ajax() ) {
			return true;
		}
		if ( is_admin() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return true;
		}
		return is_user_logged_in() && current_user_can( 'manage_options' );
	}

	/* ---------------- Credential stuffing ---------------- */

	public function on_login_failed( $username ) {
		$ip  = Helper::get_ip_address();
		$key = 'gemsec_cs_' . md5( $ip );
		$set = get_transient( $key );
		$set = is_array( $set ) ? $set : [];
		$set[ strtolower( (string) $username ) ] = 1;
		set_transient( $key, $set, 15 * MINUTE_IN_SECONDS );

		$threshold = max( 2, (int) Helper::get_setting( 'credential_stuffing_threshold', 5 ) );
		if ( count( $set ) >= $threshold ) {
			Logger::log(
				'credential_stuffing',
				sprintf(
					/* translators: 1: ip, 2: count */
					__( 'Credential stuffing from %1$s — %2$d distinct usernames tried.', 'gemsecurity' ),
					$ip,
					count( $set )
				),
				Logger::SEVERITY_CRITICAL,
				[ 'user_id' => 0, 'ip_address' => $ip ]
			);
			if ( class_exists( '\GemSecurity\Security\BanList' ) ) {
				BanList::record_strike( $ip, 'credential stuffing' );
			}
			delete_transient( $key );
		}
	}

	/* ---------------- Behavioral anomaly scoring ---------------- */

	public function score_request() {
		if ( $this->skip() ) {
			return;
		}
		$ua     = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$score  = 0;

		if ( '' === $ua ) {
			$score += 2;
		}
		if ( 'POST' === $method && empty( $_SERVER['HTTP_REFERER'] ) ) {
			$score += 1;
		}
		if ( ( count( $_GET ) + count( $_POST ) ) > 25 ) { // phpcs:ignore WordPress.Security.NonceVerification
			$score += 2;
		}
		if ( preg_match( '/%00|%27|%3C|%3E|\.\.\//i', $uri ) ) {
			$score += 2;
		}
		if ( strlen( $uri ) > 1500 ) {
			$score += 1;
		}

		$threshold = max( 2, (int) Helper::get_setting( 'anomaly_threshold', 4 ) );
		if ( $score < $threshold ) {
			return;
		}

		$ip  = Helper::get_ip_address();
		$key = 'gemsec_anom_' . md5( $ip );
		if ( get_transient( $key ) ) {
			return; // one log per IP per hour.
		}
		set_transient( $key, 1, HOUR_IN_SECONDS );
		Logger::log(
			'anomaly_detected',
			sprintf(
				/* translators: 1: score, 2: ip */
				__( 'Behavioral anomaly (score %1$d) from %2$s.', 'gemsecurity' ),
				$score,
				$ip
			),
			Logger::SEVERITY_WARNING,
			[ 'user_id' => 0, 'ip_address' => $ip, 'context' => [ 'score' => $score, 'ua' => substr( $ua, 0, 200 ) ] ]
		);
	}

	/* ---------------- Live traffic ---------------- */

	public function record_traffic() {
		if ( $this->skip() ) {
			return;
		}
		$log = get_option( self::TRAFFIC_OPTION, [] );
		$log = is_array( $log ) ? $log : [];
		array_unshift( $log, [
			'time'   => gmdate( 'H:i:s' ),
			'ip'     => Helper::get_ip_address(),
			'method' => isset( $_SERVER['REQUEST_METHOD'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ), 0, 8 ) : '',
			'uri'    => isset( $_SERVER['REQUEST_URI'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), 0, 200 ) : '',
			'ua'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 160 ) : '',
		] );
		update_option( self::TRAFFIC_OPTION, array_slice( $log, 0, self::TRAFFIC_MAX ), false );
	}

	/** REST: GET /live-traffic */
	public static function rest_traffic() {
		$log = get_option( self::TRAFFIC_OPTION, [] );
		return rest_ensure_response( [ 'success' => true, 'items' => is_array( $log ) ? $log : [] ] );
	}
}
