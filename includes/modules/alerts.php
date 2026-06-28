<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Real-time alert channels (Slack, Telegram, generic webhook) and a weekly
 * security digest. Listens on the central `gemsecurity/event_logged` action and
 * forwards qualifying events to the enabled channels (non-blocking, debounced).
 */
class Alerts {

	const SEVERITY_RANK = [ 'info' => 0, 'notice' => 1, 'warning' => 2, 'critical' => 3 ];

	public static function init() {
		$self = new self();
		if ( Helper::get_setting( 'alerts_enabled', false ) ) {
			add_action( 'gemsecurity/event_logged', [ $self, 'on_event' ], 10, 4 );
		}
		add_action( 'gemsecurity_weekly_digest', [ $self, 'send_digest' ] );
	}

	/**
	 * @param string $event_type
	 * @param string $message
	 * @param string $severity
	 * @param array  $args
	 */
	public function on_event( $event_type, $message, $severity, $args ) {
		$min  = Helper::get_setting( 'alert_min_severity', 'critical' );
		$rank = self::SEVERITY_RANK;
		if ( ( $rank[ $severity ] ?? 0 ) < ( $rank[ $min ] ?? 3 ) ) {
			return;
		}

		// Debounce: at most one alert per event type per 5 minutes.
		$key = 'gemsec_alert_' . md5( $event_type );
		if ( get_transient( $key ) ) {
			return;
		}
		set_transient( $key, 1, 5 * MINUTE_IN_SECONDS );

		$site = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
		$text = sprintf( '[%s] %s: %s', $site, strtoupper( $severity ), $message );
		$this->dispatch( $text );
	}

	/**
	 * Send a text payload to every configured channel (fire-and-forget).
	 *
	 * @param string $text
	 */
	public function dispatch( $text ) {
		$slack = trim( (string) Helper::get_setting( 'alert_slack_webhook', '' ) );
		if ( $slack ) {
			wp_remote_post( $slack, [
				'blocking' => false,
				'timeout'  => 5,
				'headers'  => [ 'Content-Type' => 'application/json' ],
				'body'     => wp_json_encode( [ 'text' => $text ] ),
			] );
		}

		$tg_token = trim( (string) Helper::get_setting( 'alert_telegram_token', '' ) );
		$tg_chat  = trim( (string) Helper::get_setting( 'alert_telegram_chat', '' ) );
		if ( $tg_token && $tg_chat ) {
			wp_remote_post( "https://api.telegram.org/bot{$tg_token}/sendMessage", [
				'blocking' => false,
				'timeout'  => 5,
				'body'     => [ 'chat_id' => $tg_chat, 'text' => $text ],
			] );
		}

		$webhook = trim( (string) Helper::get_setting( 'alert_webhook_url', '' ) );
		if ( $webhook ) {
			wp_remote_post( $webhook, [
				'blocking' => false,
				'timeout'  => 5,
				'headers'  => [ 'Content-Type' => 'application/json' ],
				'body'     => wp_json_encode( [ 'site' => home_url(), 'message' => $text ] ),
			] );
		}
	}

	/**
	 * Weekly digest: summarise the last 7 days and send by email + channels.
	 */
	public function send_digest() {
		if ( ! Helper::get_setting( 'digest_enabled', false ) ) {
			return;
		}
		global $wpdb;
		$table = $wpdb->prefix . 'gemsecurity_logs';
		$since = gmdate( 'Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS );

		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT severity, COUNT(*) c FROM {$table} WHERE created_at >= %s GROUP BY severity", $since ),
			ARRAY_A
		);
		$by_sev = [];
		foreach ( (array) $rows as $r ) {
			$by_sev[ $r['severity'] ] = (int) $r['c'];
		}

		$site  = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
		$lines = [
			sprintf( __( 'GemSecurity weekly report for %s', 'gemsecurity' ), $site ),
			'',
			sprintf( __( 'Critical events: %d', 'gemsecurity' ), $by_sev['critical'] ?? 0 ),
			sprintf( __( 'Warnings:        %d', 'gemsecurity' ), $by_sev['warning'] ?? 0 ),
			sprintf( __( 'Notices:         %d', 'gemsecurity' ), $by_sev['notice'] ?? 0 ),
			sprintf( __( 'Active IP bans:  %d', 'gemsecurity' ), \GemSecurity\Security\BanList::count_active() ),
		];
		$vuln = \GemSecurity\Security\Vulnerability::get_last_result();
		if ( is_array( $vuln ) ) {
			$lines[] = sprintf( __( 'Known vulnerabilities: %d', 'gemsecurity' ), (int) $vuln['count'] );
		}
		$body = implode( "\n", $lines );

		$to = trim( (string) Helper::get_setting( 'alert_to_email', '' ) ) ?: get_option( 'admin_email' );
		wp_mail( $to, sprintf( __( '[%s] Weekly security report', 'gemsecurity' ), $site ), $body );

		if ( Helper::get_setting( 'alerts_enabled', false ) ) {
			$this->dispatch( $body );
		}
	}
}
