<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Real-time alerts and the weekly security digest.
 *
 * Listens on the central `gemsecurity/event_logged` action and forwards
 * qualifying events to every enabled channel: email first, then the fast
 * channels (Slack, Telegram, generic webhook) which are fire-and-forget.
 *
 * Email used to be missing here even though the settings screen offered an
 * alert address and a "send a test email" button next to the master switch —
 * so a site configured for email alerts received none of them.
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

		$this->email( $event_type, $message, $severity, $args );
		$this->dispatch( $text );
	}

	/**
	 * Email one alert to the site's security address.
	 *
	 * @param string $event_type
	 * @param string $message
	 * @param string $severity
	 * @param array  $args
	 * @return void
	 */
	private function email( $event_type, $message, $severity, $args = [] ) {
		$emoji = ( 'critical' === $severity ) ? '🚨' : '⚠️';
		$rows  = [
			[ __( 'Event', 'gemsecurity' ), $event_type ],
			[ __( 'Severity', 'gemsecurity' ), ucfirst( $severity ) ],
			[ __( 'Time', 'gemsecurity' ), wp_date( 'F j, Y \a\t g:i a' ) ],
		];

		$ip = isset( $args['ip'] ) ? $args['ip'] : \GemSecurity\Helper::get_ip_address();
		if ( $ip ) {
			$rows[] = [ __( 'IP address', 'gemsecurity' ), $ip ];
		}

		\GemSecurity\Mailer::send(
			\GemSecurity\Mailer::recipient(),
			$emoji,
			sprintf(
				/* translators: %s: severity, e.g. Critical. */
				__( '%s security alert', 'gemsecurity' ),
				ucfirst( $severity )
			),
			[
				[
					'type' => 'notice',
					'tone' => ( 'critical' === $severity ) ? 'critical' : 'warning',
					'text' => $message,
				],
				[
					'type'    => 'table',
					'heading' => __( 'Details', 'gemsecurity' ),
					'rows'    => $rows,
				],
				[
					'type'  => 'button',
					'url'   => admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG . '-logs' ),
					'label' => __( 'Open the activity log', 'gemsecurity' ),
				],
			]
		);
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
			/* translators: %s: site name. */
			sprintf( __( 'GemSecurity weekly report for %s', 'gemsecurity' ), $site ),
			'',
			/* translators: %d: number of critical events in the past week. */
			sprintf( __( 'Critical events: %d', 'gemsecurity' ), $by_sev['critical'] ?? 0 ),
			/* translators: %d: number of warning events in the past week. */
			sprintf( __( 'Warnings:        %d', 'gemsecurity' ), $by_sev['warning'] ?? 0 ),
			/* translators: %d: number of notice events in the past week. */
			sprintf( __( 'Notices:         %d', 'gemsecurity' ), $by_sev['notice'] ?? 0 ),
			/* translators: %d: number of currently-active IP bans. */
			sprintf( __( 'Active IP bans:  %d', 'gemsecurity' ), \GemSecurity\Security\BanList::count_active() ),
		];
		$vuln = \GemSecurity\Security\Vulnerability::get_last_result();
		if ( is_array( $vuln ) ) {
			/* translators: %d: number of known vulnerabilities across installed plugins and themes. */
			$lines[] = sprintf( __( 'Known vulnerabilities: %d', 'gemsecurity' ), (int) $vuln['count'] );
		}
		$body = implode( "\n", $lines );

		\GemSecurity\Mailer::send(
			\GemSecurity\Mailer::recipient(),
			'📊',
			__( 'Weekly security report', 'gemsecurity' ),
			[
				[
					'type'  => 'stats',
					'items' => [
						__( 'Critical', 'gemsecurity' ) => $by_sev['critical'] ?? 0,
						__( 'Warnings', 'gemsecurity' ) => $by_sev['warning'] ?? 0,
						__( 'Notices', 'gemsecurity' )  => $by_sev['notice'] ?? 0,
						__( 'IP bans', 'gemsecurity' )  => \GemSecurity\Security\BanList::count_active(),
					],
				],
				[
					'type'    => 'list',
					'heading' => __( 'The last 7 days', 'gemsecurity' ),
					'items'   => array_map( 'esc_html', array_slice( $lines, 2 ) ),
				],
				[
					'type'  => 'button',
					'url'   => admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG . '-logs' ),
					'label' => __( 'Open the activity log', 'gemsecurity' ),
				],
			],
			[ 'intro' => __( 'A summary of everything GemSecurity recorded over the last seven days.', 'gemsecurity' ) ]
		);

		if ( Helper::get_setting( 'alerts_enabled', false ) ) {
			$this->dispatch( $body );
		}
	}
}
