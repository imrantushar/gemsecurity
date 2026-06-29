<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;
use GemSecurity\Security\BanList;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Web Application Firewall.
 *
 * Always enforces the IP ban ledger; the remaining protections (malicious
 * request patterns, rate limiting, 404 throttling, bad-bot blocking) are each
 * individually toggleable and feed the escalating auto-ban engine. Logged-in
 * administrators are always exempt.
 */
class Waf {

	public static function init() {
		$self = new self();
		add_action( 'init', [ $self, 'protect' ], 1 );
		if ( Helper::get_setting( 'throttle_404_enabled', false ) ) {
			add_action( 'template_redirect', [ $self, 'watch_404' ] );
		}
	}

	public function protect() {
		// Never firewall CLI / cron contexts.
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}
		$ip = Helper::get_ip_address();
		if ( '0.0.0.0' === $ip ) {
			return;
		}
		// Administrators are never firewalled.
		if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
			return;
		}

		// 1. Existing ban (always enforced).
		if ( BanList::is_banned( $ip ) ) {
			$this->deny( __( 'Your access has been temporarily blocked.', 'gemsecurity' ) );
		}

		// 2. Bad / malicious bots.
		if ( Helper::get_setting( 'block_bad_bots', false ) ) {
			$bot = $this->is_bad_bot();
			if ( $bot ) {
				Logger::log(
					'waf_bad_bot',
					sprintf( 'Blocked malicious user-agent from %s.', $ip ),
					Logger::SEVERITY_WARNING,
					[
						'user_id'    => 0,
						'ip_address' => $ip,
						'context'    => [
							'ua'      => $bot['ua'],
							'matched' => $bot['matched'],
						],
					]
				);
				BanList::record_strike( $ip, 'bad bot' );
				$this->deny( __( 'Access denied.', 'gemsecurity' ) );
			}
		}

		// 3. Rate limiting.
		if ( Helper::get_setting( 'rate_limit_enabled', false ) && $this->rate_limited( $ip ) ) {
			Logger::log( 'waf_rate_limited', sprintf( 'Rate limit exceeded by %s.', $ip ), Logger::SEVERITY_WARNING, [ 'user_id' => 0, 'ip_address' => $ip ] );
			BanList::record_strike( $ip, 'rate limit' );
			$this->deny( __( 'Too many requests. Please slow down.', 'gemsecurity' ), 429 );
		}

		// 4. Malicious request inspection (front-end / login only — avoids admin & REST false positives).
		if (
			Helper::get_setting( 'waf_enabled', false ) &&
			! is_admin() &&
			! ( defined( 'REST_REQUEST' ) && REST_REQUEST ) &&
			! wp_doing_ajax()
		) {
			$hit = $this->inspect();
			if ( $hit ) {
				Logger::log(
					'waf_block',
					sprintf( 'Blocked %s attempt from %s.', strtoupper( $hit['type'] ), $ip ),
					Logger::SEVERITY_CRITICAL,
					[ 'user_id' => 0, 'ip_address' => $ip, 'context' => [ 'rule' => $hit['type'], 'match' => substr( $hit['value'], 0, 200 ) ] ]
				);
				BanList::record_strike( $ip, 'waf:' . $hit['type'] );
				$this->deny( __( 'Your request was blocked for security reasons.', 'gemsecurity' ) );
			}
		}
	}

	/* ------------------------------------------------------------------ */
	/* 404 throttling                                                      */
	/* ------------------------------------------------------------------ */

	public function watch_404() {
		if ( ! is_404() ) {
			return;
		}
		$ip = Helper::get_ip_address();
		if ( '0.0.0.0' === $ip || ( is_user_logged_in() && current_user_can( 'manage_options' ) ) ) {
			return;
		}
		$max    = max( 3, (int) Helper::get_setting( 'throttle_404_max', 20 ) );
		$window = max( 1, (int) Helper::get_setting( 'throttle_404_window', 5 ) ) * MINUTE_IN_SECONDS;
		$key    = 'gemsec_404_' . md5( $ip );

		$count = (int) get_transient( $key ) + 1;
		set_transient( $key, $count, $window );

		if ( $count >= $max ) {
			delete_transient( $key );
			Logger::log( 'waf_404_flood', sprintf( '404 flood from %s (%d in window).', $ip, $count ), Logger::SEVERITY_WARNING, [ 'user_id' => 0, 'ip_address' => $ip ] );
			BanList::record_strike( $ip, '404 flood' );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Detection helpers                                                   */
	/* ------------------------------------------------------------------ */

	private function rate_limited( $ip ) {
		$max    = max( 10, (int) Helper::get_setting( 'rate_limit_max', 240 ) );
		$window = max( 1, (int) Helper::get_setting( 'rate_limit_window', 1 ) ) * MINUTE_IN_SECONDS;
		$key    = 'gemsec_rl_' . md5( $ip );

		$count = (int) get_transient( $key ) + 1;
		set_transient( $key, $count, $window );
		return $count > $max;
	}

	private function is_bad_bot() {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		if ( '' === $ua ) {
			return Helper::get_setting( 'block_empty_ua', true )
				? [ 'ua' => '', 'matched' => '(empty user-agent)' ]
				: false;
		}
		$bad = 'sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|netsparker|fimap|dirbuster|gobuster|wpscan|hydra|libwww-perl|python-requests|curl/|wget/';
		$bad = apply_filters( 'gemsecurity/bad_bot_pattern', $bad );
		if ( preg_match( '#(' . $bad . ')#i', $ua, $m ) ) {
			return [ 'ua' => $ua, 'matched' => '(built-in: ' . $m[1] . ')' ];
		}
		foreach ( (array) Helper::get_setting( 'bot_blocklist', [] ) as $entry ) {
			$entry = (string) $entry;
			if ( '' === $entry ) {
				continue;
			}
			if ( false !== strpos( $entry, '*' ) ) {
				$regex = '#^' . str_replace( '\*', '.*', preg_quote( $entry, '#' ) ) . '$#i';
				if ( preg_match( $regex, $ua ) ) {
					return [ 'ua' => $ua, 'matched' => $entry ];
				}
			} elseif ( false !== stripos( $ua, $entry ) ) {
				return [ 'ua' => $ua, 'matched' => $entry ];
			}
		}
		return false;
	}

	/**
	 * Inspect the request URI and query values for attack signatures.
	 *
	 * @return array|false { type, value }
	 */
	private function inspect() {
		$rules = $this->rules();

		$candidates = [];
		if ( isset( $_SERVER['REQUEST_URI'] ) ) {
			$candidates[] = rawurldecode( wp_unslash( $_SERVER['REQUEST_URI'] ) );
		}
		$this->collect( $_GET, $candidates );
		if ( Helper::get_setting( 'waf_inspect_body', false ) ) {
			$this->collect( $_POST, $candidates );
		}

		foreach ( $candidates as $value ) {
			$value = is_string( $value ) ? $value : '';
			if ( '' === $value ) {
				continue;
			}
			foreach ( $rules as $type => $pattern ) {
				if ( preg_match( $pattern, $value ) ) {
					return [ 'type' => $type, 'value' => $value ];
				}
			}
		}
		return false;
	}

	private function collect( $arr, &$out ) {
		foreach ( (array) $arr as $v ) {
			if ( is_array( $v ) ) {
				$this->collect( $v, $out );
			} else {
				$out[] = wp_unslash( (string) $v );
			}
		}
	}

	/**
	 * Enabled rule set keyed by type.
	 *
	 * @return array<string,string>
	 */
	private function rules() {
		$all = [
			'sqli' => '/(\bunion\b.{1,40}\bselect\b|\bselect\b.{1,100}\bfrom\b|\binsert\b\s+\binto\b|\bdrop\b\s+\btable\b|information_schema|\bor\b\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|\bupdatexml\s*\()/i',
			'xss'  => '/(<script\b|javascript:|onerror\s*=|onload\s*=|<iframe\b|document\.cookie|String\.fromCharCode|<svg\b.{0,40}onload)/i',
			'lfi'  => '/(\.\.\/\.\.\/|\.\.%2f|\/etc\/passwd|\/proc\/self\/environ|php:\/\/|data:\/\/|file:\/\/|expect:\/\/)/i',
			'rce'  => '/(\bsystem\s*\(|\bexec\s*\(|passthru\s*\(|shell_exec\s*\(|popen\s*\(|proc_open\s*\(|base64_decode\s*\(|\bphpinfo\s*\(|\$\{.{1,40}\})/i',
		];
		$out = [];
		foreach ( $all as $type => $pattern ) {
			if ( Helper::get_setting( 'waf_block_' . $type, true ) ) {
				$out[ $type ] = $pattern;
			}
		}
		return $out;
	}

	/**
	 * @param string $message
	 * @param int    $code
	 */
	private function deny( $message, $code = 403 ) {
		status_header( $code );
		nocache_headers();
		wp_die(
			esc_html( $message ),
			esc_html__( 'Blocked', 'gemsecurity' ),
			[ 'response' => $code ]
		);
	}
}
