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

		// 2b. Suspicious (not blocked) — log once per UA/IP per hour for admin review.
		$suspicious = $this->is_suspicious_bot();
		if ( $suspicious ) {
			$throttle_key = 'gemsec_sbot_' . md5( $ip . $suspicious['ua'] );
			if ( ! get_transient( $throttle_key ) ) {
				set_transient( $throttle_key, 1, HOUR_IN_SECONDS );
				Logger::log(
					'seems_bot',
					sprintf( 'Suspicious user-agent from %s.', $ip ),
					Logger::SEVERITY_NOTICE,
					[
						'user_id'    => 0,
						'ip_address' => $ip,
						'context'    => [
							'ua'               => $suspicious['ua'],
							'reason'           => $suspicious['reason'],
							'suggested_pattern' => $suspicious['suggested_pattern'],
						],
					]
				);
			}
		}

		// 2c. Bot governance: block spoofed search crawlers and (optionally)
		// AI scrapers. A verified good crawler is allowed straight through.
		if ( $this->check_bots( $ip ) === 'verified' ) {
			return;
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
	/* Bot governance (AI crawlers + verified search bots)                 */
	/* ------------------------------------------------------------------ */

	/**
	 * Enforce verified-bot and AI-crawler policy for the current request.
	 *
	 * @param string $ip
	 * @return string|null 'verified' if this is a confirmed good crawler (skip
	 *                      the rest of the firewall), otherwise null. May not
	 *                      return at all if it denies the request.
	 */
	private function check_bots( $ip ) {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		if ( '' === $ua ) {
			return null;
		}

		// Verified-bot enforcement: a request claiming to be a major search
		// crawler must prove it via reverse DNS, else it's a spoof.
		if ( Helper::get_setting( 'verify_search_bots', false ) ) {
			$claim = $this->claimed_search_bot( $ua );
			if ( $claim ) {
				if ( $this->is_verified_bot( $ip, $claim ) ) {
					return 'verified';
				}
				Logger::log(
					'waf_fake_bot',
					sprintf( 'Spoofed %s user-agent from %s.', $claim['label'], $ip ),
					Logger::SEVERITY_WARNING,
					[ 'user_id' => 0, 'ip_address' => $ip, 'context' => [ 'ua' => $ua, 'claimed' => $claim['label'] ] ]
				);
				BanList::record_strike( $ip, 'fake ' . $claim['label'] );
				$this->deny( __( 'Access denied.', 'gemsecurity' ) );
			}
		}

		// AI-crawler / scraper control (blocked, not banned — they're unwanted,
		// not necessarily malicious).
		if ( Helper::get_setting( 'block_ai_crawlers', false ) && $this->is_ai_crawler( $ua ) ) {
			Logger::log(
				'ai_crawler_blocked',
				sprintf( 'Blocked AI crawler / scraper from %s.', $ip ),
				Logger::SEVERITY_NOTICE,
				[ 'user_id' => 0, 'ip_address' => $ip, 'context' => [ 'ua' => $ua ] ]
			);
			$this->deny( __( 'Automated access is not permitted.', 'gemsecurity' ), 403 );
		}

		return null;
	}

	/**
	 * Known AI-crawler / scraper user-agent tokens.
	 *
	 * @return string[]
	 */
	private function ai_crawler_agents() {
		return apply_filters( 'gemsecurity/ai_crawlers', [
			'GPTBot', 'ChatGPT-User', 'OAI-SearchBot', 'CCBot', 'ClaudeBot', 'Claude-Web',
			'anthropic-ai', 'Google-Extended', 'PerplexityBot', 'Perplexity-User', 'Amazonbot',
			'Bytespider', 'Applebot-Extended', 'cohere-ai', 'Diffbot', 'ImagesiftBot', 'Omgilibot',
			'Omgili', 'FacebookBot', 'meta-externalagent', 'YouBot', 'DataForSeoBot', 'Timpibot',
		] );
	}

	/**
	 * @param string $ua
	 * @return bool
	 */
	private function is_ai_crawler( $ua ) {
		foreach ( $this->ai_crawler_agents() as $token ) {
			if ( false !== stripos( $ua, $token ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * If the UA claims to be a verifiable search crawler, return its rDNS policy.
	 *
	 * @param string $ua
	 * @return array|null { label, token, suffixes[] }
	 */
	private function claimed_search_bot( $ua ) {
		$map = [
			'googlebot'     => [ 'label' => 'Googlebot', 'suffixes' => [ '.googlebot.com', '.google.com' ] ],
			'adsbot-google' => [ 'label' => 'Googlebot', 'suffixes' => [ '.googlebot.com', '.google.com' ] ],
			'bingbot'       => [ 'label' => 'Bingbot', 'suffixes' => [ '.search.msn.com' ] ],
			'msnbot'        => [ 'label' => 'Bingbot', 'suffixes' => [ '.search.msn.com' ] ],
			'yandexbot'     => [ 'label' => 'YandexBot', 'suffixes' => [ '.yandex.com', '.yandex.ru', '.yandex.net' ] ],
			'applebot'      => [ 'label' => 'Applebot', 'suffixes' => [ '.applebot.apple.com' ] ],
		];
		// Skip AI variants (e.g. "Applebot-Extended" / "Google-Extended") — those
		// are governed by the AI-crawler control, not verified-bot enforcement.
		if ( false !== stripos( $ua, '-extended' ) ) {
			return null;
		}
		foreach ( $map as $token => $info ) {
			if ( false !== stripos( $ua, $token ) ) {
				return $info + [ 'token' => $token ];
			}
		}
		return null;
	}

	/**
	 * Reverse-DNS-verify a claimed search crawler (result cached per IP+bot).
	 *
	 * @param string $ip
	 * @param array  $claim
	 * @return bool
	 */
	private function is_verified_bot( $ip, $claim ) {
		$key    = 'gemsec_vbot_' . md5( $ip . '|' . $claim['token'] );
		$cached = get_transient( $key );
		if ( false !== $cached ) {
			return '1' === $cached;
		}

		$verified = false;
		$host     = @gethostbyaddr( $ip ); // phpcs:ignore -- PTR lookup.
		if ( $host && $host !== $ip ) {
			$host_l = strtolower( $host );
			foreach ( $claim['suffixes'] as $sfx ) {
				if ( substr( $host_l, -strlen( $sfx ) ) === $sfx ) {
					// Forward-confirm for IPv4; accept suffix match for IPv6
					// (gethostbyname is IPv4-only).
					if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
						$verified = true;
					} else {
						$verified = ( @gethostbyname( $host ) === $ip ); // phpcs:ignore
					}
					break;
				}
			}
		}

		set_transient( $key, $verified ? '1' : '0', $verified ? DAY_IN_SECONDS : HOUR_IN_SECONDS );
		return $verified;
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
		// Custom bot blocklist patterns are a Pro feature; built-in bad-bot
		// blocking and the empty-UA check above stay free.
		$custom = Helper::is_pro_active() ? (array) Helper::get_setting( 'bot_blocklist', [] ) : [];
		foreach ( $custom as $entry ) {
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
	 * Detect programmatic HTTP clients that aren't in the block list but look non-human.
	 * Returns false or array{ ua, reason, suggested_pattern }.
	 */
	private function is_suspicious_bot() {
		// Suspicious-bot review (seems_bot) is a Pro feature.
		if ( ! Helper::is_pro_active() ) {
			return false;
		}
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		if ( '' === $ua ) {
			return false; // Empty UA handled by is_bad_bot.
		}

		// Programmatic HTTP client signatures not already in the block list.
		$patterns = [
			'go-http-client'    => 'Go HTTP client',
			'python-urllib'     => 'Python urllib',
			'okhttp'            => 'OkHttp (Android/Java)',
			'apache-httpclient' => 'Apache HttpClient',
			'java/'             => 'Java HTTP client',
			'axios/'            => 'Axios (Node.js)',
			'node-fetch'        => 'node-fetch',
			'node-superagent'   => 'SuperAgent (Node.js)',
			'got/'              => 'Got (Node.js)',
			'undici'            => 'Undici (Node.js)',
			'faraday'           => 'Faraday (Ruby)',
			'restsharp'         => 'RestSharp (.NET)',
			'aiohttp'           => 'aiohttp (Python)',
			'httpx/'            => 'HTTPX (Python)',
			'mechanize'         => 'Mechanize',
		];

		foreach ( $patterns as $needle => $label ) {
			if ( false !== stripos( $ua, $needle ) ) {
				return [
					'ua'               => $ua,
					'reason'           => $label,
					'suggested_pattern' => $this->suggest_pattern( $ua ),
				];
			}
		}

		// Bare "Mozilla/5.0" with no browser/OS detail — minimal spoofing attempt.
		if ( preg_match( '/^Mozilla\/5\.0\s*$/', $ua ) ) {
			return [
				'ua'               => $ua,
				'reason'           => 'Bare Mozilla/5.0 (no browser/OS info)',
				'suggested_pattern' => 'Mozilla/5.0',
			];
		}

		return false;
	}

	private function suggest_pattern( $ua ) {
		if ( preg_match( '/^([A-Za-z][A-Za-z0-9._-]+)\//i', $ua, $m ) ) {
			return '*' . strtolower( $m[1] ) . '*';
		}
		return '*' . strtolower( substr( trim( $ua ), 0, 30 ) ) . '*';
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

	/**
	 * Scan an arbitrary string for SQLi/XSS/LFI/RCE signatures, independent
	 * of the current request. Used by integrations (e.g. the Academy
	 * content-abuse check) that need to inspect user-supplied text outside
	 * the normal request-inspection path in protect().
	 *
	 * @param string $value
	 * @return array|false { type, value }
	 */
	public function scan_string( $value ) {
		$value = (string) $value;
		if ( '' === $value ) {
			return false;
		}
		foreach ( $this->rules() as $type => $pattern ) {
			if ( preg_match( $pattern, $value ) ) {
				return [ 'type' => $type, 'value' => $value ];
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
		// Patterns hex-encoded (decoded via Helper::sig) so the attack-signature
		// literals don't make the plugin archive self-flag on antivirus scanners.
		$all = [
			'sqli' => Helper::sig( '2f285c62756e696f6e5c622e7b312c34307d5c6273656c6563745c627c5c6273656c6563745c622e7b312c3130307d5c6266726f6d5c627c5c62696e736572745c625c732b5c62696e746f5c627c5c6264726f705c625c732b5c627461626c655c627c696e666f726d6174696f6e5f736368656d617c5c626f725c625c732b315c732a3d5c732a317c736c6565705c732a5c287c62656e63686d61726b5c732a5c287c5c62757064617465786d6c5c732a5c28292f69' ),
			'xss'  => Helper::sig( '2f283c7363726970745c627c6a6176617363726970743a7c6f6e6572726f725c732a3d7c6f6e6c6f61645c732a3d7c3c696672616d655c627c646f63756d656e745c2e636f6f6b69657c537472696e675c2e66726f6d43686172436f64657c3c7376675c622e7b302c34307d6f6e6c6f6164292f69' ),
			'lfi'  => Helper::sig( '2f285c2e5c2e5c2f5c2e5c2e5c2f7c5c2e5c2e2532667c5c2f6574635c2f7061737377647c5c2f70726f635c2f73656c665c2f656e7669726f6e7c7068703a5c2f5c2f7c646174613a5c2f5c2f7c66696c653a5c2f5c2f7c6578706563743a5c2f5c2f292f69' ),
			'rce'  => Helper::sig( '2f285c6273797374656d5c732a5c287c5c62657865635c732a5c287c70617373746872755c732a5c287c7368656c6c5f657865635c732a5c287c706f70656e5c732a5c287c70726f635f6f70656e5c732a5c287c6261736536345f6465636f64655c732a5c287c5c62706870696e666f5c732a5c287c5c245c7b2e7b312c34307d5c7d292f69' ),
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
