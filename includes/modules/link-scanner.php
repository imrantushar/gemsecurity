<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Outbound link / malicious-site detector.
 *
 * Pulls every external link out of the site's own content — published posts and
 * pages, options (widgets, theme mods, "custom HTML" blocks) and approved
 * comments — then groups them by destination domain. A domain is flagged when
 * it is:
 *
 *   - on the administrator's blocklist, or
 *   - linked from a hidden / off-screen element (an SEO-spam cloak), or
 *   - a name (or link text) matching a common spam category (gambling, pharma,
 *     adult, replica, essay-mill…).
 *
 * Even when nothing is flagged, the full list of external domains is returned so
 * an owner can eyeball it and notice a site they never chose to link to — which
 * is how injected link-spam (the classic "hidden backlink farm") is caught even
 * when it is not hidden.
 *
 * This is deliberately self-contained: it makes no outbound reputation calls, so
 * it is safe for a free plugin and cannot leak the site's content anywhere. A
 * remote threat feed can be layered on via the `gemsecurity/link_blocklist`
 * filter.
 */
class LinkScanner {

	const MAX_POSTS    = 300;
	const MAX_OPTIONS  = 1500;
	const MAX_COMMENTS = 500;
	const MAX_LINKS    = 20000;   // hard stop on total anchors parsed.
	const MAX_REPORTED = 200;

	/**
	 * Run the scan.
	 *
	 * @return array
	 */
	public static function run() {
		// Scanner runs can take minutes on large sites.
		@set_time_limit( 0 ); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged

		$allow = self::allowlist();
		$block = self::blocklist();

		// domain => { count, hidden, texthits(set of categories), sources[] }
		$domains = [];
		$total   = 0;

		$sources = [
			'posts'    => self::post_contents(),
			'options'  => self::option_contents(),
			'comments' => self::comment_contents(),
		];
		$counts = [ 'posts' => 0, 'options' => 0, 'comments' => 0 ];

		foreach ( $sources as $type => $rows ) {
			foreach ( $rows as $row ) {
				$counts[ $type ]++;
				$content = (string) $row['content'];
				if ( '' === $content || false === stripos( $content, 'href' ) ) {
					continue;
				}
				// Hosts that sit inside an off-screen-styled container in THIS
				// document (a per-region test, so a hidden element cannot taint
				// unrelated links elsewhere in the same document).
				$hidden_hosts = self::hidden_hosts( $content );

				foreach ( self::extract_links( $content ) as $link ) {
					if ( $total >= self::MAX_LINKS ) {
						break 3;
					}
					$total++;

					$host = self::host( $link['href'] );
					if ( '' === $host || self::is_allowed( $host, $allow ) ) {
						continue;
					}

					if ( ! isset( $domains[ $host ] ) ) {
						$domains[ $host ] = [
							'count'      => 0,
							'hidden'     => false,
							'categories' => [],
							'sample'     => sprintf( '%s: %s', $type, $row['label'] ),
						];
					}
					$domains[ $host ]['count']++;
					if ( isset( $hidden_hosts[ $host ] ) ) {
						$domains[ $host ]['hidden'] = true;
					}
					foreach ( self::spam_categories( $host . ' ' . $link['text'] ) as $cat ) {
						$domains[ $host ]['categories'][ $cat ] = true;
					}
				}
			}
		}

		// Build the flagged list + the informational domain list.
		$flagged     = [];
		$domain_list = [];
		foreach ( $domains as $host => $d ) {
			$domain_list[] = [ 'domain' => $host, 'count' => $d['count'] ];

			$reason   = self::reason_for( $host, $d, $block );
			if ( $reason ) {
				$flagged[] = [
					'domain'   => $host,
					'count'    => $d['count'],
					'severity' => $reason['severity'],
					'reason'   => $reason['label'],
					'sample'   => $d['sample'],
				];
			}
		}

		// Most-linked first for the informational list; severest first for flags.
		usort( $domain_list, static function ( $a, $b ) {
			return $b['count'] <=> $a['count'];
		} );
		usort( $flagged, static function ( $a, $b ) {
			$rank = [ 'critical' => 0, 'warning' => 1 ];
			if ( ( $rank[ $a['severity'] ] ?? 2 ) !== ( $rank[ $b['severity'] ] ?? 2 ) ) {
				return ( $rank[ $a['severity'] ] ?? 2 ) <=> ( $rank[ $b['severity'] ] ?? 2 );
			}
			return $b['count'] <=> $a['count'];
		} );

		return [
			'sources'          => $counts,
			'links_scanned'    => $total,
			'external_domains' => count( $domains ),
			'domains'          => array_slice( $domain_list, 0, self::MAX_REPORTED ),
			'flagged'          => array_slice( $flagged, 0, self::MAX_REPORTED ),
			'flagged_count'    => count( $flagged ),
			'issue_count'      => count( $flagged ),
		];
	}

	/* --------------------------------------------------------------------- */
	/* Scoring                                                               */
	/* --------------------------------------------------------------------- */

	/**
	 * Decide whether an aggregated domain is a problem, and why.
	 *
	 * @param string   $host
	 * @param array    $d     Aggregated data for the domain.
	 * @param string[] $block Normalised blocklist.
	 * @return array|null { severity, label }
	 */
	private static function reason_for( $host, array $d, array $block ) {
		if ( self::matches_list( $host, $block ) ) {
			return [ 'severity' => 'critical', 'label' => __( 'On your link blocklist.', 'gemsecurity' ) ];
		}
		if ( ! empty( $d['hidden'] ) ) {
			return [ 'severity' => 'critical', 'label' => __( 'Linked from a hidden / off-screen element — the signature of an SEO-spam link cloak.', 'gemsecurity' ) ];
		}
		if ( ! empty( $d['categories'] ) ) {
			return [
				'severity' => 'warning',
				'label'    => sprintf(
					/* translators: %s: comma-separated spam categories. */
					__( 'Domain or link text matches a common spam category: %s.', 'gemsecurity' ),
					implode( ', ', array_keys( $d['categories'] ) )
				),
			];
		}
		return null;
	}

	/**
	 * Which spam categories a blob of text hits. Keyword stems are matched as
	 * substrings against the lower-cased domain + anchor text.
	 *
	 * @param string $text
	 * @return string[] category slugs.
	 */
	private static function spam_categories( $text ) {
		$text = strtolower( $text );
		$map  = [
			'gambling' => [ 'casino', 'gambl', 'betting', 'roulette', 'blackjack', 'jackpot', 'pokie', 'slot-', 'sportsbook' ],
			'pharma'   => [ 'pharma', 'viagra', 'cialis', 'tadalafil', 'sildenafil' ],
			'adult'    => [ 'porn', 'xxx', 'escort', 'sexcam' ],
			'replica'  => [ 'replica-', 'rolex-replica' ],
			'essay'    => [ 'essay-writ', 'homework-help', 'write-my-' ],
		];

		$hits = [];
		foreach ( $map as $cat => $needles ) {
			foreach ( $needles as $n ) {
				if ( false !== strpos( $text, $n ) ) {
					$hits[] = $cat;
					break;
				}
			}
		}
		return $hits;
	}

	/* --------------------------------------------------------------------- */
	/* Allow / block lists                                                   */
	/* --------------------------------------------------------------------- */

	/**
	 * Domains that are always treated as internal / safe: the site's own host
	 * (with and without www) plus the admin's allowlist.
	 *
	 * @return string[]
	 */
	private static function allowlist() {
		$host = self::normalise_host( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$list = [ $host ];
		if ( 0 === strpos( $host, 'www.' ) ) {
			$list[] = substr( $host, 4 );
		} else {
			$list[] = 'www.' . $host;
		}
		foreach ( (array) Helper::get_setting( 'link_allowlist', [] ) as $d ) {
			$d = self::normalise_host( (string) $d );
			if ( '' !== $d ) {
				$list[] = $d;
			}
		}
		return array_values( array_unique( array_filter( $list ) ) );
	}

	/**
	 * The admin blocklist, filterable so a Pro addon or threat feed can inject
	 * more known-bad domains.
	 *
	 * @return string[]
	 */
	private static function blocklist() {
		$list = [];
		foreach ( (array) Helper::get_setting( 'link_blocklist', [] ) as $d ) {
			$d = self::normalise_host( (string) $d );
			if ( '' !== $d ) {
				$list[] = $d;
			}
		}

		/**
		 * Filter the effective link blocklist (normalised bare hosts).
		 *
		 * @param string[] $list
		 */
		$list = apply_filters( 'gemsecurity/link_blocklist', $list );

		return array_values( array_unique( array_filter( array_map( [ __CLASS__, 'normalise_host' ], (array) $list ) ) ) );
	}

	/**
	 * Whether a host is on the allowlist (exact host or a subdomain of an
	 * allowlisted host).
	 *
	 * @param string   $host
	 * @param string[] $allow
	 * @return bool
	 */
	private static function is_allowed( $host, array $allow ) {
		return self::matches_list( $host, $allow );
	}

	/**
	 * Match a host against a list of bare hosts, where a list entry also matches
	 * any of its subdomains (example.com matches a.example.com).
	 *
	 * @param string   $host
	 * @param string[] $list
	 * @return bool
	 */
	private static function matches_list( $host, array $list ) {
		foreach ( $list as $entry ) {
			if ( $host === $entry || self::str_ends_with( $host, '.' . $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/* --------------------------------------------------------------------- */
	/* Content sources                                                       */
	/* --------------------------------------------------------------------- */

	/**
	 * @return array<int,array{content:string,label:string}>
	 */
	private static function post_contents() {
		global $wpdb;
		// Full-content LIKE scan of wp_posts; the scanner intentionally
		// bypasses caches so a planted link in a published post is seen.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_title, post_content FROM {$wpdb->posts}
				 WHERE post_status = 'publish'
				   AND post_content LIKE %s
				 ORDER BY post_modified DESC
				 LIMIT %d",
				'%href%',
				self::MAX_POSTS
			),
			ARRAY_A
		);
		$out = [];
		foreach ( (array) $rows as $r ) {
			$out[] = [
				'content' => $r['post_content'],
				'label'   => '#' . (int) $r['ID'] . ' ' . $r['post_title'],
			];
		}
		return $out;
	}

	/**
	 * @return array<int,array{content:string,label:string}>
	 */
	private static function option_contents() {
		global $wpdb;
		// Direct LIKE scan of wp_options; cached values would miss a link
		// written into a serialized option by an attacker.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options}
				 WHERE option_value LIKE %s
				 LIMIT %d",
				'%href%',
				self::MAX_OPTIONS
			),
			ARRAY_A
		);
		$out = [];
		foreach ( (array) $rows as $r ) {
			$out[] = [ 'content' => $r['option_value'], 'label' => $r['option_name'] ];
		}
		return $out;
	}

	/**
	 * @return array<int,array{content:string,label:string}>
	 */
	private static function comment_contents() {
		global $wpdb;
		// Direct LIKE scan of wp_comments; the scanner needs fresh content.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT comment_ID, comment_content FROM {$wpdb->comments}
				 WHERE comment_approved = '1'
				   AND comment_content LIKE %s
				 ORDER BY comment_ID DESC
				 LIMIT %d",
				'%http%',
				self::MAX_COMMENTS
			),
			ARRAY_A
		);
		$out = [];
		foreach ( (array) $rows as $r ) {
			$out[] = [ 'content' => $r['comment_content'], 'label' => 'comment #' . (int) $r['comment_ID'] ];
		}
		return $out;
	}

	/* --------------------------------------------------------------------- */
	/* Parsing helpers                                                       */
	/* --------------------------------------------------------------------- */

	/**
	 * Off-screen positioning that hides an element far outside the viewport —
	 * the CSS half of an SEO-spam link cloak (top:-10001px, left:-9999px, …).
	 */
	const OFFSCREEN_RE = '(?:top|left|right|bottom|text-indent|margin-left|margin-top)\s*:\s*-\s*[1-9][0-9]{3,}\s*px';

	/**
	 * Extract { href, text } for every anchor with an absolute http(s) target.
	 *
	 * @param string $content
	 * @return array<int,array{href:string,text:string}>
	 */
	private static function extract_links( $content ) {
		$out = [];
		if ( ! preg_match_all( '/<a\b[^>]*\bhref\s*=\s*["\'](https?:\/\/[^"\']+)["\'][^>]*>(.*?)<\/a>/is', $content, $m, PREG_SET_ORDER ) ) {
			return $out;
		}
		foreach ( $m as $match ) {
			$out[] = [
				'href' => $match[1],
				'text' => trim( wp_strip_all_tags( $match[2] ) ),
			];
		}
		return $out;
	}

	/**
	 * Hosts linked from inside an element whose own inline style pushes it
	 * off-screen. Matches such a container and captures its inner HTML, then
	 * pulls the links out of that region only — so a hidden block cannot taint
	 * links that live outside it (even a visible link a few characters later).
	 *
	 * @param string $content
	 * @return array<string,true> set of hidden hosts.
	 */
	private static function hidden_hosts( $content ) {
		$hosts = [];
		$re = '/<(div|span|p|section|ul|ol|li|a|table|td)\b[^>]*\bstyle\s*=\s*(["\'])(?:(?!\2).)*?' . self::OFFSCREEN_RE . '(?:(?!\2).)*?\2[^>]*>(.*?)<\/\1>/is';
		if ( ! preg_match_all( $re, $content, $regions, PREG_SET_ORDER ) ) {
			return $hosts;
		}
		foreach ( $regions as $region ) {
			foreach ( self::extract_links( $region[3] ) as $link ) {
				$host = self::host( $link['href'] );
				if ( '' !== $host ) {
					$hosts[ $host ] = true;
				}
			}
		}
		return $hosts;
	}

	/**
	 * The bare host for a URL (lower-cased, leading "www." stripped).
	 *
	 * @param string $url
	 * @return string
	 */
	private static function host( $url ) {
		$host = (string) wp_parse_url( html_entity_decode( $url ), PHP_URL_HOST );
		return self::normalise_host( $host );
	}

	/**
	 * @param string $host
	 * @return string
	 */
	public static function normalise_host( $host ) {
		$host = strtolower( trim( (string) $host ) );
		// Accept a bare domain typed with scheme/path (blocklist entries).
		if ( false !== strpos( $host, '/' ) ) {
			$host = (string) wp_parse_url( ( false === strpos( $host, '://' ) ? 'http://' : '' ) . $host, PHP_URL_HOST );
			$host = strtolower( (string) $host );
		}
		if ( 0 === strpos( $host, 'www.' ) ) {
			$host = substr( $host, 4 );
		}
		return $host;
	}

	/**
	 * Polyfill for str_ends_with (PHP < 8).
	 *
	 * @param string $haystack
	 * @param string $needle
	 * @return bool
	 */
	private static function str_ends_with( $haystack, $needle ) {
		if ( function_exists( 'str_ends_with' ) ) {
			return str_ends_with( $haystack, $needle );
		}
		$len = strlen( $needle );
		return 0 === $len || substr( $haystack, -$len ) === $needle;
	}
}
