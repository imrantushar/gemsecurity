<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One place that builds and sends every GemSecurity email.
 *
 * Two problems this solves:
 *
 *  - **Which site is this about?** Alerts used to arrive as "[Site] Weekly
 *    security report", and a person running the plugin on a dozen sites got a
 *    dozen identical-looking subjects. Every subject now carries the site name
 *    *and* the host, which is the only part guaranteed to be unique, plus a
 *    leading emoji so the kind of message is readable in a notification
 *    preview before the mail is even opened.
 *
 *  - **What am I looking at?** Plain-text bodies made a critical alert and a
 *    routine digest look identical. Messages are composed from typed blocks
 *    (paragraph, stats, table, list, notice, button) rendered into a
 *    table-based HTML layout with inline styles — the only thing mail clients
 *    reliably agree on — with a matching plain-text alternative for clients
 *    that refuse HTML.
 */
class Mailer {

	/** Accent used for the header bar and links. */
	const ACCENT = '#2f6bff';

	/** Tone → [ background, border, text ] for notice blocks. */
	const TONES = [
		'critical' => [ '#fdf2f2', '#f5c2c2', '#a01919' ],
		'warning'  => [ '#fdf6ec', '#f3d9ab', '#8a5a00' ],
		'success'  => [ '#f0faf4', '#b7e4c7', '#1b6b3a' ],
		'info'     => [ '#f1f5fd', '#c9d8f5', '#1f3f86' ],
	];

	/**
	 * The site's display name, decoded, falling back to the host.
	 *
	 * @return string
	 */
	public static function site_name() {
		$name = trim( wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES ) );
		return '' !== $name ? $name : self::site_host();
	}

	/** The site's host, e.g. "shop.example.com". */
	public static function site_host() {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		return $host ? (string) $host : 'wordpress';
	}

	/**
	 * Build a subject line: emoji, then an identity nobody can confuse with
	 * another install, then the message itself.
	 *
	 * @param string $emoji
	 * @param string $text
	 * @return string
	 */
	public static function subject( $emoji, $text ) {
		$name = self::site_name();
		$host = self::site_host();

		// Don't print the host twice when the site is named after its domain.
		$identity = ( strcasecmp( $name, $host ) === 0 ) ? $host : $name . ' · ' . $host;

		/**
		 * Filter the identity shown in every GemSecurity email subject.
		 *
		 * @param string $identity
		 * @param string $name
		 * @param string $host
		 */
		$identity = apply_filters( 'gemsecurity/email_identity', $identity, $name, $host );

		$emoji = trim( (string) $emoji );
		$parts = [];
		if ( '' !== $emoji ) {
			$parts[] = $emoji;
		}
		$parts[] = '[' . $identity . ']';
		$parts[] = $text;

		return implode( ' ', $parts );
	}

	/**
	 * The one address GemSecurity notifies.
	 *
	 * Every alert, report and failure notice goes here. There used to be four
	 * separate recipient settings plus a handful of places that hardcoded the
	 * site admin address, so changing "where security email goes" meant finding
	 * and changing all of them.
	 *
	 * @return string
	 */
	public static function recipient() {
		$to = trim( (string) Helper::get_setting( 'alert_to_email', '' ) );
		if ( '' === $to || ! is_email( $to ) ) {
			$to = (string) get_option( 'admin_email' );
		}

		/**
		 * Filter the security notification recipient.
		 *
		 * @param string $to
		 */
		return (string) apply_filters( 'gemsecurity/notification_recipient', $to );
	}

	/**
	 * Compose and send a message.
	 *
	 * @param string $to       Recipient. Empty or invalid falls back to
	 *                         {@see recipient()}.
	 * @param string $emoji    Leading emoji for the subject.
	 * @param string $title    Subject text and the heading inside the email.
	 * @param array  $blocks   Ordered content blocks (see render_block()).
	 * @param array  $args     intro (string), footer (string).
	 * @return bool
	 */
	public static function send( $to, $emoji, $title, array $blocks, array $args = [] ) {
		$to = trim( (string) $to );
		if ( '' === $to || ! is_email( $to ) ) {
			$to = self::recipient();
		}

		$subject = self::subject( $emoji, $title );
		$html    = self::render_html( $emoji, $title, $blocks, $args );
		$text    = self::render_text( $title, $blocks, $args );

		$html_type = static function () {
			return 'text/html';
		};
		// Give clients that refuse HTML the same content as readable text.
		$alt_body = static function ( $phpmailer ) use ( $text ) {
			$phpmailer->AltBody = $text; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		};

		add_filter( 'wp_mail_content_type', $html_type );
		add_action( 'phpmailer_init', $alt_body );

		$sent = wp_mail( $to, $subject, $html );

		remove_action( 'phpmailer_init', $alt_body );
		remove_filter( 'wp_mail_content_type', $html_type );

		return (bool) $sent;
	}

	/* ------------------------------------------------------------------ */
	/* Rendering                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string $emoji
	 * @param string $title
	 * @param array  $blocks
	 * @param array  $args
	 * @return string
	 */
	private static function render_html( $emoji, $title, array $blocks, array $args ) {
		$name   = esc_html( self::site_name() );
		$host   = esc_html( self::site_host() );
		$intro  = isset( $args['intro'] ) ? $args['intro'] : '';
		$footer = isset( $args['footer'] ) ? $args['footer'] : sprintf(
			/* translators: %s: site name. */
			__( 'Sent by GemSecurity on %s. You are receiving this because you are listed as a security contact.', 'gemsecurity' ),
			self::site_name()
		);

		$body = '';
		foreach ( $blocks as $block ) {
			$body .= self::render_block( $block );
		}

		// Shown in the inbox preview line, after the subject.
		$preheader = $intro ? wp_strip_all_tags( $intro ) : wp_strip_all_tags( $title );

		$out  = '<!DOCTYPE html><html><head><meta charset="utf-8">';
		$out .= '<meta name="viewport" content="width=device-width,initial-scale=1">';
		$out .= '<title>' . esc_html( $title ) . '</title></head>';
		$out .= '<body style="margin:0;padding:0;background:#eef1f6;">';
		$out .= '<div style="display:none;max-height:0;overflow:hidden;opacity:0;">' . esc_html( $preheader ) . '</div>';
		$out .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef1f6;padding:24px 12px;">';
		$out .= '<tr><td align="center">';
		$out .= '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #dfe4ec;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;">';

		// Header: which site this is about, stated before anything else.
		$out .= '<tr><td style="background:' . self::ACCENT . ';padding:18px 24px;">';
		$out .= '<div style="color:#ffffff;font-size:15px;font-weight:700;line-height:1.3;">' . $name . '</div>';
		$out .= '<div style="color:rgba(255,255,255,.82);font-size:12px;line-height:1.4;">' . $host . '</div>';
		$out .= '</td></tr>';

		// Title.
		$out .= '<tr><td style="padding:26px 24px 0;">';
		$out .= '<h1 style="margin:0;font-size:20px;line-height:1.35;color:#1e2533;font-weight:700;">';
		$out .= ( $emoji ? esc_html( $emoji ) . ' ' : '' ) . esc_html( $title );
		$out .= '</h1>';
		if ( $intro ) {
			$out .= '<p style="margin:10px 0 0;font-size:14px;line-height:1.6;color:#5b6474;">' . wp_kses_post( $intro ) . '</p>';
		}
		$out .= '</td></tr>';

		$out .= '<tr><td style="padding:8px 24px 26px;">' . $body . '</td></tr>';

		$out .= '<tr><td style="padding:16px 24px;background:#f7f9fc;border-top:1px solid #e6eaf2;">';
		$out .= '<p style="margin:0;font-size:12px;line-height:1.6;color:#78808f;">' . wp_kses_post( $footer ) . '</p>';
		$out .= '<p style="margin:6px 0 0;font-size:12px;"><a href="' . esc_url( home_url( '/' ) ) . '" style="color:' . self::ACCENT . ';text-decoration:none;">' . $host . '</a></p>';
		$out .= '</td></tr>';

		$out .= '</table></td></tr></table></body></html>';

		return $out;
	}

	/**
	 * One content block.
	 *
	 * Supported types:
	 *  - paragraph { text }
	 *  - notice    { tone, text }
	 *  - stats     { items: [ label => value ] }
	 *  - table     { heading, columns[], rows[][] }
	 *  - list      { heading, items[], empty }
	 *  - button    { url, label }
	 *
	 * @param array $block
	 * @return string
	 */
	private static function render_block( array $block ) {
		$type = isset( $block['type'] ) ? $block['type'] : 'paragraph';

		switch ( $type ) {
			case 'notice':
				$tone   = isset( $block['tone'], self::TONES[ $block['tone'] ] ) ? $block['tone'] : 'info';
				list( $bg, $border, $color ) = self::TONES[ $tone ];
				return '<div style="margin:18px 0 0;padding:12px 14px;background:' . $bg . ';border:1px solid ' . $border . ';border-radius:8px;color:' . $color . ';font-size:14px;line-height:1.6;">'
					. wp_kses_post( $block['text'] ) . '</div>';

			case 'stats':
				$cells = '';
				foreach ( (array) $block['items'] as $label => $value ) {
					$cells .= '<td style="padding:12px 14px;background:#f7f9fc;border:1px solid #e6eaf2;border-radius:8px;" align="center">'
						. '<div style="font-size:22px;font-weight:700;color:#1e2533;line-height:1.2;">' . esc_html( (string) $value ) . '</div>'
						. '<div style="font-size:11px;color:#78808f;text-transform:uppercase;letter-spacing:.04em;margin-top:2px;">' . esc_html( (string) $label ) . '</div>'
						. '</td><td style="width:8px;"></td>';
				}
				return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:18px 0 0;"><tr>' . $cells . '</tr></table>';

			case 'table':
				$out = self::heading( $block );
				$out .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:10px 0 0;border-collapse:collapse;font-size:13px;">';
				if ( ! empty( $block['columns'] ) ) {
					$out .= '<tr>';
					foreach ( $block['columns'] as $col ) {
						$out .= '<th align="left" style="padding:8px 10px;background:#f7f9fc;border-bottom:1px solid #e6eaf2;color:#5b6474;font-size:11px;text-transform:uppercase;letter-spacing:.04em;">' . esc_html( (string) $col ) . '</th>';
					}
					$out .= '</tr>';
				}
				foreach ( (array) $block['rows'] as $row ) {
					$out .= '<tr>';
					foreach ( (array) $row as $cell ) {
						$out .= '<td style="padding:9px 10px;border-bottom:1px solid #eef1f6;color:#1e2533;line-height:1.5;">' . wp_kses_post( (string) $cell ) . '</td>';
					}
					$out .= '</tr>';
				}
				$out .= '</table>';
				return $out;

			case 'list':
				$out   = self::heading( $block );
				$items = (array) $block['items'];
				if ( ! $items ) {
					return $out . '<p style="margin:8px 0 0;font-size:13px;color:#78808f;">' . esc_html( isset( $block['empty'] ) ? $block['empty'] : __( 'Nothing to report.', 'gemsecurity' ) ) . '</p>';
				}
				$out .= '<ul style="margin:8px 0 0;padding-left:20px;font-size:14px;line-height:1.7;color:#1e2533;">';
				foreach ( $items as $item ) {
					$out .= '<li>' . wp_kses_post( (string) $item ) . '</li>';
				}
				return $out . '</ul>';

			case 'button':
				return '<p style="margin:20px 0 0;"><a href="' . esc_url( $block['url'] ) . '" style="display:inline-block;padding:11px 20px;background:' . self::ACCENT . ';color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;border-radius:8px;">' . esc_html( $block['label'] ) . '</a></p>';

			case 'paragraph':
			default:
				return '<p style="margin:16px 0 0;font-size:14px;line-height:1.65;color:#1e2533;">' . wp_kses_post( $block['text'] ) . '</p>';
		}
	}

	/** Section heading shared by table/list blocks. */
	private static function heading( array $block ) {
		if ( empty( $block['heading'] ) ) {
			return '';
		}
		return '<h2 style="margin:24px 0 0;font-size:13px;font-weight:700;color:#5b6474;text-transform:uppercase;letter-spacing:.05em;">' . esc_html( $block['heading'] ) . '</h2>';
	}

	/**
	 * Plain-text alternative built from the same blocks, so the fallback says
	 * the same thing rather than being an empty or stripped-tag mess.
	 *
	 * @param string $title
	 * @param array  $blocks
	 * @param array  $args
	 * @return string
	 */
	private static function render_text( $title, array $blocks, array $args ) {
		$lines = [
			self::site_name() . ' (' . self::site_host() . ')',
			str_repeat( '=', 48 ),
			$title,
		];
		if ( ! empty( $args['intro'] ) ) {
			$lines[] = '';
			$lines[] = wp_strip_all_tags( $args['intro'] );
		}

		foreach ( $blocks as $block ) {
			$type = isset( $block['type'] ) ? $block['type'] : 'paragraph';
			$lines[] = '';

			switch ( $type ) {
				case 'stats':
					foreach ( (array) $block['items'] as $label => $value ) {
						$lines[] = sprintf( '%-24s %s', $label . ':', $value );
					}
					break;

				case 'table':
					if ( ! empty( $block['heading'] ) ) {
						$lines[] = strtoupper( $block['heading'] );
					}
					foreach ( (array) $block['rows'] as $row ) {
						$lines[] = '- ' . implode( ' | ', array_map( 'wp_strip_all_tags', (array) $row ) );
					}
					break;

				case 'list':
					if ( ! empty( $block['heading'] ) ) {
						$lines[] = strtoupper( $block['heading'] );
					}
					$items = (array) $block['items'];
					if ( ! $items ) {
						$lines[] = isset( $block['empty'] ) ? $block['empty'] : __( 'Nothing to report.', 'gemsecurity' );
						break;
					}
					foreach ( $items as $item ) {
						$lines[] = '- ' . wp_strip_all_tags( (string) $item );
					}
					break;

				case 'button':
					$lines[] = $block['label'] . ': ' . $block['url'];
					break;

				default:
					$lines[] = wp_strip_all_tags( $block['text'] );
			}
		}

		$lines[] = '';
		$lines[] = str_repeat( '-', 48 );
		$lines[] = home_url( '/' );

		return implode( "\n", $lines );
	}
}
