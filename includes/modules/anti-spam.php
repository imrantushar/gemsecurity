<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Anti-spam: frictionless (silent) bot checks on public forms, plus an optional
 * heuristic content filter for comments.
 *
 * "Silent" means no visible puzzle — a hidden honeypot field plus a signed
 * minimum-time-on-page token catch the overwhelming majority of automated
 * submissions without bothering real visitors.
 */
class AntiSpam {

	const HP    = 'gemsec_as_hp';
	const TOKEN = 'gemsec_as_t';

	public static function init() {
		$self = new self();

		if ( Helper::get_setting( 'antispam_enabled', true ) ) {
			// Comments.
			add_action( 'comment_form', [ $self, 'fields' ] );
			add_filter( 'preprocess_comment', [ $self, 'check_comment' ], 1 );
			// Registration.
			add_action( 'register_form', [ $self, 'fields' ] );
			add_filter( 'registration_errors', [ $self, 'check_registration' ], 10, 1 );
		}

		// Heuristic comment scoring (Pro).
		if ( Helper::is_pro_active() && Helper::get_setting( 'antispam_heuristics', false ) ) {
			add_filter( 'pre_comment_approved', [ $self, 'score_comment' ], 10, 2 );
		}
	}

	/** Print the silent honeypot + time token on a form. */
	public function fields() {
		$ts    = time();
		$token = $ts . '|' . hash_hmac( 'sha256', (string) $ts, wp_salt( 'auth' ) );
		echo '<div style="position:absolute;left:-9999px;" aria-hidden="true">'
			. '<input type="text" name="' . esc_attr( self::HP ) . '" value="" tabindex="-1" autocomplete="off" />'
			. '</div>';
		echo '<input type="hidden" name="' . esc_attr( self::TOKEN ) . '" value="' . esc_attr( $token ) . '" />';
	}

	/** True when the silent checks indicate a bot. */
	private function looks_like_bot() {
		if ( ! empty( $_POST[ self::HP ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return true;
		}
		$token = isset( $_POST[ self::TOKEN ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::TOKEN ] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		if ( '' === $token || false === strpos( $token, '|' ) ) {
			return true; // token missing/malformed → almost certainly a bot.
		}
		list( $ts, $sig ) = explode( '|', $token, 2 );
		if ( ! hash_equals( hash_hmac( 'sha256', $ts, wp_salt( 'auth' ) ), $sig ) ) {
			return true; // forged token.
		}
		$min = max( 1, (int) Helper::get_setting( 'antispam_min_seconds', 3 ) );
		return ( time() - (int) $ts ) < $min; // submitted too fast.
	}

	/**
	 * @param array $commentdata
	 * @return array
	 */
	public function check_comment( $commentdata ) {
		// Only guard anonymous submissions.
		if ( ! is_user_logged_in() && $this->looks_like_bot() ) {
			Logger::log( 'antispam_comment_blocked', sprintf( 'Blocked spam comment from %s.', Helper::get_ip_address() ), Logger::SEVERITY_NOTICE, [ 'user_id' => 0 ] );
			wp_die(
				esc_html__( 'Your comment was blocked as spam.', 'gemsecurity' ),
				esc_html__( 'Comment blocked', 'gemsecurity' ),
				[ 'response' => 403, 'back_link' => true ]
			);
		}
		return $commentdata;
	}

	/**
	 * @param \WP_Error $errors
	 * @return \WP_Error
	 */
	public function check_registration( $errors ) {
		if ( $this->looks_like_bot() ) {
			$errors->add( 'gemsec_antispam', __( 'Registration blocked. Please try again.', 'gemsecurity' ) );
			Logger::log( 'antispam_register_blocked', sprintf( 'Blocked spam registration from %s.', Helper::get_ip_address() ), Logger::SEVERITY_NOTICE, [ 'user_id' => 0 ] );
		}
		return $errors;
	}

	/**
	 * Heuristic comment scoring — flag as spam on too many links or blocklisted
	 * words/domains.
	 *
	 * @param int|string $approved
	 * @param array      $commentdata
	 * @return int|string
	 */
	public function score_comment( $approved, $commentdata ) {
		if ( 'spam' === $approved || 'trash' === $approved ) {
			return $approved;
		}
		$content = isset( $commentdata['comment_content'] ) ? strtolower( $commentdata['comment_content'] ) : '';
		$author  = isset( $commentdata['comment_author'] ) ? strtolower( $commentdata['comment_author'] ) : '';

		$max_links = max( 0, (int) Helper::get_setting( 'antispam_max_links', 3 ) );
		$links     = preg_match_all( '#https?://#i', $content );
		if ( $links > $max_links ) {
			return 'spam';
		}

		$keywords = (array) Helper::get_setting( 'antispam_keywords', [] );
		foreach ( $keywords as $kw ) {
			$kw = strtolower( trim( (string) $kw ) );
			if ( '' !== $kw && ( false !== strpos( $content, $kw ) || false !== strpos( $author, $kw ) ) ) {
				return 'spam';
			}
		}

		// Reuse the link blocklist from the link scanner if present.
		$blocklist = (array) Helper::get_setting( 'link_blocklist', [] );
		foreach ( $blocklist as $domain ) {
			$domain = strtolower( trim( (string) $domain ) );
			if ( '' !== $domain && false !== strpos( $content, $domain ) ) {
				return 'spam';
			}
		}

		return $approved;
	}
}
