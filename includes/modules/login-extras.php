<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Mailer;
use GemSecurity\Logger;
use GemSecurity\Security\BanList;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Login-security extras that sit alongside the core brute-force lockout:
 *  - Login honeypot (free): a hidden field bots fill in → instant strike/deny.
 */
class LoginExtras {

	const HONEYPOT    = 'gemsec_hp_url';

	public static function init() {
		$self = new self();

		if ( Helper::get_setting( 'login_honeypot_enabled', true ) ) {
			add_action( 'login_form', [ $self, 'honeypot_field' ] );
			add_action( 'register_form', [ $self, 'honeypot_field' ] );
			add_filter( 'authenticate', [ $self, 'honeypot_check' ], 5 );
		}

	}

	/* ---------------- Honeypot ---------------- */

	public function honeypot_field() {
		// Off-screen, aria-hidden, not tab-reachable — humans never fill it.
		echo '<div style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true">'
			. '<label>' . esc_html__( 'Leave this field empty', 'gemsecurity' ) . '</label>'
			. '<input type="text" name="' . esc_attr( self::HONEYPOT ) . '" value="" tabindex="-1" autocomplete="off" />'
			. '</div>';
	}

	/**
	 * @param mixed $user
	 * @return mixed
	 */
	public function honeypot_check( $user ) {
		if ( empty( $_POST[ self::HONEYPOT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return $user;
		}
		$ip = Helper::get_ip_address();
		Logger::log( 'login_honeypot', sprintf( 'Login honeypot tripped by %s.', $ip ), Logger::SEVERITY_WARNING, [ 'user_id' => 0, 'ip_address' => $ip ] );
		if ( class_exists( '\GemSecurity\Security\BanList' ) ) {
			BanList::record_strike( $ip, 'login honeypot' );
		}
		return new \WP_Error( 'gemsec_honeypot', __( 'Access denied.', 'gemsecurity' ) );
	}
}
