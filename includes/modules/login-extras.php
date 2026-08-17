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
 *  - Trusted devices / new-device alerts (Pro): fingerprint each successful
 *    login and email the user when an unrecognised device signs in.
 *  - Magic-link recovery (Pro): an admin-issued, single-use, expiring login
 *    link that lets a legitimate user in even if their IP is locked out.
 */
class LoginExtras {

	const DEVICE_META = '_gemsec_devices';
	const MAGIC_META  = '_gemsec_magic_login';
	const HONEYPOT    = 'gemsec_hp_url';

	public static function init() {
		$self = new self();

		if ( Helper::get_setting( 'login_honeypot_enabled', true ) ) {
			add_action( 'login_form', [ $self, 'honeypot_field' ] );
			add_action( 'register_form', [ $self, 'honeypot_field' ] );
			add_filter( 'authenticate', [ $self, 'honeypot_check' ], 5 );
		}

		// Trusted devices + magic link are Pro.
		if ( Helper::is_pro_active() ) {
			if ( Helper::get_setting( 'trusted_devices_enabled', false ) ) {
				add_action( 'wp_login', [ $self, 'track_device' ], 10, 2 );
			}
			if ( Helper::get_setting( 'magic_link_enabled', false ) ) {
				add_action( 'login_init', [ $self, 'maybe_consume_magic_link' ], 1 );
			}
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

	/* ---------------- Trusted devices ---------------- */

	/**
	 * @param string   $user_login
	 * @param \WP_User $user
	 */
	public function track_device( $user_login, $user ) {
		if ( ! ( $user instanceof \WP_User ) ) {
			return;
		}
		$ua  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$ip  = Helper::get_ip_address();
		$sig = substr( hash_hmac( 'sha256', $ua . '|' . $this->ip_class( $ip ), wp_salt( 'auth' ) ), 0, 20 );

		$devices = get_user_meta( $user->ID, self::DEVICE_META, true );
		$devices = is_array( $devices ) ? $devices : [];
		$known   = wp_list_pluck( $devices, 'sig' );

		if ( in_array( $sig, $known, true ) ) {
			return;
		}

		$first_ever = empty( $devices );
		$devices[]  = [ 'sig' => $sig, 'ua' => substr( $ua, 0, 200 ), 'ip' => $ip, 'first_seen' => gmdate( 'Y-m-d H:i:s' ) ];
		update_user_meta( $user->ID, self::DEVICE_META, array_slice( $devices, -20 ) );

		// Don't alert on the very first device we ever record for a user.
		if ( ! $first_ever ) {
			Logger::log(
				'new_device_login',
				sprintf( 'New device signed in as "%s" from %s.', $user->user_login, $ip ),
				Logger::SEVERITY_WARNING,
				[ 'user_id' => $user->ID, 'ip_address' => $ip, 'context' => [ 'ua' => $ua ] ]
			);
			if ( Helper::get_setting( 'trusted_devices_alert', true ) && $user->user_email ) {
				Mailer::send(
					$user->user_email,
					'💻',
					__( 'New device sign-in', 'gemsecurity' ),
					[
						[
							'type' => 'paragraph',
							'text' => __( 'A device that has not been seen before just signed in to your account.', 'gemsecurity' ),
						],
						[
							'type'    => 'table',
							'heading' => __( 'Device', 'gemsecurity' ),
							'rows'    => [
								[ __( 'IP address', 'gemsecurity' ), esc_html( $ip ) ],
								[ __( 'Device', 'gemsecurity' ), esc_html( $ua ) ],
								[ __( 'Time', 'gemsecurity' ), esc_html( gmdate( 'Y-m-d H:i:s' ) . ' UTC' ) ],
							],
						],
						[
							'type' => 'paragraph',
							'text' => __( 'If this was not you, change your password immediately.', 'gemsecurity' ),
						],
					]
				);
			}
		}
	}

	/** Coarse IP class so a dynamic last octet doesn't churn device sigs. */
	private function ip_class( $ip ) {
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts = explode( '.', $ip );
			return $parts[0] . '.' . $parts[1] . '.' . $parts[2];
		}
		return $ip;
	}

	/* ---------------- Magic-link recovery ---------------- */

	/**
	 * Issue a one-time, 15-minute login link for a user and email it. Called
	 * from the REST controller (admin only).
	 *
	 * @param int $user_id
	 * @return true|\WP_Error
	 */
	public static function issue_magic_link( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user || ! $user->user_email ) {
			return new \WP_Error( 'gemsec_no_user', __( 'That user has no email address.', 'gemsecurity' ) );
		}
		$token = wp_generate_password( 40, false, false );
		update_user_meta( $user_id, self::MAGIC_META, [
			'hash'    => hash_hmac( 'sha256', $token, wp_salt( 'auth' ) ),
			'expires' => time() + 15 * MINUTE_IN_SECONDS,
		] );

		$link = add_query_arg(
			[ 'gemsec_magic' => rawurlencode( $token ), 'uid' => $user_id ],
			wp_login_url()
		);
		$sent = Mailer::send(
			$user->user_email,
			'🔗',
			__( 'Your one-time sign-in link', 'gemsecurity' ),
			[
				[
					'type' => 'paragraph',
					'text' => __( 'Use the button below within 15 minutes to sign in. The link works once.', 'gemsecurity' ),
				],
				[
					'type'  => 'button',
					'url'   => $link,
					'label' => __( 'Sign in', 'gemsecurity' ),
				],
				[
					'type' => 'paragraph',
					'text' => __( 'If you did not request this, ignore the email — nothing has changed.', 'gemsecurity' ),
				],
			]
		);
		Logger::log( 'magic_link_issued', sprintf( 'Magic login link issued for user #%d.', $user_id ), Logger::SEVERITY_NOTICE, [ 'user_id' => $user_id ] );
		return $sent ? true : new \WP_Error( 'gemsec_mail_failed', __( 'The email could not be sent.', 'gemsecurity' ) );
	}

	/** Validate and consume a magic link on the login screen. */
	public function maybe_consume_magic_link() {
		if ( empty( $_GET['gemsec_magic'] ) || empty( $_GET['uid'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return;
		}
		$uid   = absint( $_GET['uid'] ); // phpcs:ignore WordPress.Security.NonceVerification
		$token = sanitize_text_field( wp_unslash( $_GET['gemsec_magic'] ) ); // phpcs:ignore WordPress.Security.NonceVerification
		$meta  = get_user_meta( $uid, self::MAGIC_META, true );

		$ok = is_array( $meta )
			&& ! empty( $meta['hash'] )
			&& ! empty( $meta['expires'] )
			&& time() < (int) $meta['expires']
			&& hash_equals( $meta['hash'], hash_hmac( 'sha256', $token, wp_salt( 'auth' ) ) );

		// Single-use: always clear on any attempt.
		delete_user_meta( $uid, self::MAGIC_META );

		if ( ! $ok ) {
			Logger::log( 'magic_link_invalid', sprintf( 'Invalid/expired magic link for user #%d from %s.', $uid, Helper::get_ip_address() ), Logger::SEVERITY_WARNING, [ 'user_id' => $uid ] );
			return;
		}

		wp_set_current_user( $uid );
		wp_set_auth_cookie( $uid, false );
		Logger::log( 'magic_link_used', sprintf( 'User #%d signed in via magic link.', $uid ), Logger::SEVERITY_NOTICE, [ 'user_id' => $uid ] );
		wp_safe_redirect( admin_url() );
		exit;
	}
}
