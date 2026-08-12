<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * API & access hardening.
 *
 * Closes the recon + non-interactive-auth surface that sits beside the normal
 * login form: the REST API, application passwords (which bypass 2FA and are
 * long-lived), and username enumeration via login error deltas.
 *
 * Each behaviour is individually gated by its own setting so activating the
 * module doesn't change anything until the site owner opts in.
 */
class ApiHardening {

	/** Transient key prefix for the per-IP REST rate-limit counter. */
	const RL_PREFIX = 'gemsec_restrl_';

	public static function init() {
		$self = new self();

		// --- Application passwords -------------------------------------
		if ( Helper::get_setting( 'app_pw_disabled', false ) ) {
			// Turn the feature off site-wide (also hides it from user profiles).
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		} else {
			// Log + optionally alert whenever a new application password is minted.
			add_action( 'wp_create_application_password', [ $self, 'on_app_password_created' ], 10, 4 );
			// Auto-expire stale application passwords on the daily cron.
			add_action( \GemSecurity\Installer::CRON_DAILY_SCAN, [ $self, 'prune_expired_app_passwords' ] );
		}

		// --- REST API rate limiting ------------------------------------
		if ( Helper::get_setting( 'rest_rate_limit_enabled', false ) ) {
			add_filter( 'rest_pre_dispatch', [ $self, 'rest_rate_limit' ], 10, 3 );
		}

		// --- Username-enumeration hardening ----------------------------
		if ( Helper::get_setting( 'login_errors_generic', false ) ) {
			add_filter( 'login_errors', [ $self, 'generic_login_error' ] );
		}
	}

	/**
	 * Whether application passwords are available at all in this WP build.
	 *
	 * @return bool
	 */
	public static function app_passwords_supported() {
		return class_exists( '\WP_Application_Passwords' );
	}

	/**
	 * Fires after a new application password is created for any user.
	 *
	 * @param int    $user_id
	 * @param array  $new_item     { uuid, name, created, ... }
	 * @param string $new_password Plaintext (ignored here).
	 * @param array  $args
	 */
	public function on_app_password_created( $user_id, $new_item, $new_password, $args ) {
		$name = isset( $new_item['name'] ) ? $new_item['name'] : '';
		Logger::log(
			'app_password_created',
			sprintf(
				/* translators: 1: application password label, 2: user id. */
				__( 'Application password "%1$s" was created for user #%2$d.', 'gemsecurity' ),
				$name,
				$user_id
			),
			Logger::SEVERITY_WARNING,
			[ 'user_id' => $user_id, 'context' => [ 'name' => $name ] ]
		);

		if ( ! Helper::get_setting( 'app_pw_alert_on_create', true ) ) {
			return;
		}

		$user = get_userdata( $user_id );
		$to   = get_option( 'admin_email' );
		wp_mail(
			$to,
			sprintf(
				/* translators: %s: site name. */
				__( '[%s] New application password created', 'gemsecurity' ),
				wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			),
			sprintf(
				/* translators: 1: label, 2: user login, 3: site url. */
				__( "An application password \"%1\$s\" was just created for user \"%2\$s\" on %3\$s.\n\nIf this wasn't expected, review it under GemSecurity → API & Access.", 'gemsecurity' ),
				$name,
				$user ? $user->user_login : $user_id,
				home_url()
			)
		);
	}

	/**
	 * Delete application passwords older than the configured max age.
	 */
	public function prune_expired_app_passwords() {
		if ( ! self::app_passwords_supported() ) {
			return;
		}
		$days = (int) Helper::get_setting( 'app_pw_max_age_days', 0 );
		if ( $days <= 0 ) {
			return;
		}
		$cutoff = time() - $days * DAY_IN_SECONDS;

		$user_ids = get_users( [ 'meta_key' => '_application_passwords', 'fields' => 'ID' ] ); // phpcs:ignore WordPress.DB.SlowDBQuery
		foreach ( $user_ids as $uid ) {
			$items = \WP_Application_Passwords::get_user_application_passwords( $uid );
			foreach ( $items as $item ) {
				if ( ! empty( $item['created'] ) && (int) $item['created'] < $cutoff ) {
					\WP_Application_Passwords::delete_application_password( $uid, $item['uuid'] );
					Logger::log(
						'app_password_expired',
						sprintf(
							/* translators: 1: label, 2: user id, 3: age in days. */
							__( 'Expired application password "%1$s" for user #%2$d (older than %3$d days).', 'gemsecurity' ),
							isset( $item['name'] ) ? $item['name'] : '',
							$uid,
							$days
						),
						Logger::SEVERITY_NOTICE,
						[ 'user_id' => $uid ]
					);
				}
			}
		}
	}

	/**
	 * Throttle REST API requests per IP for non-privileged callers.
	 *
	 * @param mixed            $result
	 * @param \WP_REST_Server  $server
	 * @param \WP_REST_Request $request
	 * @return mixed
	 */
	public function rest_rate_limit( $result, $server, $request ) {
		// Respect an already-computed response, and never throttle admins or the
		// plugin's own authenticated screens.
		if ( null !== $result || current_user_can( 'manage_options' ) ) {
			return $result;
		}

		$ip = Helper::get_ip_address();
		if ( '0.0.0.0' === $ip ) {
			return $result;
		}

		$max    = max( 1, (int) Helper::get_setting( 'rest_rate_limit_max', 120 ) );
		$window = max( 1, (int) Helper::get_setting( 'rest_rate_limit_window', 1 ) ); // minutes.
		$key    = self::RL_PREFIX . md5( $ip );
		$count  = (int) get_transient( $key );

		if ( $count >= $max ) {
			return new \WP_Error(
				'gemsecurity_rest_throttled',
				__( 'Too many requests. Please slow down.', 'gemsecurity' ),
				[ 'status' => 429 ]
			);
		}

		set_transient( $key, $count + 1, $window * MINUTE_IN_SECONDS );
		return $result;
	}

	/**
	 * Replace specific login errors with a generic message so an attacker can't
	 * tell valid usernames apart from wrong passwords.
	 *
	 * @return string
	 */
	public function generic_login_error() {
		return __( 'The username or password you entered is incorrect.', 'gemsecurity' );
	}
}
