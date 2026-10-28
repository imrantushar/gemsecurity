<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Mailer;
use GemSecurity\Logger;
use GemSecurity\Store;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * API & access hardening.
 *
 * Closes the non-interactive-auth surface that sits beside the normal login
 * form: the REST API and application passwords, which bypass the login form,
 * two-factor and CAPTCHA and are long-lived.
 *
 * Username-enumeration hardening lives with the firewall's other recon
 * switches (author scans, the REST users endpoint) rather than here.
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
			// Priority 20: WordPress core registers __return_true at priority 10
			// on `init`, so running after it ensures our false wins.
			add_filter( 'wp_is_application_passwords_available', '__return_false', 20 );
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

		Mailer::send(
			\GemSecurity\Mailer::recipient(),
			'🔐',
			__( 'New application password created', 'gemsecurity' ),
			[
				[
					'type' => 'paragraph',
					'text' => sprintf(
						/* translators: 1: password label, 2: username. */
						__( 'An application password <strong>%1$s</strong> was just created for <strong>%2$s</strong>. Application passwords bypass the login form, two-factor and CAPTCHA.', 'gemsecurity' ),
						esc_html( $name ),
						esc_html( $user ? $user->user_login : (string) $user_id )
					),
				],
				[
					'type' => 'paragraph',
					'text' => __( 'If this was not expected, revoke it now.', 'gemsecurity' ),
				],
				[
					'type'  => 'button',
					'url'   => admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG . '-api-hardening' ),
					'label' => __( 'Review application passwords', 'gemsecurity' ),
				],
			]
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
		$count  = (int) Store::get( $key );

		if ( $count >= $max ) {
			return new \WP_Error(
				'gemsecurity_rest_throttled',
				__( 'Too many requests. Please slow down.', 'gemsecurity' ),
				[ 'status' => 429 ]
			);
		}

		Store::set( $key, $count + 1, $window * MINUTE_IN_SECONDS );
		return $result;
	}
}
