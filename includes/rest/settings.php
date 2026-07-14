<?php
namespace GemSecurity\Rest;

use GemSecurity\Installer;
use GemSecurity\Modules\AdminGuard;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings REST controller.
 */
class Settings {

	/**
	 * Field type map used for sanitisation. Anything not listed is ignored.
	 */
	private static function schema() {
		$schema = [
			// Firewall / hardening.
			'firewall_enabled'              => 'bool',
			'ip_blocklist'                  => 'ip_list',
			'xmlrpc_disabled'               => 'bool',
			'disable_file_editing'          => 'bool',
			'block_author_enumeration'      => 'bool',
			'disable_user_rest'             => 'bool',
			'hide_wp_version'               => 'bool',
			'disable_application_passwords' => 'bool',

			// Login security.
			'login_attempts_enabled'        => 'bool',
			'login_attempts_limit'          => 'int',
			'login_lockout_duration'        => 'int',
			'admin_login_alert_enabled'     => 'bool',
			'admin_login_alert_email'       => 'email',
			'admin_session_timeout_enabled' => 'bool',
			'admin_session_timeout_hours'   => 'int',

			// Admin whitelist guard.
			'admin_whitelist_enabled'       => 'bool',
			'admin_whitelist'               => 'email_list',
			'rogue_admin_action'            => 'enum:demote,delete',
			'notify_on_rogue_admin'         => 'bool',
			'hidden_admin_detection'        => 'bool',
			'notify_on_hidden_admin'        => 'bool',

			// Scanner.
			'scanner_auto_scan'             => 'bool',

			// Logs / audit.
			'logs_retention_days'           => 'int',
			'audit_log_enabled'             => 'bool',
			'audit_content'                 => 'bool',
			'audit_plugins_themes'          => 'bool',
			'audit_users'                   => 'bool',
			'audit_settings'                => 'bool',

			// Security headers.
			'security_headers_enabled'      => 'bool',
			'header_x_frame_options'        => 'enum:SAMEORIGIN,DENY,off',
			'header_x_content_type_options' => 'bool',
			'header_referrer_policy'        => 'text',
			'header_permissions_policy'     => 'text',
			'header_hsts_enabled'           => 'bool',
			'header_hsts_max_age'           => 'int',
			'header_hsts_subdomains'        => 'bool',
			'header_hsts_preload'           => 'bool',
			'header_csp_enabled'            => 'bool',
			'header_csp_value'              => 'textarea',
			'header_csp_report_only'        => 'bool',

			// CAPTCHA.
			'captcha_enabled'               => 'bool',
			'captcha_provider'              => 'enum:recaptcha_v2,recaptcha_v3,hcaptcha,turnstile',
			'captcha_site_key'              => 'text',
			'captcha_secret_key'            => 'text',
			'captcha_on_login'              => 'bool',
			'captcha_on_register'           => 'bool',
			'captcha_on_lostpassword'       => 'bool',
			'captcha_v3_threshold'          => 'float',

			// Two-factor.
			'two_factor_enabled'            => 'bool',
			'two_factor_enforced_roles'     => 'slug_list',

			// Social / OAuth login.
			'social_login_enabled'          => 'bool',
			'social_allow_registration'     => 'bool',
			'social_link_by_email'          => 'bool',
			'social_default_role'           => 'text',
			'social_google_enabled'         => 'bool',
			'social_google_client_id'       => 'text',
			'social_google_client_secret'   => 'text',
			'social_facebook_enabled'       => 'bool',
			'social_facebook_client_id'     => 'text',
			'social_facebook_client_secret' => 'text',
			'social_github_enabled'         => 'bool',
			'social_github_client_id'       => 'text',
			'social_github_client_secret'   => 'text',
			'social_twitter_enabled'        => 'bool',
			'social_twitter_client_id'      => 'text',
			'social_twitter_client_secret'  => 'text',

			// Vulnerability scanner.
			'vuln_scan_enabled'             => 'bool',

			// WAF / threat defense.
			'waf_enabled'                   => 'bool',
			'waf_block_sqli'                => 'bool',
			'waf_block_xss'                 => 'bool',
			'waf_block_lfi'                 => 'bool',
			'waf_block_rce'                 => 'bool',
			'waf_inspect_body'              => 'bool',
			'rate_limit_enabled'            => 'bool',
			'rate_limit_max'                => 'int',
			'rate_limit_window'             => 'int',
			'throttle_404_enabled'          => 'bool',
			'throttle_404_max'              => 'int',
			'throttle_404_window'           => 'int',
			'block_bad_bots'                => 'bool',
			'block_empty_ua'                => 'bool',
			'bot_blocklist'                 => 'array',
			'mu_loader_enabled'             => 'bool',
			'autoban_enabled'               => 'bool',
			'autoban_threshold'             => 'int',
			'autoban_window'                => 'int',
			'autoban_duration'              => 'int',

			// Password policy.
			'password_policy_enabled'       => 'bool',
			'password_min_length'           => 'int',
			'password_require_complexity'   => 'bool',
			'password_check_breached'       => 'bool',
			'password_expiry_days'          => 'int',

			// Sessions.
			'idle_timeout_enabled'          => 'bool',
			'idle_timeout_minutes'          => 'int',

			// Custom login URL.
			'custom_login_enabled'          => 'bool',
			'custom_login_slug'             => 'text',

			// Alerts + digest.
			'alerts_enabled'                => 'bool',
			'alert_min_severity'            => 'enum:critical,warning,notice',
			'alert_to_email'                => 'email',
			'alert_slack_webhook'           => 'text',
			'alert_telegram_token'          => 'text',
			'alert_telegram_chat'           => 'text',
			'alert_webhook_url'             => 'text',
			'digest_enabled'                => 'bool',

			// Lockdown + backup.
			'lockdown_enabled'              => 'bool',
			'lockdown_message'              => 'textarea',
			'backup_before_updates'         => 'bool',

			// Geolocation.
			'geo_enabled'                   => 'bool',
			'geo_whitelist_login_enabled'   => 'bool',
			'geo_block_site_enabled'        => 'bool',
			'geo_block_unknown'             => 'bool',
			'geo_whitelist_block_admins'    => 'bool',
			'geo_allowed_countries'         => 'country_list',
			'geo_user_lock_enabled'         => 'bool',
			'geo_user_lock_action'          => 'enum:verify,block',
		];

		/**
		 * Allow addons (Pro) to register their own settings keys + sanitiser
		 * types. Values use the same type tokens as the core schema
		 * (bool, int, float, text, textarea, email, *_list, enum:a,b).
		 *
		 * @param array $schema
		 */
		return apply_filters( 'gemsecurity/settings_schema', $schema );
	}

	/**
	 * GET /settings
	 */
	public static function get() {
		$settings = get_option( GEMSECURITY_SETTINGS_NAME, [] );
		if ( ! is_array( $settings ) ) {
			$settings = [];
		}
		$settings = array_merge( Installer::default_settings(), $settings );

		return rest_ensure_response( [
			'success'  => true,
			'settings' => $settings,
		] );
	}

	/**
	 * POST /settings
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function save( $request ) {
		$incoming = $request->get_param( 'settings' );
		if ( ! is_array( $incoming ) ) {
			$incoming = $request->get_json_params();
			$incoming = isset( $incoming['settings'] ) ? $incoming['settings'] : [];
		}

		$current = get_option( GEMSECURITY_SETTINGS_NAME, [] );
		if ( ! is_array( $current ) ) {
			$current = [];
		}
		$current = array_merge( Installer::default_settings(), $current );

		$was_whitelist_enabled = ! empty( $current['admin_whitelist_enabled'] );
		$was_mu_enabled        = ! empty( $current['mu_loader_enabled'] );

		$merged = array_merge( $current, self::sanitize_all( $incoming ) );

		// When the whitelist guard is switched on and the list is empty, seed it
		// with every current administrator so no legitimate admin is removed.
		$now_enabled = ! empty( $merged['admin_whitelist_enabled'] );
		if ( $now_enabled && ! $was_whitelist_enabled && empty( $merged['admin_whitelist'] ) ) {
			$merged['admin_whitelist'] = AdminGuard::current_admin_emails();
		}

		// Install/remove the extended-protection mu-plugin when toggled.
		$now_mu = ! empty( $merged['mu_loader_enabled'] );
		if ( $now_mu !== $was_mu_enabled ) {
			$ok = \GemSecurity\Security\MuLoader::sync( $now_mu );
			if ( ! $ok ) {
				// Couldn't write the file — reflect reality so the UI doesn't lie.
				$merged['mu_loader_enabled'] = \GemSecurity\Security\MuLoader::is_installed();
			}
		}

		update_option( GEMSECURITY_SETTINGS_NAME, $merged );

		return rest_ensure_response( [
			'success'  => true,
			'settings' => $merged,
		] );
	}

	/* --------------------------------------------------------------------- */
	/* Sanitisers                                                             */
	/* --------------------------------------------------------------------- */

	/**
	 * Run all incoming values through the schema sanitizers, returning only known keys.
	 *
	 * @param array $incoming
	 * @return array
	 */
	private static function sanitize_all( array $incoming ): array {
		$clean = [];
		foreach ( self::schema() as $key => $type ) {
			if ( ! array_key_exists( $key, $incoming ) ) {
				continue;
			}
			$clean[ $key ] = self::sanitize( $type, $incoming[ $key ] );
		}
		return $clean;
	}

	private static function sanitize( $type, $value ) {
		if ( 0 === strpos( $type, 'enum:' ) ) {
			$allowed = explode( ',', substr( $type, 5 ) );
			$value   = sanitize_text_field( (string) $value );
			return in_array( $value, $allowed, true ) ? $value : $allowed[0];
		}

		switch ( $type ) {
			case 'bool':
				return (bool) rest_sanitize_boolean( $value );

			case 'int':
				return max( 0, absint( $value ) );

			case 'float':
				return max( 0, (float) $value );

			case 'array':
				$list = is_array( $value ) ? $value : [];
				$out  = [];
				foreach ( $list as $item ) {
					$item = sanitize_text_field( (string) $item );
					if ( '' !== $item ) {
						$out[] = $item;
					}
				}
				return array_values( $out );

			case 'textarea':
				return sanitize_textarea_field( (string) $value );

			case 'slug_list':
				$list = self::to_array( $value );
				$out  = [];
				foreach ( $list as $item ) {
					$slug = sanitize_key( trim( (string) $item ) );
					if ( '' !== $slug ) {
						$out[] = $slug;
					}
				}
				return array_values( array_unique( $out ) );

			case 'country_list':
				$list = self::to_array( $value );
				$out  = [];
				foreach ( $list as $item ) {
					$code = strtoupper( substr( trim( (string) $item ), 0, 2 ) );
					if ( preg_match( '/^[A-Z]{2}$/', $code ) && ! in_array( $code, $out, true ) ) {
						$out[] = $code;
					}
				}
				return $out;

			case 'email':
				$value = sanitize_email( (string) $value );
				return is_email( $value ) ? $value : '';

			case 'email_list':
				$list = self::to_array( $value );
				$out  = [];
				foreach ( $list as $item ) {
					$email = sanitize_email( trim( (string) $item ) );
					if ( is_email( $email ) ) {
						$out[] = strtolower( $email );
					}
				}
				return array_values( array_unique( $out ) );

			case 'ip_list':
				$list = self::to_array( $value );
				$out  = [];
				foreach ( $list as $item ) {
					$ip = trim( (string) $item );
					if ( '' === $ip ) {
						continue;
					}
					// Allow plain IPs and CIDR ranges.
					if ( false !== strpos( $ip, '/' ) ) {
						list( $addr ) = explode( '/', $ip, 2 );
						if ( filter_var( $addr, FILTER_VALIDATE_IP ) ) {
							$out[] = $ip;
						}
					} elseif ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
						$out[] = $ip;
					}
				}
				return array_values( array_unique( $out ) );

			default:
				return sanitize_text_field( (string) $value );
		}
	}

	/**
	 * Accept either an array or a newline/comma separated string.
	 *
	 * @param mixed $value
	 * @return array
	 */
	private static function to_array( $value ) {
		if ( is_array( $value ) ) {
			return $value;
		}
		return preg_split( '/[\r\n,]+/', (string) $value );
	}
}
