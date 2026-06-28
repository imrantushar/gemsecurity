<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Password policy + breached-password protection.
 *
 * Enforces a minimum strength on every password-set path (profile, user edit,
 * password reset) and optionally rejects passwords found in the Have I Been
 * Pwned breach corpus (via k-anonymity — only a 5-char SHA-1 prefix is sent).
 * Optionally flags expired passwords with an admin notice.
 */
class PasswordPolicy {

	const PW_SET_META = '_gemsec_pw_set';

	public static function init() {
		if ( ! Helper::get_setting( 'password_policy_enabled', false ) ) {
			return;
		}
		$self = new self();

		add_action( 'user_profile_update_errors', [ $self, 'validate_profile' ], 10, 3 );
		add_action( 'validate_password_reset', [ $self, 'validate_reset' ], 10, 2 );
		add_action( 'after_password_reset', [ $self, 'stamp' ], 10, 1 );
		add_action( 'profile_update', [ $self, 'stamp_on_update' ], 10, 1 );
		add_action( 'admin_notices', [ $self, 'expiry_notice' ] );
	}

	/* --------------------------- Validation --------------------------- */

	/**
	 * @param \WP_Error $errors
	 * @param bool      $update
	 * @param \stdClass $user
	 */
	public function validate_profile( $errors, $update, $user ) {
		$pw = isset( $_POST['pass1'] ) ? (string) $_POST['pass1'] : '';
		if ( '' === $pw || $errors->get_error_code() ) {
			return;
		}
		$this->check( $pw, $errors );
	}

	/**
	 * @param \WP_Error $errors
	 * @param \WP_User|\WP_Error $user
	 */
	public function validate_reset( $errors, $user ) {
		$pw = isset( $_POST['pass1'] ) ? (string) $_POST['pass1'] : '';
		if ( '' === $pw ) {
			return;
		}
		$this->check( $pw, $errors );
	}

	/**
	 * Apply every enabled rule, adding messages to $errors.
	 *
	 * @param string    $pw
	 * @param \WP_Error $errors
	 */
	private function check( $pw, $errors ) {
		$min = max( 6, (int) Helper::get_setting( 'password_min_length', 10 ) );
		if ( strlen( $pw ) < $min ) {
			$errors->add( 'gemsec_pw_short', sprintf( __( '<strong>Error:</strong> Password must be at least %d characters.', 'gemsecurity' ), $min ) );
		}

		if ( Helper::get_setting( 'password_require_complexity', true ) ) {
			$missing = [];
			if ( ! preg_match( '/[a-z]/', $pw ) ) { $missing[] = __( 'a lowercase letter', 'gemsecurity' ); }
			if ( ! preg_match( '/[A-Z]/', $pw ) ) { $missing[] = __( 'an uppercase letter', 'gemsecurity' ); }
			if ( ! preg_match( '/[0-9]/', $pw ) ) { $missing[] = __( 'a number', 'gemsecurity' ); }
			if ( ! preg_match( '/[^a-zA-Z0-9]/', $pw ) ) { $missing[] = __( 'a symbol', 'gemsecurity' ); }
			if ( $missing ) {
				$errors->add( 'gemsec_pw_weak', sprintf( __( '<strong>Error:</strong> Password must include %s.', 'gemsecurity' ), implode( ', ', $missing ) ) );
			}
		}

		if ( Helper::get_setting( 'password_check_breached', true ) && $this->is_breached( $pw ) ) {
			$errors->add( 'gemsec_pw_breached', __( '<strong>Error:</strong> This password has appeared in a known data breach. Please choose a different one.', 'gemsecurity' ) );
		}
	}

	/**
	 * Have I Been Pwned range query (k-anonymity). Fail-open on error.
	 *
	 * @param string $pw
	 * @return bool
	 */
	private function is_breached( $pw ) {
		$hash   = strtoupper( sha1( $pw ) );
		$prefix = substr( $hash, 0, 5 );
		$suffix = substr( $hash, 5 );

		$response = wp_remote_get( 'https://api.pwnedpasswords.com/range/' . $prefix, [
			'timeout' => 5,
			'headers' => [ 'Add-Padding' => 'true' ],
		] );
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		foreach ( preg_split( '/\r?\n/', wp_remote_retrieve_body( $response ) ) as $line ) {
			$parts = explode( ':', trim( $line ) );
			if ( isset( $parts[0] ) && hash_equals( $suffix, strtoupper( $parts[0] ) ) ) {
				return (int) ( $parts[1] ?? 0 ) > 0;
			}
		}
		return false;
	}

	/* ----------------------------- Expiry ----------------------------- */

	public function stamp( $user ) {
		if ( $user instanceof \WP_User ) {
			update_user_meta( $user->ID, self::PW_SET_META, time() );
		}
	}

	public function stamp_on_update( $user_id ) {
		if ( ! empty( $_POST['pass1'] ) ) {
			update_user_meta( $user_id, self::PW_SET_META, time() );
		}
	}

	public function expiry_notice() {
		$days = (int) Helper::get_setting( 'password_expiry_days', 0 );
		if ( $days <= 0 || ! current_user_can( 'read' ) ) {
			return;
		}
		$set = (int) get_user_meta( get_current_user_id(), self::PW_SET_META, true );
		if ( ! $set ) {
			// Unknown — stamp now so the clock starts.
			update_user_meta( get_current_user_id(), self::PW_SET_META, time() );
			return;
		}
		if ( ( time() - $set ) > $days * DAY_IN_SECONDS ) {
			printf(
				'<div class="notice notice-warning"><p>%s <a href="%s">%s</a></p></div>',
				esc_html__( 'Your password has expired under the site security policy.', 'gemsecurity' ),
				esc_url( admin_url( 'profile.php' ) ),
				esc_html__( 'Change it now', 'gemsecurity' )
			);
		}
	}
}
