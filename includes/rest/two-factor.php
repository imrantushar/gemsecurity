<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\TwoFactor as TwoFactorModule;
use GemSecurity\Security\Totp;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two-factor enrollment for the current user.
 */
class TwoFactor {

	/**
	 * GET /2fa — current user's 2FA status.
	 */
	public static function status() {
		$uid     = get_current_user_id();
		$enabled = (bool) get_user_meta( $uid, '_gemsec_2fa_enabled', true );
		$method  = get_user_meta( $uid, '_gemsec_2fa_method', true );
		$codes   = (array) get_user_meta( $uid, '_gemsec_2fa_backup_codes', true );
		$user    = wp_get_current_user();

		return rest_ensure_response( [
			'success'         => true,
			'enabled'         => $enabled,
			'method'          => $method ?: '',
			'backup_remaining' => count( $codes ),
			'enforced'        => TwoFactorModule::role_enforced( $user ),
			'system_enabled'  => (bool) \GemSecurity\Helper::get_setting( 'two_factor_enabled', false ),
		] );
	}

	/**
	 * POST /2fa/setup — generate a pending TOTP secret + QR URI.
	 */
	public static function setup() {
		$uid    = get_current_user_id();
		$user   = wp_get_current_user();
		$secret = Totp::generate_secret();
		update_user_meta( $uid, '_gemsec_2fa_secret_pending', $secret );

		$issuer = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
		$uri    = Totp::provisioning_uri( $secret, $user->user_email, $issuer );

		return rest_ensure_response( [
			'success' => true,
			'secret'  => $secret,
			'otpauth' => $uri,
		] );
	}

	/**
	 * POST /2fa/activate — verify a code against the pending secret and enable TOTP.
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function activate( $request ) {
		$uid    = get_current_user_id();
		$code   = preg_replace( '/\D/', '', (string) $request->get_param( 'code' ) );
		$secret = get_user_meta( $uid, '_gemsec_2fa_secret_pending', true );

		if ( ! $secret ) {
			return new \WP_Error( 'no_pending', __( 'Start setup first.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		if ( ! Totp::verify( $secret, $code, 1 ) ) {
			return new \WP_Error( 'bad_code', __( 'That code is incorrect. Check your authenticator app and try again.', 'gemsecurity' ), [ 'status' => 400 ] );
		}

		update_user_meta( $uid, '_gemsec_2fa_secret', $secret );
		delete_user_meta( $uid, '_gemsec_2fa_secret_pending' );
		update_user_meta( $uid, '_gemsec_2fa_method', 'totp' );
		update_user_meta( $uid, '_gemsec_2fa_enabled', 1 );

		$backup = TwoFactorModule::generate_backup_codes( $uid );

		\GemSecurity\Logger::log( '2fa_success', sprintf( 'Authenticator app enabled for "%s".', wp_get_current_user()->user_login ), \GemSecurity\Logger::SEVERITY_NOTICE );

		return rest_ensure_response( [ 'success' => true, 'backup_codes' => $backup ] );
	}

	/**
	 * POST /2fa/enable-email — enroll with email OTP (no app).
	 */
	public static function enable_email() {
		$uid = get_current_user_id();
		update_user_meta( $uid, '_gemsec_2fa_method', 'email' );
		update_user_meta( $uid, '_gemsec_2fa_enabled', 1 );
		delete_user_meta( $uid, '_gemsec_2fa_secret' );
		delete_user_meta( $uid, '_gemsec_2fa_secret_pending' );
		$backup = TwoFactorModule::generate_backup_codes( $uid );

		return rest_ensure_response( [ 'success' => true, 'backup_codes' => $backup ] );
	}

	/**
	 * POST /2fa/disable.
	 */
	public static function disable() {
		$uid = get_current_user_id();
		foreach ( [ '_gemsec_2fa_enabled', '_gemsec_2fa_method', '_gemsec_2fa_secret', '_gemsec_2fa_secret_pending', '_gemsec_2fa_backup_codes' ] as $m ) {
			delete_user_meta( $uid, $m );
		}
		\GemSecurity\Logger::log( '2fa_success', sprintf( 'Two-factor disabled for "%s".', wp_get_current_user()->user_login ), \GemSecurity\Logger::SEVERITY_NOTICE );
		return rest_ensure_response( [ 'success' => true ] );
	}

	/**
	 * POST /2fa/backup-codes — regenerate.
	 */
	public static function backup_codes() {
		if ( ! get_user_meta( get_current_user_id(), '_gemsec_2fa_enabled', true ) ) {
			return new \WP_Error( 'not_enabled', __( 'Enable two-factor first.', 'gemsecurity' ), [ 'status' => 400 ] );
		}
		$backup = TwoFactorModule::generate_backup_codes( get_current_user_id() );
		return rest_ensure_response( [ 'success' => true, 'backup_codes' => $backup ] );
	}
}
