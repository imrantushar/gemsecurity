<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * CAPTCHA on the login, registration and lost-password forms.
 *
 * Supports Google reCAPTCHA v2 (checkbox), reCAPTCHA v3 (score), hCaptcha and
 * Cloudflare Turnstile — all share a widget-div + server siteverify pattern.
 */
class Captcha {

	/**
	 * Provider integration metadata.
	 */
	public static function providers() {
		return [
			'recaptcha_v2' => [
				'script'  => 'https://www.google.com/recaptcha/api.js',
				'class'   => 'g-recaptcha',
				'field'   => 'g-recaptcha-response',
				'verify'  => 'https://www.google.com/recaptcha/api/siteverify',
				'v3'      => false,
			],
			'recaptcha_v3' => [
				'script'  => 'https://www.google.com/recaptcha/api.js?render=',
				'class'   => 'g-recaptcha-v3',
				'field'   => 'g-recaptcha-response',
				'verify'  => 'https://www.google.com/recaptcha/api/siteverify',
				'v3'      => true,
			],
			'hcaptcha'     => [
				'script'  => 'https://js.hcaptcha.com/1/api.js',
				'class'   => 'h-captcha',
				'field'   => 'h-captcha-response',
				'verify'  => 'https://api.hcaptcha.com/siteverify',
				'v3'      => false,
			],
			'turnstile'    => [
				'script'  => 'https://challenges.cloudflare.com/turnstile/v0/api.js',
				'class'   => 'cf-turnstile',
				'field'   => 'cf-turnstile-response',
				'verify'  => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
				'v3'      => false,
			],
		];
	}

	public static function init() {
		if ( ! Helper::get_setting( 'captcha_enabled', false ) ) {
			return;
		}
		if ( ! self::is_configured() ) {
			return;
		}
		$self = new self();

		add_action( 'login_enqueue_scripts', [ $self, 'enqueue' ] );

		if ( Helper::get_setting( 'captcha_on_login', true ) ) {
			add_action( 'login_form', [ $self, 'render_widget' ] );
			add_filter( 'authenticate', [ $self, 'verify_login' ], 25, 1 );
		}
		if ( Helper::get_setting( 'captcha_on_register', true ) ) {
			add_action( 'register_form', [ $self, 'render_widget' ] );
			add_filter( 'registration_errors', [ $self, 'verify_register' ], 10, 1 );
		}
		if ( Helper::get_setting( 'captcha_on_lostpassword', false ) ) {
			add_action( 'lostpassword_form', [ $self, 'render_widget' ] );
			add_action( 'lostpassword_post', [ $self, 'verify_lostpassword' ], 10, 1 );
		}
	}

	public static function is_configured() {
		return Helper::get_setting( 'captcha_site_key', '' ) && Helper::get_setting( 'captcha_secret_key', '' );
	}

	private function provider() {
		$key = Helper::get_setting( 'captcha_provider', 'recaptcha_v2' );
		$providers = self::providers();
		return isset( $providers[ $key ] ) ? $providers[ $key ] : $providers['recaptcha_v2'];
	}

	/* ----------------------------- Render ------------------------------ */

	public function enqueue() {
		$p        = $this->provider();
		$site_key = Helper::get_setting( 'captcha_site_key', '' );
		$src      = $p['v3'] ? $p['script'] . rawurlencode( $site_key ) : $p['script'];
		wp_enqueue_script( 'gemsecurity-captcha', $src, [], null, true );

		if ( $p['v3'] ) {
			$inline = sprintf(
				'document.addEventListener("submit",function(e){var f=e.target;if(!f||f.querySelector(".gs-captcha-token"))return;},true);' .
				'window.gemsecRecaptchaV3=function(form){return new Promise(function(res){grecaptcha.ready(function(){grecaptcha.execute("%s",{action:"login"}).then(function(t){res(t);});});});};',
				esc_js( $site_key )
			);
			wp_add_inline_script( 'gemsecurity-captcha', $inline );
		}

		// Minimal spacing for the widget on wp-login.php.
		wp_add_inline_style( 'login', '.gs-captcha{margin:0 0 16px;}' );
	}

	public function render_widget() {
		$p        = $this->provider();
		$site_key = esc_attr( Helper::get_setting( 'captcha_site_key', '' ) );

		if ( $p['v3'] ) {
			// Hidden token populated on submit.
			echo '<div class="gs-captcha"></div>';
			printf(
				'<input type="hidden" name="%s" class="gs-captcha-token" value="" />',
				esc_attr( $p['field'] )
			);
			$field = esc_js( $p['field'] );
			echo '<script>(function(){var fld=document.querySelector(".gs-captcha-token");if(!fld)return;var form=fld.form;if(!form)return;form.addEventListener("submit",function(e){if(fld.value)return;e.preventDefault();window.gemsecRecaptchaV3&&window.gemsecRecaptchaV3(form).then(function(t){fld.value=t;form.submit();});});})();</script>';
			return;
		}

		printf(
			'<div class="gs-captcha %s" data-sitekey="%s"></div>',
			esc_attr( $p['class'] ),
			$site_key
		);
	}

	/* ---------------------------- Verify ------------------------------- */

	/**
	 * @param \WP_User|\WP_Error|null $user
	 * @return \WP_User|\WP_Error|null
	 */
	public function verify_login( $user ) {
		// Only guard real login-form submissions.
		if ( empty( $_POST['log'] ) || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
			return $user;
		}
		// Don't pile errors onto an already-failed auth.
		if ( is_wp_error( $user ) ) {
			return $user;
		}
		if ( ! $this->passes() ) {
			$this->log_fail( 'login' );
			return new \WP_Error( 'gemsecurity_captcha', __( '<strong>Error:</strong> Please complete the CAPTCHA challenge.', 'gemsecurity' ) );
		}
		return $user;
	}

	public function verify_register( $errors ) {
		if ( ! $this->passes() ) {
			$this->log_fail( 'register' );
			$errors->add( 'gemsecurity_captcha', __( '<strong>Error:</strong> Please complete the CAPTCHA challenge.', 'gemsecurity' ) );
		}
		return $errors;
	}

	public function verify_lostpassword( $errors ) {
		if ( is_wp_error( $errors ) && ! $this->passes() ) {
			$this->log_fail( 'lostpassword' );
			$errors->add( 'gemsecurity_captcha', __( '<strong>Error:</strong> Please complete the CAPTCHA challenge.', 'gemsecurity' ) );
		}
	}

	/**
	 * Verify the submitted token with the provider.
	 */
	private function passes() {
		$p     = $this->provider();
		$token = isset( $_POST[ $p['field'] ] ) ? sanitize_text_field( wp_unslash( $_POST[ $p['field'] ] ) ) : '';
		if ( '' === $token ) {
			return false;
		}

		$response = wp_remote_post( $p['verify'], [
			'timeout' => 10,
			'body'    => [
				'secret'   => Helper::get_setting( 'captcha_secret_key', '' ),
				'response' => $token,
				'remoteip' => Helper::get_ip_address(),
			],
		] );

		if ( is_wp_error( $response ) ) {
			// Fail open on network error to avoid locking out admins.
			return true;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['success'] ) ) {
			return false;
		}

		// reCAPTCHA v3 score gate.
		if ( ! empty( $p['v3'] ) && isset( $body['score'] ) ) {
			$threshold = (float) Helper::get_setting( 'captcha_v3_threshold', 0.5 );
			return (float) $body['score'] >= $threshold;
		}

		return true;
	}

	private function log_fail( $where ) {
		Logger::log(
			'captcha_failed',
			sprintf( 'CAPTCHA verification failed on %s form.', $where ),
			Logger::SEVERITY_NOTICE,
			[ 'user_id' => 0 ]
		);
	}
}
