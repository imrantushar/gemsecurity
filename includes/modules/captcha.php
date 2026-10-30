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
				'script'  => 'https://www.google.com/recaptcha/api.js', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- provider API script must load from its own host; disclosed in readme.
				'class'   => 'g-recaptcha',
				'field'   => 'g-recaptcha-response',
				'verify'  => 'https://www.google.com/recaptcha/api/siteverify',
				'v3'      => false,
			],
			'recaptcha_v3' => [
				'script'  => 'https://www.google.com/recaptcha/api.js?render=', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- provider API script must load from its own host; disclosed in readme.
				'class'   => 'g-recaptcha-v3',
				'field'   => 'g-recaptcha-response',
				'verify'  => 'https://www.google.com/recaptcha/api/siteverify',
				'v3'      => true,
			],
			'hcaptcha'     => [
				'script'  => 'https://js.hcaptcha.com/1/api.js', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- provider API script must load from its own host; disclosed in readme.
				'class'   => 'h-captcha',
				'field'   => 'h-captcha-response',
				'verify'  => 'https://api.hcaptcha.com/siteverify',
				'v3'      => false,
			],
			'turnstile'    => [
				'script'  => 'https://challenges.cloudflare.com/turnstile/v0/api.js', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- provider API script must load from its own host; disclosed in readme.
				'class'   => 'cf-turnstile',
				'field'   => 'cf-turnstile-response',
				'verify'  => 'https://challenges.cloudflare.com/turnstile/v0/siteverify', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- provider verification API called server-side; disclosed in readme.
				'v3'      => false,
			],
		];
	}

	public static function init() {
		$self = new self();

		if ( ! Helper::get_setting( 'captcha_enabled', false ) || ! self::is_configured() ) {
			return;
		}

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
		if ( Helper::get_setting( 'captcha_on_comments', false ) ) {
			add_action( 'wp_enqueue_scripts', [ $self, 'enqueue_frontend' ] );
			add_action( 'comment_form', [ $self, 'render_widget' ] );
			add_filter( 'preprocess_comment', [ $self, 'verify_comment' ], 20 );
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

	/**
	 * Enqueue the provider widget script (shared by login + front-end).
	 */
	public function enqueue_script() {
		$p        = $this->provider();
		$site_key = Helper::get_setting( 'captcha_site_key', '' );
		$src      = $p['v3'] ? $p['script'] . rawurlencode( $site_key ) : $p['script'];
		// The widget script is a third-party CAPTCHA endpoint (Google reCAPTCHA,
		// hCaptcha, Cloudflare Turnstile) whose URL the operator picks in
		// settings; its version is managed by the provider, not us.
		// phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion,PluginCheck.CodeAnalysis.Offloading.OffloadedContent
		wp_enqueue_script( 'gemsecurity-captcha', $src, [], null, true );

		if ( $p['v3'] ) {
			$inline = sprintf(
				'window.gemsecRecaptchaV3=function(form){return new Promise(function(res){grecaptcha.ready(function(){grecaptcha.execute("%s",{action:"login"}).then(function(t){res(t);});});});};' .
				'document.addEventListener("submit",function(e){var f=e.target;if(!f||!f.querySelector)return;var fld=f.querySelector(".gs-captcha-token");if(!fld||fld.value)return;e.preventDefault();window.gemsecRecaptchaV3(f).then(function(t){fld.value=t;f.submit();});},true);',
				esc_js( $site_key )
			);
			wp_add_inline_script( 'gemsecurity-captcha', $inline );
		}
	}

	public function enqueue() {
		$this->enqueue_script();
		// Minimal spacing for the widget on wp-login.php.
		wp_add_inline_style( 'login', '.gs-captcha{margin:0 0 16px;}' );
	}

	/**
	 * Front-end enqueue — only where a comment form with the widget will render.
	 */
	public function enqueue_frontend() {
		if ( is_singular() && comments_open() ) {
			$this->enqueue_script();
		}
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
			return;
		}

		printf(
			'<div class="gs-captcha %s" data-sitekey="%s"></div>',
			esc_attr( $p['class'] ),
			esc_attr( $site_key )
		);
	}

	/* ---------------------------- Verify ------------------------------- */

	/**
	 * @param \WP_User|\WP_Error|null $user
	 * @return \WP_User|\WP_Error|null
	 */
	public function verify_login( $user ) {
		// Only guard real login-form submissions. $_POST['log'] is the
		// username field WP itself reads before we see it, and this hook
		// runs on wp_authenticate, so WP has already accepted the request.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
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
	 * Verify the CAPTCHA on a comment submission.
	 *
	 * @param array $commentdata
	 * @return array
	 */
	public function verify_comment( $commentdata ) {
		// Trusted logged-in users skip the challenge.
		if ( is_user_logged_in() ) {
			return $commentdata;
		}
		if ( ! $this->passes() ) {
			$this->log_fail( 'comment' );
			wp_die(
				esc_html__( 'Please complete the CAPTCHA challenge to post your comment.', 'gemsecurity' ),
				esc_html__( 'Comment blocked', 'gemsecurity' ),
				[ 'response' => 403, 'back_link' => true ]
			);
		}
		return $commentdata;
	}

	/* ---------------------------- Honeypot ----------------------------- */


	/**
	 * Verify the submitted token with the provider.
	 */
	private function passes() {
		$p     = $this->provider();
		// Called from wp_authenticate / registration hooks WP already
		// nonce-verifies; the token itself IS the CAPTCHA proof.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$token = isset( $_POST[ $p['field'] ] ) ? sanitize_text_field( wp_unslash( $_POST[ $p['field'] ] ) ) : '';
		return $this->verify_token( $token );
	}

	/**
	 * Verify an explicit token against the configured provider's siteverify
	 * endpoint. Exposed (not just consumed via $_POST internally) so other
	 * integrations — e.g. GemSecurity's Academy integration, which receives
	 * a token via a REST JSON body rather than a classic form POST — can
	 * reuse the same provider-verification logic instead of duplicating it.
	 *
	 * @param string $token
	 * @return bool
	 */
	public function verify_token( $token ) {
		$token = is_string( $token ) ? $token : '';
		if ( '' === $token ) {
			return false;
		}

		$p = $this->provider();

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
			// Distinguish "this visitor failed the challenge" from "this site
			// is misconfigured". A wrong or missing secret makes the provider
			// reject *every* submission, which would lock every user —
			// administrators included — out of a form nobody can pass. That is
			// a site problem, not an attack, so fail open and shout about it in
			// the log rather than bolting the door with the keys inside.
			$errors = isset( $body['error-codes'] ) ? (array) $body['error-codes'] : [];
			foreach ( $errors as $code ) {
				if ( false !== strpos( (string) $code, 'secret' ) ) {
					Logger::log(
						'captcha_misconfigured',
						sprintf(
							'CAPTCHA secret key rejected by the provider (%s). Verification is being skipped so logins keep working — fix the keys on the CAPTCHA page.',
							sanitize_text_field( (string) $code )
						),
						Logger::SEVERITY_CRITICAL,
						[ 'user_id' => 0 ]
					);
					return true;
				}
			}
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
