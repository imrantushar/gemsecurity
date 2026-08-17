<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\Captcha;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Credential tester — "are these keys actually right?" before they go live.
 *
 * Third-party credentials are the one class of setting where a typo is not
 * merely inert: a wrong CAPTCHA secret rejects every login, a wrong OAuth
 * secret breaks social sign-in, a wrong webhook silently drops alerts. The
 * damage only shows up on the login form, which is the worst possible place
 * to discover it. Each tester below talks to the real provider and reports
 * back before anything is saved.
 *
 * POST /credentials/test { target, values{} } → { ok, message, detail }
 *
 * Values come from the unsaved form, so a key can be checked before it is
 * committed. Nothing here writes settings.
 */
class Credentials {

	/**
	 * POST /credentials/test
	 *
	 * @param \WP_REST_Request $request
	 * @return \WP_REST_Response|\WP_Error
	 */
	public static function test( $request ) {
		$target = sanitize_key( (string) $request->get_param( 'target' ) );
		$values = (array) $request->get_param( 'values' );

		// Test values are secrets in transit; never log or echo them back.
		$values = array_map(
			static function ( $v ) {
				return is_scalar( $v ) ? trim( (string) $v ) : '';
			},
			$values
		);

		switch ( $target ) {
			case 'captcha':
				return self::respond( self::test_captcha( $values ) );

			case 'slack':
				return self::respond( self::test_slack( $values ) );

			case 'telegram':
				return self::respond( self::test_telegram( $values ) );

			case 'webhook':
			case 'siem':
				return self::respond( self::test_endpoint( $values, $target ) );

			case 'social':
				return self::respond( self::test_social( $values ) );
		}

		return new \WP_Error(
			'gemsecurity_unknown_test',
			__( 'Unknown credential test.', 'gemsecurity' ),
			[ 'status' => 400 ]
		);
	}

	/** Normalise a tester result into the REST envelope. */
	private static function respond( array $result ) {
		return rest_ensure_response(
			array_merge(
				[ 'success' => true, 'ok' => false, 'message' => '', 'detail' => '' ],
				$result
			)
		);
	}

	/* ------------------------------------------------------------------ */
	/* CAPTCHA                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Verify a CAPTCHA key pair end to end.
	 *
	 * There is no dry-run: posting a dummy token proves nothing, because
	 * Google and hCaptcha answer `invalid-input-response` whether the secret
	 * is right or wrong (only Turnstile reports `invalid-input-secret`). A
	 * check built on that would report a mistyped secret as fine — the exact
	 * failure this feature exists to prevent.
	 *
	 * So the browser renders the real widget with the site key (which is where
	 * a bad site key is caught) and sends the resulting token here; a
	 * `success: true` from the provider is then proof that both keys are right
	 * for this domain. Anything short of that is never reported as a pass.
	 *
	 * @param array $values provider, site_key, secret_key, token
	 * @return array
	 */
	private static function test_captcha( array $values ) {
		$provider  = $values['provider'] ?? 'recaptcha_v2';
		$secret    = $values['secret_key'] ?? '';
		$site_key  = $values['site_key'] ?? '';
		$token     = $values['token'] ?? '';
		$providers = Captcha::providers();

		if ( ! isset( $providers[ $provider ] ) ) {
			return [ 'message' => __( 'Unknown CAPTCHA provider.', 'gemsecurity' ) ];
		}
		if ( '' === $secret || '' === $site_key ) {
			return [ 'message' => __( 'Enter both the site key and the secret key first.', 'gemsecurity' ) ];
		}

		$response = wp_remote_post( $providers[ $provider ]['verify'], [
			'timeout' => 10,
			'body'    => [
				'secret'   => $secret,
				// Without a widget token this can still catch a bad secret on
				// Turnstile, which is the one provider that says so.
				'response' => '' !== $token ? $token : 'gemsecurity-credential-test',
			],
		] );

		if ( is_wp_error( $response ) ) {
			return [
				'message' => __( 'Could not reach the provider.', 'gemsecurity' ),
				'detail'  => $response->get_error_message(),
			];
		}

		$body   = json_decode( wp_remote_retrieve_body( $response ), true );
		$errors = isset( $body['error-codes'] ) ? (array) $body['error-codes'] : [];

		// A token the provider accepted: both keys are proven good.
		if ( ! empty( $body['success'] ) ) {
			return [
				'ok'      => true,
				'message' => __( 'Verified — both keys work on this site.', 'gemsecurity' ),
			];
		}

		// Check every code for a secret-level failure before looking at the
		// token, so a reply carrying both never reads as a pass.
		foreach ( $errors as $code ) {
			if ( false !== strpos( (string) $code, 'secret' ) ) {
				return [
					'message' => __( 'The secret key was rejected by the provider.', 'gemsecurity' ),
					'detail'  => sanitize_text_field( (string) $code ),
				];
			}
		}

		if ( '' === $token ) {
			return [
				'message' => __( 'Solve the challenge to finish the test.', 'gemsecurity' ),
				'detail'  => __( 'This provider cannot confirm a secret key on its own — the widget token is what proves the pair.', 'gemsecurity' ),
			];
		}

		return [
			'message' => __( 'The provider rejected this attempt.', 'gemsecurity' ),
			'detail'  => $errors
				? implode( ', ', array_map( 'sanitize_text_field', $errors ) )
				: __( 'The token may have expired — solve the challenge again.', 'gemsecurity' ),
		];
	}

	/* ------------------------------------------------------------------ */
	/* Alert channels                                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * Post a real (clearly labelled) message to the Slack webhook. Slack has
	 * no dry-run endpoint, so delivering one test line is the only way to
	 * prove the URL works — and seeing it arrive is the point of the test.
	 *
	 * @param array $values url
	 * @return array
	 */
	private static function test_slack( array $values ) {
		$url = $values['url'] ?? '';
		if ( '' === $url ) {
			return [ 'message' => __( 'Enter a webhook URL first.', 'gemsecurity' ) ];
		}
		if ( ! wp_http_validate_url( $url ) ) {
			return [ 'message' => __( 'That does not look like a valid URL.', 'gemsecurity' ) ];
		}

		$response = wp_remote_post( $url, [
			'timeout' => 10,
			'headers' => [ 'Content-Type' => 'application/json' ],
			'body'    => wp_json_encode( [
				'text' => sprintf(
					/* translators: %s: site name. */
					__( 'GemSecurity test alert from %s — if you can read this, alerts are working.', 'gemsecurity' ),
					get_bloginfo( 'name' )
				),
			] ),
		] );

		if ( is_wp_error( $response ) ) {
			return [
				'message' => __( 'Could not reach Slack.', 'gemsecurity' ),
				'detail'  => $response->get_error_message(),
			];
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 === $code ) {
			return [ 'ok' => true, 'message' => __( 'Test message delivered — check the channel.', 'gemsecurity' ) ];
		}

		return [
			'message' => __( 'Slack rejected the webhook.', 'gemsecurity' ),
			/* translators: 1: HTTP status, 2: response body. */
			'detail'  => sprintf( __( 'HTTP %1$d: %2$s', 'gemsecurity' ), $code, sanitize_text_field( wp_remote_retrieve_body( $response ) ) ),
		];
	}

	/**
	 * Validate the bot token with getMe, then — only if a chat ID is given —
	 * deliver a test message, which is the only way to prove the chat ID and
	 * that someone has actually opened a conversation with the bot.
	 *
	 * @param array $values token, chat_id
	 * @return array
	 */
	private static function test_telegram( array $values ) {
		$token = $values['token'] ?? '';
		$chat  = $values['chat_id'] ?? '';

		if ( '' === $token ) {
			return [ 'message' => __( 'Enter the bot token first.', 'gemsecurity' ) ];
		}

		$me = wp_remote_get( 'https://api.telegram.org/bot' . rawurlencode( $token ) . '/getMe', [ 'timeout' => 10 ] );
		if ( is_wp_error( $me ) ) {
			return [ 'message' => __( 'Could not reach Telegram.', 'gemsecurity' ), 'detail' => $me->get_error_message() ];
		}

		$me_body = json_decode( wp_remote_retrieve_body( $me ), true );
		if ( empty( $me_body['ok'] ) ) {
			return [
				'message' => __( 'That bot token is not valid.', 'gemsecurity' ),
				'detail'  => isset( $me_body['description'] ) ? sanitize_text_field( $me_body['description'] ) : '',
			];
		}

		$bot_name = isset( $me_body['result']['username'] ) ? sanitize_text_field( $me_body['result']['username'] ) : '';

		if ( '' === $chat ) {
			return [
				'ok'      => true,
				/* translators: %s: bot username. */
				'message' => sprintf( __( 'Bot token valid (@%s).', 'gemsecurity' ), $bot_name ),
				'detail'  => __( 'Add the chat ID and test again to confirm delivery.', 'gemsecurity' ),
			];
		}

		$send = wp_remote_post( 'https://api.telegram.org/bot' . rawurlencode( $token ) . '/sendMessage', [
			'timeout' => 10,
			'body'    => [
				'chat_id' => $chat,
				'text'    => sprintf(
					/* translators: %s: site name. */
					__( 'GemSecurity test alert from %s — if you can read this, alerts are working.', 'gemsecurity' ),
					get_bloginfo( 'name' )
				),
			],
		] );

		if ( is_wp_error( $send ) ) {
			return [ 'message' => __( 'Could not reach Telegram.', 'gemsecurity' ), 'detail' => $send->get_error_message() ];
		}

		$send_body = json_decode( wp_remote_retrieve_body( $send ), true );
		if ( ! empty( $send_body['ok'] ) ) {
			return [
				'ok'      => true,
				/* translators: %s: bot username. */
				'message' => sprintf( __( 'Test message delivered by @%s.', 'gemsecurity' ), $bot_name ),
			];
		}

		return [
			/* translators: %s: bot username. */
			'message' => sprintf( __( 'Token is valid (@%s) but the message could not be delivered.', 'gemsecurity' ), $bot_name ),
			'detail'  => isset( $send_body['description'] )
				? sanitize_text_field( $send_body['description'] )
				: __( 'Check the chat ID, and make sure someone has messaged the bot first.', 'gemsecurity' ),
		];
	}

	/**
	 * Generic HTTP receiver (alert webhook / SIEM collector): post the same
	 * shape a real event uses and report what came back.
	 *
	 * @param array  $values url
	 * @param string $target webhook|siem
	 * @return array
	 */
	private static function test_endpoint( array $values, $target ) {
		$url = $values['url'] ?? '';
		if ( '' === $url ) {
			return [ 'message' => __( 'Enter a URL first.', 'gemsecurity' ) ];
		}
		if ( ! wp_http_validate_url( $url ) ) {
			return [ 'message' => __( 'That does not look like a valid URL.', 'gemsecurity' ) ];
		}

		$response = wp_remote_post( $url, [
			'timeout' => 10,
			'headers' => [ 'Content-Type' => 'application/json' ],
			'body'    => wp_json_encode( [
				'event'    => 'gemsecurity_test',
				'severity' => 'notice',
				'message'  => 'GemSecurity connection test',
				'site'     => home_url(),
				'time'     => current_time( 'mysql' ),
				'source'   => 'siem' === $target ? 'siem-test' : 'webhook-test',
			] ),
		] );

		if ( is_wp_error( $response ) ) {
			return [ 'message' => __( 'Could not reach that URL.', 'gemsecurity' ), 'detail' => $response->get_error_message() ];
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code >= 200 && $code < 300 ) {
			/* translators: %d: HTTP status code. */
			return [ 'ok' => true, 'message' => sprintf( __( 'Test event accepted (HTTP %d).', 'gemsecurity' ), $code ) ];
		}

		return [
			'message' => __( 'The receiver rejected the test event.', 'gemsecurity' ),
			/* translators: %d: HTTP status code. */
			'detail'  => sprintf( __( 'HTTP %d', 'gemsecurity' ), $code ),
		];
	}

	/* ------------------------------------------------------------------ */
	/* Social login                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Check an OAuth client ID/secret pair without a user round trip.
	 *
	 * Each provider's token endpoint separates "I don't recognise this client"
	 * from "that authorisation code is bad", so exchanging a deliberately
	 * invalid code proves whether the client credentials themselves are good.
	 * Facebook is simpler: it hands out an app token for a valid pair.
	 *
	 * @param array $values provider, client_id, client_secret
	 * @return array
	 */
	private static function test_social( array $values ) {
		$provider = sanitize_key( $values['provider'] ?? '' );
		$id       = $values['client_id'] ?? '';
		$secret   = $values['client_secret'] ?? '';

		if ( '' === $id || '' === $secret ) {
			return [ 'message' => __( 'Enter both the client ID and the client secret first.', 'gemsecurity' ) ];
		}

		$bad_client = [ 'message' => __( 'The provider does not recognise this client ID / secret pair.', 'gemsecurity' ) ];
		$good       = [
			'ok'      => true,
			'message' => __( 'Client ID and secret accepted by the provider.', 'gemsecurity' ),
			'detail'  => __( 'The redirect URI is only checked during a real sign-in — make sure it is registered too.', 'gemsecurity' ),
		];

		switch ( $provider ) {
			case 'google':
				$r = wp_remote_post( 'https://oauth2.googleapis.com/token', [
					'timeout' => 10,
					'body'    => [
						'grant_type'    => 'authorization_code',
						'code'          => 'gemsecurity-credential-test',
						'client_id'     => $id,
						'client_secret' => $secret,
						'redirect_uri'  => home_url( '/' ),
					],
				] );
				break;

			case 'github':
				$r = wp_remote_post( 'https://github.com/login/oauth/access_token', [
					'timeout' => 10,
					'headers' => [ 'Accept' => 'application/json' ],
					'body'    => [
						'code'          => 'gemsecurity-credential-test',
						'client_id'     => $id,
						'client_secret' => $secret,
					],
				] );
				break;

			case 'facebook':
				$r = wp_remote_get( add_query_arg( [
					'grant_type'    => 'client_credentials',
					'client_id'     => rawurlencode( $id ),
					'client_secret' => rawurlencode( $secret ),
				], 'https://graph.facebook.com/oauth/access_token' ), [ 'timeout' => 10 ] );
				break;

			case 'twitter':
				$r = wp_remote_post( 'https://api.x.com/2/oauth2/token', [
					'timeout' => 10,
					'headers' => [
						'Authorization' => 'Basic ' . base64_encode( $id . ':' . $secret ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- HTTP Basic auth, not obfuscation.
						'Content-Type'  => 'application/x-www-form-urlencoded',
					],
					'body'    => [
						'grant_type'   => 'authorization_code',
						'code'         => 'gemsecurity-credential-test',
						'redirect_uri' => home_url( '/' ),
						'code_verifier' => 'gemsecurity',
					],
				] );
				break;

			default:
				return [ 'message' => __( 'Unknown provider.', 'gemsecurity' ) ];
		}

		if ( is_wp_error( $r ) ) {
			return [ 'message' => __( 'Could not reach the provider.', 'gemsecurity' ), 'detail' => $r->get_error_message() ];
		}

		$code = (int) wp_remote_retrieve_response_code( $r );
		$body = json_decode( wp_remote_retrieve_body( $r ), true );
		// OAuth 2.0 puts a string in `error`; Facebook's Graph API puts an
		// object there instead, so read both shapes rather than casting blind.
		$err = '';
		if ( is_array( $body ) && isset( $body['error'] ) ) {
			if ( is_array( $body['error'] ) ) {
				$err = (string) ( $body['error']['message'] ?? $body['error']['type'] ?? '' );
			} elseif ( is_scalar( $body['error'] ) ) {
				$err = (string) $body['error'];
			}
		}

		// Facebook returns a token straight away for a valid pair.
		if ( 'facebook' === $provider ) {
			if ( 200 === $code && ( isset( $body['access_token'] ) || false !== strpos( wp_remote_retrieve_body( $r ), 'access_token' ) ) ) {
				return $good;
			}
			return array_merge( $bad_client, [ 'detail' => sanitize_text_field( $err ) ] );
		}

		// Everyone else: a client-level error means bad credentials, while a
		// complaint about the deliberately invalid *code* means the client was
		// accepted and only the fake grant failed.
		//
		// Checked against live responses: Google answers an unrecognised client
		// with `invalid_request` (not `invalid_client`), and GitHub answers one
		// with HTTP 404 — so neither may be treated as "credentials fine".
		$client_errors = [ 'invalid_client', 'unauthorized_client', 'incorrect_client_credentials', 'invalid_request' ];
		$grant_errors  = [ 'invalid_grant', 'bad_verification_code' ];

		if ( in_array( $err, $grant_errors, true ) ) {
			return $good;
		}
		if ( in_array( $err, $client_errors, true ) || 401 === $code || 404 === $code ) {
			return array_merge( $bad_client, [ 'detail' => sanitize_text_field( $err ) ] );
		}

		return [
			'message' => __( 'Could not confirm these credentials.', 'gemsecurity' ),
			/* translators: 1: HTTP status, 2: provider error code. */
			'detail'  => sprintf( __( 'Provider replied HTTP %1$d (%2$s).', 'gemsecurity' ), $code, sanitize_text_field( $err ) ),
		];
	}
}
