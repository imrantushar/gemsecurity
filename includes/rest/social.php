<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\SocialLogin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Social-login metadata for the admin UI (provider list + redirect URI).
 */
class Social {

	/**
	 * GET /social
	 */
	public static function config() {
		$providers = [];
		foreach ( SocialLogin::providers_meta() as $key => $meta ) {
			$providers[] = [
				'key'      => $key,
				'label'    => $meta['label'],
				'color'    => $meta['color'],
				'pkce'     => ! empty( $meta['pkce'] ),
				'verified' => SocialLogin::is_verified( $key ),
				// Set when the provider stopped accepting the credentials and the
				// provider was switched off automatically: { at, reason }.
				'broken'   => SocialLogin::broken( $key ),
				// A real sign-in against the saved credentials; finishing it verifies them.
				'test_url' => add_query_arg(
					[ 'gemsec_oauth' => $key, 'gemsec_oauth_test' => wp_create_nonce( 'gemsec_oauth_test_' . $key ) ],
					site_url( 'wp-login.php' )
				),
			];
		}

		return rest_ensure_response( [
			'success'      => true,
			'redirect_uri' => SocialLogin::redirect_uri(),
			'providers'    => $providers,
		] );
	}
}
