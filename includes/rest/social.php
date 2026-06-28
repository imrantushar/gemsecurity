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
				'key'   => $key,
				'label' => $meta['label'],
				'color' => $meta['color'],
				'pkce'  => ! empty( $meta['pkce'] ),
			];
		}

		return rest_ensure_response( [
			'success'      => true,
			'redirect_uri' => SocialLogin::redirect_uri(),
			'providers'    => $providers,
		] );
	}
}
