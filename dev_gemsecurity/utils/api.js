import axios from 'axios';

const globals = window.GemSecurityGlobal || {};

const api = axios.create( {
	baseURL: ( globals.rest_url || '/wp-json/' ) + ( globals.namespace || 'gemsecurity/v1/' ),
	headers: {
		'X-WP-Nonce': globals.nonce || '',
		'Content-Type': 'application/json',
	},
} );

export const GS = globals;

/**
 * A second axios instance for the StoreEngine SDK's own REST routes
 * (`storeengine-sdk/v1/{slug}/…` — license activate/deactivate/status,
 * updates, insights opt-in). These live under a different namespace and
 * nonce than the plugin's own `gemsecurity/v1` API, localized separately as
 * `GS.SeSdk.rest_url` / `GS.SeSdk.nonce`.
 *
 * Only present when the active SDK client has `init_restapi` on — today
 * that's GemSecurity Pro's real license client, not the free plugin's
 * (which proxies its one SDK-backed action, the insights opt-in, through
 * `gemsecurity/v1/license/insights` instead). Returns null otherwise so
 * callers can tell "no license API available" apart from "request failed".
 */
export function sdkApi() {
	if ( ! GS.SeSdk || ! GS.SeSdk.rest_url ) {
		return null;
	}
	return axios.create( {
		baseURL: GS.SeSdk.rest_url,
		headers: {
			'X-WP-Nonce': GS.SeSdk.nonce || '',
			'Content-Type': 'application/json',
		},
	} );
}

export default api;
