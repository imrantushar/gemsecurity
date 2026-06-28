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

export default api;
