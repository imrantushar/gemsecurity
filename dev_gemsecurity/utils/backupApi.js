import axios from 'axios';

const globals = window.GemSecurityGlobal || {};

/**
 * Axios instance for the GemBackup plugin's REST API (gembackup/v1). Only used
 * when GemBackup is active (`GemSecurityGlobal.gembackup.active`). Reuses the
 * same WP REST nonce as the security API.
 */
const backupApi = axios.create( {
	baseURL: ( globals.rest_url || '/wp-json/' ) + 'gembackup/v1/',
	headers: {
		'X-WP-Nonce': globals.nonce || '',
		'Content-Type': 'application/json',
	},
} );

export default backupApi;
