import axios from 'axios';

const globals = window.GemSecurityGlobal || {};

/**
 * Axios instance for the backup engine, which registers its REST routes under
 * the gembackup/v1 namespace (the re-homed GemBackup engine). Reuses the same
 * WP REST nonce as the security API.
 */
const backupApi = axios.create( {
	baseURL: ( globals.rest_url || '/wp-json/' ) + 'gembackup/v1/',
	headers: {
		'X-WP-Nonce': globals.nonce || '',
		'Content-Type': 'application/json',
	},
} );

export default backupApi;
