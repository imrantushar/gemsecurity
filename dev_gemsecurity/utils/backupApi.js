import { __ } from '@wordpress/i18n';
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

/**
 * Destinations a backup can be sent to right now: local storage, plus every
 * cloud driver that is both enabled and connected on the Storage card.
 *
 * @return {Promise<Array<{value:string,label:string}>>}
 */
export async function loadDestinations() {
	const local = { value: 'local', label: __( 'Local storage', 'gemsecurity' ) };
	try {
		const { data } = await backupApi.get( 'storage' );
		const list = data?.drivers ?? data ?? {};
		const drivers = Array.isArray( list ) ? list : Object.values( list );
		const cloud = drivers
			.filter( ( d ) => d && d.key && 'local' !== d.key && d.enabled && d.connected )
			.map( ( d ) => ( { value: d.key, label: d.label || d.key } ) );
		return [ local, ...cloud ];
	} catch ( e ) {
		return [ local ];
	}
}
