import React, { useState, useEffect, useCallback } from 'react';
import { __ } from '@wordpress/i18n';
import backupApi from '@Utils/backupApi';
import { useToast } from '@Components/ui/Toast';
import { Card, Button, Field, TextInput, Toggle, Badge, Loading } from '@Components/ui/Controls';
import { isPro, ProBadge, upgradeUrl } from '@Components/ui/Pro';

const FREE_DRIVERS = [ 'local' ];
const OAUTH_DRIVERS = [ 'gdrive', 'dropbox', 'onedrive' ];

// Manual-credential drivers and their fields (sent without the driver prefix).
const DRIVER_FIELDS = {
	s3: [
		{ k: 'access_key', label: __( 'Access key ID', 'gemsecurity' ) },
		{ k: 'secret_key', label: __( 'Secret access key', 'gemsecurity' ), secret: true },
		{ k: 'region', label: __( 'Region', 'gemsecurity' ), ph: 'us-east-1' },
		{ k: 'bucket', label: __( 'Bucket', 'gemsecurity' ) },
		{ k: 'folder', label: __( 'Folder (optional)', 'gemsecurity' ) },
	],
	r2: [
		{ k: 'account_id', label: __( 'Account ID', 'gemsecurity' ) },
		{ k: 'access_key', label: __( 'Access key ID', 'gemsecurity' ) },
		{ k: 'secret_key', label: __( 'Secret access key', 'gemsecurity' ), secret: true },
		{ k: 'bucket', label: __( 'Bucket', 'gemsecurity' ) },
		{ k: 'folder', label: __( 'Folder (optional)', 'gemsecurity' ) },
	],
	backblaze: [
		{ k: 'key_id', label: __( 'Key ID', 'gemsecurity' ) },
		{ k: 'application_key', label: __( 'Application key', 'gemsecurity' ), secret: true },
		{ k: 'bucket', label: __( 'Bucket', 'gemsecurity' ) },
		{ k: 'folder', label: __( 'Folder (optional)', 'gemsecurity' ) },
	],
	ftp: [
		{ k: 'host', label: __( 'Host', 'gemsecurity' ) },
		{ k: 'port', label: __( 'Port', 'gemsecurity' ), ph: '21' },
		{ k: 'username', label: __( 'Username', 'gemsecurity' ) },
		{ k: 'password', label: __( 'Password', 'gemsecurity' ), secret: true },
		{ k: 'folder', label: __( 'Remote folder', 'gemsecurity' ) },
		{ k: 'use_sftp', label: __( 'Use SFTP', 'gemsecurity' ), type: 'toggle' },
	],
};

export default function BackupStorage() {
	const toast = useToast();
	const pro = isPro();
	const [ drivers, setDrivers ] = useState( null );
	const [ expanded, setExpanded ] = useState( '' );
	const [ form, setForm ] = useState( {} );
	const [ busy, setBusy ] = useState( '' );

	const load = useCallback( async () => {
		try {
			const { data } = await backupApi.get( 'storage' );
			// The endpoint returns { active, drivers: { key: {...} } }.
			const list = data?.drivers ?? data ?? [];
			setDrivers( ( Array.isArray( list ) ? list : Object.values( list ) ).filter( ( d ) => d && d.key ) );
		} catch ( e ) {
			setDrivers( [] );
		}
	}, [] );

	useEffect( () => {
		load();
	}, [ load ] );

	const openConfig = async ( key ) => {
		if ( expanded === key ) {
			setExpanded( '' );
			return;
		}
		setExpanded( key );
		setForm( {} );
		try {
			const { data } = await backupApi.get( `storage/${ key }` );
			const fields = data.fields || {};
			// Don't prefill masked secrets — leave blank so they're only sent if changed.
			const next = {};
			( DRIVER_FIELDS[ key ] || [] ).forEach( ( f ) => {
				next[ f.k ] = f.secret ? '' : ( fields[ f.k ] ?? '' );
			} );
			setForm( next );
		} catch ( e ) {
			/* ignore */
		}
	};

	const setField = ( k, v ) => setForm( ( f ) => ( { ...f, [ k ]: v } ) );

	const save = async ( key ) => {
		setBusy( `save:${ key }` );
		try {
			// Omit empty secret fields so a blank doesn't wipe a stored credential.
			const payload = {};
			( DRIVER_FIELDS[ key ] || [] ).forEach( ( f ) => {
				if ( f.secret && ! form[ f.k ] ) return;
				payload[ f.k ] = form[ f.k ];
			} );
			await backupApi.put( `storage/${ key }`, payload );
			toast( __( 'Storage settings saved.', 'gemsecurity' ), 'success' );
			await load();
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not save.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const test = async ( key ) => {
		setBusy( `test:${ key }` );
		try {
			await backupApi.post( `storage/${ key }/test`, {} );
			toast( __( 'Connection successful.', 'gemsecurity' ), 'success' );
			await load();
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Connection failed.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const toggleEnabled = async ( d ) => {
		setBusy( `en:${ d.key }` );
		try {
			await backupApi.put( `storage/${ d.key }`, { enabled: ! d.enabled } );
			await load();
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not update.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const connectOauth = async ( key ) => {
		setBusy( `oauth:${ key }` );
		try {
			const { data } = await backupApi.get( `oauth/${ key }/start` );
			if ( data.auth_url ) {
				window.location.href = data.auth_url;
				return;
			}
			toast( __( 'Could not start authorization.', 'gemsecurity' ), 'error' );
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not start authorization.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const disconnectOauth = async ( key ) => {
		setBusy( `oauth:${ key }` );
		try {
			await backupApi.post( `oauth/${ key }/disconnect`, {} );
			await load();
		} catch ( e ) { /* ignore */ }
		setBusy( '' );
	};

	if ( drivers === null ) {
		return <Loading />;
	}

	const renderConfig = ( d ) => {
		if ( OAUTH_DRIVERS.includes( d.key ) ) {
			return (
				<div style={ { padding: '4px 0 8px' } }>
					<p className="gs-card__desc">{ __( 'Connect your account to authorize backups to this destination.', 'gemsecurity' ) }</p>
					{ d.connected ? (
						<Button variant="secondary" loading={ busy === `oauth:${ d.key }` } onClick={ () => disconnectOauth( d.key ) }>{ __( 'Disconnect', 'gemsecurity' ) }</Button>
					) : (
						<Button loading={ busy === `oauth:${ d.key }` } onClick={ () => connectOauth( d.key ) }>{ __( 'Connect account', 'gemsecurity' ) }</Button>
					) }
				</div>
			);
		}
		const fields = DRIVER_FIELDS[ d.key ] || [];
		return (
			<div style={ { padding: '4px 0 8px' } }>
				{ fields.map( ( f ) => (
					f.type === 'toggle' ? (
						<Toggle key={ f.k } label={ f.label } checked={ !! form[ f.k ] } onChange={ ( v ) => setField( f.k, v ) } />
					) : (
						<Field key={ f.k } label={ f.label }>
							<TextInput
								type={ f.secret ? 'password' : 'text' }
								value={ form[ f.k ] ?? '' }
								placeholder={ f.secret && d.connected ? '•••••••• ' + __( '(unchanged)', 'gemsecurity' ) : ( f.ph || '' ) }
								onChange={ ( e ) => setField( f.k, e.target.value ) }
							/>
						</Field>
					)
				) ) }
				<div style={ { display: 'flex', gap: 10, marginTop: 8 } }>
					<Button loading={ busy === `save:${ d.key }` } onClick={ () => save( d.key ) }>{ __( 'Save', 'gemsecurity' ) }</Button>
					<Button variant="secondary" loading={ busy === `test:${ d.key }` } onClick={ () => test( d.key ) }>{ __( 'Test connection', 'gemsecurity' ) }</Button>
				</div>
			</div>
		);
	};

	return (
		<>
			<Card
				title={ __( 'Storage destinations', 'gemsecurity' ) }
				description={ __( 'Local storage is included. Cloud destinations are available in Pro.', 'gemsecurity' ) }
			>
				<table className="gs-table">
					<tbody>
						{ drivers.map( ( d ) => {
							const free = FREE_DRIVERS.includes( d.key );
							const locked = ! free && ! pro;
							const isOpen = expanded === d.key;
							return (
								<React.Fragment key={ d.key }>
									<tr>
										<td>
											<strong style={ { textTransform: 'capitalize' } }>{ d.label || d.key }</strong>
											{ locked && <ProBadge /> }
										</td>
										<td>
											{ d.connected
												? <Badge tone="success">{ __( 'Connected', 'gemsecurity' ) }</Badge>
												: <Badge tone="info">{ free ? __( 'Ready', 'gemsecurity' ) : __( 'Not configured', 'gemsecurity' ) }</Badge> }
											{ d.enabled && ' ' }
											{ d.enabled && <Badge tone="success">{ __( 'Enabled', 'gemsecurity' ) }</Badge> }
										</td>
										<td style={ { textAlign: 'right', whiteSpace: 'nowrap' } }>
											{ locked ? (
												<a className="gs-btn gs-btn--secondary" href={ upgradeUrl() } target="_blank" rel="noreferrer">{ __( 'Unlock in Pro', 'gemsecurity' ) }</a>
											) : (
												<>
													{ ! free && (
														<Button variant="secondary" onClick={ () => openConfig( d.key ) }>
															{ isOpen ? __( 'Close', 'gemsecurity' ) : __( 'Configure', 'gemsecurity' ) }
														</Button>
													) }
													{ /* Local is the fallback every backup can always reach; it is not switchable. */ }
													{ ! free && ' ' }
													{ ! free && (
														<Button variant="secondary" loading={ busy === `en:${ d.key }` } onClick={ () => toggleEnabled( d ) }>
															{ d.enabled ? __( 'Disable', 'gemsecurity' ) : __( 'Enable', 'gemsecurity' ) }
														</Button>
													) }
												</>
											) }
										</td>
									</tr>
									{ isOpen && ! locked && ! free && (
										<tr><td colSpan={ 3 }>{ renderConfig( d ) }</td></tr>
									) }
								</React.Fragment>
							);
						} ) }
					</tbody>
				</table>
				{ ! pro && (
					<p className="gs-card__desc" style={ { marginTop: 12 } }>
						{ __( 'Amazon S3, Backblaze B2, Cloudflare R2, Dropbox, Google Drive, OneDrive and FTP are unlocked with GemSecurity Pro.', 'gemsecurity' ) }
					</p>
				) }
			</Card>
		</>
	);
}
