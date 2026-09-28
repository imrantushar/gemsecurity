import React, { useState, useEffect, useCallback, useRef } from 'react';
import { __ } from '@wordpress/i18n';
import backupApi, { loadDestinations } from '@Utils/backupApi';
import { useToast } from '@Components/ui/Toast';
import { Card, Button, Toggle, Field, Select, Badge, EmptyState } from '@Components/ui/Controls';
import { isPro, ProBadge } from '@Components/ui/Pro';
import BackupSchedule from '@Containers/pages/BackupSchedule';
import BackupStorage from '@Containers/pages/BackupStorage';
import BackupSettings from '@Containers/pages/BackupSettings';

const TYPES = [
	{ value: 'full', label: __( 'Full site (database + files)', 'gemsecurity' ) },
	{ value: 'database', label: __( 'Database only', 'gemsecurity' ) },
	{ value: 'files', label: __( 'Files only', 'gemsecurity' ) },
];

const TERMINAL = [ 'completed', 'failed' ];

function fmtSize( bytes ) {
	if ( ! bytes ) return '—';
	const u = [ 'B', 'KB', 'MB', 'GB' ];
	let i = 0;
	let n = bytes;
	while ( n >= 1024 && i < u.length - 1 ) { n /= 1024; i++; }
	return `${ n.toFixed( n < 10 && i > 0 ? 1 : 0 ) } ${ u[ i ] }`;
}

function statusTone( s ) {
	if ( s === 'completed' ) return 'success';
	if ( s === 'failed' ) return 'error';
	return 'warning';
}

export default function Backup() {
	const toast = useToast();
	const pro = isPro();

	const [ items, setItems ] = useState( [] );
	const [ type, setType ] = useState( 'full' );
	const [ encrypt, setEncrypt ] = useState( false );
	const [ destination, setDestination ] = useState( 'local' );
	const [ destinations, setDestinations ] = useState( [] );
	const [ encryptReady, setEncryptReady ] = useState( true );
	const [ creating, setCreating ] = useState( false );
	const [ busy, setBusy ] = useState( '' );
	const pollRef = useRef( null );

	const load = useCallback( async () => {
		try {
			const { data } = await backupApi.get( 'backups', { params: { per_page: 25 } } );
			setItems( data.items || [] );
		} catch ( e ) {
			/* ignore */
		}
	}, [] );

	useEffect( () => {
		load();
		if ( pro ) {
			loadDestinations().then( setDestinations );
			// Encryption needs it switched on and a passphrase saved in Backup
			// settings; without both the runner quietly writes a plain archive.
			backupApi.get( 'settings' )
				.then( ( { data } ) => setEncryptReady( !! ( data?.encryption_enabled && data?.encryption_passphrase_set ) ) )
				.catch( () => {} );
		}
	}, [ load, pro ] );

	// Poll while any backup is in progress.
	useEffect( () => {
		const active = items.some( ( b ) => ! TERMINAL.includes( b.status ) );
		if ( active && ! pollRef.current ) {
			pollRef.current = setInterval( load, 3000 );
		} else if ( ! active && pollRef.current ) {
			clearInterval( pollRef.current );
			pollRef.current = null;
		}
		return () => {
			if ( ! active && pollRef.current ) {
				clearInterval( pollRef.current );
				pollRef.current = null;
			}
		};
	}, [ items, load ] );

	const create = async () => {
		setCreating( true );
		try {
			await backupApi.post( 'backups', { type, drivers: [ pro ? destination : 'local' ], encrypted: pro && encrypt } );
			toast( __( 'Backup started.', 'gemsecurity' ), 'success' );
			load();
		} catch ( e ) {
			toast( __( 'Could not start the backup.', 'gemsecurity' ), 'error' );
		}
		setCreating( false );
	};

	const download = async ( id ) => {
		setBusy( `dl${ id }` );
		try {
			const { data } = await backupApi.get( `backups/${ id }/download` );
			if ( data.url ) window.location.href = data.url;
		} catch ( e ) {
			toast( __( 'Download not available.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const restore = async ( id ) => {
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( __( 'Restore this backup? It will overwrite current files and database.', 'gemsecurity' ) ) ) return;
		setBusy( `rs${ id }` );
		try {
			await backupApi.post( `backups/${ id }/restore`, {} );
			toast( __( 'Restore started.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( __( 'Could not start restore.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const remove = async ( id ) => {
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( __( 'Delete this backup permanently?', 'gemsecurity' ) ) ) return;
		setBusy( `del${ id }` );
		try {
			await backupApi.delete( `backups/${ id }` );
			setItems( ( list ) => list.filter( ( b ) => b.id !== id ) );
		} catch ( e ) {
			toast( __( 'Could not delete.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Create a backup', 'gemsecurity' ) }
				description={ pro ? __( 'Run a one-off backup now.', 'gemsecurity' ) : __( 'Back up to local storage. Cloud destinations and encryption are available in Pro.', 'gemsecurity' ) }
				actions={
					<Button loading={ creating } onClick={ create }>
						{ __( 'Create backup', 'gemsecurity' ) }
					</Button>
				}
			>
				<Field label={ __( 'What to back up', 'gemsecurity' ) }>
					<Select options={ TYPES } value={ type } onChange={ ( e ) => setType( e.target.value ) } />
				</Field>
				<Field
					label={ <span>{ __( 'Destination', 'gemsecurity' ) } { ! pro && <ProBadge /> }</span> }
					description={ pro
						? ( destinations.length > 1 ? null : __( 'Enable and connect a cloud destination under Storage destinations below to send backups off-site.', 'gemsecurity' ) )
						: __( 'Cloud destinations (S3, R2, Backblaze, Google Drive, Dropbox, OneDrive, FTP) are available in Pro.', 'gemsecurity' ) }
				>
					<Select
						options={ pro && destinations.length ? destinations : [ { value: 'local', label: __( 'Local storage', 'gemsecurity' ) } ] }
						value={ pro ? destination : 'local' }
						disabled={ ! pro || destinations.length < 2 }
						onChange={ ( e ) => setDestination( e.target.value ) }
					/>
				</Field>
				<Toggle
					label={
						<span>{ __( 'Encrypt backup', 'gemsecurity' ) } { ! pro && <ProBadge /> }</span>
					}
					description={ pro && ! encryptReady
						? __( 'Turn on encryption and save a passphrase under Backup settings below first.', 'gemsecurity' )
						: __( 'AES-encrypt the archive at rest.', 'gemsecurity' ) }
					checked={ pro && encryptReady && encrypt }
					disabled={ ! pro || ! encryptReady }
					onChange={ ( v ) => setEncrypt( v ) }
				/>
			</Card>

			<Card title={ __( 'Backups', 'gemsecurity' ) }>
				{ items.length === 0 ? (
					<EmptyState title={ __( 'No backups yet.', 'gemsecurity' ) } description={ __( 'Create your first backup above.', 'gemsecurity' ) } />
				) : (
					<table className="gs-table">
						<thead>
							<tr>
								<th>{ __( 'Backup', 'gemsecurity' ) }</th>
								<th>{ __( 'Type', 'gemsecurity' ) }</th>
								<th>{ __( 'Size', 'gemsecurity' ) }</th>
								<th>{ __( 'Status', 'gemsecurity' ) }</th>
								<th></th>
							</tr>
						</thead>
						<tbody>
							{ items.map( ( b ) => (
								<tr key={ b.id }>
									<td>
										{ b.backup_name || `#${ b.id }` }
										<div style={ { color: '#6b7385', fontSize: 11 } }>
											{ b.created_at }{ b.encrypted ? ' · 🔒' : '' }{ b.storage_driver ? ` · ${ b.storage_driver }` : '' }
										</div>
									</td>
									<td style={ { textTransform: 'capitalize' } }>{ b.backup_type }</td>
									<td>{ fmtSize( b.file_size ) }</td>
									<td>
										<Badge tone={ statusTone( b.status ) }>
											{ TERMINAL.includes( b.status ) ? b.status : `${ b.status } ${ b.progress }%` }
										</Badge>
									</td>
									<td style={ { textAlign: 'right', whiteSpace: 'nowrap' } }>
										{ b.status === 'completed' && (
											<>
												<Button variant="secondary" loading={ busy === `dl${ b.id }` } onClick={ () => download( b.id ) }>{ __( 'Download', 'gemsecurity' ) }</Button>
												{ ' ' }
												<Button variant="secondary" loading={ busy === `rs${ b.id }` } onClick={ () => restore( b.id ) }>{ __( 'Restore', 'gemsecurity' ) }</Button>
											</>
										) }
										{ ' ' }
										<Button variant="danger" loading={ busy === `del${ b.id }` } onClick={ () => remove( b.id ) }>{ __( 'Delete', 'gemsecurity' ) }</Button>
									</td>
								</tr>
							) ) }
						</tbody>
					</table>
				) }
			</Card>

			{ /*
			   Schedules, destinations and configuration belong with the backups
			   they govern. These used to render at the bottom of the Settings
			   page — including when the Backup module was switched off, where
			   their endpoints are not registered and every card failed to load.
			*/ }
			<BackupSchedule />
			<BackupStorage />
			<BackupSettings />
		</div>
	);
}
