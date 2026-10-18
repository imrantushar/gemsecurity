import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import backupApi from '@Utils/backupApi';
import { Card, Button, Badge, EmptyState, Field, TextInput } from '@Components/ui/Controls';
import { useToast } from '@Components/ui/Toast';

const CAT_TONE = { auth: 'info', file: 'warning', firewall: 'warning', admin: 'danger', content: 'info', other: 'info' };

export default function IncidentResponse() {
	const toast = useToast();
	const [ timeline, setTimeline ] = useState( null );
	const [ quar, setQuar ] = useState( null );
	const [ path, setPath ] = useState( '' );
	const [ busy, setBusy ] = useState( '' );

	const loadTimeline = () => api.get( 'incident/timeline', { params: { days: 7 } } ).then( ( r ) => setTimeline( r.data.items ) ).catch( () => setTimeline( [] ) );
	const loadQuar = () => api.get( 'incident/quarantine' ).then( ( r ) => setQuar( r.data.items ) ).catch( () => setQuar( [] ) );
	useEffect( () => { loadTimeline(); loadQuar(); }, [] );

	const logoutAll = async () => {
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( __( 'Log out every user on the site? Everyone, including you, will need to sign in again.', 'gemsecurity' ) ) ) {
			return;
		}
		setBusy( 'logout' );
		try {
			const r = await api.post( 'incident/recover', { action: 'logout_everyone' } );
			toast( `${ __( 'All sessions cleared.', 'gemsecurity' ) } (${ r.data.affected })`, 'success' );
		} catch ( e ) { toast( __( 'Failed.', 'gemsecurity' ), 'error' ); }
		setBusy( '' );
	};

	const regenerateSalts = async () => {
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( __( 'Regenerate security keys & salts? This rewrites wp-config.php and signs everyone out immediately.', 'gemsecurity' ) ) ) {
			return;
		}
		setBusy( 'salts' );
		try {
			await api.post( 'pro/recovery/regenerate-salts', {} );
			toast( __( 'Keys regenerated — you will be signed out.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not regenerate keys.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const rollback = async () => {
		setBusy( 'rollback' );
		try {
			const { data } = await backupApi.get( 'backups', { params: { per_page: 50 } } );
			const clean = ( data.items || [] ).find( ( b ) => b.status === 'completed' );
			if ( ! clean ) {
				toast( __( 'No completed backup found to restore.', 'gemsecurity' ), 'error' );
				setBusy( '' );
				return;
			}
			// eslint-disable-next-line no-alert
			if ( ! window.confirm( `${ __( 'Restore the most recent backup', 'gemsecurity' ) } (#${ clean.id }, ${ clean.created_at })? ${ __( 'This overwrites current files and database.', 'gemsecurity' ) }` ) ) {
				setBusy( '' );
				return;
			}
			await backupApi.post( `backups/${ clean.id }/restore`, {} );
			toast( __( 'Rollback started from the latest backup.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( __( 'Could not start rollback.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const quarantine = async () => {
		if ( ! path.trim() ) {
			return;
		}
		setBusy( 'quarantine' );
		try {
			await api.post( 'incident/quarantine', { path: path.trim() } );
			toast( __( 'File quarantined.', 'gemsecurity' ), 'success' );
			setPath( '' );
			loadQuar();
		} catch ( e ) { toast( e?.response?.data?.message || __( 'Failed.', 'gemsecurity' ), 'error' ); }
		setBusy( '' );
	};

	const restore = async ( id ) => {
		try {
			await api.post( 'incident/restore', { id } );
			toast( __( 'Restored.', 'gemsecurity' ), 'success' );
			loadQuar();
		} catch ( e ) { toast( __( 'Failed.', 'gemsecurity' ), 'error' ); }
	};

	return (
		<div className="gs-page">
			{ /*
			   Every containment action is here. Two of these also sat on the
			   Scanner's malware tab, which meant two "log everyone out"
			   buttons in two places calling two different implementations.
			*/ }
			<Card
				title={ __( 'Recovery actions', 'gemsecurity' ) }
				description={ __( 'Immediate containment steps after a suspected compromise. Each is destructive — read what it does before clicking.', 'gemsecurity' ) }
			>
				<div className="gs-recovery">
					<div>
						<strong>{ __( 'Log everyone out', 'gemsecurity' ) }</strong>
						<p className="gs-card__desc">{ __( 'Destroys every active session site-wide, which stops a hijacked session immediately.', 'gemsecurity' ) }</p>
					</div>
					<Button variant="danger" onClick={ logoutAll } loading={ busy === 'logout' }>{ __( 'Log out everyone', 'gemsecurity' ) }</Button>

					<div>
						<strong>{ __( 'Regenerate keys & salts', 'gemsecurity' ) }</strong>
						<p className="gs-card__desc">{ __( 'Rewrites the wp-config.php secret keys (backed up first) and invalidates every auth cookie.', 'gemsecurity' ) }</p>
					</div>
					<Button variant="danger" onClick={ regenerateSalts } loading={ busy === 'salts' }>{ __( 'Regenerate', 'gemsecurity' ) }</Button>

					{ /* Backups come from the GemBackup plugin; without it there is nothing to roll back to. */ }
					{ window.GemSecurityGlobal?.gembackup?.active && (
						<>
							<div>
								<strong>{ __( 'Roll back to last clean backup', 'gemsecurity' ) }</strong>
								<p className="gs-card__desc">{ __( 'Restores the most recent completed GemBackup backup over the current files and database.', 'gemsecurity' ) }</p>
							</div>
							<Button variant="danger" onClick={ rollback } loading={ busy === 'rollback' }>{ __( 'Restore latest backup', 'gemsecurity' ) }</Button>
						</>
					) }
				</div>
			</Card>

			<Card
				title={ __( 'Forensic timeline', 'gemsecurity' ) }
				description={ __( 'Warning & critical security events across auth, files, firewall and admin — the last 7 days.', 'gemsecurity' ) }
				actions={ <Button variant="secondary" onClick={ loadTimeline }>{ __( 'Refresh', 'gemsecurity' ) }</Button> }
			>
				{ ! timeline ? (
					<p className="gs-muted">{ __( 'Loading…', 'gemsecurity' ) }</p>
				) : timeline.length === 0 ? (
					<EmptyState title={ __( 'Nothing notable', 'gemsecurity' ) } description={ __( 'No warning or critical events in the window.', 'gemsecurity' ) } />
				) : (
					<table className="gs-table">
						<thead><tr><th>{ __( 'When', 'gemsecurity' ) }</th><th>{ __( 'Category', 'gemsecurity' ) }</th><th>{ __( 'Event', 'gemsecurity' ) }</th><th>{ __( 'Message', 'gemsecurity' ) }</th><th>{ __( 'IP', 'gemsecurity' ) }</th></tr></thead>
						<tbody>
							{ timeline.map( ( t ) => (
								<tr key={ t.id }>
									<td className="gs-nowrap">{ t.time }</td>
									<td><Badge tone={ CAT_TONE[ t.category ] || 'info' }>{ t.category }</Badge></td>
									<td className="gs-nowrap">{ t.event }</td>
									<td>{ t.message }</td>
									<td className="gs-nowrap">{ t.ip || '—' }</td>
								</tr>
							) ) }
						</tbody>
					</table>
				) }
			</Card>

			<Card
				title={ __( 'Quarantine', 'gemsecurity' ) }
				description={ __( 'Move a suspicious file out of harm’s way (reversible) instead of deleting it. This is the whole site’s quarantine — anything the malware scanner moved shows up here too.', 'gemsecurity' ) }
			>
				<Field label={ __( 'File path (relative to WordPress root)', 'gemsecurity' ) }>
					<div className="gs-addrow">
						<TextInput value={ path } onChange={ ( e ) => setPath( e.target.value ) } placeholder="wp-content/uploads/evil.php" />
						<Button onClick={ quarantine } loading={ busy === 'quarantine' }>{ __( 'Quarantine', 'gemsecurity' ) }</Button>
					</div>
				</Field>
				{ quar && quar.length > 0 && (
					<table className="gs-table" style={ { marginTop: 12 } }>
						<thead><tr><th>{ __( 'Item', 'gemsecurity' ) }</th><th>{ __( 'Type', 'gemsecurity' ) }</th><th>{ __( 'When', 'gemsecurity' ) }</th><th /></tr></thead>
						<tbody>
							{ quar.map( ( q ) => (
								<tr key={ q.id }>
									<td><code>{ q.label || q.relative }</code></td>
									<td><Badge tone={ q.type === 'db' ? 'info' : 'warning' }>{ q.type === 'db' ? __( 'database', 'gemsecurity' ) : __( 'file', 'gemsecurity' ) }</Badge></td>
									<td className="gs-nowrap">{ q.quarantined_at }</td>
									<td>
										{ q.type === 'db' ? (
											<span className="gs-muted">{ __( 'Restore from the malware scanner', 'gemsecurity' ) }</span>
										) : (
											<Button variant="secondary" onClick={ () => restore( q.id ) }>{ __( 'Restore', 'gemsecurity' ) }</Button>
										) }
									</td>
								</tr>
							) ) }
						</tbody>
					</table>
				) }
			</Card>
		</div>
	);
}
