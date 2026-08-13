import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import { Card, Button, Badge, EmptyState, Field, TextInput } from '@Components/ui/Controls';
import { useToast } from '@Components/ui/Toast';

const CAT_TONE = { auth: 'info', file: 'warning', firewall: 'warning', admin: 'danger', content: 'info', other: 'info' };

export default function IncidentResponse() {
	const toast = useToast();
	const [ timeline, setTimeline ] = useState( null );
	const [ quar, setQuar ] = useState( null );
	const [ path, setPath ] = useState( '' );
	const [ busy, setBusy ] = useState( false );

	const loadTimeline = () => api.get( 'incident/timeline', { params: { days: 7 } } ).then( ( r ) => setTimeline( r.data.items ) ).catch( () => setTimeline( [] ) );
	const loadQuar = () => api.get( 'incident/quarantine' ).then( ( r ) => setQuar( r.data.items ) ).catch( () => setQuar( [] ) );
	useEffect( () => { loadTimeline(); loadQuar(); }, [] );

	const logoutAll = async () => {
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( __( 'Log out every user on the site? Everyone will need to sign in again.', 'gemsecurity' ) ) ) {
			return;
		}
		setBusy( true );
		try {
			const r = await api.post( 'incident/recover', { action: 'logout_everyone' } );
			toast( `${ __( 'Logged out', 'gemsecurity' ) } ${ r.data.affected }`, 'success' );
		} catch ( e ) { toast( __( 'Failed.', 'gemsecurity' ), 'error' ); }
		setBusy( false );
	};

	const quarantine = async () => {
		if ( ! path.trim() ) {
			return;
		}
		setBusy( true );
		try {
			await api.post( 'incident/quarantine', { path: path.trim() } );
			toast( __( 'File quarantined.', 'gemsecurity' ), 'success' );
			setPath( '' );
			loadQuar();
		} catch ( e ) { toast( e?.response?.data?.message || __( 'Failed.', 'gemsecurity' ), 'error' ); }
		setBusy( false );
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
			<Card
				title={ __( 'Recovery actions', 'gemsecurity' ) }
				description={ __( 'Immediate containment steps after a suspected compromise.', 'gemsecurity' ) }
			>
				<div className="gs-addrow">
					<Button variant="danger" onClick={ logoutAll } loading={ busy }>{ __( 'Log everyone out', 'gemsecurity' ) }</Button>
					<span className="gs-muted">{ __( 'Destroys all sessions site-wide (stops a hijacked session immediately).', 'gemsecurity' ) }</span>
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
				description={ __( 'Move a suspicious file out of harm’s way (reversible) instead of deleting it.', 'gemsecurity' ) }
			>
				<Field label={ __( 'File path (relative to WordPress root)', 'gemsecurity' ) }>
					<div className="gs-addrow">
						<TextInput value={ path } onChange={ ( e ) => setPath( e.target.value ) } placeholder="wp-content/uploads/evil.php" />
						<Button onClick={ quarantine } loading={ busy }>{ __( 'Quarantine', 'gemsecurity' ) }</Button>
					</div>
				</Field>
				{ quar && quar.length > 0 && (
					<table className="gs-table" style={ { marginTop: 12 } }>
						<thead><tr><th>{ __( 'Original path', 'gemsecurity' ) }</th><th>{ __( 'When', 'gemsecurity' ) }</th><th /></tr></thead>
						<tbody>
							{ quar.map( ( q ) => (
								<tr key={ q.id }>
									<td><code>{ q.orig }</code></td>
									<td className="gs-nowrap">{ q.time }</td>
									<td><Button variant="secondary" onClick={ () => restore( q.id ) }>{ __( 'Restore', 'gemsecurity' ) }</Button></td>
								</tr>
							) ) }
						</tbody>
					</table>
				) }
			</Card>
		</div>
	);
}
