import React, { useEffect, useState, useCallback, useRef } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import { Card, Badge, Button, Select, TextInput, Loading, EmptyState } from '@Components/ui/Controls';
import { useToast } from '@Components/ui/Toast';

const SEVERITY_TONE = { info: 'info', notice: 'info', warning: 'warning', critical: 'danger' };

function AddToBlocklist( { pattern, alreadyBlocked } ) {
	const toast = useToast();
	const [ added, setAdded ] = useState( false );
	const [ busy, setBusy ] = useState( false );

	const isBlocked = alreadyBlocked || added;

	const handle = async () => {
		setBusy( true );
		try {
			await api.post( 'bots/blocklist', { pattern } );
			setAdded( true );
			toast( __( 'Pattern added to blocklist.', 'gemsecurity' ), 'success' );
		} catch {
			toast( __( 'Could not add pattern.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};

	if ( isBlocked ) {
		return (
			<span className="gs-block-action">
				<code className="gs-block-action__pattern">{ pattern }</code>
				<Badge tone="success">{ __( 'Blocked', 'gemsecurity' ) }</Badge>
			</span>
		);
	}
	return (
		<span className="gs-block-action">
			<code className="gs-block-action__pattern">{ pattern }</code>
			<Button variant="secondary" onClick={ handle } loading={ busy }>
				{ __( 'Block', 'gemsecurity' ) }
			</Button>
		</span>
	);
}

export default function Logs() {
	const toast = useToast();
	const [ state, setState ] = useState( { logs: [], total: 0, total_pages: 1 } );
	const [ loading, setLoading ] = useState( true );
	const [ page, setPage ] = useState( 1 );
	const [ severity, setSeverity ] = useState( '' );
	const [ category, setCategory ] = useState( '' );
	const [ search, setSearch ] = useState( '' );
	const [ botBlocklist, setBotBlocklist ] = useState( [] );

	useEffect( () => {
		api.get( 'settings' ).then( ( r ) => {
			const list = r.data?.settings?.bot_blocklist;
			setBotBlocklist( Array.isArray( list ) ? list : [] );
		} ).catch( () => {} );
	}, [] );

	const load = useCallback( () => {
		setLoading( true );
		api.get( 'logs', { params: { page, severity, category, search, per_page: 20 } } )
			.then( ( r ) => setState( r.data ) )
			.catch( () => {} )
			.finally( () => setLoading( false ) );
	}, [ page, severity, category, search ] );

	useEffect( () => {
		const t = setTimeout( load, search ? 350 : 0 );
		return () => clearTimeout( t );
	}, [ load, search ] );

	const exportCsv = async () => {
		try {
			const r = await api.get( 'logs/export', { params: { severity, category, search } } );
			const blob = new Blob( [ r.data.csv ], { type: 'text/csv' } );
			const a = document.createElement( 'a' );
			a.href = URL.createObjectURL( blob );
			a.download = 'gemsecurity-logs.csv';
			a.click();
		} catch ( e ) {
			toast( __( 'Export failed.', 'gemsecurity' ), 'error' );
		}
	};

	const clearLogs = async () => {
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( __( 'Clear all activity logs? This cannot be undone.', 'gemsecurity' ) ) ) {
			return;
		}
		await api.delete( 'logs' );
		toast( __( 'Logs cleared.', 'gemsecurity' ), 'success' );
		setPage( 1 );
		load();
	};

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Activity log', 'gemsecurity' ) }
				description={ `${ state.total } ${ __( 'events', 'gemsecurity' ) }` }
				actions={
					<div style={ { display: 'flex', gap: 8 } }>
						<Button variant="secondary" onClick={ exportCsv }>{ __( 'Export CSV', 'gemsecurity' ) }</Button>
						<Button variant="danger" onClick={ clearLogs }>{ __( 'Clear logs', 'gemsecurity' ) }</Button>
					</div>
				}
			>
				<div className="gs-filters">
					<Select
						value={ category }
						onChange={ ( e ) => { setCategory( e.target.value ); setPage( 1 ); } }
						options={ [
							{ value: '', label: __( 'All categories', 'gemsecurity' ) },
							{ value: 'login', label: __( 'Login & 2FA', 'gemsecurity' ) },
							{ value: 'firewall', label: __( 'Firewall', 'gemsecurity' ) },
							{ value: 'bots', label: __( 'Bots', 'gemsecurity' ) },
							{ value: 'admin_guard', label: __( 'Admin Guard', 'gemsecurity' ) },
							{ value: 'scanner', label: __( 'Scanner', 'gemsecurity' ) },
							{ value: 'vulnerability', label: __( 'Vulnerabilities', 'gemsecurity' ) },
							{ value: 'content', label: __( 'Content', 'gemsecurity' ) },
							{ value: 'plugins_themes', label: __( 'Plugins & themes', 'gemsecurity' ) },
							{ value: 'users', label: __( 'Users', 'gemsecurity' ) },
							{ value: 'settings', label: __( 'Settings', 'gemsecurity' ) },
							{ value: 'geolocation', label: __( 'Geolocation', 'gemsecurity' ) },
						] }
					/>
					<Select
						value={ severity }
						onChange={ ( e ) => { setSeverity( e.target.value ); setPage( 1 ); } }
						options={ [
							{ value: '', label: __( 'All severities', 'gemsecurity' ) },
							{ value: 'info', label: __( 'Info', 'gemsecurity' ) },
							{ value: 'notice', label: __( 'Notice', 'gemsecurity' ) },
							{ value: 'warning', label: __( 'Warning', 'gemsecurity' ) },
							{ value: 'critical', label: __( 'Critical', 'gemsecurity' ) },
						] }
					/>
					<TextInput
						placeholder={ __( 'Search message or IP…', 'gemsecurity' ) }
						value={ search }
						onChange={ ( e ) => { setSearch( e.target.value ); setPage( 1 ); } }
					/>
				</div>

				{ loading ? (
					<Loading />
				) : state.logs.length === 0 ? (
					<EmptyState title={ __( 'No events', 'gemsecurity' ) } description={ __( 'Nothing matches your filters yet.', 'gemsecurity' ) } />
				) : (
					<table className="gs-table gs-table--logs">
						<thead>
							<tr>
								<th>{ __( 'Severity', 'gemsecurity' ) }</th>
								<th>{ __( 'Event', 'gemsecurity' ) }</th>
								<th>{ __( 'Message', 'gemsecurity' ) }</th>
								<th>{ __( 'User / UA', 'gemsecurity' ) }</th>
								<th>{ __( 'IP', 'gemsecurity' ) }</th>
								<th>{ __( 'When', 'gemsecurity' ) }</th>
							</tr>
						</thead>
						<tbody>
							{ state.logs.map( ( l ) => {
								const ctx = l.context ? ( () => { try { return JSON.parse( l.context ); } catch { return null; } } )() : null;
								return (
									<tr key={ l.id }>
										<td><Badge tone={ SEVERITY_TONE[ l.severity ] || 'info' }>{ l.severity }</Badge></td>
										<td><code>{ l.event_type }</code></td>
										<td className="gs-table__msg">
											{ l.message }
											{ ctx?.matched && <span className="gs-muted"> · { ctx.matched }</span> }
											{ ctx?.reason && <span className="gs-muted"> · { ctx.reason }</span> }
											{ l.event_type === 'seems_bot' && ctx?.suggested_pattern && (
												<div style={ { marginTop: 6 } }>
													<AddToBlocklist
														pattern={ ctx.suggested_pattern }
														alreadyBlocked={ botBlocklist.includes( ctx.suggested_pattern ) }
													/>
												</div>
											) }
										</td>
										<td className="gs-table__msg">
											{ ( l.event_type === 'waf_bad_bot' || l.event_type === 'seems_bot' ) && ctx?.ua
												? <code title={ ctx.ua }>{ ctx.ua.length > 48 ? ctx.ua.slice( 0, 48 ) + '…' : ctx.ua }</code>
												: ( l.user_display || '—' )
											}
										</td>
										<td>{ l.ip_address || '—' }</td>
										<td className="gs-nowrap">{ l.created_at }</td>
									</tr>
								);
							} ) }
						</tbody>
					</table>
				) }

				{ state.total_pages > 1 && (
					<div className="gs-pager">
						<Button variant="secondary" disabled={ page <= 1 } onClick={ () => setPage( page - 1 ) }>
							{ __( 'Previous', 'gemsecurity' ) }
						</Button>
						<span>{ page } / { state.total_pages }</span>
						<Button variant="secondary" disabled={ page >= state.total_pages } onClick={ () => setPage( page + 1 ) }>
							{ __( 'Next', 'gemsecurity' ) }
						</Button>
					</div>
				) }
			</Card>
		</div>
	);
}
