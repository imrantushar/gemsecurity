import React, { useEffect, useState, useCallback, useRef } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Badge, Button, Select, TextInput, Toggle, Loading, EmptyState } from '@Components/ui/Controls';
import { useToast } from '@Components/ui/Toast';

/*
 * What the audit log records. These settings have always been live in PHP and
 * accepted by the REST schema, but no screen ever rendered them — the only way
 * to stop logging a category was to edit the option by hand.
 */
const AUDIT_KEYS = [
	'audit_log_enabled',
	'audit_content',
	'audit_plugins_themes',
	'audit_users',
	'audit_settings',
];

const AUDIT_SOURCES = [
	{ key: 'audit_users', label: __( 'User accounts', 'gemsecurity' ), desc: __( 'Registrations, role changes, deletions and profile edits.', 'gemsecurity' ) },
	{ key: 'audit_plugins_themes', label: __( 'Plugins & themes', 'gemsecurity' ), desc: __( 'Activation, deactivation, installation, updates and deletion.', 'gemsecurity' ) },
	{ key: 'audit_settings', label: __( 'Settings changes', 'gemsecurity' ), desc: __( 'Edits to WordPress options, including by other plugins.', 'gemsecurity' ) },
	{ key: 'audit_content', label: __( 'Content', 'gemsecurity' ), desc: __( 'Posts and pages created, edited, published or deleted. The noisiest source on an active site.', 'gemsecurity' ) },
];

/** What gets written to the activity log. */
function AuditSettings() {
	const { form, setField, save, saving, dirty } = useSettingsForm( AUDIT_KEYS );

	return (
		<Card
			title={ __( 'What gets logged', 'gemsecurity' ) }
			description={ __( 'Choose which activity is recorded. Security events — logins, firewall blocks, scans, bans — are always logged and are not affected by these.', 'gemsecurity' ) }
			actions={
				dirty ? (
					<Button variant="secondary" onClick={ () => save() } loading={ saving }>
						{ __( 'Save', 'gemsecurity' ) }
					</Button>
				) : null
			}
		>
			<Toggle
				label={ __( 'Record activity in the audit log', 'gemsecurity' ) }
				description={ __( 'Turning this off stops all of the below. Anything already logged is kept.', 'gemsecurity' ) }
				checked={ form.audit_log_enabled ?? true }
				onChange={ ( v ) => setField( 'audit_log_enabled', v ) }
			/>
			{ ( form.audit_log_enabled ?? true ) && (
				<div className="gs-toggle-list">
					{ AUDIT_SOURCES.map( ( a ) => (
						<Toggle
							key={ a.key }
							label={ a.label }
							description={ a.desc }
							checked={ form[ a.key ] ?? true }
							onChange={ ( v ) => setField( a.key, v ) }
						/>
					) ) }
				</div>
			) }
		</Card>
	);
}

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

/** Expanded detail for one log row: what changed, how, and from which login. */
function LogDetails( { log, ctx, onPost } ) {
	const changes = ctx?.changes && typeof ctx.changes === 'object' ? Object.entries( ctx.changes ) : [];
	return (
		<div className="gs-log-details">
			{ changes.length > 0 && (
				<table className="gs-log-details__diff">
					<tbody>
						{ changes.map( ( [ field, c ] ) => (
							<tr key={ field }>
								<th>{ field }</th>
								<td><del>{ String( c?.old ?? '' ) || '—' }</del></td>
								<td><ins>{ String( c?.new ?? '' ) || '—' }</ins></td>
							</tr>
						) ) }
					</tbody>
				</table>
			) }
			{ ctx?.meta_key && (
				<p><strong>{ ctx.meta_key }</strong> → <code>{ ctx.new === null ? __( '(removed)', 'gemsecurity' ) : String( ctx.new ) }</code></p>
			) }
			{ Array.isArray( ctx?.new_links ) && ctx.new_links.length > 0 && (
				<div className="gs-log-details__links">
					<strong>{ __( 'New outbound links:', 'gemsecurity' ) }</strong>
					<ul>{ ctx.new_links.map( ( u ) => <li key={ u }><code>{ u }</code></li> ) }</ul>
				</div>
			) }
			<dl className="gs-log-details__meta">
				{ ctx?.via && <><dt>{ __( 'Via', 'gemsecurity' ) }</dt><dd>{ ctx.via }</dd></> }
				{ ctx?.session && <><dt>{ __( 'Login session', 'gemsecurity' ) }</dt><dd><code>{ ctx.session }</code></dd></> }
				{ ctx?.ua && <><dt>{ __( 'Browser', 'gemsecurity' ) }</dt><dd>{ ctx.ua }</dd></> }
			</dl>
			<div className="gs-log-details__actions">
				{ log.revision_url && (
					<a className="gs-btn gs-btn--secondary" href={ log.revision_url } target="_blank" rel="noreferrer">
						{ __( 'Compare / restore revision', 'gemsecurity' ) }
					</a>
				) }
				{ ctx?.post_id && (
					<Button variant="secondary" onClick={ () => onPost( ctx.post_id ) }>
						{ __( 'History of this post', 'gemsecurity' ) }
					</Button>
				) }
			</div>
		</div>
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
	const [ userFilter, setUserFilter ] = useState( null ); // { id, name }
	const [ postFilter, setPostFilter ] = useState( 0 );
	const [ open, setOpen ] = useState( {} );
	const [ botBlocklist, setBotBlocklist ] = useState( [] );

	useEffect( () => {
		api.get( 'settings' ).then( ( r ) => {
			const list = r.data?.settings?.bot_blocklist;
			setBotBlocklist( Array.isArray( list ) ? list : [] );
		} ).catch( () => {} );
	}, [] );

	const load = useCallback( () => {
		setLoading( true );
		api.get( 'logs', { params: { page, severity, category, search, per_page: 20, user_id: userFilter?.id || undefined, post_id: postFilter || undefined } } )
			.then( ( r ) => setState( r.data ) )
			.catch( () => {} )
			.finally( () => setLoading( false ) );
	}, [ page, severity, category, search, userFilter, postFilter ] );

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
			<AuditSettings />

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

				{ ( userFilter || postFilter > 0 ) && (
					<div className="gs-log-chips">
						{ userFilter && (
							<button type="button" className="gs-log-chip" onClick={ () => { setUserFilter( null ); setPage( 1 ); } }>
								{ __( 'User:', 'gemsecurity' ) } <strong>{ userFilter.name }</strong> ×
							</button>
						) }
						{ postFilter > 0 && (
							<button type="button" className="gs-log-chip" onClick={ () => { setPostFilter( 0 ); setPage( 1 ); } }>
								{ __( 'Post', 'gemsecurity' ) } <strong>#{ postFilter }</strong> ×
							</button>
						) }
					</div>
				) }

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
								const hasDetails = !! ( ctx && ( ctx.changes || ctx.meta_key || ctx.via || ctx.session ) );
								return (
									<React.Fragment key={ l.id }>
									<tr>
										<td><Badge tone={ SEVERITY_TONE[ l.severity ] || 'info' }>{ l.severity }</Badge></td>
										<td><code>{ l.event_type }</code></td>
										<td className="gs-table__msg">
											{ l.message }
											{ ctx?.matched && <span className="gs-muted"> · { ctx.matched }</span> }
											{ ctx?.reason && <span className="gs-muted"> · { ctx.reason }</span> }
											{ hasDetails && (
												<button type="button" className="gs-link-btn" onClick={ () => setOpen( { ...open, [ l.id ]: ! open[ l.id ] } ) }>
													{ open[ l.id ] ? __( 'Hide details', 'gemsecurity' ) : __( 'Details', 'gemsecurity' ) }
												</button>
											) }
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
												: ( l.user_id
													? (
														<button type="button" className="gs-link-btn" title={ __( 'Show everything this user did', 'gemsecurity' ) }
															onClick={ () => { setUserFilter( { id: l.user_id, name: l.user_display } ); setPage( 1 ); } }>
															{ l.user_display }{ ! String( l.user_display ).startsWith( '#' ) && <span className="gs-muted"> #{ l.user_id }</span> }
														</button>
													)
													: '—' )
											}
											{ ctx?.via && <div className="gs-muted">{ ctx.via }</div> }
										</td>
										<td>{ l.ip_address || '—' }</td>
										<td className="gs-nowrap">{ l.created_at }</td>
									</tr>
									{ open[ l.id ] && (
										<tr className="gs-log-details-row">
											<td colSpan={ 6 }>
												<LogDetails log={ l } ctx={ ctx } onPost={ ( id ) => { setPostFilter( Number( id ) ); setUserFilter( null ); setPage( 1 ); } } />
											</td>
										</tr>
									) }
									</React.Fragment>
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
