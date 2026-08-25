import React, { useEffect, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Button, Badge, EmptyState, Field, ListInput } from '@Components/ui/Controls';
import TestCredentials from '@Components/ui/TestCredentials';
import Icon from '@Components/ui/Icon';
import { useToast } from '@Components/ui/Toast';
import { ProGate, ProBadge, isLocked, isPro, proFeatures } from '@Components/ui/Pro';
import MalwareScan from '@Containers/pages/MalwareScan';
import SearchPanel from '@Containers/pages/SearchPanel';

/* Stable reference: an inline array here would be a new value on every render. */
const SCANNER_KEYS = [
	'scanner_auto_scan',
	'vuln_scan_enabled',
	'file_watcher_enabled',
	'link_scanner_enabled',
	'link_blocklist',
	'link_allowlist',
	// Pro extends the one file baseline to more of the tree rather than
	// running a second baseline of its own.
	'file_baseline_scopes',
	// Pro auto-update enforcement — it belongs next to the vulnerability scan
	// that decides what counts as "vulnerable".
	'auto_update_vulnerable_enabled',
	'auto_update_all_plugins',
	'auto_update_all_themes',
];

/** Extra trees Pro can fold into the file baseline. */
const BASELINE_SCOPES = [
	{ key: 'core', label: __( 'WordPress core', 'gemsecurity' ) },
	{ key: 'plugins', label: __( 'All plugins', 'gemsecurity' ) },
	{ key: 'themes', label: __( 'All themes', 'gemsecurity' ) },
];

/**
 * .htaccess findings, with a one-click removal.
 *
 * Removal is a quarantine, not a delete: the file moves into the protected
 * store and can be put back from Incident Response if the rule turns out to be
 * something the host legitimately added. The site's own root .htaccess is
 * never offered — it carries the WordPress permalink rules, and an attacker
 * normally appends to it rather than replacing it, so moving the whole file
 * would take the working half with it.
 */
function HtaccessFindings( { rows, onChanged } ) {
	const toast = useToast();
	const [ busy, setBusy ] = useState( '' );

	if ( ! rows || rows.length === 0 ) {
		return (
			<Card title={ __( '.htaccess rules', 'gemsecurity' ) }>
				<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'No .htaccess file grants execution or redirects traffic.', 'gemsecurity' ) }</p>
			</Card>
		);
	}

	const remove = async ( path ) => {
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( sprintf( /* translators: %s: file path. */ __( 'Move %s into quarantine? It can be restored from Incident Response.', 'gemsecurity' ), path ) ) ) {
			return;
		}
		setBusy( path );
		try {
			await api.post( 'scan/quarantine', { path } );
			toast( __( 'Moved into quarantine.', 'gemsecurity' ), 'success' );
			onChanged();
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not move that file.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	return (
		<Card
			title={ __( '.htaccess rules', 'gemsecurity' ) }
			description={ __( 'Rules that grant execution or send traffic elsewhere. Directory lock-downs written by plugins are not listed — only directives that hand something out.', 'gemsecurity' ) }
		>
			<table className="gs-table">
				<thead><tr>
					<th>{ __( 'File', 'gemsecurity' ) }</th>
					<th>{ __( 'What it does', 'gemsecurity' ) }</th>
					<th>{ __( 'Severity', 'gemsecurity' ) }</th>
					<th />
				</tr></thead>
				<tbody>
					{ rows.map( ( h ) => (
						<tr key={ h.file }>
							<td><code>{ h.file }</code></td>
							<td>
								{ h.reason }
								{ h.note && <div className="gs-muted" style={ { marginTop: 4 } }>{ h.note }</div> }
							</td>
							<td><Badge tone={ h.severity === 'critical' ? 'danger' : 'warning' }>{ h.severity }</Badge></td>
							<td>
								{ h.removable ? (
									<Button variant="danger" loading={ busy === h.file } onClick={ () => remove( h.file ) }>
										{ __( 'Quarantine', 'gemsecurity' ) }
									</Button>
								) : (
									<span className="gs-muted">{ __( 'Edit by hand', 'gemsecurity' ) }</span>
								) }
							</td>
						</tr>
					) ) }
				</tbody>
			</table>
		</Card>
	);
}

/** Open the Malware tab directly when arriving via the legacy ?page= alias. */
function initialTab() {
	try {
		return new URLSearchParams( window.location.search ).get( 'page' ) === 'gemsecurity-malware'
			? 'malware'
			: 'integrity';
	} catch ( e ) {
		return 'integrity';
	}
}

function SupplyChainReport() {
	const [ data, setData ] = useState( null );
	const [ busy, setBusy ] = useState( false );
	const load = () => {
		setBusy( true );
		api.get( 'supply-chain' ).then( ( r ) => setData( r.data ) ).catch( () => setData( { plugins: [], persistence: [] } ) ).finally( () => setBusy( false ) );
	};
	useEffect( load, [] );

	const risky = data ? data.plugins.filter( ( p ) => p.status !== 'ok' ) : [];

	return (
		<>
			<Card
				title={ __( 'Supply chain', 'gemsecurity' ) }
				description={ __( 'Installed plugins cross-checked against the WordPress.org directory — removed (possible takedown), abandoned, or outdated.', 'gemsecurity' ) }
				actions={ <Button variant="secondary" onClick={ load } loading={ busy }>{ __( 'Re-check', 'gemsecurity' ) }</Button> }
			>
				{ ! data ? (
					<p className="gs-muted">{ __( 'Checking…', 'gemsecurity' ) }</p>
				) : risky.length === 0 ? (
					<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'Every installed plugin is current and present in the directory.', 'gemsecurity' ) }</p>
				) : (
					<table className="gs-table">
						<thead><tr><th>{ __( 'Plugin', 'gemsecurity' ) }</th><th>{ __( 'Version', 'gemsecurity' ) }</th><th>{ __( 'Status', 'gemsecurity' ) }</th><th>{ __( 'Note', 'gemsecurity' ) }</th></tr></thead>
						<tbody>
							{ risky.map( ( p ) => (
								<tr key={ p.slug }>
									<td>{ p.name }</td>
									<td className="gs-nowrap">{ p.version }</td>
									<td><Badge tone={ p.status === 'closed' ? 'danger' : p.status === 'abandoned' ? 'warning' : 'info' }>{ p.status }</Badge></td>
									<td>{ p.note }</td>
								</tr>
							) ) }
						</tbody>
					</table>
				) }
			</Card>

			<Card
				title={ __( 'Persistence checks', 'gemsecurity' ) }
				description={ __( 'Places attackers hide to survive a cleanup: must-use plugins, drop-ins, obfuscated code and suspicious cron.', 'gemsecurity' ) }
			>
				{ ! data ? (
					<p className="gs-muted">{ __( 'Checking…', 'gemsecurity' ) }</p>
				) : data.persistence.length === 0 ? (
					<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'No must-use plugins, drop-ins, obfuscated code or suspicious cron found.', 'gemsecurity' ) }</p>
				) : (
					<table className="gs-table">
						<thead><tr><th>{ __( 'Type', 'gemsecurity' ) }</th><th>{ __( 'Path / hook', 'gemsecurity' ) }</th><th>{ __( 'Reason', 'gemsecurity' ) }</th><th>{ __( 'Severity', 'gemsecurity' ) }</th></tr></thead>
						<tbody>
							{ data.persistence.map( ( r, i ) => (
								<tr key={ i }>
									<td className="gs-nowrap">{ r.type }</td>
									<td><code>{ r.path }</code></td>
									<td>{ r.reason }</td>
									<td><Badge tone={ r.severity === 'critical' ? 'danger' : r.severity === 'warning' ? 'warning' : 'info' }>{ r.severity }</Badge></td>
								</tr>
							) ) }
						</tbody>
					</table>
				) }
			</Card>
		</>
	);
}

/**
 * Restore WordPress core from the official package.
 *
 * Separate from the scan because it writes to disk: the analysis is shown
 * first, and the button says exactly how many files it will touch. Eviction of
 * files core does not ship is opt-in, since a host occasionally drops
 * something legitimate into wp-admin.
 */
function CoreRepair() {
	const toast = useToast();
	const [ info, setInfo ] = useState( null );
	const [ busy, setBusy ] = useState( '' );
	const [ evict, setEvict ] = useState( true );

	const check = async () => {
		setBusy( 'check' );
		try {
			const { data } = await api.get( 'pro/core-repair' );
			setInfo( data );
			if ( ! data.available ) {
				toast( __( 'WordPress.org did not return checksums for this version.', 'gemsecurity' ), 'warning' );
			}
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not check core files.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const repair = async () => {
		const total = ( info?.modified?.length || 0 ) + ( info?.missing?.length || 0 );
		const extras = evict ? info?.extras?.length || 0 : 0;
		if (
			! window.confirm(
				sprintf(
					/* translators: 1: core files, 2: foreign files. */
					__(
						'Replace %1$d core file(s) with clean copies from WordPress.org and quarantine %2$d file(s) core does not ship? The current version of each is saved to quarantine first, and wp-content is not touched.',
						'gemsecurity'
					),
					total,
					extras
				)
			)
		) {
			return;
		}
		setBusy( 'repair' );
		try {
			const { data } = await api.post( 'pro/core-repair', { restore: true, evict } );
			setInfo( data.analysis );
			toast(
				sprintf(
					/* translators: 1: restored, 2: quarantined, 3: failed. */
					__( '%1$d core file(s) restored, %2$d quarantined, %3$d failed.', 'gemsecurity' ),
					data.restored.length,
					data.evicted.length,
					data.failed.length
				),
				data.failed.length ? 'warning' : 'success'
			);
			( data.failed || [] ).forEach( ( f ) => toast( `${ f.file }: ${ f.reason }`, 'error' ) );
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Core repair failed.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const needed = ( info?.modified?.length || 0 ) + ( info?.missing?.length || 0 ) + ( evict ? info?.extras?.length || 0 : 0 );

	return (
		<div className="gs-corerepair">
		<div className="gs-addrow">
			<Button variant="secondary" onClick={ check } loading={ busy === 'check' }>
				{ __( 'Check core files', 'gemsecurity' ) }
			</Button>
			{ info && info.available && (
				<>
					<Toggle
						label={ __( 'Also quarantine files core does not ship', 'gemsecurity' ) }
						checked={ evict }
						onChange={ setEvict }
					/>
					{ needed > 0 ? (
						<Button variant="danger" onClick={ repair } loading={ busy === 'repair' }>
							{ sprintf(
								/* translators: %d: number of files. */
								__( 'Repair %d file(s)', 'gemsecurity' ),
								needed
							) }
						</Button>
					) : (
						<Badge tone="success">{ __( 'Core matches WordPress.org', 'gemsecurity' ) }</Badge>
					) }
				</>
			) }
		</div>

		{ /* Show exactly what would be removed before offering to remove it. */ }
		{ info && info.note && (
			<div className="gs-alert gs-alert--warning">
				<Icon name="alert" size={ 18 } />
				<span>{ info.note }</span>
			</div>
		) }
		{ info && ( info.extras || [] ).length > 0 && (
			<table className="gs-table">
				<thead>
					<tr>
						<th>{ __( 'Path', 'gemsecurity' ) }</th>
						<th>{ __( 'Why', 'gemsecurity' ) }</th>
					</tr>
				</thead>
				<tbody>
					{ info.extras.slice( 0, 100 ).map( ( e ) => (
						<tr key={ e.file }>
							<td>
								<code>{ e.file }</code>
								{ 'dir' === e.type && ' /' }
							</td>
							<td>
								<Badge tone={ 'critical' === e.severity ? 'danger' : 'warning' }>
									{ e.reason }
								</Badge>
							</td>
						</tr>
					) ) }
				</tbody>
			</table>
		) }
		</div>
	);
}

/**
 * "I have looked at this file and it is fine."
 *
 * A scanner works on patterns, so some findings are unusual-but-legitimate
 * code. Marking one keeps the list meaningful — but the mark is tied to the
 * file's current contents, so if it changes later it is reported again rather
 * than becoming a permanent blind spot.
 */
function MarkSafe( { path, onMarked } ) {
	const toast = useToast();
	const [ busy, setBusy ] = useState( false );

	const mark = async () => {
		setBusy( true );
		try {
			await api.post( 'safe-files', { path } );
			toast(
				sprintf( /* translators: %s: file path. */ __( '%s marked as safe.', 'gemsecurity' ), path ),
				'success'
			);
			if ( onMarked ) {
				onMarked( path );
			}
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not mark that file.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};

	return (
		<Button variant="secondary" onClick={ mark } loading={ busy }>
			{ __( 'Mark as safe', 'gemsecurity' ) }
		</Button>
	);
}

/** The files somebody has reviewed, so the decision can be undone. */
function SafeFiles() {
	const toast = useToast();
	const [ files, setFiles ] = useState( null );

	const load = () =>
		api.get( 'safe-files' ).then( ( r ) => setFiles( r.data.files ) ).catch( () => setFiles( [] ) );
	useEffect( () => { load(); }, [] );

	const remove = async ( path ) => {
		try {
			const { data } = await api.delete( 'safe-files', { data: { path } } );
			setFiles( data.files );
			toast( __( 'That file will be reported again.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( __( 'Could not remove the mark.', 'gemsecurity' ), 'error' );
		}
	};

	if ( ! files || files.length === 0 ) {
		return null;
	}

	return (
		<Card
			title={ __( 'Files marked as safe', 'gemsecurity' ) }
			description={ __( 'Reviewed by you and skipped by every scan. A mark covers the exact contents that were reviewed — if the file changes, it is reported again.', 'gemsecurity' ) }
		>
			<table className="gs-table">
				<thead>
					<tr>
						<th>{ __( 'File', 'gemsecurity' ) }</th>
						<th>{ __( 'Marked', 'gemsecurity' ) }</th>
						<th />
					</tr>
				</thead>
				<tbody>
					{ files.map( ( f ) => (
						<tr key={ f.path }>
							<td>
								<code>{ f.path }</code>
								{ f.changed && (
									<> <Badge tone="warning">{ __( 'changed since review', 'gemsecurity' ) }</Badge></>
								) }
								{ f.missing && (
									<> <Badge tone="info">{ __( 'no longer exists', 'gemsecurity' ) }</Badge></>
								) }
							</td>
							<td className="gs-nowrap">{ f.marked_at }</td>
							<td>
								<Button variant="secondary" onClick={ () => remove( f.path ) }>
									{ __( 'Remove', 'gemsecurity' ) }
								</Button>
							</td>
						</tr>
					) ) }
				</tbody>
			</table>
		</Card>
	);
}

export default function Scanner() {
	const { form, setField, save, saving, dirty } = useSettingsForm( SCANNER_KEYS );
	const toast = useToast();
	const [ tab, setTab ] = useState( initialTab );
	const [ result, setResult ] = useState( null );
	const [ vuln, setVuln ] = useState( null );
	const [ mu, setMu ] = useState( null );
	const [ running, setRunning ] = useState( false );
	const [ resetting, setResetting ] = useState( false );

	const malwareLocked = isLocked( 'gemsecurity-malware' );
	const malwareFeature = proFeatures()[ 'gemsecurity-malware' ] || {};

	useEffect( () => {
		api.get( 'scan' ).then( ( r ) => { setResult( r.data.result ); setVuln( r.data.vuln ); } ).catch( () => {} );
		api.get( 'mu-plugins' ).then( ( r ) => setMu( r.data ) ).catch( () => {} );
	}, [] );

	const runScan = async () => {
		setRunning( true );
		try {
			const r = await api.post( 'scan' );
			setResult( r.data.result );
			setVuln( r.data.vuln );
			// Refresh the auto-loaded code inventory so the scan re-checks it.
			api.get( 'mu-plugins' ).then( ( m ) => setMu( m.data ) ).catch( () => {} );
			const issues = ( r.data.result?.issue_count || 0 ) + ( r.data.vuln?.count || 0 );
			toast( __( 'Scan complete.', 'gemsecurity' ), issues ? 'warning' : 'success' );
		} catch ( e ) {
			toast( __( 'Scan failed.', 'gemsecurity' ), 'error' );
		}
		setRunning( false );
	};

	const resetBaseline = async () => {
		setResetting( true );
		try {
			await api.post( 'scan/baseline' );
			toast( __( 'Clean baseline saved. Future scans compare against it.', 'gemsecurity' ), 'success' );
			// Refresh the view so the just-captured baseline is reflected.
			const r = await api.post( 'scan' );
			setResult( r.data.result );
			setVuln( r.data.vuln );
		} catch ( e ) {
			toast( __( 'Could not save the baseline.', 'gemsecurity' ), 'error' );
		}
		setResetting( false );
	};

	const SEV_TONE = { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', none: 'info' };
	const CHANGE_TONE = { added: 'danger', modified: 'danger', deleted: 'warning' };

	return (
		<div className="gs-page">
			<div className="gs-tabs" role="tablist">
				<button
					type="button"
					role="tab"
					aria-selected={ tab === 'integrity' }
					className={ `gs-tab ${ tab === 'integrity' ? 'is-active' : '' }` }
					onClick={ () => setTab( 'integrity' ) }
				>
					<Icon name="radar" size={ 15 } /> { __( 'Integrity & files', 'gemsecurity' ) }
				</button>
				<button
					type="button"
					role="tab"
					aria-selected={ tab === 'malware' }
					className={ `gs-tab ${ tab === 'malware' ? 'is-active' : '' }` }
					onClick={ () => setTab( 'malware' ) }
				>
					<Icon name="bug" size={ 15 } /> { __( 'Malware & recovery', 'gemsecurity' ) }
					{ malwareLocked && <ProBadge /> }
				</button>
				<button
					type="button"
					role="tab"
					aria-selected={ tab === 'search' }
					className={ `gs-tab ${ tab === 'search' ? 'is-active' : '' }` }
					onClick={ () => setTab( 'search' ) }
				>
					<Icon name="list" size={ 15 } /> { __( 'Search', 'gemsecurity' ) }
				</button>
			</div>

			{ tab === 'malware' && (
				<ProGate title={ malwareFeature.title } description={ malwareFeature.desc }>
					<MalwareScan />
				</ProGate>
			) }

			{ tab === 'search' && <SearchPanel /> }

			{ tab === 'integrity' && (
				<>
					<Card
						title={ __( 'Integrity & file scanner', 'gemsecurity' ) }
						description={ __( 'Checks WordPress core files against official checksums and looks for suspicious PHP in your uploads folder.', 'gemsecurity' ) }
						actions={
							<Button onClick={ runScan } loading={ running }>
								<Icon name="radar" size={ 16 } /> { __( 'Run scan now', 'gemsecurity' ) }
							</Button>
						}
					>
						<Toggle
							label={ __( 'Run a scan automatically every day', 'gemsecurity' ) }
							checked={ form.scanner_auto_scan }
							onChange={ ( v ) => setField( 'scanner_auto_scan', v ) }
						/>
						<Toggle
							label={ __( 'Check core, plugins & themes for known vulnerabilities', 'gemsecurity' ) }
							description={ __( 'Compares installed versions against a public vulnerability database during the daily scan.', 'gemsecurity' ) }
							checked={ form.vuln_scan_enabled }
							onChange={ ( v ) => setField( 'vuln_scan_enabled', v ) }
						/>
						{ /* Both scans depend on an outbound call that a locked-down
						     host can block, which would look like "nothing found". */ }
						<TestCredentials
							target="service"
							getValues={ () => ( { service: 'vulnerability_feed' } ) }
							label={ __( 'Test vulnerability feed', 'gemsecurity' ) }
						/>
						<TestCredentials
							target="service"
							getValues={ () => ( { service: 'wordpress_org' } ) }
							label={ __( 'Test WordPress.org connection', 'gemsecurity' ) }
						/>
						<Toggle
							label={ __( 'Watch theme, must-use plugins & drop-ins for file changes', 'gemsecurity' ) }
							description={ __( 'Baselines these files and reports any that are added, modified or removed. Also scans files and the database for hidden spam-link injections that core checksums cannot see.', 'gemsecurity' ) }
							checked={ form.file_watcher_enabled }
							onChange={ ( v ) => setField( 'file_watcher_enabled', v ) }
						/>
						{ form.file_watcher_enabled && (
							<Field
								label={ <>{ __( 'Also baseline', 'gemsecurity' ) } { ! isPro() && <ProBadge /> }</> }
								description={ __( 'Widen the same baseline to more of the install. Bigger trees make each scan slower, so add only what this site needs watched.', 'gemsecurity' ) }
							>
								<div style={ { display: 'flex', gap: 18, flexWrap: 'wrap' } }>
									{ BASELINE_SCOPES.map( ( sc ) => {
										const scopes = Array.isArray( form.file_baseline_scopes ) ? form.file_baseline_scopes : [];
										return (
											<label key={ sc.key } style={ { display: 'flex', alignItems: 'center', gap: 6 } }>
												<input
													type="checkbox"
													checked={ scopes.includes( sc.key ) }
													disabled={ ! isPro() }
													onChange={ ( e ) => setField(
														'file_baseline_scopes',
														e.target.checked
															? [ ...new Set( [ ...scopes, sc.key ] ) ]
															: scopes.filter( ( x ) => x !== sc.key )
													) }
												/>
												{ sc.label }
											</label>
										);
									} ) }
								</div>
							</Field>
						) }
						<Toggle
							label={ __( 'Detect links to malicious or spam sites', 'gemsecurity' ) }
							description={ __( 'Lists every external site your content links to and flags blocklisted, hidden/cloaked, or spam-category (gambling, pharma, adult…) domains — catching injected backlink spam.', 'gemsecurity' ) }
							checked={ form.link_scanner_enabled }
							onChange={ ( v ) => setField( 'link_scanner_enabled', v ) }
						/>
						{ form.link_scanner_enabled && (
							<>
								<Field
									label={ __( 'Link blocklist', 'gemsecurity' ) }
									description={ __( 'One domain per line. Any content that links to these (or their subdomains) is flagged.', 'gemsecurity' ) }
								>
									<ListInput
										value={ form.link_blocklist }
										onChange={ ( v ) => setField( 'link_blocklist', v ) }
										placeholder={ 'chickenroad.de\nbad-spam-site.example' }
									/>
								</Field>
								<Field
									label={ __( 'Link allowlist', 'gemsecurity' ) }
									description={ __( 'One domain per line. Trusted external sites to never flag. Your own domain is always allowed.', 'gemsecurity' ) }
								>
									<ListInput
										value={ form.link_allowlist }
										onChange={ ( v ) => setField( 'link_allowlist', v ) }
										placeholder={ 'github.com\nyoutube.com' }
									/>
								</Field>
							</>
						) }
						<div className="gs-subcard">
							<strong>{ __( 'Auto-update enforcement', 'gemsecurity' ) } { ! isPro() && <ProBadge /> }</strong>
							<p className="gs-card__desc">{ __( 'Close the gap between a vulnerability being disclosed and this site being patched.', 'gemsecurity' ) }</p>
							<Toggle
								label={ __( 'Auto-update vulnerable plugins & themes', 'gemsecurity' ) }
								description={ __( 'Automatically update anything the vulnerability scan above has flagged.', 'gemsecurity' ) }
								checked={ form.auto_update_vulnerable_enabled }
								onChange={ ( v ) => setField( 'auto_update_vulnerable_enabled', v ) }
								disabled={ ! isPro() }
							/>
							<Toggle
								label={ __( 'Auto-update all plugins', 'gemsecurity' ) }
								checked={ form.auto_update_all_plugins }
								onChange={ ( v ) => setField( 'auto_update_all_plugins', v ) }
								disabled={ ! isPro() }
							/>
							<Toggle
								label={ __( 'Auto-update all themes', 'gemsecurity' ) }
								checked={ form.auto_update_all_themes }
								onChange={ ( v ) => setField( 'auto_update_all_themes', v ) }
								disabled={ ! isPro() }
							/>
						</div>
						{ dirty && (
							<div className="gs-savebar gs-savebar--inline">
								<Button variant="secondary" onClick={ () => save() } loading={ saving }>
									{ __( 'Save', 'gemsecurity' ) }
								</Button>
							</div>
						) }
					</Card>

					{ ! result ? (
						<Card>
							<EmptyState
								title={ __( 'No scan yet', 'gemsecurity' ) }
								description={ __( 'Run your first scan to check this site for integrity issues.', 'gemsecurity' ) }
							/>
						</Card>
					) : (
						<>
							<Card>
								<div className="gs-scan-summary">
									<Badge tone={ result.status === 'clean' ? 'success' : 'danger' }>
										{ result.status === 'clean' ? __( 'No issues found', 'gemsecurity' ) : `${ result.issue_count } ${ __( 'issue(s)', 'gemsecurity' ) }` }
									</Badge>
									<span className="gs-muted">
										{ __( 'WordPress', 'gemsecurity' ) } { result.wp_version } · { __( 'scanned', 'gemsecurity' ) } { result.scanned_at }
									</span>
								</div>
							</Card>

							<Card
								title={ __( 'Core file integrity', 'gemsecurity' ) }
								actions={ isPro() ? <CoreRepair /> : null }
							>
								{ result.core_issues.length === 0 ? (
									<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'All core files match the official checksums.', 'gemsecurity' ) }</p>
								) : (
									<table className="gs-table">
										<thead><tr><th>{ __( 'File', 'gemsecurity' ) }</th><th>{ __( 'Issue', 'gemsecurity' ) }</th></tr></thead>
										<tbody>
											{ result.core_issues.map( ( c, i ) => (
												<tr key={ i }>
													<td><code>{ c.file }</code></td>
													<td><Badge tone={ c.issue === 'missing' ? 'warning' : 'danger' }>{ c.issue }</Badge></td>
												</tr>
											) ) }
										</tbody>
									</table>
								) }
							</Card>

							<Card
							title={ __( 'Unexpected / foreign files', 'gemsecurity' ) }
							description={ __( 'Files that are not part of WordPress core and belong to no installed plugin — code hidden in wp-admin / wp-includes, loose files in the plugins folder, and plugins that run but never show on the Plugins screen.', 'gemsecurity' ) }
						>
							{ ! result.foreign_files || result.foreign_files.length === 0 ? (
								<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'No unexpected files in core directories or the plugins folder.', 'gemsecurity' ) }</p>
							) : (
								<table className="gs-table">
									<thead><tr><th>{ __( 'File', 'gemsecurity' ) }</th><th>{ __( 'Reason', 'gemsecurity' ) }</th><th>{ __( 'Severity', 'gemsecurity' ) }</th><th /></tr></thead>
									<tbody>
										{ result.foreign_files.map( ( f, i ) => (
											<tr key={ i }>
												<td><code>{ f.file }</code></td>
												<td>{ f.reason }</td>
												<td><Badge tone={ f.severity === 'critical' ? 'danger' : 'warning' }>{ f.severity }</Badge></td>
												<td><MarkSafe path={ f.file } onMarked={ runScan } /></td>
											</tr>
										) ) }
									</tbody>
								</table>
							) }
						</Card>

						{ ! isPro() && (
						<Card
							title={ __( 'Suspicious files', 'gemsecurity' ) }
							description={ __( 'Heuristic pattern check over uploads and must-use plugins.', 'gemsecurity' ) }
						>
								{ result.suspicious.length === 0 ? (
									<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'No suspicious files detected.', 'gemsecurity' ) }</p>
								) : (
									<table className="gs-table">
										<thead><tr><th>{ __( 'File', 'gemsecurity' ) }</th><th>{ __( 'Reason', 'gemsecurity' ) }</th><th>{ __( 'Severity', 'gemsecurity' ) }</th><th /></tr></thead>
										<tbody>
											{ result.suspicious.map( ( s, i ) => (
												<tr key={ i }>
													<td><code>{ s.file }</code></td>
													<td>{ s.reason }</td>
													<td><Badge tone={ s.severity === 'critical' ? 'danger' : 'warning' }>{ s.severity }</Badge></td>
													<td><MarkSafe path={ s.file } onMarked={ runScan } /></td>
												</tr>
											) ) }
										</tbody>
									</table>
								) }
							</Card>
						) }

							<HtaccessFindings rows={ result.htaccess } onChanged={ runScan } />

							<SafeFiles />

							{ result.file_watcher && (
								<Card
									title={ __( 'File change watcher', 'gemsecurity' ) }
									description={ __( 'Baseline integrity of your active theme, must-use plugins and drop-ins — plus hidden spam-link injection checks across those files and the database.', 'gemsecurity' ) }
									actions={
										<Button variant="secondary" onClick={ resetBaseline } loading={ resetting }>
											<Icon name="check" size={ 16 } /> { __( 'Set current files as clean baseline', 'gemsecurity' ) }
										</Button>
									}
								>
									<div className="gs-scan-summary">
										<Badge tone={ result.file_watcher.issue_count ? 'danger' : 'success' }>
											{ result.file_watcher.issue_count
												? sprintf(
													/* translators: 1: changed file count, 2: injection count. */
													__( '%1$d changed · %2$d injection(s)', 'gemsecurity' ),
													result.file_watcher.change_count,
													result.file_watcher.injection_count
												)
												: __( 'No file changes or injections', 'gemsecurity' ) }
										</Badge>
										<span className="gs-muted">
											{ result.file_watcher.baseline && result.file_watcher.baseline.established_at
												? sprintf(
													/* translators: 1: number of baselined files, 2: date/time. */
													__( 'Baseline: %1$d files · %2$s', 'gemsecurity' ),
													result.file_watcher.baseline.file_count,
													result.file_watcher.baseline.established_at
												)
												: __( 'No baseline captured yet', 'gemsecurity' ) }
										</span>
									</div>

									{ result.file_watcher.baseline && result.file_watcher.baseline.just_created && (
										<div className="gs-alert gs-alert--warning">
											<Icon name="alert" size={ 18 } />
											<span>{ __( 'Baseline captured for the first time — later scans will flag any added, modified or deleted file. Anything already present is still checked by the injection scan below.', 'gemsecurity' ) }</span>
										</div>
									) }

									{ result.file_watcher.injections.length > 0 && (
										<>
											<div className="gs-muted" style={ { fontWeight: 600, margin: '14px 0 6px' } }>{ __( 'Injected code / hidden spam links', 'gemsecurity' ) }</div>
											<table className="gs-table">
												<thead><tr><th>{ __( 'Location', 'gemsecurity' ) }</th><th>{ __( 'Reason', 'gemsecurity' ) }</th><th>{ __( 'Severity', 'gemsecurity' ) }</th></tr></thead>
												<tbody>
													{ result.file_watcher.injections.map( ( s, i ) => (
														<tr key={ i }>
															<td><code>{ s.file }</code></td>
															<td>{ s.reason }</td>
															<td><Badge tone={ s.severity === 'critical' ? 'danger' : 'warning' }>{ s.severity }</Badge></td>
														</tr>
													) ) }
												</tbody>
											</table>
										</>
									) }

									{ result.file_watcher.changes.length > 0 && (
										<>
											<div className="gs-muted" style={ { fontWeight: 600, margin: '14px 0 6px' } }>{ __( 'Changed files since baseline', 'gemsecurity' ) }</div>
											<table className="gs-table">
												<thead><tr><th>{ __( 'File', 'gemsecurity' ) }</th><th>{ __( 'Change', 'gemsecurity' ) }</th></tr></thead>
												<tbody>
													{ result.file_watcher.changes.map( ( c, i ) => (
														<tr key={ i }>
															<td><code>{ c.file }</code></td>
															<td><Badge tone={ CHANGE_TONE[ c.status ] || 'warning' }>{ c.status }</Badge></td>
														</tr>
													) ) }
												</tbody>
											</table>
										</>
									) }

									{ result.file_watcher.injections.length === 0 && result.file_watcher.changes.length === 0 && (
										<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'No file changes or code injections detected.', 'gemsecurity' ) }</p>
									) }
								</Card>
							) }
						</>
					) }

					{ result && result.link_scan && (
					<Card
						title={ __( 'Linked sites (outbound links)', 'gemsecurity' ) }
						description={ sprintf(
							/* translators: 1: external domain count, 2: total link count. */
							__( 'Your content links to %1$d external domain(s) across %2$d link(s). Flagged rows are blocklisted, hidden/cloaked, or match a spam category.', 'gemsecurity' ),
							result.link_scan.external_domains,
							result.link_scan.links_scanned
						) }
					>
						{ result.link_scan.flagged.length === 0 ? (
							<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'No links to blocklisted, hidden or spam-category sites.', 'gemsecurity' ) }</p>
						) : (
							<table className="gs-table">
								<thead><tr>
									<th>{ __( 'Domain', 'gemsecurity' ) }</th>
									<th>{ __( 'Links', 'gemsecurity' ) }</th>
									<th>{ __( 'Reason', 'gemsecurity' ) }</th>
									<th>{ __( 'Severity', 'gemsecurity' ) }</th>
								</tr></thead>
								<tbody>
									{ result.link_scan.flagged.map( ( f, i ) => (
										<tr key={ i }>
											<td>
												<code>{ f.domain }</code>
												<div className="gs-muted" style={ { fontSize: 11 } }>{ f.sample }</div>
											</td>
											<td>{ f.count }</td>
											<td>{ f.reason }</td>
											<td><Badge tone={ f.severity === 'critical' ? 'danger' : 'warning' }>{ f.severity }</Badge></td>
										</tr>
									) ) }
								</tbody>
							</table>
						) }
					</Card>
				) }

				{ vuln && (
						<Card
							title={ __( 'Known vulnerabilities', 'gemsecurity' ) }
							description={ vuln.scanned_at ? `${ __( 'Scanned', 'gemsecurity' ) } ${ vuln.scanned_at }` : '' }
						>
							{ ! vuln.items || vuln.items.length === 0 ? (
								<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'No known vulnerabilities in your installed core, plugins or themes.', 'gemsecurity' ) }</p>
							) : (
								<table className="gs-table">
									<thead><tr>
										<th>{ __( 'Component', 'gemsecurity' ) }</th>
										<th>{ __( 'Vulnerability', 'gemsecurity' ) }</th>
										<th>{ __( 'Severity', 'gemsecurity' ) }</th>
										<th>{ __( 'Fixed in', 'gemsecurity' ) }</th>
									</tr></thead>
									<tbody>
										{ vuln.items.map( ( item ) => item.vulnerabilities.map( ( v, i ) => (
											<tr key={ item.slug + i }>
												<td>
													<strong>{ item.name }</strong>
													<span className="gs-muted"> { item.type } · { item.version }</span>
												</td>
												<td>
													{ v.link ? <a href={ v.link } target="_blank" rel="noreferrer">{ v.title }</a> : v.title }
													{ v.cve && <div className="gs-muted"><code>{ v.cve }</code></div> }
												</td>
												<td><Badge tone={ SEV_TONE[ v.severity ] || 'warning' }>{ v.severity }</Badge></td>
												<td>{ v.fixed_in ? v.fixed_in : '—' }</td>
											</tr>
										) ) ) }
									</tbody>
								</table>
							) }
						</Card>
					) }

					{ mu && (
						<Card
							title={ __( 'Auto-executed code (mu-plugins & drop-ins)', 'gemsecurity' ) }
							description={ __( 'Every PHP file WordPress auto-runs from wp-content/mu-plugins, plus drop-ins like db.php and object-cache.php. None appear on the Plugins screen — review anything you did not install, especially a headerless file or an unexpected drop-in.', 'gemsecurity' ) }
						>
							{ mu.relocated && (
								<div className="gs-alert gs-alert--warning">
									<Icon name="alert" size={ 18 } />
									<span>
										{ sprintf(
											/* translators: %s: mu-plugins directory path. */
											__( 'The must-use plugins directory has been relocated to %s via WPMU_PLUGIN_DIR. If you did not set this, treat it as a compromise.', 'gemsecurity' ),
											mu.dir
										) }
									</span>
								</div>
							) }
							{ mu.has_loader && (
								<div className="gs-alert gs-alert--warning">
									<Icon name="alert" size={ 18 } />
									<span>{ __( 'A must-use plugin loads PHP from a subfolder. That is a legitimate pattern, but also how malware hides its payload one level down — review any nested files flagged below.', 'gemsecurity' ) }</span>
								</div>
							) }
							{ ! mu.dir_exists || mu.count === 0 ? (
								<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'No must-use plugins or drop-ins are installed.', 'gemsecurity' ) }</p>
							) : (
								<>
									{ mu.suspicious_count > 0 && (
										<div className="gs-alert gs-alert--warning">
											<Icon name="alert" size={ 18 } />
											<span>
												{ sprintf(
													/* translators: %d: number of flagged files. */
													__( '%d auto-loaded file(s) look suspicious. A hidden back-door often lives here — review the flagged rows below.', 'gemsecurity' ),
													mu.suspicious_count
												) }
											</span>
										</div>
									) }
									<table className="gs-table">
										<thead><tr>
											<th>{ __( 'File', 'gemsecurity' ) }</th>
											<th>{ __( 'Name', 'gemsecurity' ) }</th>
											<th>{ __( 'Modified', 'gemsecurity' ) }</th>
											<th>{ __( 'Status', 'gemsecurity' ) }</th>
										</tr></thead>
										<tbody>
											{ mu.items.map( ( m, i ) => (
												<tr key={ i }>
													<td>
														<code>{ m.file }</code>{ m.type && m.type !== 'mu-plugin' && ( <div className="gs-muted" style={ { fontSize: 11 } }>{ m.type === 'dropin' ? __( 'drop-in', 'gemsecurity' ) : __( 'nested', 'gemsecurity' ) }</div> ) }
														<div className="gs-muted" style={ { fontSize: 11 } }>{ m.size }</div>
													</td>
													<td>
														{ m.name }{ m.version ? ` · v${ m.version }` : '' }
														{ m.reason && <div className="gs-muted" style={ { fontSize: 11 } }>{ m.reason }</div> }
													</td>
													<td className="gs-nowrap">{ m.modified }</td>
													<td>
														{ m.severity === 'critical' && <Badge tone="danger">{ __( 'Malicious', 'gemsecurity' ) }</Badge> }
														{ m.severity === 'warning' && <Badge tone="warning">{ __( 'Review', 'gemsecurity' ) }</Badge> }
														{ m.severity === 'ok' && <Badge tone={ m.is_stub ? 'info' : 'success' }>{ m.is_stub ? __( 'Placeholder', 'gemsecurity' ) : __( 'OK', 'gemsecurity' ) }</Badge> }
													</td>
												</tr>
											) ) }
										</tbody>
									</table>
								</>
							) }
						</Card>
					) }

					<SupplyChainReport />
				</>
			) }
		</div>
	);
}
