import React, { useEffect, useMemo, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api from '@Utils/api';
import { useToast } from '@Components/ui/Toast';
import Icon from '@Components/ui/Icon';
import { Card, Badge, Button, EmptyState, Loading, TextInput, Select, Toggle } from '@Components/ui/Controls';

const STATUS = {
	verified: [ 'success', __( 'Verified · WordPress.org', 'gemsecurity' ) ],
	own: [ 'info', __( 'GemSecurity', 'gemsecurity' ) ],
	not_org: [ 'warning', __( 'Not on WordPress.org', 'gemsecurity' ) ],
	modified: [ 'danger', __( 'Modified — differs from .org', 'gemsecurity' ) ],
	unknown: [ 'info', __( 'Could not check', 'gemsecurity' ) ],
	unchecked: [ 'info', __( 'Not checked yet', 'gemsecurity' ) ],
	missing: [ 'info', __( 'Missing', 'gemsecurity' ) ],
	org: [ 'success', __( 'On WordPress.org', 'gemsecurity' ) ],
	trusted: [ 'success', __( 'Trusted', 'gemsecurity' ) ],
	changed: [ 'danger', __( 'Edited since trusted', 'gemsecurity' ) ],
	untrusted: [ 'warning', __( 'Not trusted', 'gemsecurity' ) ],
};

const EVENT = {
	plugin_deactivated: __( 'Force-deactivated', 'gemsecurity' ),
	activation_blocked: __( 'Activation blocked', 'gemsecurity' ),
	mu_quarantined: __( 'Must-use plugin quarantined', 'gemsecurity' ),
	install_blocked: __( 'Install blocked', 'gemsecurity' ),
	upload_blocked: __( 'Executable upload blocked', 'gemsecurity' ),
	install_unlocked: __( 'Install Lock lifted', 'gemsecurity' ),
};

const LOCK_HELP = {
	off: __( 'Anyone with the right role can upload and install plugins and themes as usual.', 'gemsecurity' ),
	uploads: __( 'Recommended. Nobody — administrators included — can upload a plugin or theme .zip. Installing from the WordPress.org directory and updating still work. Zip uploads are how custom backdoors usually get in.', 'gemsecurity' ),
	installs: __( 'No new plugins or themes at all, from uploads or the directory. Updates of what is installed still work.', 'gemsecurity' ),
	full: __( 'The site is frozen: no installs, updates (including automatic and translation updates), deletes or code editing. Use for sites that should never change; remember to unlock for maintenance.', 'gemsecurity' ),
};

function Countdown( { until } ) {
	const [ now, setNow ] = useState( Date.now() );
	useEffect( () => { const t = setInterval( () => setNow( Date.now() ), 1000 ); return () => clearInterval( t ); }, [] );
	const left = Math.max( 0, Math.round( until - now / 1000 ) );
	return <>{ Math.floor( left / 60 ) }:{ String( left % 60 ).padStart( 2, '0' ) }</>;
}

function StatusBadge( { status } ) {
	const [ tone, label ] = STATUS[ status ] || [ 'info', status ];
	return <Badge tone={ tone }>{ label }</Badge>;
}

export default function PluginGuard() {
	const toast = useToast();
	const [ data, setData ] = useState( null );
	const [ busy, setBusy ] = useState( '' );
	const [ tab, setTab ] = useState( 'plugins' );
	const [ setup, setSetup ] = useState( false );
	const [ picked, setPicked ] = useState( {} );
	const [ pre, setPre ] = useState( { type: 'plugin', slug: '' } );

	const load = () => api.get( 'plugin-guard' ).then( ( r ) => setData( r.data ) ).catch( () => toast( __( 'Could not load Plugin Guard.', 'gemsecurity' ), 'error' ) );
	useEffect( () => { load(); }, [] );

	const call = async ( key, path, body, ok ) => {
		setBusy( key );
		try {
			const r = await api.post( path, body || {} );
			setData( r.data );
			if ( ok ) toast( ok, 'success' );
			return true;
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Request failed.', 'gemsecurity' ), 'error' );
			return false;
		} finally {
			setBusy( '' );
		}
	};

	// Items that would be blocked if enforcement were switched on now.
	const needsTrust = useMemo( () => {
		if ( ! data ) return [];
		return [
			...data.plugins.filter( ( p ) => ! p.allowed ).map( ( p ) => ( { key: p.key, label: p.name, sub: `${ p.file } · ${ ( STATUS[ p.status ] || [] )[ 1 ] || p.status }`, active: p.active, danger: p.status === 'modified' } ) ),
			...data.mu_plugins.filter( ( m ) => ! m.allowed ).map( ( m ) => ( { key: m.key, label: m.name, sub: `mu-plugins/${ m.file } · ${ __( 'must-use', 'gemsecurity' ) }`, active: true, danger: m.status === 'changed' } ) ),
		];
	}, [ data ] );

	const openSetup = () => {
		const def = {};
		// Pre-tick what is running today, except anything that looks tampered.
		needsTrust.forEach( ( i ) => { def[ i.key ] = i.active && ! i.danger; } );
		setPicked( def );
		setSetup( true );
	};

	if ( ! data ) return <Loading />;

	const counts = {
		verified: data.plugins.filter( ( p ) => p.status === 'verified' ).length,
		trusted: data.plugins.filter( ( p ) => p.trusted ).length,
		blocked: data.plugins.filter( ( p ) => ! p.allowed ).length + data.mu_plugins.filter( ( m ) => ! m.allowed ).length,
		modified: data.plugins.filter( ( p ) => p.status === 'modified' ).length,
	};

	const trustBtn = ( row ) => row.trusted ? (
		<Button variant="secondary" loading={ busy === 'u' + row.key } onClick={ () => call( 'u' + row.key, 'plugin-guard/untrust', { key: row.key }, __( 'Trust removed.', 'gemsecurity' ) ) }>
			{ __( 'Remove trust', 'gemsecurity' ) }
		</Button>
	) : (
		<Button variant="secondary" loading={ busy === 't' + row.key } onClick={ () => call( 't' + row.key, 'plugin-guard/trust', { key: row.key }, __( 'Marked trusted.', 'gemsecurity' ) ) }>
			{ __( 'Trust', 'gemsecurity' ) }
		</Button>
	);

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Plugin Guard', 'gemsecurity' ) }
				description={ __( 'Only plugins verified against WordPress.org, or marked trusted by you, can run or be installed. Anything else — including a must-use plugin dropped in by an attacker — is stopped, and you get a DANGER email.', 'gemsecurity' ) }
				actions={ data.enabled
					? <Badge tone="success">{ __( 'Enforcing', 'gemsecurity' ) }</Badge>
					: <Badge tone="warning">{ __( 'Report only', 'gemsecurity' ) }</Badge> }
			>
				{ data.kill_switch && (
					<div className="gs-alert gs-alert--warning"><Icon name="alert" size={ 16 } />{ __( 'GEMSECURITY_PLUGIN_GUARD_OFF is defined in wp-config.php, so enforcement is disabled.', 'gemsecurity' ) }</div>
				) }
				{ data.enabled && ! data.mu_installed && (
					<div className="gs-alert gs-alert--warning"><Icon name="alert" size={ 16 } />{ __( 'The early loader could not be written to wp-content/mu-plugins (not writable). Untrusted plugins are still blocked from activating, but one switched on directly in the database runs once before it is deactivated.', 'gemsecurity' ) }</div>
				) }

				<table className="gs-table">
					<tbody>
						<tr><td>{ __( 'Verified on WordPress.org', 'gemsecurity' ) }</td><td><strong>{ counts.verified }</strong></td></tr>
						<tr><td>{ __( 'Trusted by you', 'gemsecurity' ) }</td><td><strong>{ counts.trusted }</strong></td></tr>
						<tr><td>{ __( 'Modified from the .org release', 'gemsecurity' ) }</td><td><strong>{ counts.modified }</strong></td></tr>
						<tr><td>{ data.enabled ? __( 'Blocked (not verified or trusted)', 'gemsecurity' ) : __( 'Would be blocked', 'gemsecurity' ) }</td><td><strong>{ counts.blocked }</strong></td></tr>
					</tbody>
				</table>

				<div className="gs-savebar gs-savebar--inline">
					<Button variant="secondary" loading={ busy === 'verify' } onClick={ () => call( 'verify', 'plugin-guard/verify', {}, __( 'Re-checked against WordPress.org.', 'gemsecurity' ) ) }>
						{ __( 'Re-check against WordPress.org', 'gemsecurity' ) }
					</Button>
					{ data.enabled ? (
						<Button variant="danger" loading={ busy === 'off' } onClick={ () => window.confirm( __( 'Turn enforcement off? Untrusted plugins will be able to run again.', 'gemsecurity' ) ) && call( 'off', 'plugin-guard/enable', { enabled: false }, __( 'Enforcement off.', 'gemsecurity' ) ) }>
							{ __( 'Turn enforcement off', 'gemsecurity' ) }
						</Button>
					) : ! setup && (
						<Button onClick={ openSetup }>{ __( 'Turn on enforcement…', 'gemsecurity' ) }</Button>
					) }
				</div>
			</Card>

			{ setup && ! data.enabled && (
				<Card
					title={ __( 'Choose what to trust', 'gemsecurity' ) }
					description={ __( 'These are not verified on WordPress.org. Ticked items are trusted and keep running; unticked ones are deactivated (plugins) or quarantined (must-use plugins) as soon as you confirm. Untick anything you do not recognise.', 'gemsecurity' ) }
				>
					{ needsTrust.length === 0 ? (
						<EmptyState title={ __( 'Everything is verified', 'gemsecurity' ) } description={ __( 'Nothing will be blocked.', 'gemsecurity' ) } />
					) : (
						<table className="gs-table">
							<tbody>
								{ needsTrust.map( ( i ) => (
									<tr key={ i.key }>
										<td style={ { width: 32 } }>
											<input type="checkbox" checked={ !! picked[ i.key ] } onChange={ ( e ) => setPicked( { ...picked, [ i.key ]: e.target.checked } ) } />
										</td>
										<td>
											<strong>{ i.label }</strong>{ ' ' }
											{ i.danger && <Badge tone="danger">{ __( 'Looks tampered', 'gemsecurity' ) }</Badge> }
											<div className="gs-muted">{ i.sub }{ i.active ? '' : ` · ${ __( 'inactive', 'gemsecurity' ) }` }</div>
										</td>
									</tr>
								) ) }
							</tbody>
						</table>
					) }
					<div className="gs-savebar gs-savebar--inline">
						<Button variant="secondary" onClick={ () => setSetup( false ) }>{ __( 'Cancel', 'gemsecurity' ) }</Button>
						<Button
							loading={ busy === 'on' }
							onClick={ async () => {
								const trust = Object.keys( picked ).filter( ( k ) => picked[ k ] );
								if ( await call( 'on', 'plugin-guard/enable', { enabled: true, trust }, __( 'Plugin Guard is now enforcing.', 'gemsecurity' ) ) ) setSetup( false );
							} }
						>
							{ __( 'Trust selected & turn on', 'gemsecurity' ) }
						</Button>
					</div>
				</Card>
			) }

			<div className="gs-tabs" role="tablist">
				{ [
					[ 'plugins', __( 'Plugins', 'gemsecurity' ), data.plugins.length ],
					[ 'lock', __( 'Install Lock', 'gemsecurity' ), data.lock.effective === 'off' ? __( 'off', 'gemsecurity' ) : __( 'on', 'gemsecurity' ) ],
					[ 'shield', __( 'Upload Shield', 'gemsecurity' ), data.shield.enabled ? __( 'on', 'gemsecurity' ) : __( 'off', 'gemsecurity' ) ],
					[ 'mu', __( 'Must-use', 'gemsecurity' ), data.mu_plugins.length ],
					[ 'themes', __( 'Themes', 'gemsecurity' ), data.themes.length ],
					[ 'preapprove', __( 'Pre-approve', 'gemsecurity' ), data.preapproved.length ],
					[ 'activity', __( 'Activity', 'gemsecurity' ), data.events.length ],
				].map( ( [ id, label, n ] ) => (
					<button key={ id } type="button" role="tab" aria-selected={ tab === id } className={ `gs-tab ${ tab === id ? 'is-active' : '' }` } onClick={ () => setTab( id ) }>
						{ label } <span className="gs-muted">{ n }</span>
					</button>
				) ) }
			</div>

			{ tab === 'plugins' && (
				<Card title={ __( 'Installed plugins', 'gemsecurity' ) }>
					<table className="gs-table">
						<thead><tr>
							<th>{ __( 'Plugin', 'gemsecurity' ) }</th>
							<th>{ __( 'Source', 'gemsecurity' ) }</th>
							<th>{ __( 'Trust', 'gemsecurity' ) }</th>
							<th></th>
						</tr></thead>
						<tbody>
							{ data.plugins.map( ( p ) => (
								<tr key={ p.file }>
									<td>
										<strong>{ p.name }</strong> <span className="gs-muted">{ p.version }</span>
										<div className="gs-muted">{ p.file }{ p.active ? ` · ${ __( 'active', 'gemsecurity' ) }` : '' }</div>
										{ p.note && p.status !== 'verified' && <div className="gs-muted">{ p.note }</div> }
									</td>
									<td className="gs-nowrap"><StatusBadge status={ p.status } /></td>
									<td className="gs-nowrap">
										{ p.trusted
											? <Badge tone="success">{ sprintf( /* translators: %s user */ __( 'Trusted by %s', 'gemsecurity' ), p.trusted.by ) }</Badge>
											: p.allowed ? <span className="gs-muted">—</span> : <Badge tone={ data.enabled ? 'danger' : 'warning' }>{ data.enabled ? __( 'Blocked', 'gemsecurity' ) : __( 'Not trusted', 'gemsecurity' ) }</Badge> }
									</td>
									<td className="gs-nowrap">{ p.status !== 'own' && trustBtn( p ) }</td>
								</tr>
							) ) }
						</tbody>
					</table>
				</Card>
			) }

			{ tab === 'lock' && (
				<Card
					title={ __( 'Install Lock', 'gemsecurity' ) }
					description={ __( 'Takes away the ability to add plugins and themes — for every account, administrators included — so a stolen admin password cannot be used to upload a backdoor. Unlock for a few minutes when you need to install something.', 'gemsecurity' ) }
					actions={ data.lock.effective === 'off'
						? <Badge tone={ data.lock.mode === 'off' ? 'warning' : 'info' }>{ data.lock.mode === 'off' ? __( 'Off', 'gemsecurity' ) : __( 'Temporarily unlocked', 'gemsecurity' ) }</Badge>
						: <Badge tone="success">{ __( 'Locked', 'gemsecurity' ) }</Badge> }
				>
					{ data.lock.file_mods_constant && (
						<div className="gs-alert gs-alert--warning"><Icon name="alert" size={ 16 } />{ __( 'DISALLOW_FILE_MODS is already set in wp-config.php, which blocks all installs and updates regardless of this setting.', 'gemsecurity' ) }</div>
					) }
					<table className="gs-table">
						<tbody>
							{ Object.entries( data.lock.modes ).map( ( [ id, label ] ) => (
								<tr key={ id }>
									<td style={ { width: 32 } }>
										<input
											type="radio"
											name="gs-lock-mode"
											checked={ data.lock.mode === id }
											disabled={ !! busy }
											onChange={ () => ( id !== 'full' || window.confirm( __( 'Freeze mode also stops security updates. Continue?', 'gemsecurity' ) ) ) && call( 'lock', 'plugin-guard/lock', { mode: id }, __( 'Install Lock updated.', 'gemsecurity' ) ) }
										/>
									</td>
									<td>
										<strong>{ label }</strong>{ id === 'uploads' && <> <Badge tone="success">{ __( 'Recommended', 'gemsecurity' ) }</Badge></> }
										<div className="gs-muted">{ LOCK_HELP[ id ] }</div>
									</td>
								</tr>
							) ) }
						</tbody>
					</table>
					{ data.lock.mode !== 'off' && (
						<div className="gs-savebar gs-savebar--inline">
							{ data.lock.unlock_until ? (
								<>
									<span className="gs-muted">{ __( 'Unlocked — re-locks in', 'gemsecurity' ) } <strong><Countdown until={ data.lock.unlock_until } /></strong></span>
									<Button variant="secondary" loading={ busy === 'relock' } onClick={ () => call( 'relock', 'plugin-guard/unlock', { minutes: 0 }, __( 'Locked again.', 'gemsecurity' ) ) }>{ __( 'Lock now', 'gemsecurity' ) }</Button>
								</>
							) : (
								<Button variant="secondary" loading={ busy === 'unlock' } onClick={ () => call( 'unlock', 'plugin-guard/unlock', { minutes: 15 }, __( 'Unlocked for 15 minutes.', 'gemsecurity' ) ) }>{ __( 'Unlock for 15 minutes', 'gemsecurity' ) }</Button>
							) }
						</div>
					) }
					<p className="gs-muted" style={ { marginTop: 12 } }>{ __( 'Unlocking is logged and sends an alert email. WP-CLI and direct file access (FTP/SSH) are not affected — Plugin Guard enforcement still stops untrusted code they add from running.', 'gemsecurity' ) }</p>
				</Card>
			) }

			{ tab === 'shield' && (
				<>
					<Card
						title={ __( 'Upload Shield', 'gemsecurity' ) }
						description={ __( 'Refuses any uploaded file that can run code on the server — on every upload path: the media library, forms, page builders, file-manager plugins and the REST API. It checks every part of the file name (so "shell.php.jpg" is caught) and the file content (so a picture with PHP hidden inside is caught too).', 'gemsecurity' ) }
						actions={ <Badge tone={ data.shield.enabled ? 'success' : 'warning' }>{ data.shield.enabled ? __( 'On', 'gemsecurity' ) : __( 'Off', 'gemsecurity' ) }</Badge> }
					>
						<Toggle
							label={ __( 'Block executable uploads', 'gemsecurity' ) }
							description={ __( 'Recommended. A .php (or similar) file is never a legitimate upload.', 'gemsecurity' ) }
							checked={ data.shield.enabled }
							disabled={ !! busy }
							onChange={ ( v ) => call( 'shield', 'plugin-guard/shield', { upload_shield: v }, v ? __( 'Upload Shield on.', 'gemsecurity' ) : __( 'Upload Shield off.', 'gemsecurity' ) ) }
						/>
						<Toggle
							label={ __( 'Also block SVG, HTML and JavaScript files', 'gemsecurity' ) }
							description={ __( 'These can carry script that runs in visitors’ browsers. Leave off if you upload SVG logos — SVGs containing script are refused either way.', 'gemsecurity' ) }
							checked={ data.shield.markup }
							disabled={ !! busy || ! data.shield.enabled }
							onChange={ ( v ) => call( 'shield', 'plugin-guard/shield', { shield_markup: v }, __( 'Saved.', 'gemsecurity' ) ) }
						/>
						<p className="gs-muted" style={ { marginTop: 12 } }>
							{ __( 'Blocked extensions:', 'gemsecurity' ) } <code>{ data.shield.exec_exts.join( ' ' ) }</code>
						</p>
					</Card>

					<Card
						title={ __( 'Can PHP run inside uploads?', 'gemsecurity' ) }
						description={ __( 'Last line of defence: even if a file reaches the uploads folder some other way (an exploited plugin, FTP), it must not be able to run. This test places a harmless PHP file in uploads, requests it, and deletes it.', 'gemsecurity' ) }
						actions={ data.shield.probe ? (
							<Badge tone={ data.shield.probe.result === 'blocked' ? 'success' : data.shield.probe.result === 'executes' ? 'danger' : 'info' }>
								{ data.shield.probe.result === 'blocked' ? __( 'Protected', 'gemsecurity' ) : data.shield.probe.result === 'executes' ? __( 'PHP executes!', 'gemsecurity' ) : __( 'Unknown', 'gemsecurity' ) }
							</Badge>
						) : null }
					>
						{ data.shield.probe && <p className={ data.shield.probe.result === 'executes' ? '' : 'gs-muted' }>{ data.shield.probe.detail } <span className="gs-muted">({ data.shield.probe.at })</span></p> }
						<p className="gs-muted">
							{ data.shield.htaccess
								? __( 'uploads/.htaccess deny rules are installed (used by Apache and LiteSpeed).', 'gemsecurity' )
								: __( 'uploads/.htaccess deny rules are not installed.', 'gemsecurity' ) }
						</p>
						{ ( data.shield.server === 'nginx' || data.shield.probe?.result === 'executes' ) && (
							<>
								<p>{ __( 'This server ignores .htaccess. Ask your host to add this to the site’s nginx config:', 'gemsecurity' ) }</p>
								<pre className="gs-code" style={ { whiteSpace: 'pre-wrap', userSelect: 'all' } }>{ data.shield.nginx }</pre>
							</>
						) }
						<div className="gs-savebar gs-savebar--inline">
							<Button variant="secondary" loading={ busy === 'probe' } onClick={ () => call( 'probe', 'plugin-guard/probe', {}, __( 'Test finished.', 'gemsecurity' ) ) }>{ __( 'Run test', 'gemsecurity' ) }</Button>
						</div>
					</Card>
				</>
			) }

			{ tab === 'mu' && (
				<>
					<Card
						title={ __( 'Must-use plugins', 'gemsecurity' ) }
						description={ __( 'Must-use plugins run on every request and cannot be switched off from wp-admin. They are trusted by exact content — if a trusted file is edited, it loses its trust and is quarantined.', 'gemsecurity' ) }
					>
						{ data.mu_plugins.length === 0 ? (
							<EmptyState title={ __( 'No must-use plugins', 'gemsecurity' ) } />
						) : (
							<table className="gs-table">
								<thead><tr><th>{ __( 'File', 'gemsecurity' ) }</th><th>{ __( 'Status', 'gemsecurity' ) }</th><th></th></tr></thead>
								<tbody>
									{ data.mu_plugins.map( ( m ) => (
										<tr key={ m.file }>
											<td><strong>{ m.name }</strong><div className="gs-muted">{ m.file } · { m.modified } · { m.size } B</div></td>
											<td className="gs-nowrap"><StatusBadge status={ m.status } /></td>
											<td className="gs-nowrap">
												{ m.status !== 'own' && ( m.status === 'trusted' ? trustBtn( m ) : (
													<Button variant="secondary" loading={ busy === 't' + m.key } onClick={ () => call( 't' + m.key, 'plugin-guard/trust', { key: m.key }, __( 'Trusted at its current content.', 'gemsecurity' ) ) }>
														{ m.status === 'changed' ? __( 'Trust new version', 'gemsecurity' ) : __( 'Trust', 'gemsecurity' ) }
													</Button>
												) ) }
											</td>
										</tr>
									) ) }
								</tbody>
							</table>
						) }
					</Card>
					<Card title={ __( 'Quarantined by Plugin Guard', 'gemsecurity' ) } description={ __( 'Moved out of mu-plugins before they could run. Restore only a file you recognise — it is trusted on restore.', 'gemsecurity' ) }>
						{ data.quarantined.length === 0 ? (
							<EmptyState title={ __( 'Nothing quarantined', 'gemsecurity' ) } />
						) : (
							<table className="gs-table">
								<tbody>
									{ data.quarantined.map( ( q ) => (
										<tr key={ q.id }>
											<td><code>{ q.relative }</code><div className="gs-muted">{ q.quarantined_at }</div></td>
											<td className="gs-nowrap">
												<Button variant="secondary" loading={ busy === 'r' + q.id } onClick={ () => window.confirm( __( 'Restore this file and trust it? It will run on every request.', 'gemsecurity' ) ) && call( 'r' + q.id, 'plugin-guard/restore', { id: q.id }, __( 'Restored and trusted.', 'gemsecurity' ) ) }>
													{ __( 'Restore & trust', 'gemsecurity' ) }
												</Button>
											</td>
										</tr>
									) ) }
								</tbody>
							</table>
						) }
					</Card>
				</>
			) }

			{ tab === 'themes' && (
				<Card
					title={ __( 'Installed themes', 'gemsecurity' ) }
					description={ __( 'WordPress.org publishes no theme checksums, so themes are matched by name. Installing a theme that is not on WordPress.org needs it to be trusted first.', 'gemsecurity' ) }
				>
					<table className="gs-table">
						<thead><tr><th>{ __( 'Theme', 'gemsecurity' ) }</th><th>{ __( 'Source', 'gemsecurity' ) }</th><th></th></tr></thead>
						<tbody>
							{ data.themes.map( ( t ) => (
								<tr key={ t.slug }>
									<td><strong>{ t.name }</strong> <span className="gs-muted">{ t.version }</span><div className="gs-muted">{ t.slug }{ t.active ? ` · ${ __( 'active', 'gemsecurity' ) }` : '' }</div></td>
									<td className="gs-nowrap">
										<StatusBadge status={ t.status } />{ ' ' }
										{ t.trusted && <Badge tone="success">{ __( 'Trusted', 'gemsecurity' ) }</Badge> }
									</td>
									<td className="gs-nowrap">{ trustBtn( t ) }</td>
								</tr>
							) ) }
						</tbody>
					</table>
				</Card>
			) }

			{ tab === 'preapprove' && (
				<Card
					title={ __( 'Pre-approve an upload', 'gemsecurity' ) }
					description={ __( 'Before uploading a premium or custom plugin/theme zip, add its folder name here. Uploads that are not on WordPress.org and not listed here are refused.', 'gemsecurity' ) }
				>
					<ul className="gs-muted" style={ { margin: '0 0 14px', paddingLeft: 18, listStyle: 'disc' } }>
						<li>{ __( 'Enter only the folder name — e.g. "academy", not "academy/academy.php".', 'gemsecurity' ) }</li>
						<li>{ __( 'It is the top-level folder inside the zip, which can differ from the zip file name: "academy-pro-2.1.0.zip" usually contains "academy-pro".', 'gemsecurity' ) }</li>
						<li>{ __( 'Allowed characters: lowercase letters, numbers, dot, dash and underscore.', 'gemsecurity' ) }</li>
						<li>{ __( 'Trust is by folder name, so it also covers future updates of that plugin or theme.', 'gemsecurity' ) }</li>
					</ul>
					<div style={ { display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' } }>
						<Select value={ pre.type } onChange={ ( e ) => setPre( { ...pre, type: e.target.value } ) } options={ [ { value: 'plugin', label: __( 'Plugin', 'gemsecurity' ) }, { value: 'theme', label: __( 'Theme', 'gemsecurity' ) } ] } />
						<TextInput value={ pre.slug } placeholder="my-pro-plugin" onChange={ ( e ) => setPre( { ...pre, slug: e.target.value.trim().toLowerCase() } ) } />
						<Button
							disabled={ ! pre.slug }
							loading={ busy === 'pre' }
							onClick={ async () => {
								if ( await call( 'pre', 'plugin-guard/trust', { key: `${ pre.type }:${ pre.slug }`, name: pre.slug }, __( 'Pre-approved. You can upload it now.', 'gemsecurity' ) ) ) setPre( { ...pre, slug: '' } );
							} }
						>
							{ __( 'Pre-approve', 'gemsecurity' ) }
						</Button>
					</div>
					{ data.preapproved.length > 0 && (
						<table className="gs-table" style={ { marginTop: 16 } }>
							<tbody>
								{ data.preapproved.map( ( p ) => (
									<tr key={ p.key }>
										<td><code>{ p.key }</code><div className="gs-muted">{ sprintf( /* translators: 1 user 2 date */ __( 'by %1$s on %2$s · not installed yet', 'gemsecurity' ), p.by, p.at ) }</div></td>
										<td className="gs-nowrap">{ trustBtn( { ...p, trusted: true } ) }</td>
									</tr>
								) ) }
							</tbody>
						</table>
					) }
				</Card>
			) }

			{ tab === 'activity' && (
				<Card title={ __( 'Blocked activity', 'gemsecurity' ) } description={ __( 'Each of these also sent a DANGER email (at most once per item every 12 hours).', 'gemsecurity' ) }>
					{ data.events.length === 0 ? (
						<EmptyState title={ __( 'Nothing blocked yet', 'gemsecurity' ) } />
					) : (
						<table className="gs-table">
							<thead><tr><th>{ __( 'When', 'gemsecurity' ) }</th><th>{ __( 'What', 'gemsecurity' ) }</th><th>{ __( 'Item', 'gemsecurity' ) }</th><th>{ __( 'User / IP', 'gemsecurity' ) }</th></tr></thead>
							<tbody>
								{ data.events.map( ( e, i ) => (
									<tr key={ i }>
										<td className="gs-nowrap">{ new Date( e.time * 1000 ).toLocaleString() }</td>
										<td className="gs-nowrap"><Badge tone={ e.type === 'install_blocked' ? 'warning' : 'danger' }>{ EVENT[ e.type ] || e.type }</Badge></td>
										<td>{ e.label }</td>
										<td className="gs-nowrap gs-muted">{ e.user || '—' } · { e.ip || '—' }</td>
									</tr>
								) ) }
							</tbody>
						</table>
					) }
				</Card>
			) }
		</div>
	);
}
