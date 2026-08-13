import React, { useEffect, useState, useCallback } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, NumberInput, TextInput, Button, Badge, Loading, EmptyState } from '@Components/ui/Controls';
import { useToast } from '@Components/ui/Toast';

const KEYS = [
	'waf_enabled', 'waf_block_sqli', 'waf_block_xss', 'waf_block_lfi', 'waf_block_rce', 'waf_inspect_body',
	'rate_limit_enabled', 'rate_limit_max', 'rate_limit_window',
	'throttle_404_enabled', 'throttle_404_max', 'throttle_404_window',
	'block_bad_bots', 'block_empty_ua', 'bot_blocklist', 'mu_loader_enabled',
	'autoban_enabled', 'autoban_threshold', 'autoban_window', 'autoban_duration',
	'anomaly_detection_enabled', 'anomaly_threshold',
	'credential_stuffing_enabled', 'credential_stuffing_threshold',
	'live_traffic_enabled',
];

function LiveTraffic() {
	const [ rows, setRows ] = useState( null );
	const load = useCallback( () => {
		api.get( 'live-traffic' ).then( ( r ) => setRows( r.data.items ) ).catch( () => setRows( [] ) );
	}, [] );
	useEffect( () => {
		load();
		const t = setInterval( load, 5000 );
		return () => clearInterval( t );
	}, [ load ] );
	return (
		<Card title={ __( 'Live traffic', 'gemsecurity' ) } description={ __( 'Recent front-end requests (refreshes every 5s). Enable “Live traffic” above to populate.', 'gemsecurity' ) }>
			{ ! rows || rows.length === 0 ? (
				<p className="gs-muted">{ __( 'No traffic captured yet.', 'gemsecurity' ) }</p>
			) : (
				<table className="gs-table">
					<thead><tr><th>{ __( 'Time', 'gemsecurity' ) }</th><th>{ __( 'IP', 'gemsecurity' ) }</th><th>{ __( 'Method', 'gemsecurity' ) }</th><th>{ __( 'URI', 'gemsecurity' ) }</th></tr></thead>
					<tbody>
						{ rows.slice( 0, 40 ).map( ( r, i ) => (
							<tr key={ i }><td className="gs-nowrap">{ r.time }</td><td className="gs-nowrap">{ r.ip }</td><td className="gs-nowrap">{ r.method }</td><td><code>{ r.uri }</code></td></tr>
						) ) }
					</tbody>
				</table>
			) }
		</Card>
	);
}

function BannedIps() {
	const toast = useToast();
	const [ bans, setBans ] = useState( null );
	const [ ip, setIp ] = useState( '' );
	const [ reason, setReason ] = useState( '' );
	const [ duration, setDuration ] = useState( 0 );
	const [ busy, setBusy ] = useState( false );

	const load = useCallback( () => {
		api.get( 'bans' ).then( ( r ) => setBans( r.data.bans ) ).catch( () => setBans( [] ) );
	}, [] );
	useEffect( () => { load(); }, [ load ] );

	const add = async () => {
		if ( ! ip.trim() ) { return; }
		setBusy( true );
		try {
			const r = await api.post( 'bans', { ip: ip.trim(), reason, duration: Number( duration ) } );
			setBans( r.data.bans );
			setIp( '' ); setReason( '' );
			toast( __( 'IP banned.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not ban IP.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};

	const remove = async ( banIp ) => {
		const r = await api.delete( 'bans', { data: { ip: banIp } } );
		setBans( r.data.bans );
		toast( __( 'Removed.', 'gemsecurity' ), 'success' );
	};

	return (
		<Card title={ __( 'Banned IP addresses', 'gemsecurity' ) } description={ __( 'Auto-banned and manually banned IPs. Permanent unless an expiry is shown.', 'gemsecurity' ) }>
			<div className="gs-addrow">
				<TextInput placeholder="203.0.113.10" value={ ip } onChange={ ( e ) => setIp( e.target.value ) } />
				<TextInput placeholder={ __( 'Reason (optional)', 'gemsecurity' ) } value={ reason } onChange={ ( e ) => setReason( e.target.value ) } />
				<NumberInput min="0" placeholder={ __( 'Minutes (0 = forever)', 'gemsecurity' ) } value={ duration } onChange={ ( e ) => setDuration( e.target.value ) } />
				<Button onClick={ add } loading={ busy }>{ __( 'Ban IP', 'gemsecurity' ) }</Button>
			</div>

			{ bans === null ? (
				<Loading />
			) : bans.length === 0 ? (
				<EmptyState title={ __( 'No banned IPs', 'gemsecurity' ) } description={ __( 'Offending IPs will appear here automatically.', 'gemsecurity' ) } />
			) : (
				<table className="gs-table">
					<thead><tr>
						<th>{ __( 'IP', 'gemsecurity' ) }</th><th>{ __( 'Reason', 'gemsecurity' ) }</th>
						<th>{ __( 'Strikes', 'gemsecurity' ) }</th><th>{ __( 'Expires', 'gemsecurity' ) }</th><th></th>
					</tr></thead>
					<tbody>
						{ bans.map( ( b ) => (
							<tr key={ b.id }>
								<td><code>{ b.ip }</code></td>
								<td>{ b.reason || '—' }</td>
								<td>{ b.strikes }</td>
								<td>{ b.expires_at ? b.expires_at : <Badge tone="danger">{ __( 'permanent', 'gemsecurity' ) }</Badge> }</td>
								<td><Button variant="secondary" onClick={ () => remove( b.ip ) }>{ __( 'Unban', 'gemsecurity' ) }</Button></td>
							</tr>
						) ) }
					</tbody>
				</table>
			) }
		</Card>
	);
}

function BotStats() {
	const [ stats, setStats ] = useState( null );

	useEffect( () => {
		api.get( 'bots/stats' ).then( ( r ) => setStats( r.data ) ).catch( () => setStats( false ) );
	}, [] );

	if ( ! stats ) {
		return stats === false ? null : <Loading />;
	}

	const maxDay = Math.max( 1, ...stats.per_day.map( ( d ) => d.count ) );

	return (
		<Card title={ __( 'Bot activity (last 7 days)', 'gemsecurity' ) }>
			<div className="gs-row" style={ { marginBottom: 16 } }>
				<div className="gs-stat">
					<span className="gs-stat__value">{ stats.total_24h }</span>
					<span className="gs-stat__label">{ __( 'Blocked (24h)', 'gemsecurity' ) }</span>
				</div>
				<div className="gs-stat">
					<span className="gs-stat__value">{ stats.total_7d }</span>
					<span className="gs-stat__label">{ __( 'Blocked (7d)', 'gemsecurity' ) }</span>
				</div>
			</div>

			<div className="gs-bars" style={ { height: 60, marginBottom: 16 } }>
				{ stats.per_day.map( ( d ) => (
					<div key={ d.date } className="gs-bars__col" title={ `${ d.date }: ${ d.count }` }>
						<div className="gs-bars__bar" style={ { height: `${ ( d.count / maxDay ) * 100 }%` } } />
						<span className="gs-bars__label">{ d.date.slice( 5 ) }</span>
					</div>
				) ) }
			</div>

			{ stats.top_patterns.length > 0 && (
				<>
					<p className="gs-label">{ __( 'Top triggered patterns (7d)', 'gemsecurity' ) }</p>
					<table className="gs-table">
						<thead><tr><th>{ __( 'Pattern', 'gemsecurity' ) }</th><th>{ __( 'Hits', 'gemsecurity' ) }</th></tr></thead>
						<tbody>
							{ stats.top_patterns.map( ( p ) => (
								<tr key={ p.pattern }>
									<td><code>{ p.pattern }</code></td>
									<td>{ p.count }</td>
								</tr>
							) ) }
						</tbody>
					</table>
				</>
			) }
		</Card>
	);
}

function BotBlocklist( { blockBadBots, onBlockBadBotsChange, blockEmptyUa, onBlockEmptyUaChange, patterns, onPatternsChange } ) {
	const [ newPattern, setNewPattern ] = useState( '' );

	const add = () => {
		const trimmed = newPattern.trim();
		if ( ! trimmed ) { return; }
		onPatternsChange( [ ...( patterns || [] ), trimmed ] );
		setNewPattern( '' );
	};

	const remove = ( entry ) => {
		onPatternsChange( ( patterns || [] ).filter( ( p ) => p !== entry ) );
	};

	const list = patterns || [];

	return (
		<Card title={ __( 'Block malicious bots & scanners', 'gemsecurity' ) } description={ __( 'Blocks known-bad user agents (sqlmap, nikto, nuclei…) plus your custom patterns. Use * as a wildcard — e.g. bot* blocks any UA starting with "bot", *crawler* blocks any UA containing "crawler". No wildcard = substring match anywhere in the UA.', 'gemsecurity' ) }>
			<Toggle
				label={ __( 'Enable bot & scanner blocking', 'gemsecurity' ) }
				checked={ blockBadBots }
				onChange={ onBlockBadBotsChange }
			/>
			{ blockBadBots && (
				<>
					<div className="gs-toggle-list">
						<Toggle
							label={ __( 'Always block empty / missing user agents', 'gemsecurity' ) }
							description={ __( 'Block requests that send no User-Agent header (almost always bots or scanners).', 'gemsecurity' ) }
							checked={ blockEmptyUa ?? true }
							onChange={ onBlockEmptyUaChange }
						/>
					</div>
					<div className="gs-addrow">
						<TextInput
							placeholder={ __( 'e.g. *crawler* or badbot*', 'gemsecurity' ) }
							value={ newPattern }
							onChange={ ( e ) => setNewPattern( e.target.value ) }
							onKeyDown={ ( e ) => { if ( e.key === 'Enter' ) { add(); } } }
						/>
						<Button onClick={ add }>{ __( 'Add pattern', 'gemsecurity' ) }</Button>
					</div>
					{ list.length === 0 ? (
						<EmptyState title={ __( 'No custom patterns', 'gemsecurity' ) } description={ __( 'Add a pattern above to block additional user agents.', 'gemsecurity' ) } />
					) : (
						<table className="gs-table">
							<thead><tr>
								<th>{ __( 'Pattern (* = wildcard)', 'gemsecurity' ) }</th><th></th>
							</tr></thead>
							<tbody>
								{ list.map( ( entry ) => (
									<tr key={ entry }>
										<td><code>{ entry }</code></td>
										<td><Button variant="secondary" onClick={ () => remove( entry ) }>{ __( 'Remove', 'gemsecurity' ) }</Button></td>
									</tr>
								) ) }
							</tbody>
						</table>
					) }
				</>
			) }
		</Card>
	);
}

export default function ThreatDefense() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );

	return (
		<div className="gs-page">
			<Card title={ __( 'Web Application Firewall', 'gemsecurity' ) } description={ __( 'Inspect requests and block common attack patterns. Administrators are always exempt.', 'gemsecurity' ) }>
				<Toggle label={ __( 'Enable request inspection (WAF)', 'gemsecurity' ) } checked={ form.waf_enabled } onChange={ ( v ) => setField( 'waf_enabled', v ) } />
				{ form.waf_enabled && (
					<div className="gs-toggle-list">
						<Toggle label={ __( 'Block SQL injection', 'gemsecurity' ) } checked={ form.waf_block_sqli } onChange={ ( v ) => setField( 'waf_block_sqli', v ) } />
						<Toggle label={ __( 'Block cross-site scripting (XSS)', 'gemsecurity' ) } checked={ form.waf_block_xss } onChange={ ( v ) => setField( 'waf_block_xss', v ) } />
						<Toggle label={ __( 'Block path traversal / file inclusion', 'gemsecurity' ) } checked={ form.waf_block_lfi } onChange={ ( v ) => setField( 'waf_block_lfi', v ) } />
						<Toggle label={ __( 'Block remote code execution patterns', 'gemsecurity' ) } checked={ form.waf_block_rce } onChange={ ( v ) => setField( 'waf_block_rce', v ) } />
						<Toggle label={ __( 'Also inspect POST request bodies', 'gemsecurity' ) } description={ __( 'Stronger, but can false-positive on legitimate form content.', 'gemsecurity' ) } checked={ form.waf_inspect_body } onChange={ ( v ) => setField( 'waf_inspect_body', v ) } />
					</div>
				) }
			</Card>

			<Card title={ __( 'Rate limiting & throttling', 'gemsecurity' ) }>
				<Toggle label={ __( 'Limit request rate per IP', 'gemsecurity' ) } checked={ form.rate_limit_enabled } onChange={ ( v ) => setField( 'rate_limit_enabled', v ) } />
				{ form.rate_limit_enabled && (
					<div className="gs-row">
						<Field label={ __( 'Max requests', 'gemsecurity' ) }><NumberInput min="10" value={ form.rate_limit_max ?? 240 } onChange={ ( e ) => setField( 'rate_limit_max', Number( e.target.value ) ) } /></Field>
						<Field label={ __( 'Per window', 'gemsecurity' ) } suffix={ __( 'minutes', 'gemsecurity' ) }><NumberInput min="1" value={ form.rate_limit_window ?? 1 } onChange={ ( e ) => setField( 'rate_limit_window', Number( e.target.value ) ) } /></Field>
					</div>
				) }
				<Toggle label={ __( 'Throttle 404 floods (vulnerability scanners)', 'gemsecurity' ) } checked={ form.throttle_404_enabled } onChange={ ( v ) => setField( 'throttle_404_enabled', v ) } />
				{ form.throttle_404_enabled && (
					<div className="gs-row">
						<Field label={ __( 'Max 404s', 'gemsecurity' ) }><NumberInput min="3" value={ form.throttle_404_max ?? 20 } onChange={ ( e ) => setField( 'throttle_404_max', Number( e.target.value ) ) } /></Field>
						<Field label={ __( 'Per window', 'gemsecurity' ) } suffix={ __( 'minutes', 'gemsecurity' ) }><NumberInput min="1" value={ form.throttle_404_window ?? 5 } onChange={ ( e ) => setField( 'throttle_404_window', Number( e.target.value ) ) } /></Field>
					</div>
				) }
				<Toggle label={ __( 'Extended protection (run firewall before other plugins)', 'gemsecurity' ) } description={ __( 'Installs a must-use plugin so banned IPs and obvious attacks are blocked earlier, before WordPress fully loads.', 'gemsecurity' ) } checked={ form.mu_loader_enabled } onChange={ ( v ) => setField( 'mu_loader_enabled', v ) } />
			</Card>

			<Card title={ __( 'Escalating auto-ban', 'gemsecurity' ) } description={ __( 'Automatically ban IPs that repeatedly trigger the protections above.', 'gemsecurity' ) }>
				<Toggle label={ __( 'Enable auto-ban', 'gemsecurity' ) } checked={ form.autoban_enabled } onChange={ ( v ) => setField( 'autoban_enabled', v ) } />
				{ form.autoban_enabled && (
					<div className="gs-row">
						<Field label={ __( 'Strikes before ban', 'gemsecurity' ) }><NumberInput min="2" value={ form.autoban_threshold ?? 10 } onChange={ ( e ) => setField( 'autoban_threshold', Number( e.target.value ) ) } /></Field>
						<Field label={ __( 'Strike window', 'gemsecurity' ) } suffix={ __( 'minutes', 'gemsecurity' ) }><NumberInput min="1" value={ form.autoban_window ?? 60 } onChange={ ( e ) => setField( 'autoban_window', Number( e.target.value ) ) } /></Field>
						<Field label={ __( 'Ban duration', 'gemsecurity' ) } suffix={ __( 'minutes (0 = forever)', 'gemsecurity' ) }><NumberInput min="0" value={ form.autoban_duration ?? 1440 } onChange={ ( e ) => setField( 'autoban_duration', Number( e.target.value ) ) } /></Field>
					</div>
				) }
			</Card>

			<BotStats />

			<BotBlocklist
				blockBadBots={ form.block_bad_bots }
				onBlockBadBotsChange={ ( v ) => setField( 'block_bad_bots', v ) }
				blockEmptyUa={ form.block_empty_ua ?? true }
				onBlockEmptyUaChange={ ( v ) => setField( 'block_empty_ua', v ) }
				patterns={ Array.isArray( form.bot_blocklist ) ? form.bot_blocklist : [] }
				onPatternsChange={ ( v ) => { setField( 'bot_blocklist', v ); save( { bot_blocklist: v } ); } }
			/>

			<Card
				title={ __( 'Advanced detection', 'gemsecurity' ) }
				description={ __( 'Behavioral scoring and credential-stuffing detection catch attacks that fixed rules and volumetric bans miss.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Behavioral anomaly detection', 'gemsecurity' ) }
					description={ __( 'Score each request for suspicious shape (bad UA, huge payloads, encoded exploits) and log anomalies.', 'gemsecurity' ) }
					checked={ form.anomaly_detection_enabled }
					onChange={ ( v ) => setField( 'anomaly_detection_enabled', v ) }
				/>
				{ form.anomaly_detection_enabled && (
					<Field label={ __( 'Anomaly score threshold', 'gemsecurity' ) }>
						<NumberInput min="2" value={ form.anomaly_threshold ?? 4 } onChange={ ( e ) => setField( 'anomaly_threshold', Number( e.target.value ) ) } />
					</Field>
				) }
				<Toggle
					label={ __( 'Credential-stuffing detection', 'gemsecurity' ) }
					description={ __( 'Ban an IP that tries many different usernames in a short window.', 'gemsecurity' ) }
					checked={ form.credential_stuffing_enabled }
					onChange={ ( v ) => setField( 'credential_stuffing_enabled', v ) }
				/>
				{ form.credential_stuffing_enabled && (
					<Field label={ __( 'Distinct usernames before ban', 'gemsecurity' ) }>
						<NumberInput min="2" value={ form.credential_stuffing_threshold ?? 5 } onChange={ ( e ) => setField( 'credential_stuffing_threshold', Number( e.target.value ) ) } />
					</Field>
				) }
				<Toggle
					label={ __( 'Live traffic monitor', 'gemsecurity' ) }
					description={ __( 'Record recent front-end requests for real-time triage (adds a small write per request).', 'gemsecurity' ) }
					checked={ form.live_traffic_enabled }
					onChange={ ( v ) => setField( 'live_traffic_enabled', v ) }
				/>
			</Card>

			<div className="gs-savebar">
				<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>{ __( 'Save changes', 'gemsecurity' ) }</Button>
			</div>

			{ form.live_traffic_enabled && <LiveTraffic /> }
			<BannedIps />
		</div>
	);
}
