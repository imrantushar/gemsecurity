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
];

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

function BotBlocklist( { patterns, onChange } ) {
	const [ newPattern, setNewPattern ] = useState( '' );

	const add = () => {
		const trimmed = newPattern.trim();
		if ( ! trimmed ) { return; }
		onChange( [ ...( patterns || [] ), trimmed ] );
		setNewPattern( '' );
	};

	const remove = ( entry ) => {
		onChange( ( patterns || [] ).filter( ( p ) => p !== entry ) );
	};

	const list = patterns || [];

	return (
		<Card title={ __( 'Custom bot / scanner blocklist', 'gemsecurity' ) } description={ __( 'Additional user-agent patterns to block (case-insensitive). Use * as a wildcard — e.g. bot* blocks any UA starting with "bot", *crawler* blocks any UA containing "crawler". No wildcard = substring match anywhere in the UA.', 'gemsecurity' ) }>
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
				<EmptyState title={ __( 'No custom patterns', 'gemsecurity' ) } description={ __( 'Requests matching these substrings will be blocked with a 403.', 'gemsecurity' ) } />
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
				<Toggle label={ __( 'Block malicious bots & scanners', 'gemsecurity' ) } description={ __( 'Blocks empty and known-bad user agents (sqlmap, nikto, nuclei…).', 'gemsecurity' ) } checked={ form.block_bad_bots } onChange={ ( v ) => setField( 'block_bad_bots', v ) } />
				{ form.block_bad_bots && (
					<div className="gs-toggle-list">
						<Toggle label={ __( 'Always block empty / missing user agents', 'gemsecurity' ) } description={ __( 'Block requests that send no User-Agent header (almost always bots or scanners).', 'gemsecurity' ) } checked={ form.block_empty_ua ?? true } onChange={ ( v ) => setField( 'block_empty_ua', v ) } />
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

			<div className="gs-savebar">
				<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>{ __( 'Save changes', 'gemsecurity' ) }</Button>
			</div>

			{ form.block_bad_bots && (
				<BotBlocklist
					patterns={ Array.isArray( form.bot_blocklist ) ? form.bot_blocklist : [] }
					onChange={ ( v ) => { setField( 'bot_blocklist', v ); save( { bot_blocklist: v } ); } }
				/>
			) }

			<BannedIps />
		</div>
	);
}
