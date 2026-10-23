import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, ListInput, Select, TextInput, NumberInput, Button, Badge, EmptyState } from '@Components/ui/Controls';
import { isPro, ProBadge } from '@Components/ui/Pro';

const KEYS = [
	'firewall_enabled',
	'ip_blocklist',
	// Real visitor IP detection.
	'trust_cloudflare_ip',
	'trusted_proxies',
	'xmlrpc_disabled',
	'disable_file_editing',
	'hide_wp_version',
	'protect_core_files_enabled',
	// Username enumeration.
	'block_author_enumeration',
	'disable_user_rest',
	'login_errors_generic',
	// WAF + rate limiting + bot control. These are free-tier protections
	// enforced by the Waf class; they used to be configurable only from the
	// Pro-gated Threat Defense page, where a free install could not reach them.
	'waf_enabled',
	'waf_block_sqli',
	'waf_block_xss',
	'waf_block_lfi',
	'waf_block_rce',
	'waf_inspect_body',
	'rate_limit_enabled',
	'rate_limit_max',
	'rate_limit_window',
	'throttle_404_enabled',
	'throttle_404_max',
	'throttle_404_window',
	'block_bad_bots',
	'block_empty_ua',
	// Security headers.
	'security_headers_enabled',
	'header_x_frame_options',
	'header_x_content_type_options',
	'header_referrer_policy',
	'header_permissions_policy',
	'header_hsts_enabled',
	'header_hsts_max_age',
	'header_hsts_subdomains',
	'header_hsts_preload',
	'header_csp_enabled',
	'header_csp_value',
	'header_csp_report_only',
	'header_csp_report',
	// Pro hardening pack.
	'admin_ip_allowlist_enabled',
	'admin_ip_allowlist',
	'block_sensitive_files_enabled',
	'block_php_in_uploads',
	'force_https_enabled',
	// Bot control.
	'block_ai_crawlers',
	'verify_search_bots',
	// security.txt.
	'securitytxt_enabled',
	'securitytxt_contact',
	'securitytxt_expires',
	'securitytxt_policy',
];

/** Read-only file-permission audit. */
function FilePermissions() {
	const [ rows, setRows ] = useState( null );
	useEffect( () => {
		api.get( 'file-permissions' ).then( ( r ) => setRows( r.data.items ) ).catch( () => setRows( [] ) );
	}, [] );
	return (
		<Card
			title={ __( 'File permissions', 'gemsecurity' ) }
			description={ __( 'Over-permissive files let a compromised process rewrite your site. World-writable paths are flagged.', 'gemsecurity' ) }
		>
			{ ! rows ? (
				<p className="gs-muted">{ __( 'Checking…', 'gemsecurity' ) }</p>
			) : (
				<table className="gs-table">
					<thead><tr>
						<th>{ __( 'Path', 'gemsecurity' ) }</th>
						<th>{ __( 'Current', 'gemsecurity' ) }</th>
						<th>{ __( 'Recommended', 'gemsecurity' ) }</th>
						<th>{ __( 'Status', 'gemsecurity' ) }</th>
					</tr></thead>
					<tbody>
						{ rows.map( ( r ) => (
							<tr key={ r.path }>
								<td>
									<code>{ r.path }</code>
									{ r.note && <div className="gs-muted" style={ { fontSize: 12, marginTop: 2 } }>{ r.note }</div> }
								</td>
								<td className="gs-nowrap">{ r.perms }</td>
								<td className="gs-nowrap">{ r.recommended }</td>
								<td><Badge tone={ r.status === 'critical' ? 'danger' : r.status === 'warning' ? 'warning' : 'success' }>{ r.status === 'ok' ? __( 'OK', 'gemsecurity' ) : r.status }</Badge></td>
							</tr>
						) ) }
					</tbody>
				</table>
			) }
		</Card>
	);
}

/** Recent CSP violations collected from the report endpoint. */
function CspViolations() {
	const [ rows, setRows ] = useState( null );
	useEffect( () => {
		api.get( 'csp-violations' ).then( ( r ) => setRows( r.data.items ) ).catch( () => setRows( [] ) );
	}, [] );
	if ( rows && rows.length === 0 ) {
		return null;
	}
	return (
		<Card title={ __( 'Recent CSP violations', 'gemsecurity' ) }>
			{ ! rows ? (
				<p className="gs-muted">{ __( 'Loading…', 'gemsecurity' ) }</p>
			) : (
				<table className="gs-table">
					<thead><tr>
						<th>{ __( 'Blocked', 'gemsecurity' ) }</th>
						<th>{ __( 'Directive', 'gemsecurity' ) }</th>
						<th>{ __( 'When', 'gemsecurity' ) }</th>
					</tr></thead>
					<tbody>
						{ rows.map( ( r, i ) => (
							<tr key={ i }>
								<td><code>{ r.blocked || '—' }</code></td>
								<td className="gs-nowrap">{ r.directive }</td>
								<td className="gs-nowrap">{ r.time }</td>
							</tr>
						) ) }
					</tbody>
				</table>
			) }
		</Card>
	);
}

const HARDENING = [
	{ key: 'disable_file_editing', label: __( 'Disable theme & plugin file editor', 'gemsecurity' ), desc: __( 'Stops attackers editing PHP from wp-admin (DISALLOW_FILE_EDIT).', 'gemsecurity' ) },
	{ key: 'xmlrpc_disabled', label: __( 'Disable XML-RPC', 'gemsecurity' ), desc: __( 'Closes a common brute-force and DDoS vector.', 'gemsecurity' ) },
	{ key: 'hide_wp_version', label: __( 'Hide WordPress version', 'gemsecurity' ), desc: __( 'Removes the generator meta tag and version from feeds.', 'gemsecurity' ) },
	{ key: 'protect_core_files_enabled', label: __( 'Protect wp-config.php, error logs and wp-admin/includes', 'gemsecurity' ), desc: __( 'Adds server rules to .htaccess so these cannot be opened from the web (Apache / LiteSpeed; on nginx add them to the server config).', 'gemsecurity' ) },
];

/*
 * Every switch whose job is to stop the site confirming which usernames exist.
 * These were previously split between here and the API & Access page, which put
 * two halves of one decision on two screens.
 */
const ENUMERATION = [
	{ key: 'block_author_enumeration', label: __( 'Block author enumeration', 'gemsecurity' ), desc: __( 'Prevents ?author=N scans that reveal usernames.', 'gemsecurity' ) },
	{ key: 'disable_user_rest', label: __( 'Block REST user enumeration', 'gemsecurity' ), desc: __( 'Hides /wp/v2/users from anonymous requests.', 'gemsecurity' ) },
	{ key: 'login_errors_generic', label: __( 'Generic login error messages', 'gemsecurity' ), desc: __( 'Replaces “unknown username” / “incorrect password” with one message, so a failed login never confirms an account exists.', 'gemsecurity' ) },
];

export default function Firewall() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const pro = isPro();

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Firewall', 'gemsecurity' ) }
				description={ __( 'Master switch for request-level protections and the IP blocklist.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Enable firewall', 'gemsecurity' ) }
					checked={ form.firewall_enabled }
					onChange={ ( v ) => setField( 'firewall_enabled', v ) }
				/>
				<Field
					label={ __( 'IP blocklist', 'gemsecurity' ) }
					description={ __( 'One IP address or CIDR range per line. Logged-in administrators are never blocked.', 'gemsecurity' ) }
				>
					<ListInput
						value={ form.ip_blocklist }
						onChange={ ( v ) => setField( 'ip_blocklist', v ) }
						placeholder={ '203.0.113.10\n198.51.100.0/24' }
					/>
				</Field>
			</Card>

			<Card
				title={ __( 'Real visitor IP detection', 'gemsecurity' ) }
				description={ __( 'Every ban, rate-limit and geolocation rule relies on knowing the visitor\u2019s real IP. Forwarding headers (X-Forwarded-For, CF-Connecting-IP) can be sent by anyone, so they\u2019re only trusted from a proxy you name here \u2014 everyone else always resolves to the raw connection IP.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'This site is behind Cloudflare', 'gemsecurity' ) }
					description={ __( 'Trusts CF-Connecting-IP, but only for requests actually arriving from Cloudflare\u2019s published IP ranges.', 'gemsecurity' ) }
					checked={ form.trust_cloudflare_ip }
					onChange={ ( v ) => setField( 'trust_cloudflare_ip', v ) }
				/>
				<Field
					label={ __( 'Other trusted proxies', 'gemsecurity' ) }
					description={ __( 'For a custom load balancer, Varnish, or a CDN other than Cloudflare. One IP or CIDR range per line \u2014 only requests arriving from these addresses get their X-Forwarded-For / X-Real-IP header trusted. Leave empty if the site isn\u2019t behind a proxy; an overly broad range (e.g. 0.0.0.0/0) defeats this protection entirely.', 'gemsecurity' ) }
				>
					<ListInput
						value={ form.trusted_proxies }
						onChange={ ( v ) => setField( 'trusted_proxies', v ) }
						placeholder={ '203.0.113.5\n198.51.100.0/24' }
					/>
				</Field>
			</Card>

			<Card
				title={ __( 'Hardening', 'gemsecurity' ) }
				description={ __( 'Recommended switches that close common WordPress attack surfaces.', 'gemsecurity' ) }
			>
				<div className="gs-toggle-list">
					{ HARDENING.map( ( h ) => (
						<Toggle
							key={ h.key }
							label={ h.label }
							description={ h.desc }
							checked={ form[ h.key ] }
							onChange={ ( v ) => setField( h.key, v ) }
						/>
					) ) }
				</div>
			</Card>

			<Card
				title={ __( 'Web Application Firewall', 'gemsecurity' ) }
				description={ __( 'Inspect incoming requests and block common attack patterns. Administrators are always exempt.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Enable request inspection (WAF)', 'gemsecurity' ) }
					checked={ form.waf_enabled }
					onChange={ ( v ) => setField( 'waf_enabled', v ) }
				/>
				{ form.waf_enabled && (
					<div className="gs-toggle-list">
						<Toggle label={ __( 'Block SQL injection', 'gemsecurity' ) } checked={ form.waf_block_sqli } onChange={ ( v ) => setField( 'waf_block_sqli', v ) } />
						<Toggle label={ __( 'Block cross-site scripting (XSS)', 'gemsecurity' ) } checked={ form.waf_block_xss } onChange={ ( v ) => setField( 'waf_block_xss', v ) } />
						<Toggle label={ __( 'Block path traversal / file inclusion', 'gemsecurity' ) } checked={ form.waf_block_lfi } onChange={ ( v ) => setField( 'waf_block_lfi', v ) } />
						<Toggle label={ __( 'Block remote code execution patterns', 'gemsecurity' ) } checked={ form.waf_block_rce } onChange={ ( v ) => setField( 'waf_block_rce', v ) } />
						<Toggle
							label={ __( 'Also inspect POST request bodies', 'gemsecurity' ) }
							description={ __( 'Stronger, but can false-positive on legitimate form content.', 'gemsecurity' ) }
							checked={ form.waf_inspect_body }
							onChange={ ( v ) => setField( 'waf_inspect_body', v ) }
						/>
					</div>
				) }
			</Card>

			<Card
				title={ __( 'Rate limiting & throttling', 'gemsecurity' ) }
				description={ __( 'Cap how hard a single IP can hit the front end. REST API requests are limited separately on the API & Access page.', 'gemsecurity' ) }
			>
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
			</Card>

			<Card
				title={ __( 'Username enumeration', 'gemsecurity' ) }
				description={ __( 'Stop the site handing out valid usernames before an attacker even tries a password.', 'gemsecurity' ) }
			>
				<div className="gs-toggle-list">
					{ ENUMERATION.map( ( h ) => (
						<Toggle
							key={ h.key }
							label={ h.label }
							description={ h.desc }
							checked={ form[ h.key ] }
							onChange={ ( v ) => setField( h.key, v ) }
						/>
					) ) }
				</div>
			</Card>

			<Card
				title={ __( 'Security headers', 'gemsecurity' ) }
				description={ __( 'Send hardening response headers on the front-end, admin and login pages.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Enable security headers', 'gemsecurity' ) }
					checked={ form.security_headers_enabled }
					onChange={ ( v ) => setField( 'security_headers_enabled', v ) }
				/>
				{ form.security_headers_enabled && (
					<>
						<div className="gs-row">
							<Field label={ __( 'X-Frame-Options', 'gemsecurity' ) } description={ __( 'Clickjacking protection.', 'gemsecurity' ) }>
								<Select
									value={ form.header_x_frame_options || 'SAMEORIGIN' }
									onChange={ ( e ) => setField( 'header_x_frame_options', e.target.value ) }
									options={ [
										{ value: 'SAMEORIGIN', label: 'SAMEORIGIN' },
										{ value: 'DENY', label: 'DENY' },
										{ value: 'off', label: __( 'Off', 'gemsecurity' ) },
									] }
								/>
							</Field>
							<Field label={ __( 'Referrer-Policy', 'gemsecurity' ) }>
								<TextInput
									value={ form.header_referrer_policy ?? '' }
									onChange={ ( e ) => setField( 'header_referrer_policy', e.target.value ) }
								/>
							</Field>
						</div>
						<Toggle
							label={ __( 'X-Content-Type-Options: nosniff', 'gemsecurity' ) }
							checked={ form.header_x_content_type_options }
							onChange={ ( v ) => setField( 'header_x_content_type_options', v ) }
						/>
						<Field label={ __( 'Permissions-Policy', 'gemsecurity' ) }>
							<TextInput
								value={ form.header_permissions_policy ?? '' }
								onChange={ ( e ) => setField( 'header_permissions_policy', e.target.value ) }
							/>
						</Field>

						<Toggle
							label={ __( 'HSTS (Strict-Transport-Security)', 'gemsecurity' ) }
							description={ __( 'Only sent over HTTPS. Be careful: forces HTTPS for the max-age duration.', 'gemsecurity' ) }
							checked={ form.header_hsts_enabled }
							onChange={ ( v ) => setField( 'header_hsts_enabled', v ) }
						/>
						{ form.header_hsts_enabled && (
							<div className="gs-row">
								<Field label={ __( 'Max-age', 'gemsecurity' ) } suffix={ __( 'seconds', 'gemsecurity' ) }>
									<NumberInput min="0" value={ form.header_hsts_max_age ?? 15552000 } onChange={ ( e ) => setField( 'header_hsts_max_age', Number( e.target.value ) ) } />
								</Field>
								<div className="gs-field">
									<Toggle label={ __( 'Include subdomains', 'gemsecurity' ) } checked={ form.header_hsts_subdomains } onChange={ ( v ) => setField( 'header_hsts_subdomains', v ) } />
									<Toggle label={ __( 'Preload', 'gemsecurity' ) } checked={ form.header_hsts_preload } onChange={ ( v ) => setField( 'header_hsts_preload', v ) } />
								</div>
							</div>
						) }

						<Toggle
							label={ __( 'Content-Security-Policy', 'gemsecurity' ) }
							description={ __( 'Advanced — a wrong policy can break your site. Start in report-only mode.', 'gemsecurity' ) }
							checked={ form.header_csp_enabled }
							onChange={ ( v ) => setField( 'header_csp_enabled', v ) }
						/>
						{ form.header_csp_enabled && (
							<>
								<Field label={ __( 'CSP directives', 'gemsecurity' ) }>
									<ListInput rows={ 3 } value={ form.header_csp_value || '' } onChange={ ( v ) => setField( 'header_csp_value', Array.isArray( v ) ? v.join( ' ' ) : v ) } />
								</Field>
								<Toggle
									label={ __( 'Report-only (do not enforce)', 'gemsecurity' ) }
									description={ __( 'Log violations without blocking. Turn off to enforce the policy.', 'gemsecurity' ) }
									checked={ form.header_csp_report_only }
									onChange={ ( v ) => setField( 'header_csp_report_only', v ) }
								/>
								<Toggle
									label={ __( 'Collect violation reports', 'gemsecurity' ) }
									description={ __( 'Send browser CSP violations to GemSecurity and list them below.', 'gemsecurity' ) }
									checked={ form.header_csp_report }
									onChange={ ( v ) => setField( 'header_csp_report', v ) }
								/>
							</>
						) }
					</>
				) }
			</Card>

			<Card
				title={ __( 'Bot control', 'gemsecurity' ) }
				description={ __( 'Govern automated traffic in one place: known-bad scanners, AI scrapers and crawlers that impersonate search engines. Custom user-agent patterns and bot analytics are on the Threat Defense page.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Block malicious bots & scanners', 'gemsecurity' ) }
					description={ __( 'Blocks known-bad user agents such as sqlmap, nikto and nuclei.', 'gemsecurity' ) }
					checked={ form.block_bad_bots }
					onChange={ ( v ) => setField( 'block_bad_bots', v ) }
				/>
				{ form.block_bad_bots && (
					<Toggle
						label={ __( 'Also block empty / missing user agents', 'gemsecurity' ) }
						description={ __( 'Requests that send no User-Agent header at all are almost always bots or scanners.', 'gemsecurity' ) }
						checked={ form.block_empty_ua ?? true }
						onChange={ ( v ) => setField( 'block_empty_ua', v ) }
					/>
				) }
				<Toggle
					label={ __( 'Block AI crawlers & scrapers', 'gemsecurity' ) }
					description={ __( 'Deny GPTBot, ClaudeBot, CCBot, PerplexityBot, Bytespider and other AI/scraper user-agents.', 'gemsecurity' ) }
					checked={ form.block_ai_crawlers }
					onChange={ ( v ) => setField( 'block_ai_crawlers', v ) }
				/>
				<Toggle
					label={ __( 'Verify search-engine bots', 'gemsecurity' ) }
					description={ __( 'Confirm Googlebot / Bingbot / YandexBot / Applebot via reverse DNS and block spoofed impostors (a common way to bypass firewalls).', 'gemsecurity' ) }
					checked={ form.verify_search_bots }
					onChange={ ( v ) => setField( 'verify_search_bots', v ) }
				/>
			</Card>

			<Card
				title={ <>{ __( 'Hardening pack', 'gemsecurity' ) } { ! pro && <ProBadge /> }</> }
				description={ __( 'Extra request-level protections: restrict wp-admin by IP, deny sensitive files, stop PHP running in uploads and force HTTPS.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Restrict wp-admin by IP', 'gemsecurity' ) }
					description={ __( 'Only the IPs below may reach wp-admin. An empty list never locks anyone out.', 'gemsecurity' ) }
					checked={ form.admin_ip_allowlist_enabled }
					onChange={ ( v ) => setField( 'admin_ip_allowlist_enabled', v ) }
					disabled={ ! pro }
				/>
				{ pro && form.admin_ip_allowlist_enabled && (
					<Field
						label={ __( 'Allowed IPs', 'gemsecurity' ) }
						description={ __( 'One IP or CIDR range per line. This is a network allowlist for wp-admin — the approved-administrator list on the Admin Guard page is about accounts, not addresses.', 'gemsecurity' ) }
					>
						<ListInput
							value={ form.admin_ip_allowlist }
							onChange={ ( v ) => setField( 'admin_ip_allowlist', v ) }
							placeholder={ '203.0.113.10\n198.51.100.0/24' }
						/>
					</Field>
				) }
				<Toggle
					label={ __( 'Block sensitive files', 'gemsecurity' ) }
					description={ __( 'Denies readme.html, license.txt, *.sql, *.bak, debug.log, dotfiles and similar.', 'gemsecurity' ) }
					checked={ form.block_sensitive_files_enabled }
					onChange={ ( v ) => setField( 'block_sensitive_files_enabled', v ) }
					disabled={ ! pro }
				/>
				<Toggle
					label={ __( 'Block PHP execution in /uploads', 'gemsecurity' ) }
					description={ __( 'Adds a server rule to uploads/.htaccess so uploaded PHP shells cannot run (Apache / LiteSpeed). On nginx, Upload Shield\'s live test shows whether PHP there still executes.', 'gemsecurity' ) }
					checked={ form.block_php_in_uploads }
					onChange={ ( v ) => setField( 'block_php_in_uploads', v ) }
					disabled={ ! pro }
				/>
				<Toggle
					label={ __( 'Force HTTPS', 'gemsecurity' ) }
					description={ __( 'Redirect HTTP to HTTPS and upgrade insecure requests.', 'gemsecurity' ) }
					checked={ form.force_https_enabled }
					onChange={ ( v ) => setField( 'force_https_enabled', v ) }
					disabled={ ! pro }
				/>
			</Card>

			<Card
				title={ __( 'security.txt', 'gemsecurity' ) }
				description={ __( 'Publish /.well-known/security.txt (RFC 9116) so researchers know how to report vulnerabilities.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Serve security.txt', 'gemsecurity' ) }
					checked={ form.securitytxt_enabled }
					onChange={ ( v ) => setField( 'securitytxt_enabled', v ) }
				/>
				{ form.securitytxt_enabled && (
					<>
						<Field label={ __( 'Contact', 'gemsecurity' ) } description={ __( 'Email or URL. Defaults to the admin email.', 'gemsecurity' ) }>
							<TextInput value={ form.securitytxt_contact ?? '' } onChange={ ( e ) => setField( 'securitytxt_contact', e.target.value ) } placeholder="security@example.com" />
						</Field>
						<Field label={ __( 'Expires', 'gemsecurity' ) } description={ __( 'ISO 8601 date. Defaults to one year out.', 'gemsecurity' ) }>
							<TextInput value={ form.securitytxt_expires ?? '' } onChange={ ( e ) => setField( 'securitytxt_expires', e.target.value ) } placeholder="2027-01-01T00:00:00Z" />
						</Field>
						<Field label={ __( 'Policy URL (optional)', 'gemsecurity' ) }>
							<TextInput value={ form.securitytxt_policy ?? '' } onChange={ ( e ) => setField( 'securitytxt_policy', e.target.value ) } placeholder="https://example.com/security-policy" />
						</Field>
					</>
				) }
			</Card>


			<FilePermissions />
			<CspViolations />
		</div>
	);
}
