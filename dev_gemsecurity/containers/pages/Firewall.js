import React from 'react';
import { __ } from '@wordpress/i18n';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, ListInput, Select, TextInput, NumberInput, Button } from '@Components/ui/Controls';

const KEYS = [
	'firewall_enabled',
	'ip_blocklist',
	'xmlrpc_disabled',
	'disable_file_editing',
	'block_author_enumeration',
	'disable_user_rest',
	'hide_wp_version',
	'disable_application_passwords',
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
];

const HARDENING = [
	{ key: 'disable_file_editing', label: __( 'Disable theme & plugin file editor', 'gemsecurity' ), desc: __( 'Stops attackers editing PHP from wp-admin (DISALLOW_FILE_EDIT).', 'gemsecurity' ) },
	{ key: 'block_author_enumeration', label: __( 'Block author enumeration', 'gemsecurity' ), desc: __( 'Prevents ?author=N scans that reveal usernames.', 'gemsecurity' ) },
	{ key: 'disable_user_rest', label: __( 'Block REST user enumeration', 'gemsecurity' ), desc: __( 'Hides /wp/v2/users from anonymous requests.', 'gemsecurity' ) },
	{ key: 'xmlrpc_disabled', label: __( 'Disable XML-RPC', 'gemsecurity' ), desc: __( 'Closes a common brute-force and DDoS vector.', 'gemsecurity' ) },
	{ key: 'hide_wp_version', label: __( 'Hide WordPress version', 'gemsecurity' ), desc: __( 'Removes the generator meta tag and version from feeds.', 'gemsecurity' ) },
	{ key: 'disable_application_passwords', label: __( 'Disable application passwords', 'gemsecurity' ), desc: __( 'Turns off the REST application-password feature.', 'gemsecurity' ) },
];

export default function Firewall() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );

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
									checked={ form.header_csp_report_only }
									onChange={ ( v ) => setField( 'header_csp_report_only', v ) }
								/>
							</>
						) }
					</>
				) }
			</Card>

			<div className="gs-savebar">
				<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>
					{ __( 'Save changes', 'gemsecurity' ) }
				</Button>
			</div>
		</div>
	);
}
