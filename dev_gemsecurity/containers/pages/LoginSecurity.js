import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api, { GS } from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, NumberInput, TextInput, Select, Button } from '@Components/ui/Controls';
import SetupGuide from '@Components/ui/SetupGuide';
import { useToast } from '@Components/ui/Toast';
import { ProSection, isPro } from '@Components/ui/Pro';

const KEYS = [
	'login_attempts_enabled',
	'login_attempts_limit',
	'login_lockout_duration',
	'admin_login_alert_enabled',
	'admin_login_alert_email',
	'admin_session_timeout_enabled',
	'admin_session_timeout_hours',
	// CAPTCHA.
	'captcha_enabled',
	'captcha_provider',
	'captcha_site_key',
	'captcha_secret_key',
	'captcha_on_login',
	'captcha_on_register',
	'captcha_on_lostpassword',
	'captcha_on_comments',
	'captcha_v3_threshold',
	'comment_honeypot_enabled',
	// Password policy.
	'password_policy_enabled',
	'password_min_length',
	'password_require_complexity',
	'password_check_breached',
	'password_expiry_days',
	// Custom login URL.
	'custom_login_enabled',
	'custom_login_slug',
	// Idle timeout.
	'idle_timeout_enabled',
	'idle_timeout_minutes',
	// Login extras.
	'login_honeypot_enabled',
	'trusted_devices_enabled',
	'trusted_devices_alert',
	'magic_link_enabled',
];

/** Admin control to email a one-time login link (Pro). */
function MagicLinkSender() {
	const toast = useToast();
	const [ who, setWho ] = useState( '' );
	const [ busy, setBusy ] = useState( false );
	const send = async () => {
		if ( ! who.trim() ) {
			return;
		}
		setBusy( true );
		try {
			await api.post( 'magic-link', { user: who.trim() } );
			toast( __( 'Login link emailed.', 'gemsecurity' ), 'success' );
			setWho( '' );
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not send.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};
	return (
		<div className="gs-addrow">
			<TextInput value={ who } onChange={ ( e ) => setWho( e.target.value ) } placeholder={ __( 'username or email', 'gemsecurity' ) } />
			<Button variant="secondary" onClick={ send } loading={ busy }>{ __( 'Send login link', 'gemsecurity' ) }</Button>
		</div>
	);
}

function ActiveSessions() {
	const toast = useToast();
	const [ sessions, setSessions ] = useState( null );
	const [ busy, setBusy ] = useState( false );
	const load = () => api.get( 'sessions' ).then( ( r ) => setSessions( r.data.sessions ) ).catch( () => setSessions( [] ) );
	useEffect( () => { load(); }, [] );

	const revoke = async () => {
		setBusy( true );
		try {
			const r = await api.post( 'sessions/revoke-others' );
			setSessions( r.data.sessions );
			toast( __( 'Other sessions ended.', 'gemsecurity' ), 'success' );
		} catch ( e ) { toast( __( 'Failed.', 'gemsecurity' ), 'error' ); }
		setBusy( false );
	};

	return (
		<Card
			title={ __( 'Your active sessions', 'gemsecurity' ) }
			actions={ <Button variant="secondary" onClick={ revoke } loading={ busy }>{ __( 'Log out other sessions', 'gemsecurity' ) }</Button> }
		>
			{ sessions === null ? <p className="gs-muted">{ __( 'Loading…', 'gemsecurity' ) }</p> : (
				<table className="gs-table">
					<thead><tr><th>{ __( 'IP', 'gemsecurity' ) }</th><th>{ __( 'Browser', 'gemsecurity' ) }</th><th>{ __( 'Signed in', 'gemsecurity' ) }</th><th>{ __( 'Expires', 'gemsecurity' ) }</th></tr></thead>
					<tbody>
						{ sessions.map( ( s, i ) => (
							<tr key={ i }>
								<td><code>{ s.ip || '—' }</code></td>
								<td className="gs-table__msg">{ s.ua || '—' }</td>
								<td className="gs-nowrap">{ s.login }</td>
								<td className="gs-nowrap">{ s.expiration }</td>
							</tr>
						) ) }
					</tbody>
				</table>
			) }
		</Card>
	);
}

export default function LoginSecurity() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const loginBase = ( GS.site_url || '' ).replace( /\/$/, '' ) + '/';

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Brute-force protection', 'gemsecurity' ) }
				description={ __( 'Limit failed login attempts and lock out offending IP addresses.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Limit login attempts', 'gemsecurity' ) }
					description={ __( 'Block further attempts from an IP once the limit is reached.', 'gemsecurity' ) }
					checked={ form.login_attempts_enabled }
					onChange={ ( v ) => setField( 'login_attempts_enabled', v ) }
				/>
				<div className="gs-row">
					<Field label={ __( 'Max attempts', 'gemsecurity' ) }>
						<NumberInput
							min="1"
							value={ form.login_attempts_limit ?? 5 }
							onChange={ ( e ) => setField( 'login_attempts_limit', Number( e.target.value ) ) }
							disabled={ ! form.login_attempts_enabled }
						/>
					</Field>
					<Field label={ __( 'Lockout duration', 'gemsecurity' ) } suffix={ __( 'minutes', 'gemsecurity' ) }>
						<NumberInput
							min="1"
							value={ form.login_lockout_duration ?? 30 }
							onChange={ ( e ) => setField( 'login_lockout_duration', Number( e.target.value ) ) }
							disabled={ ! form.login_attempts_enabled }
						/>
					</Field>
				</div>
			</Card>

			<Card
				title={ __( 'Administrator login alerts', 'gemsecurity' ) }
				description={ __( 'Send an email notification whenever an administrator signs in.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Email me when an administrator logs in', 'gemsecurity' ) }
					checked={ form.admin_login_alert_enabled }
					onChange={ ( v ) => setField( 'admin_login_alert_enabled', v ) }
				/>
				<Field
					label={ __( 'Notification email', 'gemsecurity' ) }
					description={ __( 'The alert (with user, time, IP and browser) is sent here. Defaults to the site admin email.', 'gemsecurity' ) }
				>
					<TextInput
						type="email"
						placeholder="security@example.com"
						value={ form.admin_login_alert_email ?? '' }
						onChange={ ( e ) => setField( 'admin_login_alert_email', e.target.value ) }
						disabled={ ! form.admin_login_alert_enabled }
					/>
				</Field>
			</Card>

			<Card
				title={ __( 'Administrator session timeout', 'gemsecurity' ) }
				description={ __( 'Force administrators to be logged out automatically after a fixed period — even with “remember me”.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Auto-logout administrators', 'gemsecurity' ) }
					checked={ form.admin_session_timeout_enabled }
					onChange={ ( v ) => setField( 'admin_session_timeout_enabled', v ) }
				/>
				<Field
					label={ __( 'Log out after', 'gemsecurity' ) }
					suffix={ __( 'hours', 'gemsecurity' ) }
					description={ __( 'Default is 24 hours. Applies from the moment the administrator signed in.', 'gemsecurity' ) }
				>
					<NumberInput
						min="1"
						value={ form.admin_session_timeout_hours ?? 24 }
						onChange={ ( e ) => setField( 'admin_session_timeout_hours', Number( e.target.value ) ) }
						disabled={ ! form.admin_session_timeout_enabled }
					/>
				</Field>
			</Card>

			<Card
				title={ __( 'CAPTCHA', 'gemsecurity' ) }
				description={ __( 'Add a bot challenge to the login, registration and lost-password forms.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Enable CAPTCHA', 'gemsecurity' ) }
					checked={ form.captcha_enabled }
					onChange={ ( v ) => setField( 'captcha_enabled', v ) }
				/>
				{ form.captcha_enabled && (
					<>
						<Field label={ __( 'Provider', 'gemsecurity' ) }>
							<Select
								value={ form.captcha_provider || 'recaptcha_v2' }
								onChange={ ( e ) => setField( 'captcha_provider', e.target.value ) }
								options={ [
									{ value: 'recaptcha_v2', label: 'Google reCAPTCHA v2 (checkbox)' },
									{ value: 'recaptcha_v3', label: 'Google reCAPTCHA v3 (score)' },
									{ value: 'hcaptcha', label: 'hCaptcha' },
									{ value: 'turnstile', label: 'Cloudflare Turnstile' },
								] }
							/>
						</Field>
						{ /* Steps for whichever provider is selected — the key
						     pairs are not interchangeable between them. */ }
						<SetupGuide
							id={ `captcha.${ form.captcha_provider || 'recaptcha_v2' }` }
							defaultOpen={ ! form.captcha_site_key }
						/>
						<div className="gs-row">
							<Field label={ __( 'Site key', 'gemsecurity' ) }>
								<TextInput value={ form.captcha_site_key ?? '' } onChange={ ( e ) => setField( 'captcha_site_key', e.target.value ) } />
							</Field>
							<Field label={ __( 'Secret key', 'gemsecurity' ) }>
								<TextInput type="password" value={ form.captcha_secret_key ?? '' } onChange={ ( e ) => setField( 'captcha_secret_key', e.target.value ) } />
							</Field>
						</div>
						{ form.captcha_provider === 'recaptcha_v3' && (
							<Field label={ __( 'v3 score threshold', 'gemsecurity' ) } description={ __( '0.0–1.0; requests scoring below this are blocked (0.5 recommended).', 'gemsecurity' ) }>
								<NumberInput step="0.1" min="0" max="1" value={ form.captcha_v3_threshold ?? 0.5 } onChange={ ( e ) => setField( 'captcha_v3_threshold', Number( e.target.value ) ) } />
							</Field>
						) }
						<div className="gs-toggle-list">
							<Toggle label={ __( 'On login form', 'gemsecurity' ) } checked={ form.captcha_on_login } onChange={ ( v ) => setField( 'captcha_on_login', v ) } />
							<Toggle label={ __( 'On registration form', 'gemsecurity' ) } checked={ form.captcha_on_register } onChange={ ( v ) => setField( 'captcha_on_register', v ) } />
							<Toggle label={ __( 'On lost-password form', 'gemsecurity' ) } checked={ form.captcha_on_lostpassword } onChange={ ( v ) => setField( 'captcha_on_lostpassword', v ) } />
							<Toggle label={ __( 'On comment form', 'gemsecurity' ) } checked={ form.captcha_on_comments } onChange={ ( v ) => setField( 'captcha_on_comments', v ) } />
						</div>
					</>
				) }
				<Toggle
					label={ __( 'Comment spam honeypot', 'gemsecurity' ) }
					description={ __( 'Silently blocks bot comments with a hidden decoy field and a too-fast-submit check. Needs no CAPTCHA keys and skips logged-in users.', 'gemsecurity' ) }
					checked={ form.comment_honeypot_enabled }
					onChange={ ( v ) => setField( 'comment_honeypot_enabled', v ) }
				/>
			</Card>

			<Card
				title={ __( 'Password policy', 'gemsecurity' ) }
				description={ __( 'Enforce strong passwords on every account and reject leaked ones.', 'gemsecurity' ) }
			>
				<Toggle label={ __( 'Enforce password policy', 'gemsecurity' ) } checked={ form.password_policy_enabled } onChange={ ( v ) => setField( 'password_policy_enabled', v ) } />
				{ form.password_policy_enabled && (
					<>
						<div className="gs-row">
							<Field label={ __( 'Minimum length', 'gemsecurity' ) } suffix={ __( 'characters', 'gemsecurity' ) }>
								<NumberInput min="6" value={ form.password_min_length ?? 10 } onChange={ ( e ) => setField( 'password_min_length', Number( e.target.value ) ) } />
							</Field>
							<Field label={ __( 'Expire passwords after', 'gemsecurity' ) } suffix={ __( 'days (0 = never)', 'gemsecurity' ) }>
								<NumberInput min="0" value={ form.password_expiry_days ?? 0 } onChange={ ( e ) => setField( 'password_expiry_days', Number( e.target.value ) ) } />
							</Field>
						</div>
						<Toggle label={ __( 'Require mixed case, number & symbol', 'gemsecurity' ) } checked={ form.password_require_complexity } onChange={ ( v ) => setField( 'password_require_complexity', v ) } />
						<Toggle label={ __( 'Reject passwords found in data breaches', 'gemsecurity' ) } description={ __( 'Checks Have I Been Pwned using k-anonymity (the password is never sent).', 'gemsecurity' ) } checked={ form.password_check_breached } onChange={ ( v ) => setField( 'password_check_breached', v ) } />
					</>
				) }
			</Card>

			<Card
				title={ __( 'Custom login URL', 'gemsecurity' ) }
				description={ __( 'Hide wp-login.php behind a secret address to stop automated login attacks.', 'gemsecurity' ) }
			>
				<Toggle label={ __( 'Enable custom login URL', 'gemsecurity' ) } checked={ form.custom_login_enabled } onChange={ ( v ) => setField( 'custom_login_enabled', v ) } />
				{ form.custom_login_enabled && (
					<>
						<Field label={ __( 'Login slug', 'gemsecurity' ) } description={ `${ __( 'Your login page will be:', 'gemsecurity' ) } ${ loginBase }${ form.custom_login_slug || 'your-slug' }` }>
							<TextInput value={ form.custom_login_slug ?? '' } onChange={ ( e ) => setField( 'custom_login_slug', e.target.value ) } placeholder="secret-login" />
						</Field>
						<div className="gs-alert gs-alert--warning">
							<span>{ __( 'Bookmark the new URL. If you get locked out, remove custom_login_enabled from the gemsecurity_settings option via the database.', 'gemsecurity' ) }</span>
						</div>
					</>
				) }
			</Card>

			<Card
				title={ __( 'Idle session timeout', 'gemsecurity' ) }
				description={ __( 'Automatically log users out after a period of inactivity.', 'gemsecurity' ) }
			>
				<Toggle label={ __( 'Enable idle timeout', 'gemsecurity' ) } checked={ form.idle_timeout_enabled } onChange={ ( v ) => setField( 'idle_timeout_enabled', v ) } />
				{ form.idle_timeout_enabled && (
					<Field label={ __( 'Log out after', 'gemsecurity' ) } suffix={ __( 'minutes idle', 'gemsecurity' ) }>
						<NumberInput min="1" value={ form.idle_timeout_minutes ?? 30 } onChange={ ( e ) => setField( 'idle_timeout_minutes', Number( e.target.value ) ) } />
					</Field>
				) }
			</Card>

			<Card
				title={ __( 'Login honeypot', 'gemsecurity' ) }
				description={ __( 'A hidden field bots fill in but humans never see — an instant, frictionless bot trap that feeds the ban ledger.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Enable login honeypot', 'gemsecurity' ) }
					checked={ form.login_honeypot_enabled }
					onChange={ ( v ) => setField( 'login_honeypot_enabled', v ) }
				/>
			</Card>

			<ProSection
				title={ __( 'Trusted devices & recovery', 'gemsecurity' ) }
				description={ __( 'New-device sign-in alerts and one-time magic-link recovery.', 'gemsecurity' ) }
			>
				<Card
					title={ __( 'Trusted devices', 'gemsecurity' ) }
					description={ __( 'Fingerprint each successful login and alert on unrecognised devices.', 'gemsecurity' ) }
				>
					<Toggle label={ __( 'Track devices & detect new ones', 'gemsecurity' ) } checked={ form.trusted_devices_enabled } onChange={ ( v ) => setField( 'trusted_devices_enabled', v ) } />
					{ form.trusted_devices_enabled && (
						<Toggle label={ __( 'Email the user on a new-device sign-in', 'gemsecurity' ) } checked={ form.trusted_devices_alert } onChange={ ( v ) => setField( 'trusted_devices_alert', v ) } />
					) }
				</Card>
				<Card
					title={ __( 'Magic-link recovery', 'gemsecurity' ) }
					description={ __( 'Email a legitimate user a one-time, 15-minute login link — even if their IP is locked out.', 'gemsecurity' ) }
				>
					<Toggle label={ __( 'Enable magic-link recovery', 'gemsecurity' ) } checked={ form.magic_link_enabled } onChange={ ( v ) => setField( 'magic_link_enabled', v ) } />
					{ form.magic_link_enabled && isPro() && <MagicLinkSender /> }
				</Card>
			</ProSection>

			<div className="gs-savebar">
				<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>
					{ __( 'Save changes', 'gemsecurity' ) }
				</Button>
			</div>

			<ActiveSessions />
		</div>
	);
}
