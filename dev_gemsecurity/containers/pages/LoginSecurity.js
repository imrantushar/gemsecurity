import React from 'react';
import { __ } from '@wordpress/i18n';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, NumberInput, TextInput, Select, Button } from '@Components/ui/Controls';

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
	'captcha_v3_threshold',
];

export default function LoginSecurity() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );

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
						</div>
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
