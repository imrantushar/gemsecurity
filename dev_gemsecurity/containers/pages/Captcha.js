import React from 'react';
import { __ } from '@wordpress/i18n';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, NumberInput, TextInput, Select, Button } from '@Components/ui/Controls';
import SetupGuide from '@Components/ui/SetupGuide';
import TestCaptcha from '@Components/ui/TestCaptcha';

const KEYS = [
	'captcha_enabled',
	'captcha_provider',
	'captcha_site_key',
	'captcha_secret_key',
	'captcha_on_login',
	'captcha_on_register',
	'captcha_on_lostpassword',
	'captcha_v3_threshold',
];

export default function Captcha() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const provider = form.captcha_provider || 'recaptcha_v2';

	return (
		<div className="gs-page">
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
								value={ provider }
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
							id={ `captcha.${ provider }` }
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
						{ /* Prove the keys here rather than on the login form:
						     renders the real widget and verifies its token. */ }
						<TestCaptcha
							provider={ provider }
							siteKey={ form.captcha_site_key || '' }
							secretKey={ form.captcha_secret_key || '' }
						/>
						{ 'recaptcha_v3' === provider && (
							<Field label={ __( 'v3 score threshold', 'gemsecurity' ) } description={ __( '0.0–1.0; requests scoring below this are blocked (0.5 recommended).', 'gemsecurity' ) }>
								<NumberInput step="0.1" min="0" max="1" value={ form.captcha_v3_threshold ?? 0.5 } onChange={ ( e ) => setField( 'captcha_v3_threshold', Number( e.target.value ) ) } />
							</Field>
						) }
						<div className="gs-toggle-list">
							<Toggle label={ __( 'On login form', 'gemsecurity' ) } checked={ form.captcha_on_login } onChange={ ( v ) => setField( 'captcha_on_login', v ) } />
							<Toggle label={ __( 'On registration form', 'gemsecurity' ) } checked={ form.captcha_on_register } onChange={ ( v ) => setField( 'captcha_on_register', v ) } />
							<Toggle label={ __( 'On lost-password form', 'gemsecurity' ) } checked={ form.captcha_on_lostpassword } onChange={ ( v ) => setField( 'captcha_on_lostpassword', v ) } />
						</div>
						<p className="gs-card__desc">
							{ __( 'To put this CAPTCHA on the comment form, turn it on under Anti-Spam, where the rest of the comment controls live.', 'gemsecurity' ) }
						</p>
					</>
				) }
			</Card>

		</div>
	);
}
