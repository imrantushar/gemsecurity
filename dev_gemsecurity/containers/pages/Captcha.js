import React, { useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import useSettingsForm from '@Utils/useSettingsForm';
import { Toggle, NumberInput, Field } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';
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

const PROVIDERS = [
	{ id: 'recaptcha_v2', name: 'Google reCAPTCHA v2', sub: __( '“I’m not a robot” checkbox', 'gemsecurity' ), brand: 'reCAPTCHA', console: 'https://www.google.com/recaptcha/admin', consoleLabel: __( 'reCAPTCHA admin console', 'gemsecurity' ), short: 'reCAPTCHA v2' },
	{ id: 'recaptcha_v3', name: 'Google reCAPTCHA v3', sub: __( 'Invisible, score based', 'gemsecurity' ), brand: 'reCAPTCHA', console: 'https://www.google.com/recaptcha/admin', consoleLabel: __( 'reCAPTCHA admin console', 'gemsecurity' ), short: 'reCAPTCHA v3' },
	{ id: 'hcaptcha', name: 'hCaptcha', sub: __( 'Checkbox, image puzzle when unsure', 'gemsecurity' ), brand: 'hCaptcha', console: 'https://dashboard.hcaptcha.com', consoleLabel: __( 'hCaptcha dashboard', 'gemsecurity' ), short: 'hCaptcha' },
	{ id: 'turnstile', name: 'Cloudflare Turnstile', sub: __( 'Usually no click needed', 'gemsecurity' ), brand: 'Turnstile', console: 'https://dash.cloudflare.com/?to=/:account/turnstile', consoleLabel: __( 'Cloudflare dashboard', 'gemsecurity' ), short: 'Turnstile' },
];

const FORMS = [
	{ key: 'captcha_on_login', icon: 'key', title: __( 'Login form', 'gemsecurity' ), sub: 'wp-login.php', short: __( 'Login', 'gemsecurity' ) },
	{ key: 'captcha_on_register', icon: 'users', title: __( 'Registration form', 'gemsecurity' ), sub: __( 'New account sign-ups', 'gemsecurity' ), short: __( 'registration', 'gemsecurity' ) },
	{ key: 'captcha_on_lostpassword', icon: 'lock', title: __( 'Lost-password form', 'gemsecurity' ), sub: __( 'Stops bots spamming reset emails.', 'gemsecurity' ), short: __( 'lost-password', 'gemsecurity' ), tag: __( 'Recommended', 'gemsecurity' ) },
];

const looksLikeEmail = ( v ) => /^\S+@\S+\.\S+$/.test( v || '' );

export default function Captcha() {
	const { form, setField } = useSettingsForm( KEYS );
	const [ showSecret, setShowSecret ] = useState( false );
	const [ tab, setTab ] = useState( 'login' );
	const provider = form.captcha_provider || 'recaptcha_v2';
	const prov = PROVIDERS.find( ( p ) => p.id === provider ) || PROVIDERS[ 0 ];
	const enabled = !! form.captcha_enabled;
	const siteKey = form.captcha_site_key ?? '';
	const secretKey = form.captcha_secret_key ?? '';

	const onForms = FORMS.filter( ( f ) => form[ f.key ] );
	const emailKey = looksLikeEmail( siteKey );
	const keysFilled = !! siteKey && !! secretKey;
	const keysValid = keysFilled && ! emailKey;
	const checklist = [
		{ ok: true, title: __( 'Provider chosen', 'gemsecurity' ), sub: prov.name },
		{
			ok: onForms.length > 0,
			title: __( 'Shown on a form', 'gemsecurity' ),
			sub: onForms.length ? onForms.map( ( f ) => f.short ).join( ' & ' ) : __( 'Turn on at least one form', 'gemsecurity' ),
		},
		{
			ok: keysValid, bad: emailKey,
			title: __( 'Keys look valid', 'gemsecurity' ),
			sub: emailKey ? __( 'Site key is an email address', 'gemsecurity' ) : keysFilled ? __( 'Both keys entered', 'gemsecurity' ) : __( 'Enter both keys', 'gemsecurity' ),
		},
		{ ok: false, idle: true, title: __( 'Keys verified', 'gemsecurity' ), sub: __( 'Run “Verify keys” after fixing', 'gemsecurity' ) },
	];
	const done = checklist.filter( ( c ) => c.ok ).length;
	const protecting = enabled && keysValid && onForms.length > 0;

	return (
		<div className="gs-page gs-cap">
			<section className="gs-cap__head">
				<span className="gs-cap__head-icon"><Icon name="bot" size={ 22 } /></span>
				<div className="gs-cap__head-text">
					<h2>
						{ __( 'CAPTCHA', 'gemsecurity' ) }
						<span className={ `gs-cap__state ${ protecting ? 'is-ok' : '' }` }>
							<i />{ protecting ? __( 'Protecting your forms', 'gemsecurity' ) : __( 'Not protecting yet — keys need fixing', 'gemsecurity' ) }
						</span>
					</h2>
					<p>{ __( 'A bot check on your login, registration and reset forms.', 'gemsecurity' ) }</p>
				</div>
				<label className="gs-cap__enable">
					<span>{ enabled ? __( 'Enabled', 'gemsecurity' ) : __( 'Disabled', 'gemsecurity' ) }</span>
					<Toggle checked={ enabled } onChange={ ( v ) => setField( 'captcha_enabled', v ) } />
				</label>
			</section>

			<div className="gs-cap__cols">
				<div className="gs-cap__main">
					<section className="gs-cap__step">
						<span className="gs-cap__num is-done"><Icon name="check" size={ 14 } /></span>
						<div className="gs-cap__step-body">
							<h3>{ __( 'Choose a provider', 'gemsecurity' ) }</h3>
							<p>{ __( 'All three are free.', 'gemsecurity' ) }</p>
							<div className="gs-cap__providers">
								{ PROVIDERS.filter( ( p ) => p.id !== 'recaptcha_v3' || provider === 'recaptcha_v3' ).map( ( p ) => (
									<button
										key={ p.id }
										type="button"
										className={ `gs-cap__provider ${ provider === p.id ? 'is-selected' : '' }` }
										onClick={ () => setField( 'captcha_provider', p.id ) }
									>
										<i />
										<span><strong>{ p.name }</strong><small>{ p.sub }</small></span>
									</button>
								) ) }
							</div>
							{ provider !== 'recaptcha_v3' && (
								<button type="button" className="gs-cap__link" onClick={ () => setField( 'captcha_provider', 'recaptcha_v3' ) }>
									{ __( 'Use reCAPTCHA v3 (invisible) instead', 'gemsecurity' ) }
								</button>
							) }
						</div>
					</section>

					<section className="gs-cap__step">
						<span className="gs-cap__num">2</span>
						<div className="gs-cap__step-body">
							<h3>{ __( 'Add your keys', 'gemsecurity' ) }</h3>
							<p>
								{ __( 'Register your site in the', 'gemsecurity' ) }{ ' ' }
								<a href={ prov.console } target="_blank" rel="noreferrer">{ prov.consoleLabel }<Icon name="link" size={ 13 } /></a>{ ' ' }
								{ __( 'then paste both keys here.', 'gemsecurity' ) }
							</p>
							<SetupGuide id={ `captcha.${ provider }` } defaultOpen={ false } />
							<div className="gs-cap__keys">
								<div className="gs-cap__key">
									<label>{ __( 'Site key', 'gemsecurity' ) }<small>{ __( 'public', 'gemsecurity' ) }</small></label>
									<div className={ `gs-cap__input ${ emailKey ? 'is-bad' : '' }` }>
										<input
											type="text"
											value={ siteKey }
											onChange={ ( e ) => setField( 'captcha_site_key', e.target.value ) }
											autoComplete="off"
										/>
										{ emailKey && <Icon name="alert" size={ 16 } /> }
									</div>
									{ emailKey && <em>{ __( 'This looks like an email, not a site key. Your browser may have autofilled it.', 'gemsecurity' ) }</em> }
								</div>
								<div className="gs-cap__key">
									<label>{ __( 'Secret key', 'gemsecurity' ) }<small>{ __( 'stays on your server', 'gemsecurity' ) }</small></label>
									<div className="gs-cap__input">
										<input
											type={ showSecret ? 'text' : 'password' }
											value={ secretKey }
											onChange={ ( e ) => setField( 'captcha_secret_key', e.target.value ) }
											autoComplete="new-password"
										/>
										<button type="button" onClick={ () => setShowSecret( ! showSecret ) } aria-label={ __( 'Show or hide the secret key', 'gemsecurity' ) }>
											<Icon name="radar" size={ 16 } />
										</button>
									</div>
									<small className="gs-cap__hint">{ __( 'Stays on your server. Use the eye to check it.', 'gemsecurity' ) }</small>
								</div>
							</div>
							<div className="gs-cap__verify">
								<TestCaptcha provider={ provider } siteKey={ siteKey } secretKey={ secretKey } />
							</div>
							{ 'recaptcha_v3' === provider && (
								<Field label={ __( 'v3 score threshold', 'gemsecurity' ) } description={ __( '0.0–1.0; requests scoring below this are blocked (0.5 recommended).', 'gemsecurity' ) }>
									<NumberInput step="0.1" min="0" max="1" value={ form.captcha_v3_threshold ?? 0.5 } onChange={ ( e ) => setField( 'captcha_v3_threshold', Number( e.target.value ) ) } />
								</Field>
							) }
						</div>
					</section>

					<section className="gs-cap__step">
						<span className="gs-cap__num">3</span>
						<div className="gs-cap__step-body">
							<h3>{ __( 'Where to show it', 'gemsecurity' ) }</h3>
							<p>{ sprintf( /* translators: 1: on, 2: total */ __( 'Shown on %1$d of %2$d forms.', 'gemsecurity' ), onForms.length, FORMS.length ) }</p>
							<div className="gs-cap__forms">
								{ FORMS.map( ( f ) => (
									<div key={ f.key } className="gs-cap__form">
										<Icon name={ f.icon } size={ 18 } />
										<div>
											<strong>{ f.title }{ f.tag && <em>{ f.tag }</em> }</strong>
											<small>{ f.sub }</small>
										</div>
										<Toggle checked={ !! form[ f.key ] } onChange={ ( v ) => setField( f.key, v ) } />
									</div>
								) ) }
								<div className="gs-cap__form is-muted">
									<Icon name="mail" size={ 18 } />
									<div>
										<strong>{ __( 'Comment form', 'gemsecurity' ) }</strong>
										<small>{ __( 'Lives with the other comment controls', 'gemsecurity' ) }</small>
									</div>
									<a href={ `${ window.location.pathname }?page=gemsecurity-antispam` }>
										{ __( 'Set up in Anti-Spam', 'gemsecurity' ) }<Icon name="arrow-right" size={ 14 } />
									</a>
								</div>
							</div>
						</div>
					</section>
				</div>

				<aside className="gs-cap__side">
					<section className="gs-cap__panel">
						<header>
							<h3><Icon name="globe" size={ 16 } />{ __( 'Live preview', 'gemsecurity' ) }</h3>
							<div className="gs-cap__tabs">
								{ [ [ 'login', __( 'Login', 'gemsecurity' ) ], [ 'register', __( 'Register', 'gemsecurity' ) ], [ 'reset', __( 'Reset', 'gemsecurity' ) ] ].map( ( [ k, l ] ) => (
									<button key={ k } type="button" className={ tab === k ? 'is-on' : '' } onClick={ () => setTab( k ) }>{ l }</button>
								) ) }
							</div>
						</header>
						<div className="gs-cap__preview">
							<span className="gs-cap__preview-logo"><Icon name="shield" size={ 22 } /></span>
							<div className="gs-cap__login">
								<label>{ tab === 'reset' ? __( 'Username or Email Address', 'gemsecurity' ) : tab === 'register' ? __( 'Username', 'gemsecurity' ) : __( 'Username or Email Address', 'gemsecurity' ) }</label>
								<span className="gs-cap__fake" />
								{ tab === 'register' && <><label>{ __( 'Email', 'gemsecurity' ) }</label><span className="gs-cap__fake" /></> }
								{ tab === 'login' && <><label>{ __( 'Password', 'gemsecurity' ) }</label><span className="gs-cap__fake" /></> }
								<div className="gs-cap__widget">
									<span className="gs-cap__box" />
									<span>{ provider === 'recaptcha_v3' ? __( 'Protected by', 'gemsecurity' ) : __( 'I’m not a robot', 'gemsecurity' ) }</span>
									<small>{ prov.brand }</small>
								</div>
								<span className="gs-cap__go">{ tab === 'login' ? __( 'Log In', 'gemsecurity' ) : tab === 'register' ? __( 'Register', 'gemsecurity' ) : __( 'Get New Password', 'gemsecurity' ) }</span>
							</div>
						</div>
						<p className="gs-cap__note"><Icon name="help" size={ 14 } />{ __( 'Preview only — the real widget appears after keys are verified.', 'gemsecurity' ) }</p>
					</section>

					<section className="gs-cap__panel gs-cap__ready">
						<header>
							<h3>{ __( 'Ready to protect?', 'gemsecurity' ) }</h3>
							<span>{ sprintf( /* translators: 1: done, 2: total */ __( '%1$d of %2$d', 'gemsecurity' ), done, checklist.length ) }</span>
						</header>
						<i className="gs-cap__bar"><b style={ { width: `${ ( done / checklist.length ) * 100 }%` } } /></i>
						<ul>
							{ checklist.map( ( c ) => (
								<li key={ c.title } className={ c.ok ? 'is-ok' : c.bad ? 'is-bad' : '' }>
									<Icon name={ c.ok ? 'check' : c.bad ? 'alert' : 'help' } size={ 16 } />
									<div><strong>{ c.title }</strong><small>{ c.sub }</small></div>
								</li>
							) ) }
						</ul>
					</section>
				</aside>
			</div>
		</div>
	);
}
