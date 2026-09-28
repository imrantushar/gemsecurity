import React, { useEffect, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api, { GS } from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, NumberInput, TextInput, Button, MultiSelect, toOptions } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';
import TestCredentials from '@Components/ui/TestCredentials';
import { useToast } from '@Components/ui/Toast';
import { ProSection, isPro } from '@Components/ui/Pro';

const KEYS = [
	'login_attempts_enabled',
	'login_attempts_limit',
	'login_lockout_duration',
	'admin_login_alert_enabled',
	'admin_session_timeout_enabled',
	'admin_session_timeout_hours',
	// Password policy.
	'password_policy_enabled',
	'password_min_length',
	'password_require_complexity',
	'password_check_breached',
	// Forced rotation.
	'password_rotation_enabled',
	'password_rotation_days',
	'password_rotation_roles',
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

const ROTATION_KEYS = [ 'password_rotation_enabled', 'password_rotation_days', 'password_rotation_roles' ];

/**
 * Forced password resets: one click now, or on a schedule, scoped by role.
 *
 * The scope is previewed before anything happens — this destroys sessions and
 * locks every affected account out until its owner sets a new password, so a
 * mis-scoped click is expensive.
 */
function PasswordRotation() {
	const { form, setField, save, saving, dirty } = useSettingsForm( ROTATION_KEYS );
	const toast = useToast();
	const roles = GS.roles || {};
	const scoped = form.password_rotation_roles || [];
	const [ preview, setPreview ] = useState( null );
	const [ busy, setBusy ] = useState( '' );
	const [ includeSelf, setIncludeSelf ] = useState( false );
	const [ notify, setNotify ] = useState( true );

	const load = async () => {
		setBusy( 'preview' );
		try {
			const { data } = await api.get( 'passwords/rotate', {
				params: { roles: scoped, include_self: includeSelf ? 1 : 0 },
			} );
			setPreview( data );
		} catch ( e ) {
			toast( __( 'Could not check who this would affect.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const run = async () => {
		setBusy( 'run' );
		try {
			const { data } = await api.post( 'passwords/rotate', {
				roles: scoped,
				include_self: includeSelf,
				notify,
			} );
			toast(
				sprintf(
					/* translators: 1: users reset, 2: emails sent. */
					__( 'Reset forced for %1$d user(s); %2$d reset link(s) emailed.', 'gemsecurity' ),
					data.count,
					data.notified
				),
				'success'
			);
			setPreview( { targets: 0, pending: data.pending } );
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not force the reset.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const clearAll = async () => {
		setBusy( 'clear' );
		try {
			const { data } = await api.post( 'passwords/rotate', { action: 'clear' } );
			toast(
				sprintf( /* translators: %d: users. */ __( 'Cleared the reset requirement for %d user(s).', 'gemsecurity' ), data.cleared ),
				'success'
			);
			setPreview( ( p ) => ( { ...( p || {} ), pending: data.pending } ) );
		} catch ( e ) {
			toast( __( 'Could not clear it.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	return (
		<Card
			title={ __( 'Password rotation', 'gemsecurity' ) }
			description={ __( 'Force users to choose a new password. Sessions are ended and the old password stops working immediately — the standard response after a breach.', 'gemsecurity' ) }
		>
			<Field
				label={ __( 'Apply to roles', 'gemsecurity' ) }
				description={ __( 'Leave empty to apply to every user.', 'gemsecurity' ) }
			>
				<MultiSelect
					options={ toOptions( roles ) }
					value={ scoped }
					onChange={ ( next ) => setField( 'password_rotation_roles', next ) }
					placeholder={ __( 'Every user', 'gemsecurity' ) }
				/>
			</Field>

			<Toggle
				label={ __( 'Email each user a reset link', 'gemsecurity' ) }
				description={ __( 'Without this they must use “Lost your password?” themselves. Passwords are never generated or emailed.', 'gemsecurity' ) }
				checked={ notify }
				onChange={ setNotify }
			/>
			<Toggle
				label={ __( 'Include my own account', 'gemsecurity' ) }
				description={ __( 'Off by default so a site-wide reset cannot lock you out in the middle of an incident.', 'gemsecurity' ) }
				checked={ includeSelf }
				onChange={ setIncludeSelf }
			/>

			<div className="gs-addrow">
				<Button variant="secondary" onClick={ load } loading={ busy === 'preview' }>
					{ __( 'Check who this affects', 'gemsecurity' ) }
				</Button>
				{ preview && preview.targets > 0 && (
					<Button variant="danger" onClick={ run } loading={ busy === 'run' }>
						{ sprintf(
							/* translators: %d: number of users. */
							__( 'Force a reset for %d user(s)', 'gemsecurity' ),
							preview.targets
						) }
					</Button>
				) }
				{ preview && preview.pending > 0 && (
					<Button variant="secondary" onClick={ clearAll } loading={ busy === 'clear' }>
						{ sprintf( /* translators: %d: users. */ __( 'Cancel for %d waiting user(s)', 'gemsecurity' ), preview.pending ) }
					</Button>
				) }
			</div>

			{ preview && (
				<div className={ `gs-alert gs-alert--${ preview.targets ? 'warning' : 'info' }` }>
					<Icon name={ preview.targets ? 'alert' : 'check' } size={ 18 } />
					<span>
						{ sprintf(
							/* translators: 1: affected users, 2: users already waiting. */
							__( '%1$d user(s) would be signed out and required to set a new password. %2$d are already waiting to do so.', 'gemsecurity' ),
							preview.targets,
							preview.pending
						) }
					</span>
				</div>
			) }

			<Toggle
				label={ __( 'Rotate passwords automatically', 'gemsecurity' ) }
				description={ __( 'Runs daily and forces a reset for anyone in the selected roles whose password is older than the age below.', 'gemsecurity' ) }
				checked={ form.password_rotation_enabled }
				onChange={ ( v ) => setField( 'password_rotation_enabled', v ) }
			/>
			{ form.password_rotation_enabled && (
				<div className="gs-row">
					<Field label={ __( 'Maximum password age', 'gemsecurity' ) } suffix={ __( 'days', 'gemsecurity' ) }>
						<NumberInput
							min="1"
							value={ form.password_rotation_days ?? 90 }
							onChange={ ( e ) => setField( 'password_rotation_days', Number( e.target.value ) ) }
						/>
					</Field>
				</div>
			) }

			<div className="gs-savebar gs-savebar--inline">
				<Button variant="secondary" onClick={ () => save() } loading={ saving } disabled={ ! dirty }>
					{ __( 'Save rotation settings', 'gemsecurity' ) }
				</Button>
			</div>
		</Card>
	);
}

export default function LoginSecurity() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const loginBase = ( GS.site_url || '' ).replace( /\/$/, '' ) + '/';

	// Mirror of the server's sanitize_title() + reserved-slug rule, so the
	// preview shows the address that will actually work. Typing "Secret Login"
	// used to preview /Secret Login and then serve /secret-login — bookmark the
	// preview and you get a 404 from a site whose wp-login.php is now hidden.
	const RESERVED_SLUGS = [
		'wp-admin', 'wp-login', 'wp-content', 'wp-includes',
		'wp-json', 'admin', 'login', 'feed', 'trackback',
	];
	const cleanSlug = ( raw ) => {
		const slug = ( raw || '' )
			.toString()
			.normalize( 'NFD' )
			.replace( /[\u0300-\u036f]/g, '' )   // strip accents, as sanitize_title does
			.toLowerCase()
			.replace( /[^a-z0-9\-_]+/g, '-' )
			.replace( /-+/g, '-' )
			.replace( /^-|-$/g, '' );
		return RESERVED_SLUGS.includes( slug ) ? '' : slug;
	};

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
				{ form.admin_login_alert_enabled && (
					<p className="gs-card__desc">
						{ __( 'The alert — user, time, IP and browser — goes to the security email on the Notifications page, along with every other notification the plugin sends.', 'gemsecurity' ) }
					</p>
				) }
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
						{ form.password_check_breached && (
							<TestCredentials
								target="service"
								getValues={ () => ( { service: 'breached_passwords' } ) }
								label={ __( 'Test connection', 'gemsecurity' ) }
							/>
						) }
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
						<Field
							label={ __( 'Login slug', 'gemsecurity' ) }
							description={
								cleanSlug( form.custom_login_slug )
									? `${ __( 'Your login page will be:', 'gemsecurity' ) } ${ loginBase }${ cleanSlug( form.custom_login_slug ) }`
									: __( 'Lowercase letters, numbers and hyphens. Anything else is converted, and addresses WordPress already owns (wp-admin, login, admin…) cannot be used.', 'gemsecurity' )
							}
						>
							<TextInput value={ form.custom_login_slug ?? '' } onChange={ ( e ) => setField( 'custom_login_slug', e.target.value ) } placeholder="secret-login" />
						</Field>
						{ form.custom_login_slug && cleanSlug( form.custom_login_slug ) !== form.custom_login_slug && (
							<div className="gs-alert gs-alert--warning">
								<Icon name="alert" size={ 18 } />
								<span>
									{ cleanSlug( form.custom_login_slug )
										? sprintf(
											/* translators: 1: typed slug, 2: slug that will be saved. */
											__( '“%1$s” will be saved as “%2$s” — that is the address to bookmark.', 'gemsecurity' ),
											form.custom_login_slug,
											cleanSlug( form.custom_login_slug )
										)
										: __( 'That slug cannot be used, so the custom login URL will stay switched off and wp-login.php will remain reachable. Pick another.', 'gemsecurity' ) }
								</span>
							</div>
						) }
						<div className="gs-alert gs-alert--warning">
							<Icon name="alert" size={ 18 } />
							<span>
								{ __( 'Bookmark the new URL before you save. wp-admin will stop redirecting to the login page — that redirect is what would otherwise give the address away — so visiting it while logged out sends you to the front page instead.', 'gemsecurity' ) }
								{ ' ' }
								{ __( 'If you ever get locked out, add this line to wp-config.php:', 'gemsecurity' ) }
								{ ' ' }
								<code>define( &apos;GEMSECURITY_DISABLE_CUSTOM_LOGIN&apos;, true );</code>
							</span>
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

			<PasswordRotation />

			<div className="gs-savebar" data-label={ __( 'Unsaved changes', 'gemsecurity' ) }>
				<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>
					{ __( 'Save changes', 'gemsecurity' ) }
				</Button>
			</div>

			<ActiveSessions />
		</div>
	);
}
