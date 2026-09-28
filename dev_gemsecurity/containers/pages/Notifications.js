import React, { useState } from 'react';
import { __ } from '@wordpress/i18n';
import { useNavigate } from 'react-router-dom';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { useModules, pageUrl, pageFromHref } from '@Utils/nav';
import { Card, Toggle, Button, Field, TextInput, NumberInput, Select } from '@Components/ui/Controls';
import TestCredentials from '@Components/ui/TestCredentials';
import SetupGuide from '@Components/ui/SetupGuide';
import Icon from '@Components/ui/Icon';
import { useToast } from '@Components/ui/Toast';
import { isPro, ProBadge } from '@Components/ui/Pro';

/* Stable reference: an inline array would be a new value on every render. */
const KEYS = [
	// Delivery — the one address and channel set every alert, report and
	// failure notice on the site goes through.
	'alerts_enabled',
	'alert_min_severity',
	'alert_to_email',
	'alert_slack_webhook',
	'alert_telegram_token',
	'alert_telegram_chat',
	'alert_webhook_url',
	// Sent on a schedule rather than in response to an event.
	'daily_report_enabled',
	'daily_report_hour',
	'digest_enabled',
	'scanner_auto_scan',
	'vuln_scan_enabled',
	// Per-module triggers. These are mirrored, not moved: each still lives on
	// the page of the module that raises the event, and both write the same key
	// through the same endpoint, so the two views cannot drift.
	'admin_login_alert_enabled',
	'trusted_devices_alert',
	'trusted_devices_enabled',
	'notify_on_rogue_admin',
	'notify_on_hidden_admin',
	'hidden_admin_detection',
	'app_pw_alert_on_create',
	'app_pw_disabled',
	'notify_on_failure',
	'health_alert_days',
];

/**
 * Every event a module can raise, and the switch that decides whether it does.
 *
 * `module` is the registry id — a row is only offered when that module is
 * active, so the page never shows a switch that could not fire. `needs` names a
 * setting the trigger depends on; when it is off the row is shown disabled with
 * the reason, rather than silently doing nothing.
 */
const TRIGGERS = [
	{
		key: 'admin_login_alert_enabled',
		module: 'login-security',
		label: __( 'An administrator signs in', 'gemsecurity' ),
	},
	{
		key: 'trusted_devices_alert',
		module: 'login-security',
		label: __( 'Someone signs in from an unrecognised device', 'gemsecurity' ),
		pro: true,
		needs: 'trusted_devices_enabled',
		needsNote: __( 'Device tracking is off, so no device is ever unrecognised.', 'gemsecurity' ),
	},
	{
		key: 'notify_on_rogue_admin',
		module: 'admin-guard',
		label: __( 'A rogue administrator is blocked', 'gemsecurity' ),
	},
	{
		key: 'notify_on_hidden_admin',
		module: 'admin-guard',
		label: __( 'An administrator hidden from the users list is found', 'gemsecurity' ),
		needs: 'hidden_admin_detection',
		needsNote: __( 'Hidden-administrator detection is off, so nothing looks for one.', 'gemsecurity' ),
	},
	{
		key: 'app_pw_alert_on_create',
		module: 'api-hardening',
		label: __( 'An application password is created', 'gemsecurity' ),
		needsNot: 'app_pw_disabled',
		needsNote: __( 'Application passwords are switched off site-wide, so none can be created.', 'gemsecurity' ),
	},
	{
		key: 'notify_on_failure',
		module: 'backup',
		label: __( 'A backup fails, or backups go quiet for too long', 'gemsecurity' ),
	},
];

/**
 * "Configured on <module>" — the module page keeps its own copy of the switch,
 * and this is how you get there without hunting through the sidebar.
 */
function ModuleLink( { module: mod } ) {
	const navigate = useNavigate();
	if ( ! mod ) {
		return null;
	}
	const href = pageUrl( mod.page_slug );

	return (
		<a
			className="gs-actionlist__go"
			href={ href }
			onClick={ ( e ) => {
				// Modifier-clicks keep their normal open-in-new-tab behaviour.
				if ( e.metaKey || e.ctrlKey || e.shiftKey || e.altKey ) {
					return;
				}
				const slug = pageFromHref( href );
				if ( ! slug ) {
					return;
				}
				e.preventDefault();
				navigate( pageUrl( slug ) );
			} }
		>
			{ mod.title }
			<Icon name="arrow-right" size={ 14 } />
		</a>
	);
}

export default function Notifications() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const toast = useToast();
	const modules = useModules();
	const [ sendingReport, setSendingReport ] = useState( false );

	const moduleById = ( id ) => modules.find( ( m ) => m.id === id );

	const sendDailyNow = async () => {
		setSendingReport( true );
		try {
			const { data } = await api.post( 'reports/daily', {} );
			toast( data.message || __( 'Daily report sent.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not send the report.', 'gemsecurity' ), 'error' );
		}
		setSendingReport( false );
	};

	// A module that is switched off cannot raise its events, so its rows are
	// left out entirely rather than shown as switches that do nothing.
	const rows = TRIGGERS.map( ( t ) => ( { ...t, mod: moduleById( t.module ) } ) )
		.filter( ( t ) => t.mod && t.mod.active );

	const scannerModule = moduleById( 'scanner' );

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Where alerts go', 'gemsecurity' ) }
				description={ __( 'One address and one set of channels for the whole plugin — real-time alerts, the daily report, the weekly digest, backup failures and monitoring notices all use these.', 'gemsecurity' ) }
			>
				<Field
					label={ __( 'Security email', 'gemsecurity' ) }
					description={ __( 'Every notification the plugin sends goes here. Leave empty to use the WordPress admin email.', 'gemsecurity' ) }
				>
					<TextInput
						type="email"
						value={ form.alert_to_email ?? '' }
						onChange={ ( e ) => setField( 'alert_to_email', e.target.value ) }
						placeholder={ __( 'Defaults to the admin email', 'gemsecurity' ) }
					/>
				</Field>
				<TestCredentials
					target="email"
					getValues={ () => ( { to: form.alert_to_email || '' } ) }
					label={ __( 'Send a test email', 'gemsecurity' ) }
				/>

				<Toggle
					label={ __( 'Enable real-time alerts', 'gemsecurity' ) }
					description={ __( 'Send an email — and a message to each channel below — as soon as a qualifying event is logged.', 'gemsecurity' ) }
					checked={ form.alerts_enabled }
					onChange={ ( v ) => setField( 'alerts_enabled', v ) }
				/>
				{ form.alerts_enabled && (
					<>
						<div className="gs-row">
							<Field label={ __( 'Alert on severity', 'gemsecurity' ) }>
								<Select
									value={ form.alert_min_severity || 'critical' }
									onChange={ ( e ) => setField( 'alert_min_severity', e.target.value ) }
									options={ [
										{ value: 'critical', label: __( 'Critical only', 'gemsecurity' ) },
										{ value: 'warning', label: __( 'Warning & above', 'gemsecurity' ) },
										{ value: 'notice', label: __( 'Notice & above', 'gemsecurity' ) },
									] }
								/>
							</Field>
						</div>
						<SetupGuide id="alerts.slack" />
						<Field label={ __( 'Slack incoming webhook URL', 'gemsecurity' ) }>
							<TextInput value={ form.alert_slack_webhook ?? '' } onChange={ ( e ) => setField( 'alert_slack_webhook', e.target.value ) } placeholder="https://hooks.slack.com/services/…" />
						</Field>
						<TestCredentials
							target="slack"
							getValues={ () => ( { url: form.alert_slack_webhook || '' } ) }
							label={ __( 'Send a test message', 'gemsecurity' ) }
						/>
						<SetupGuide id="alerts.telegram" />
						<div className="gs-row">
							<Field label={ __( 'Telegram bot token', 'gemsecurity' ) }>
								<TextInput value={ form.alert_telegram_token ?? '' } onChange={ ( e ) => setField( 'alert_telegram_token', e.target.value ) } />
							</Field>
							<Field label={ __( 'Telegram chat ID', 'gemsecurity' ) }>
								<TextInput value={ form.alert_telegram_chat ?? '' } onChange={ ( e ) => setField( 'alert_telegram_chat', e.target.value ) } />
							</Field>
						</div>
						<TestCredentials
							target="telegram"
							getValues={ () => ( {
								token: form.alert_telegram_token || '',
								chat_id: form.alert_telegram_chat || '',
							} ) }
							label={ __( 'Test bot & chat', 'gemsecurity' ) }
						/>
						<SetupGuide id="alerts.webhook" />
						<Field label={ __( 'Generic webhook URL', 'gemsecurity' ) }>
							<TextInput value={ form.alert_webhook_url ?? '' } onChange={ ( e ) => setField( 'alert_webhook_url', e.target.value ) } placeholder="https://example.com/webhook" />
						</Field>
						<TestCredentials
							target="webhook"
							getValues={ () => ( { url: form.alert_webhook_url || '' } ) }
							label={ __( 'Send a test event', 'gemsecurity' ) }
						/>
					</>
				) }
			</Card>

			<Card
				title={ __( 'What you get told about', 'gemsecurity' ) }
				description={ __( 'Every event a module can raise. Each switch also lives on the page of the module that raises it — changing it in either place changes the same setting.', 'gemsecurity' ) }
			>
				{ ! form.alerts_enabled && (
					<div className="gs-alert gs-alert--warning">
						<Icon name="alert" size={ 18 } />
						<span>{ __( 'Real-time alerts are off, so these events are still recorded in the log but nothing is sent. Switch them on above.', 'gemsecurity' ) }</span>
					</div>
				) }
				{ rows.length === 0 ? (
					<p className="gs-muted">{ __( 'No module that raises alerts is active yet.', 'gemsecurity' ) }</p>
				) : (
					rows.map( ( t ) => {
						const proLocked = t.pro && ! isPro();
						const blocked = proLocked || ( t.needs && ! form[ t.needs ] ) || ( t.needsNot && form[ t.needsNot ] );
						return (
							<div className="gs-alertrow" key={ t.key }>
								<Toggle
									label={ proLocked ? <span>{ t.label } <ProBadge /></span> : t.label }
									description={ proLocked ? __( 'Trusted-device tracking is part of GemSecurity Pro.', 'gemsecurity' ) : ( blocked ? t.needsNote : undefined ) }
									// A switch that cannot fire is shown off, whatever is stored.
									checked={ ! blocked && !! form[ t.key ] }
									onChange={ ( v ) => setField( t.key, v ) }
									disabled={ blocked }
								/>
								<ModuleLink module={ t.mod } />
							</div>
						);
					} )
				) }
				{ /* The one trigger that carries a threshold rather than a plain switch. */ }
				{ rows.some( ( t ) => t.key === 'notify_on_failure' ) && form.notify_on_failure && (
					<Field
						label={ __( 'Warn after this long without a successful backup', 'gemsecurity' ) }
						suffix={ __( 'days', 'gemsecurity' ) }
					>
						<NumberInput
							min="1"
							value={ form.health_alert_days ?? 7 }
							onChange={ ( e ) => setField( 'health_alert_days', Number( e.target.value ) ) }
						/>
					</Field>
				) }
			</Card>

			<Card
				title={ __( 'Sent on a schedule', 'gemsecurity' ) }
				description={ __( 'Mail that arrives whether or not anything happened — the quiet weeks are the point.', 'gemsecurity' ) }
				actions={
					<Button variant="secondary" onClick={ sendDailyNow } loading={ sendingReport }>
						{ __( 'Send a report now', 'gemsecurity' ) }
					</Button>
				}
			>
				<Toggle
					label={ __( 'Email a daily report', 'gemsecurity' ) }
					description={ __( 'A morning email listing every administrator and active plugin, and anything that changed since yesterday — so an unexpected change is visible even when no alert fired.', 'gemsecurity' ) }
					checked={ form.daily_report_enabled }
					onChange={ ( v ) => setField( 'daily_report_enabled', v ) }
				/>
				{ form.daily_report_enabled && (
					<div className="gs-row">
						<Field
							label={ __( 'Send at', 'gemsecurity' ) }
							description={ __( 'In your site’s timezone.', 'gemsecurity' ) }
						>
							<Select
								value={ String( form.daily_report_hour ?? 7 ) }
								onChange={ ( e ) => setField( 'daily_report_hour', Number( e.target.value ) ) }
								options={ Array.from( { length: 24 }, ( _, h ) => ( {
									value: String( h ),
									label: `${ String( h ).padStart( 2, '0' ) }:00`,
								} ) ) }
							/>
						</Field>
					</div>
				) }
				<Toggle
					label={ __( 'Send a weekly security digest', 'gemsecurity' ) }
					description={ __( 'A summary email (and channel message) every week.', 'gemsecurity' ) }
					checked={ form.digest_enabled }
					onChange={ ( v ) => setField( 'digest_enabled', v ) }
				/>

				{ /* The daily scan is a schedule, not a notification — but it is what
				     produces most of what the reports above have to say, so it is
				     reachable here as well as on the Scanner. */ }
				{ scannerModule && scannerModule.active && (
					<div className="gs-subcard">
						<div className="gs-alertrow">
							<div>
								<strong>{ __( 'Daily security scan', 'gemsecurity' ) }</strong>
								<p className="gs-card__desc">{ __( 'Not a notification itself — it is what finds most of what you get notified about.', 'gemsecurity' ) }</p>
							</div>
							<ModuleLink module={ scannerModule } />
						</div>
						<Toggle
							label={ __( 'Run a scan automatically every day', 'gemsecurity' ) }
							checked={ form.scanner_auto_scan }
							onChange={ ( v ) => setField( 'scanner_auto_scan', v ) }
						/>
						<Toggle
							label={ __( 'Check core, plugins & themes for known vulnerabilities', 'gemsecurity' ) }
							description={ __( 'Compares installed versions against a public vulnerability database during the daily scan.', 'gemsecurity' ) }
							checked={ form.vuln_scan_enabled }
							onChange={ ( v ) => setField( 'vuln_scan_enabled', v ) }
						/>
					</div>
				) }
			</Card>

			{ /* Always present, disabled when clean — same as the Settings page
			     this sits next to, so the save button never moves. */ }
			<div className="gs-savebar" data-label={ __( 'Unsaved changes', 'gemsecurity' ) }>
				<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>
					{ __( 'Save changes', 'gemsecurity' ) }
				</Button>
			</div>
		</div>
	);
}
