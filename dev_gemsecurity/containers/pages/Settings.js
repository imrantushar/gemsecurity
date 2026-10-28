import React, { useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Field, Toggle, NumberInput, TextInput, Select, ListInput, Button, Badge } from '@Components/ui/Controls';
import SetupGuide from '@Components/ui/SetupGuide';
import TestCredentials from '@Components/ui/TestCredentials';
import { useToast } from '@Components/ui/Toast';
import { useDispatch } from 'react-redux';
import { fetchSettings } from '@Redux/settingsSlice';
import useNavigate from '@Utils/useGuardedNavigate';
import { setModules, pageUrl } from '@Utils/nav';
import { isPro, ProBadge } from '@Components/ui/Pro';
import Icon from '@Components/ui/Icon';

const KEYS = [
	'logs_retention_days',
	// Compliance / SIEM.
	'log_hash_chain_enabled',
	'siem_enabled',
	'siem_endpoint',
	'siem_syslog',
	'siem_min_severity',
	// Lockdown + backup.
	'lockdown_enabled',
	'lockdown_message',
	'backup_before_updates',
];

/** Takes you to the page these settings moved to. */
function NotificationsLink() {
	const navigate = useNavigate();
	const href = pageUrl( 'gemsecurity-notifications' );

	return (
		<a
			className="gs-actionlist__go"
			href={ href }
			onClick={ ( e ) => {
				// Modifier-clicks keep their normal open-in-new-tab behaviour.
				if ( e.metaKey || e.ctrlKey || e.shiftKey || e.altKey ) {
					return;
				}
				e.preventDefault();
				navigate( href );
			} }
		>
			{ __( 'Open Notifications', 'gemsecurity' ) }
			<Icon name="arrow-right" size={ 14 } />
		</a>
	);
}

export default function Settings() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const toast = useToast();
	const dispatch = useDispatch();
	const pro = isPro();
	const [ verifyResult, setVerifyResult ] = useState( null );
	const [ verifying, setVerifying ] = useState( false );
	const [ busy, setBusy ] = useState( '' );
	const [ includeSecrets, setIncludeSecrets ] = useState( false );

	/* ------------------------- Settings portability ------------------------- */

	const exportSettings = async () => {
		setBusy( 'export' );
		try {
			const { data } = await api.get( 'pro/settings/export', { params: includeSecrets ? { include_secrets: 1 } : {} } );
			const blob = new Blob( [ JSON.stringify( data.exported, null, 2 ) ], { type: 'application/json' } );
			const url = URL.createObjectURL( blob );
			const a = document.createElement( 'a' );
			a.href = url;
			// Host + date, so files from several sites stay distinguishable.
			a.download = `gemsecurity-settings-${ window.location.hostname }-${ new Date()
				.toISOString()
				.slice( 0, 10 ) }.json`;
			// The anchor must be in the document for Firefox to honour the
			// click, and the object URL has to outlive it — revoking straight
			// away cancels the download in Safari.
			a.style.display = 'none';
			document.body.appendChild( a );
			a.click();
			setTimeout( () => {
				document.body.removeChild( a );
				URL.revokeObjectURL( url );
			}, 1000 );
			toast(
				data.omitted && data.omitted.length
					? __( 'Settings exported. API keys, tokens and webhook URLs were left out.', 'gemsecurity' )
					: __( 'Settings exported.', 'gemsecurity' ),
				'success'
			);
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Export failed.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const importSettings = ( e ) => {
		const file = e.target.files && e.target.files[ 0 ];
		e.target.value = '';
		if ( ! file ) {
			return;
		}
		const reader = new FileReader();
		reader.onload = async () => {
			setBusy( 'import' );
			let parsed;
			try {
				parsed = JSON.parse( reader.result );
			} catch ( err ) {
				toast( __( 'Import failed — that file is not valid JSON.', 'gemsecurity' ), 'error' );
				setBusy( '' );
				return;
			}
			try {
				const { data } = await api.post(
					'pro/settings/import',
					parsed.exported ? parsed : { exported: parsed }
				);
				// Module activation may have changed, so refresh the nav/menu
				// from the server rather than leaving a stale module list.
				await dispatch( fetchSettings() );
				const fresh = await api.get( 'modules' );
				if ( Array.isArray( fresh.data?.modules ) ) {
					setModules( fresh.data.modules );
				}
				toast(
					sprintf(
						/* translators: 1: settings count, 2: module count. */
						__( 'Imported %1$d settings and %2$d module states.', 'gemsecurity' ),
						data?.imported ?? 0,
						data?.modules ?? 0
					),
					'success'
				);
				if ( data?.skipped?.length ) {
					toast(
						sprintf(
							/* translators: %s: comma-separated module ids. */
							__( 'Skipped modules this site cannot enable: %s', 'gemsecurity' ),
							data.skipped.join( ', ' )
						),
						'warning'
					);
				}
			} catch ( err ) {
				// Surface the server's reason (version mismatch, empty payload,
				// Pro inactive) instead of blaming the file for everything.
				toast( err?.response?.data?.message || __( 'Import failed.', 'gemsecurity' ), 'error' );
			}
			setBusy( '' );
		};
		reader.readAsText( file );
	};

	const runVerify = async () => {
		setVerifying( true );
		try {
			const r = await api.get( 'logs/verify' );
			setVerifyResult( r.data );
		} catch ( e ) { toast( __( 'Verification failed.', 'gemsecurity' ), 'error' ); }
		setVerifying( false );
	};

	const downloadReport = async () => {
		try {
			const r = await api.get( 'logs/report', { params: { days: 30 } } );
			const blob = new Blob( [ JSON.stringify( r.data.report, null, 2 ) ], { type: 'application/json' } );
			const url = URL.createObjectURL( blob );
			const a = document.createElement( 'a' );
			a.href = url;
			a.download = 'gemsecurity-compliance-report.json';
			a.click();
			URL.revokeObjectURL( url );
		} catch ( e ) { toast( __( 'Could not generate report.', 'gemsecurity' ), 'error' ); }
	};

	return (
		<div className="gs-page">
			<Card
				title={ __( 'General settings', 'gemsecurity' ) }
				description={ __( 'Plugin-wide preferences. Firewall, login and admin options live on their own pages.', 'gemsecurity' ) }
			>
				<Field
					label={ __( 'Log retention', 'gemsecurity' ) }
					suffix={ __( 'days', 'gemsecurity' ) }
					description={ __( 'Activity log entries older than this are pruned daily. Set to 0 to keep them forever.', 'gemsecurity' ) }
				>
					<NumberInput min="0" value={ form.logs_retention_days ?? 30 } onChange={ ( e ) => setField( 'logs_retention_days', Number( e.target.value ) ) } />
				</Field>
			</Card>

			<Card
				title={ __( 'Compliance & SIEM', 'gemsecurity' ) }
				description={ __( 'Tamper-evident logging and forwarding for GDPR / PCI / SOC2 evidence.', 'gemsecurity' ) }
				actions={
					<div style={ { display: 'flex', gap: 8 } }>
						<Button variant="secondary" onClick={ runVerify } loading={ verifying }>{ __( 'Verify integrity', 'gemsecurity' ) }</Button>
						<Button variant="secondary" onClick={ downloadReport }>{ __( 'Download report', 'gemsecurity' ) }</Button>
					</div>
				}
			>
				<Toggle
					label={ __( 'Tamper-evident audit log', 'gemsecurity' ) }
					description={ __( 'Hash-chain each log entry so any edit or deletion is detectable.', 'gemsecurity' ) }
					checked={ form.log_hash_chain_enabled }
					onChange={ ( v ) => setField( 'log_hash_chain_enabled', v ) }
				/>
				{ verifyResult && (
					<div className={ `gs-notice gs-notice--${ verifyResult.ok ? 'info' : 'error' }` } style={ { margin: '4px 0 12px' } }>
						{ verifyResult.ok
							? sprintf( /* translators: %d rows */ __( 'Chain intact — %d entries verified.', 'gemsecurity' ), verifyResult.checked )
							: sprintf( /* translators: %d id */ __( 'Tampering detected at log entry #%d.', 'gemsecurity' ), verifyResult.tampered_at ) }
					</div>
				) }
				<Toggle
					label={ __( 'Forward events to SIEM', 'gemsecurity' ) }
					description={ __( 'Stream security events to an external collector and/or system syslog.', 'gemsecurity' ) }
					checked={ form.siem_enabled }
					onChange={ ( v ) => setField( 'siem_enabled', v ) }
				/>
				{ form.siem_enabled && (
					<>
						<SetupGuide id="siem.endpoint" defaultOpen={ ! form.siem_endpoint } />
						<Field label={ __( 'HTTP collector endpoint', 'gemsecurity' ) }>
							<TextInput value={ form.siem_endpoint ?? '' } onChange={ ( e ) => setField( 'siem_endpoint', e.target.value ) } placeholder="https://siem.example.com/ingest" />
						</Field>
						<TestCredentials
							target="siem"
							getValues={ () => ( { url: form.siem_endpoint || '' } ) }
							label={ __( 'Send a test event', 'gemsecurity' ) }
						/>
						<div className="gs-row">
							<Field label={ __( 'Minimum severity', 'gemsecurity' ) }>
								<Select
									value={ form.siem_min_severity || 'warning' }
									onChange={ ( e ) => setField( 'siem_min_severity', e.target.value ) }
									options={ [
										{ value: 'info', label: __( 'Info & above', 'gemsecurity' ) },
										{ value: 'notice', label: __( 'Notice & above', 'gemsecurity' ) },
										{ value: 'warning', label: __( 'Warning & above', 'gemsecurity' ) },
										{ value: 'critical', label: __( 'Critical only', 'gemsecurity' ) },
									] }
								/>
							</Field>
						</div>
						<Toggle label={ __( 'Also write to system syslog', 'gemsecurity' ) } checked={ form.siem_syslog } onChange={ ( v ) => setField( 'siem_syslog', v ) } />
					</>
				) }
			</Card>

			{ /* Alert delivery, the per-module triggers and the scheduled sends
			     moved to their own page — they are the one thing every module
			     feeds into, and they were unfindable as a card down here. */ }
			<Card title={ __( 'Notifications & reports', 'gemsecurity' ) }>
				<div className="gs-alertrow">
					<div>
						<strong>{ __( 'Configured on the Notifications page', 'gemsecurity' ) }</strong>
						<p className="gs-card__desc">{ __( 'The security email and its channels, what each module alerts on, the daily report and the weekly digest.', 'gemsecurity' ) }</p>
					</div>
					<NotificationsLink />
				</div>
			</Card>

			<Card
				title={ __( 'Maintenance & recovery', 'gemsecurity' ) }
				description={ __( 'Emergency lockdown and pre-update backups.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Lockdown mode', 'gemsecurity' ) }
					description={ __( 'Close the public site to everyone except administrators (shows a 503 maintenance page). Login still works.', 'gemsecurity' ) }
					checked={ form.lockdown_enabled }
					onChange={ ( v ) => setField( 'lockdown_enabled', v ) }
				/>
				{ form.lockdown_enabled && (
					<Field label={ __( 'Maintenance message', 'gemsecurity' ) }>
						<ListInput rows={ 2 } value={ form.lockdown_message || '' } onChange={ ( v ) => setField( 'lockdown_message', Array.isArray( v ) ? v.join( ' ' ) : v ) } placeholder={ __( 'We’ll be back shortly.', 'gemsecurity' ) } />
					</Field>
				) }
				{ /* Backups are the separate GemBackup plugin: only offer this when it can run. */ }
				{ ( window.GemSecurityGlobal?.gembackup?.active ) && (
					<Toggle
						label={ __( 'Back up before plugin/theme/core updates', 'gemsecurity' ) }
						description={ __( 'Asks GemBackup to take a backup before any update starts.', 'gemsecurity' ) }
						checked={ form.backup_before_updates }
						onChange={ ( v ) => setField( 'backup_before_updates', v ) }
					/>
				) }
			</Card>

			{ pro && (
				<Card
					title={ <>{ __( 'Settings import / export', 'gemsecurity' ) } { ! pro && <ProBadge /> }</> }
					description={ __( 'Back up or migrate the whole GemSecurity configuration — settings and module activation — as JSON.', 'gemsecurity' ) }
				>
					<Toggle
						label={ __( 'Include API keys and secrets', 'gemsecurity' ) }
						description={ __( 'CAPTCHA and sign-in secrets, alert tokens and webhook URLs. Leave off for files you share; importing a file without them keeps this site\'s own.', 'gemsecurity' ) }
						checked={ includeSecrets }
						onChange={ setIncludeSecrets }
						disabled={ ! pro }
					/>
					<div style={ { display: 'flex', gap: 10 } }>
						<Button variant="secondary" loading={ busy === 'export' } onClick={ exportSettings } disabled={ ! pro }>
							{ __( 'Export settings', 'gemsecurity' ) }
						</Button>
						{ pro ? (
							<label className="gs-btn gs-btn--secondary" style={ { cursor: 'pointer' } }>
								{ busy === 'import' ? __( 'Importing…', 'gemsecurity' ) : __( 'Import settings', 'gemsecurity' ) }
								<input type="file" accept="application/json,.json" onChange={ importSettings } style={ { display: 'none' } } />
							</label>
						) : (
							<Button variant="secondary" disabled>{ __( 'Import settings', 'gemsecurity' ) }</Button>
						) }
					</div>
				</Card>
			) }

		</div>
	);
}
