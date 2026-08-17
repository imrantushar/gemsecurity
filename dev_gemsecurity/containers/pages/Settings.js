import React, { useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Field, Toggle, NumberInput, TextInput, Select, ListInput, Button, Badge } from '@Components/ui/Controls';
import SetupGuide from '@Components/ui/SetupGuide';
import { useToast } from '@Components/ui/Toast';
import BackupSchedule from '@Containers/pages/BackupSchedule';
import BackupStorage from '@Containers/pages/BackupStorage';

const KEYS = [
	'logs_retention_days',
	// Compliance / SIEM.
	'log_hash_chain_enabled',
	'siem_enabled',
	'siem_endpoint',
	'siem_syslog',
	'siem_min_severity',
	// Alerts + digest.
	'alerts_enabled',
	'alert_min_severity',
	'alert_to_email',
	'alert_slack_webhook',
	'alert_telegram_token',
	'alert_telegram_chat',
	'alert_webhook_url',
	'digest_enabled',
	// Lockdown + backup.
	'lockdown_enabled',
	'lockdown_message',
	'backup_before_updates',
];

export default function Settings() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const toast = useToast();
	const [ verifyResult, setVerifyResult ] = useState( null );
	const [ verifying, setVerifying ] = useState( false );

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

			<Card
				title={ __( 'Alerts & notifications', 'gemsecurity' ) }
				description={ __( 'Get notified about important security events beyond email.', 'gemsecurity' ) }
			>
				<Toggle label={ __( 'Enable real-time alerts', 'gemsecurity' ) } checked={ form.alerts_enabled } onChange={ ( v ) => setField( 'alerts_enabled', v ) } />
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
							<Field label={ __( 'Alert email (optional)', 'gemsecurity' ) }>
								<TextInput type="email" value={ form.alert_to_email ?? '' } onChange={ ( e ) => setField( 'alert_to_email', e.target.value ) } placeholder={ __( 'Defaults to admin email', 'gemsecurity' ) } />
							</Field>
						</div>
						<SetupGuide id="alerts.slack" />
						<Field label={ __( 'Slack incoming webhook URL', 'gemsecurity' ) }>
							<TextInput value={ form.alert_slack_webhook ?? '' } onChange={ ( e ) => setField( 'alert_slack_webhook', e.target.value ) } placeholder="https://hooks.slack.com/services/…" />
						</Field>
						<SetupGuide id="alerts.telegram" />
						<div className="gs-row">
							<Field label={ __( 'Telegram bot token', 'gemsecurity' ) }>
								<TextInput value={ form.alert_telegram_token ?? '' } onChange={ ( e ) => setField( 'alert_telegram_token', e.target.value ) } />
							</Field>
							<Field label={ __( 'Telegram chat ID', 'gemsecurity' ) }>
								<TextInput value={ form.alert_telegram_chat ?? '' } onChange={ ( e ) => setField( 'alert_telegram_chat', e.target.value ) } />
							</Field>
						</div>
						<SetupGuide id="alerts.webhook" />
						<Field label={ __( 'Generic webhook URL', 'gemsecurity' ) }>
							<TextInput value={ form.alert_webhook_url ?? '' } onChange={ ( e ) => setField( 'alert_webhook_url', e.target.value ) } placeholder="https://example.com/webhook" />
						</Field>
					</>
				) }
				<Toggle label={ __( 'Send a weekly security digest', 'gemsecurity' ) } description={ __( 'A summary email (and alert) every week.', 'gemsecurity' ) } checked={ form.digest_enabled } onChange={ ( v ) => setField( 'digest_enabled', v ) } />
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
				<Toggle
					label={ __( 'Back up before plugin/theme/core updates', 'gemsecurity' ) }
					description={ __( 'Triggers GemBackup (if active) before any update runs.', 'gemsecurity' ) }
					checked={ form.backup_before_updates }
					onChange={ ( v ) => setField( 'backup_before_updates', v ) }
				/>
			</Card>

			<div className="gs-savebar">
				<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>
					{ __( 'Save changes', 'gemsecurity' ) }
				</Button>
			</div>

			{ /* Backup configuration — schedules and storage destinations. */ }
			<BackupSchedule />
			<BackupStorage />
		</div>
	);
}
