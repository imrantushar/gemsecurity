import React from 'react';
import { __ } from '@wordpress/i18n';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Field, Toggle, NumberInput, TextInput, Select, ListInput, Button } from '@Components/ui/Controls';
import BackupSchedule from '@Containers/pages/BackupSchedule';
import BackupStorage from '@Containers/pages/BackupStorage';

const KEYS = [
	'logs_retention_days',
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
						<Field label={ __( 'Slack incoming webhook URL', 'gemsecurity' ) }>
							<TextInput value={ form.alert_slack_webhook ?? '' } onChange={ ( e ) => setField( 'alert_slack_webhook', e.target.value ) } placeholder="https://hooks.slack.com/services/…" />
						</Field>
						<div className="gs-row">
							<Field label={ __( 'Telegram bot token', 'gemsecurity' ) }>
								<TextInput value={ form.alert_telegram_token ?? '' } onChange={ ( e ) => setField( 'alert_telegram_token', e.target.value ) } />
							</Field>
							<Field label={ __( 'Telegram chat ID', 'gemsecurity' ) }>
								<TextInput value={ form.alert_telegram_chat ?? '' } onChange={ ( e ) => setField( 'alert_telegram_chat', e.target.value ) } />
							</Field>
						</div>
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
