import React, { useState, useEffect, useCallback } from 'react';
import { __ } from '@wordpress/i18n';
import backupApi from '@Utils/backupApi';
import { useToast } from '@Components/ui/Toast';
import { Card, Button, Toggle, Field, NumberInput, TextInput, ListInput, Loading } from '@Components/ui/Controls';
import { pageUrl } from '@Utils/nav';

/**
 * Backup configuration.
 *
 * These settings were live in PHP — retention, encryption, exclusions, the
 * failure notice, the pre-restore snapshot, the health threshold — but nothing
 * in the admin ever rendered them, so the only way to change one was to edit
 * the option directly. The REST controller behind them had no consumer at all.
 *
 * Backup keeps its own option store (it is a self-contained subsystem), so this
 * talks to the backup API rather than the plugin-wide settings form.
 */
export default function BackupSettings() {
	const toast = useToast();
	const [ form, setForm ] = useState( null );
	const [ dirty, setDirty ] = useState( false );
	const [ saving, setSaving ] = useState( false );

	const load = useCallback( async () => {
		try {
			// The controller returns the settings object directly.
			const { data } = await backupApi.get( 'settings' );
			setForm( data && typeof data === 'object' ? data : {} );
		} catch ( e ) {
			setForm( {} );
		}
	}, [] );

	useEffect( () => {
		load();
	}, [ load ] );

	const set = ( k, v ) => {
		setForm( ( f ) => ( { ...f, [ k ]: v } ) );
		setDirty( true );
	};

	const save = async () => {
		setSaving( true );
		try {
			await backupApi.put( 'settings', form );
			toast( __( 'Backup settings saved.', 'gemsecurity' ), 'success' );
			setDirty( false );
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not save.', 'gemsecurity' ), 'error' );
		}
		setSaving( false );
	};

	if ( ! form ) {
		return <Loading label={ __( 'Loading backup settings…', 'gemsecurity' ) } />;
	}

	return (
		<Card
			title={ __( 'Backup settings', 'gemsecurity' ) }
			description={ __( 'Retention, encryption, what to leave out, and when to warn that backups have stopped.', 'gemsecurity' ) }
			actions={
				<Button onClick={ save } loading={ saving } disabled={ ! dirty }>
					{ __( 'Save', 'gemsecurity' ) }
				</Button>
			}
		>
			<div className="gs-row">
				<Field
					label={ __( 'Keep this many backups', 'gemsecurity' ) }
					description={ __( 'Older ones are pruned automatically after a successful run.', 'gemsecurity' ) }
				>
					<NumberInput min="1" value={ form.backup_retention ?? 10 } onChange={ ( e ) => set( 'backup_retention', Number( e.target.value ) ) } />
				</Field>
				<Field
					label={ __( 'Backup log retention', 'gemsecurity' ) }
					suffix={ __( 'days', 'gemsecurity' ) }
					description={ __( 'Backup job logs only. The security activity log has its own retention under Settings.', 'gemsecurity' ) }
				>
					<NumberInput min="1" value={ form.backup_logs_retention_days ?? 30 } onChange={ ( e ) => set( 'backup_logs_retention_days', Number( e.target.value ) ) } />
				</Field>
			</div>

			<Toggle
				label={ __( 'Encrypt backup archives', 'gemsecurity' ) }
				description={ __( 'Encrypts each archive before it leaves the server. Without the passphrase a backup cannot be restored — store it somewhere other than this site.', 'gemsecurity' ) }
				checked={ !! form.encryption_enabled }
				onChange={ ( v ) => set( 'encryption_enabled', v ) }
			/>
			{ form.encryption_enabled && (
				<Field label={ __( 'Encryption passphrase', 'gemsecurity' ) }>
					<TextInput
						type="password"
						value={ form.encryption_passphrase ?? '' }
						onChange={ ( e ) => set( 'encryption_passphrase', e.target.value ) }
						autoComplete="new-password"
					/>
				</Field>
			) }

			<Field
				label={ __( 'Exclude paths', 'gemsecurity' ) }
				description={ __( 'One path per line, relative to the WordPress root. Caches and upgrade temp directories are excluded by default because they rebuild themselves.', 'gemsecurity' ) }
			>
				<ListInput
					rows={ 3 }
					value={ form.exclude_paths || '' }
					onChange={ ( v ) => set( 'exclude_paths', Array.isArray( v ) ? v.join( '\n' ) : v ) }
					placeholder={ 'wp-content/cache\nwp-content/uploads/cache' }
				/>
			</Field>

			<Toggle
				label={ __( 'Skip transient & cache tables', 'gemsecurity' ) }
				description={ __( 'Leaves out tables that only hold regenerable data, which keeps database dumps much smaller.', 'gemsecurity' ) }
				checked={ !! form.exclude_tables_smart }
				onChange={ ( v ) => set( 'exclude_tables_smart', v ) }
			/>
			<Field
				label={ __( 'Also exclude these tables', 'gemsecurity' ) }
				description={ __( 'One table name per line.', 'gemsecurity' ) }
			>
				<ListInput
					rows={ 2 }
					value={ form.exclude_tables_extra || '' }
					onChange={ ( v ) => set( 'exclude_tables_extra', Array.isArray( v ) ? v.join( '\n' ) : v ) }
				/>
			</Field>

			<Toggle
				label={ __( 'Snapshot before restoring', 'gemsecurity' ) }
				description={ __( 'Takes a safety copy first, so a restore that turns out to be the wrong one can itself be undone.', 'gemsecurity' ) }
				checked={ !! form.restore_safety_snapshot }
				onChange={ ( v ) => set( 'restore_safety_snapshot', v ) }
			/>

			<Toggle
				label={ __( 'Notify on backup failures', 'gemsecurity' ) }
				description={ __( 'Emails the site’s security address when a backup fails, and again when backups have gone quiet for too long. A silent backup failure is the worst outcome a backup can have.', 'gemsecurity' ) }
				checked={ !! form.notify_on_failure }
				onChange={ ( v ) => set( 'notify_on_failure', v ) }
			/>
			{ form.notify_on_failure && (
				<Field
					label={ __( 'Warn after this long without a successful backup', 'gemsecurity' ) }
					suffix={ __( 'days', 'gemsecurity' ) }
				>
					<NumberInput min="1" value={ form.health_alert_days ?? 7 } onChange={ ( e ) => set( 'health_alert_days', Number( e.target.value ) ) } />
				</Field>
			) }
			<p className="gs-card__desc">
				{ __( 'Backup notices go to the security email and webhook configured under', 'gemsecurity' ) }{ ' ' }
				<a href={ pageUrl( 'gemsecurity-notifications' ) }>{ __( 'the Notifications page', 'gemsecurity' ) }</a>.
			</p>
		</Card>
	);
}
