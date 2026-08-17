import React, { useState, useEffect, useCallback } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import { useDispatch } from 'react-redux';
import useSettingsForm from '@Utils/useSettingsForm';
import { fetchSettings } from '@Redux/settingsSlice';
import { useToast } from '@Components/ui/Toast';
import api from '@Utils/api';
import { setModules } from '@Utils/nav';
import { Card, Toggle, Field, ListInput, Button, Badge } from '@Components/ui/Controls';

const KEYS = [
	// Hardening pack.
	'admin_ip_allowlist_enabled',
	'admin_ip_allowlist',
	'block_sensitive_files_enabled',
	'block_php_in_uploads',
	'force_https_enabled',
	// File baseline.
	'file_baseline_enabled',
	'file_baseline_scopes',
	// Auto-update.
	'auto_update_vulnerable_enabled',
	'auto_update_all_plugins',
	'auto_update_all_themes',
];

const SCOPES = [ 'core', 'plugins', 'themes' ];

export default function ProTools() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const dispatch = useDispatch();
	const toast = useToast();

	const [ baseline, setBaseline ] = useState( null );
	const [ diff, setDiff ] = useState( null );
	const [ busy, setBusy ] = useState( '' );

	const loadBaseline = useCallback( async () => {
		try {
			const { data } = await api.get( 'pro/file-baseline' );
			setBaseline( data.status );
		} catch ( e ) {
			/* gated or unavailable */
		}
	}, [] );

	useEffect( () => {
		loadBaseline();
	}, [ loadBaseline ] );

	const scopes = Array.isArray( form.file_baseline_scopes ) ? form.file_baseline_scopes : [];
	const toggleScope = ( scope, on ) => {
		const next = on ? [ ...new Set( [ ...scopes, scope ] ) ] : scopes.filter( ( s ) => s !== scope );
		setField( 'file_baseline_scopes', next );
	};

	/* ----------------------------- Import / Export ----------------------------- */

	const exportSettings = async () => {
		setBusy( 'export' );
		try {
			const { data } = await api.get( 'pro/settings/export' );
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
			toast( __( 'Settings exported.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast(
				e?.response?.data?.message || __( 'Export failed.', 'gemsecurity' ),
				'error'
			);
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
				toast(
					err?.response?.data?.message ||
						__( 'Import failed.', 'gemsecurity' ),
					'error'
				);
			}
			setBusy( '' );
		};
		reader.readAsText( file );
	};

	/* ----------------------------- File baseline ----------------------------- */

	const buildBaseline = async () => {
		setBusy( 'build' );
		try {
			const { data } = await api.post( 'pro/file-baseline/build', {} );
			setBaseline( data.status );
			setDiff( null );
			toast( __( 'Baseline created.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( __( 'Could not build baseline.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const runDiff = async () => {
		setBusy( 'diff' );
		try {
			const { data } = await api.get( 'pro/file-baseline/diff' );
			setDiff( data.diff );
		} catch ( e ) {
			toast( __( 'Could not run diff.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	return (
		<div className="gs-page">
			{ /* ---------------- Hardening pack ---------------- */ }
			<Card
				title={ __( 'Hardening pack', 'gemsecurity' ) }
				description={ __( 'Extra request-level protections.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Restrict wp-admin by IP', 'gemsecurity' ) }
					description={ __( 'Only the IPs below may reach wp-admin. An empty list never locks anyone out.', 'gemsecurity' ) }
					checked={ form.admin_ip_allowlist_enabled }
					onChange={ ( v ) => setField( 'admin_ip_allowlist_enabled', v ) }
				/>
				{ form.admin_ip_allowlist_enabled && (
					<Field
						label={ __( 'Allowed IPs', 'gemsecurity' ) }
						description={ __( 'One IP or CIDR range per line.', 'gemsecurity' ) }
					>
						<ListInput
							value={ form.admin_ip_allowlist }
							onChange={ ( v ) => setField( 'admin_ip_allowlist', v ) }
							placeholder={ '203.0.113.10\n198.51.100.0/24' }
						/>
					</Field>
				) }
				<Toggle
					label={ __( 'Block sensitive files', 'gemsecurity' ) }
					description={ __( 'Denies readme.html, license.txt, *.sql, *.bak, debug.log, dotfiles, etc.', 'gemsecurity' ) }
					checked={ form.block_sensitive_files_enabled }
					onChange={ ( v ) => setField( 'block_sensitive_files_enabled', v ) }
				/>
				<Toggle
					label={ __( 'Block PHP execution in /uploads', 'gemsecurity' ) }
					description={ __( 'Stops uploaded PHP shells from running.', 'gemsecurity' ) }
					checked={ form.block_php_in_uploads }
					onChange={ ( v ) => setField( 'block_php_in_uploads', v ) }
				/>
				<Toggle
					label={ __( 'Force HTTPS', 'gemsecurity' ) }
					description={ __( 'Redirect HTTP to HTTPS and upgrade insecure requests.', 'gemsecurity' ) }
					checked={ form.force_https_enabled }
					onChange={ ( v ) => setField( 'force_https_enabled', v ) }
				/>
			</Card>

			{ /* ---------------- Auto-update enforcement ---------------- */ }
			<Card
				title={ __( 'Auto-update enforcement', 'gemsecurity' ) }
				description={ __( 'Close the gap between disclosure and patching.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Auto-update vulnerable plugins/themes', 'gemsecurity' ) }
					description={ __( 'Automatically update any item the vulnerability scanner has flagged.', 'gemsecurity' ) }
					checked={ form.auto_update_vulnerable_enabled }
					onChange={ ( v ) => setField( 'auto_update_vulnerable_enabled', v ) }
				/>
				<Toggle
					label={ __( 'Auto-update all plugins', 'gemsecurity' ) }
					checked={ form.auto_update_all_plugins }
					onChange={ ( v ) => setField( 'auto_update_all_plugins', v ) }
				/>
				<Toggle
					label={ __( 'Auto-update all themes', 'gemsecurity' ) }
					checked={ form.auto_update_all_themes }
					onChange={ ( v ) => setField( 'auto_update_all_themes', v ) }
				/>
			</Card>

			{ /* ---------------- File-change baseline ---------------- */ }
			<Card
				title={ __( 'File-change baseline', 'gemsecurity' ) }
				description={ __( 'Snapshot file hashes, then detect added, modified or removed files.', 'gemsecurity' ) }
				actions={
					<>
						<Button variant="secondary" loading={ busy === 'diff' } onClick={ runDiff } disabled={ ! baseline || ! baseline.has_baseline }>
							{ __( 'Run diff', 'gemsecurity' ) }
						</Button>
						<Button loading={ busy === 'build' } onClick={ buildBaseline }>
							{ baseline && baseline.has_baseline ? __( 'Rebuild baseline', 'gemsecurity' ) : __( 'Create baseline', 'gemsecurity' ) }
						</Button>
					</>
				}
			>
				<Toggle
					label={ __( 'Daily drift alerts', 'gemsecurity' ) }
					description={ __( 'Run a diff each day and log/alert on any change.', 'gemsecurity' ) }
					checked={ form.file_baseline_enabled }
					onChange={ ( v ) => setField( 'file_baseline_enabled', v ) }
				/>
				<Field label={ __( 'Scopes to track', 'gemsecurity' ) }>
					<div style={ { display: 'flex', gap: 18 } }>
						{ SCOPES.map( ( s ) => (
							<label key={ s } style={ { display: 'flex', alignItems: 'center', gap: 6, textTransform: 'capitalize' } }>
								<input type="checkbox" checked={ scopes.includes( s ) } onChange={ ( e ) => toggleScope( s, e.target.checked ) } />
								{ s }
							</label>
						) ) }
					</div>
				</Field>

				{ baseline && baseline.has_baseline && (
					<p className="gs-card__desc">
						{ __( 'Baseline:', 'gemsecurity' ) } { baseline.file_count } { __( 'files', 'gemsecurity' ) }
						{ baseline.created_at ? ` · ${ baseline.created_at }` : '' }
					</p>
				) }

				{ diff && (
					<div style={ { marginTop: 12 } }>
						<div style={ { display: 'flex', gap: 8, marginBottom: 10 } }>
							<Badge tone="success">{ diff.added ? diff.added.length : 0 } { __( 'added', 'gemsecurity' ) }</Badge>
							<Badge tone="warning">{ diff.modified ? diff.modified.length : 0 } { __( 'modified', 'gemsecurity' ) }</Badge>
							<Badge tone="error">{ diff.removed ? diff.removed.length : 0 } { __( 'removed', 'gemsecurity' ) }</Badge>
						</div>
						{ diff.changed === 0 && <p className="gs-card__desc">{ __( 'No changes since the baseline.', 'gemsecurity' ) }</p> }
						{ [ 'added', 'modified', 'removed' ].map( ( k ) =>
							diff[ k ] && diff[ k ].length ? (
								<details key={ k } style={ { marginTop: 6 } }>
									<summary style={ { cursor: 'pointer', textTransform: 'capitalize' } }>{ k } ({ diff[ k ].length })</summary>
									<ul style={ { margin: '6px 0 0', maxHeight: 200, overflow: 'auto', fontFamily: 'monospace', fontSize: 12 } }>
										{ diff[ k ].slice( 0, 200 ).map( ( f ) => <li key={ f }>{ f }</li> ) }
									</ul>
								</details>
							) : null
						) }
					</div>
				) }
			</Card>

			{ /* ---------------- Import / Export ---------------- */ }
			<Card
				title={ __( 'Settings import / export', 'gemsecurity' ) }
				description={ __( 'Back up or migrate the GemSecurity configuration as JSON.', 'gemsecurity' ) }
			>
				<div style={ { display: 'flex', gap: 10 } }>
					<Button variant="secondary" loading={ busy === 'export' } onClick={ exportSettings }>
						{ __( 'Export settings', 'gemsecurity' ) }
					</Button>
					<label className="gs-btn gs-btn--secondary" style={ { cursor: 'pointer' } }>
						{ busy === 'import' ? __( 'Importing…', 'gemsecurity' ) : __( 'Import settings', 'gemsecurity' ) }
						<input type="file" accept="application/json,.json" onChange={ importSettings } style={ { display: 'none' } } />
					</label>
				</div>
			</Card>

			<div className="gs-savebar">
				<Button loading={ saving } disabled={ ! dirty } onClick={ () => save() }>
					{ __( 'Save changes', 'gemsecurity' ) }
				</Button>
			</div>
		</div>
	);
}
