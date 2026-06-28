import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Button, Badge, EmptyState } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';
import { useToast } from '@Components/ui/Toast';

export default function Scanner() {
	const { form, setField, save, saving, dirty } = useSettingsForm( [ 'scanner_auto_scan' ] );
	const toast = useToast();
	const [ result, setResult ] = useState( null );
	const [ running, setRunning ] = useState( false );

	useEffect( () => {
		api.get( 'scan' ).then( ( r ) => setResult( r.data.result ) ).catch( () => {} );
	}, [] );

	const runScan = async () => {
		setRunning( true );
		try {
			const r = await api.post( 'scan' );
			setResult( r.data.result );
			toast( __( 'Scan complete.', 'gemsecurity' ), r.data.result.issue_count ? 'warning' : 'success' );
		} catch ( e ) {
			toast( __( 'Scan failed.', 'gemsecurity' ), 'error' );
		}
		setRunning( false );
	};

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Malware & integrity scanner', 'gemsecurity' ) }
				description={ __( 'Checks WordPress core files against official checksums and looks for suspicious PHP in your uploads folder.', 'gemsecurity' ) }
				actions={
					<Button onClick={ runScan } loading={ running }>
						<Icon name="radar" size={ 16 } /> { __( 'Run scan now', 'gemsecurity' ) }
					</Button>
				}
			>
				<Toggle
					label={ __( 'Run a scan automatically every day', 'gemsecurity' ) }
					checked={ form.scanner_auto_scan }
					onChange={ ( v ) => setField( 'scanner_auto_scan', v ) }
				/>
				{ dirty && (
					<div className="gs-savebar gs-savebar--inline">
						<Button variant="secondary" onClick={ () => save() } loading={ saving }>
							{ __( 'Save', 'gemsecurity' ) }
						</Button>
					</div>
				) }
			</Card>

			{ ! result ? (
				<Card>
					<EmptyState
						title={ __( 'No scan yet', 'gemsecurity' ) }
						description={ __( 'Run your first scan to check this site for integrity issues.', 'gemsecurity' ) }
					/>
				</Card>
			) : (
				<>
					<Card>
						<div className="gs-scan-summary">
							<Badge tone={ result.status === 'clean' ? 'success' : 'danger' }>
								{ result.status === 'clean' ? __( 'No issues found', 'gemsecurity' ) : `${ result.issue_count } ${ __( 'issue(s)', 'gemsecurity' ) }` }
							</Badge>
							<span className="gs-muted">
								{ __( 'WordPress', 'gemsecurity' ) } { result.wp_version } · { __( 'scanned', 'gemsecurity' ) } { result.scanned_at }
							</span>
						</div>
					</Card>

					<Card title={ __( 'Core file integrity', 'gemsecurity' ) }>
						{ result.core_issues.length === 0 ? (
							<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'All core files match the official checksums.', 'gemsecurity' ) }</p>
						) : (
							<table className="gs-table">
								<thead><tr><th>{ __( 'File', 'gemsecurity' ) }</th><th>{ __( 'Issue', 'gemsecurity' ) }</th></tr></thead>
								<tbody>
									{ result.core_issues.map( ( c, i ) => (
										<tr key={ i }>
											<td><code>{ c.file }</code></td>
											<td><Badge tone={ c.issue === 'missing' ? 'warning' : 'danger' }>{ c.issue }</Badge></td>
										</tr>
									) ) }
								</tbody>
							</table>
						) }
					</Card>

					<Card title={ __( 'Suspicious files', 'gemsecurity' ) }>
						{ result.suspicious.length === 0 ? (
							<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'No suspicious files detected.', 'gemsecurity' ) }</p>
						) : (
							<table className="gs-table">
								<thead><tr><th>{ __( 'File', 'gemsecurity' ) }</th><th>{ __( 'Reason', 'gemsecurity' ) }</th><th>{ __( 'Severity', 'gemsecurity' ) }</th></tr></thead>
								<tbody>
									{ result.suspicious.map( ( s, i ) => (
										<tr key={ i }>
											<td><code>{ s.file }</code></td>
											<td>{ s.reason }</td>
											<td><Badge tone={ s.severity === 'critical' ? 'danger' : 'warning' }>{ s.severity }</Badge></td>
										</tr>
									) ) }
								</tbody>
							</table>
						) }
					</Card>
				</>
			) }
		</div>
	);
}
