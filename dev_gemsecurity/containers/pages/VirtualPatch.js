import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Badge, EmptyState, Button } from '@Components/ui/Controls';

const KEYS = [ 'virtual_patch_enabled' ];

export default function VirtualPatch() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const [ data, setData ] = useState( null );

	useEffect( () => {
		api.get( 'vpatch' ).then( ( r ) => setData( r.data ) ).catch( () => setData( { count: 0, total: 0, items: [] } ) );
	}, [] );

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Virtual patching', 'gemsecurity' ) }
				description={ __( 'Blocks exploit attempts against known vulnerabilities in your installed plugins and themes — even when no update exists yet. Only rules that match this site’s software are enforced.', 'gemsecurity' ) }
				actions={ data ? <Badge tone={ data.count ? 'success' : 'info' }>{ `${ data.count } ${ __( 'active mitigations', 'gemsecurity' ) }` }</Badge> : null }
			>
				<Toggle
					label={ __( 'Enable virtual patching', 'gemsecurity' ) }
					checked={ form.virtual_patch_enabled }
					onChange={ ( v ) => setField( 'virtual_patch_enabled', v ) }
				/>
				<div className="gs-savebar gs-savebar--inline">
					<Button variant="secondary" onClick={ () => save() } loading={ saving } disabled={ ! dirty }>
						{ __( 'Save', 'gemsecurity' ) }
					</Button>
				</div>
			</Card>

			<Card title={ __( 'Active mitigations', 'gemsecurity' ) }>
				{ ! data ? (
					<p className="gs-muted">{ __( 'Loading…', 'gemsecurity' ) }</p>
				) : data.items.length === 0 ? (
					<EmptyState
						title={ __( 'Nothing to mitigate right now', 'gemsecurity' ) }
						description={ __( 'No installed plugin or theme matches a known-vulnerability rule. New rules arrive automatically with the Pro feed.', 'gemsecurity' ) }
					/>
				) : (
					<table className="gs-table">
						<thead><tr>
							<th>{ __( 'CVE / Rule', 'gemsecurity' ) }</th>
							<th>{ __( 'Protects against', 'gemsecurity' ) }</th>
							<th>{ __( 'Target', 'gemsecurity' ) }</th>
							<th>{ __( 'Severity', 'gemsecurity' ) }</th>
						</tr></thead>
						<tbody>
							{ data.items.map( ( it ) => (
								<tr key={ it.id }>
									<td><code>{ it.cve || it.id }</code></td>
									<td>{ it.title }</td>
									<td className="gs-nowrap">
										{ it.plugin === '*'
											? __( 'all requests', 'gemsecurity' )
											: `${ it.plugin }${ it.installed_version ? ' @ ' + it.installed_version : '' }` }
									</td>
									<td><Badge tone={ it.severity === 'critical' ? 'danger' : 'warning' }>{ it.severity }</Badge></td>
								</tr>
							) ) }
						</tbody>
					</table>
				) }
			</Card>
		</div>
	);
}
