import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, ListInput, Button, Badge, EmptyState } from '@Components/ui/Controls';
import { useToast } from '@Components/ui/Toast';

const KEYS = [ 'payment_integrity_enabled', 'payment_page_ids' ];

export default function PaymentIntegrity() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const toast = useToast();
	const [ data, setData ] = useState( null );
	const [ busy, setBusy ] = useState( false );

	const load = () => api.get( 'payment-scripts' ).then( ( r ) => setData( r.data ) ).catch( () => setData( { inventory: [], alerts: [], has_baseline: false } ) );
	useEffect( () => { load(); }, [] );

	const authorize = async () => {
		setBusy( true );
		try {
			await api.post( 'payment-scripts/authorize' );
			toast( __( 'Current scripts authorised as the baseline.', 'gemsecurity' ), 'success' );
			load();
		} catch ( e ) { toast( __( 'Failed.', 'gemsecurity' ), 'error' ); }
		setBusy( false );
	};

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Payment-page integrity', 'gemsecurity' ) }
				description={ __( 'Detects unauthorised scripts injected into your checkout — the Magecart card-skimming pattern — and satisfies PCI-DSS 4.0 §6.4.3 / §11.6.1.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Monitor payment-page scripts', 'gemsecurity' ) }
					description={ __( 'Adds a lightweight collector to checkout pages that reports which scripts the browser loaded.', 'gemsecurity' ) }
					checked={ form.payment_integrity_enabled }
					onChange={ ( v ) => setField( 'payment_integrity_enabled', v ) }
				/>
				{ form.payment_integrity_enabled && (
					<Field
						label={ __( 'Extra payment page IDs', 'gemsecurity' ) }
						description={ __( 'WooCommerce checkout is detected automatically. Add other checkout page IDs here (one per line).', 'gemsecurity' ) }
					>
						<ListInput value={ form.payment_page_ids || [] } onChange={ ( v ) => setField( 'payment_page_ids', v ) } placeholder={ '42\n108' } />
					</Field>
				) }
			</Card>

			{ data && data.alerts && data.alerts.length > 0 && (
				<Card title={ __( 'Unauthorised scripts detected', 'gemsecurity' ) }>
					<div className="gs-notice gs-notice--error" style={ { marginBottom: 12 } }>
						{ __( 'New scripts appeared on your payment page that are not in the authorised baseline. Investigate immediately.', 'gemsecurity' ) }
					</div>
					<table className="gs-table">
						<thead><tr><th>{ __( 'Script', 'gemsecurity' ) }</th><th>{ __( 'Page', 'gemsecurity' ) }</th><th>{ __( 'When', 'gemsecurity' ) }</th></tr></thead>
						<tbody>
							{ data.alerts.map( ( a, i ) => (
								<tr key={ i }><td><code>{ a.src }</code></td><td className="gs-nowrap">{ a.page }</td><td className="gs-nowrap">{ a.time }</td></tr>
							) ) }
						</tbody>
					</table>
				</Card>
			) }

			<Card
				title={ __( 'Authorised script inventory', 'gemsecurity' ) }
				description={ data && data.last_seen ? __( 'Latest scripts seen on a payment page. Authorise them to set your baseline.', 'gemsecurity' ) : __( 'Visit your checkout page once with monitoring on to capture the script inventory.', 'gemsecurity' ) }
				actions={ data && data.inventory.length > 0 ? <Button onClick={ authorize } loading={ busy }>{ __( 'Authorise current', 'gemsecurity' ) }</Button> : null }
			>
				{ ! data ? (
					<p className="gs-muted">{ __( 'Loading…', 'gemsecurity' ) }</p>
				) : data.inventory.length === 0 ? (
					<EmptyState title={ __( 'No inventory yet', 'gemsecurity' ) } description={ __( 'Load your checkout page once to populate this.', 'gemsecurity' ) } />
				) : (
					<>
						{ data.seen_page && (
							<p className="gs-muted" style={ { marginTop: 0 } }>
								{ __( 'Captured from:', 'gemsecurity' ) } <code>{ data.seen_page }</code>{ ' — ' }
								{ __( 'check this is really your checkout page before authorising.', 'gemsecurity' ) }
							</p>
						) }
						<table className="gs-table">
							<thead><tr><th>{ __( 'Script', 'gemsecurity' ) }</th><th>{ __( 'Status', 'gemsecurity' ) }</th></tr></thead>
							<tbody>
								{ data.inventory.map( ( it, i ) => (
									<tr key={ i }>
										<td><code>{ it.src }</code></td>
										<td><Badge tone={ it.authorised ? 'success' : ( data.has_baseline ? 'danger' : 'info' ) }>{ it.authorised ? __( 'authorised', 'gemsecurity' ) : ( data.has_baseline ? __( 'unauthorised', 'gemsecurity' ) : __( 'pending', 'gemsecurity' ) ) }</Badge></td>
									</tr>
								) ) }
							</tbody>
						</table>
					</>
				) }
			</Card>
		</div>
	);
}
