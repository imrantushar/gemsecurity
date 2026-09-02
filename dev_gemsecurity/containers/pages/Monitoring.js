import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Button, Badge } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';

const KEYS = [ 'monitoring_enabled' ];

function Row( { label, ok, value, tone } ) {
	return (
		<div className="gs-admins__row">
			<span>{ label }</span>
			<span className="gs-admins__trailing">
				{ value && <span className="gs-muted">{ value }</span> }
				<Badge tone={ tone || ( ok ? 'success' : 'danger' ) }>{ ok ? __( 'OK', 'gemsecurity' ) : __( 'Attention', 'gemsecurity' ) }</Badge>
			</span>
		</div>
	);
}

export default function Monitoring() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const [ data, setData ] = useState( null );
	const [ busy, setBusy ] = useState( false );

	const load = ( fresh ) => {
		setBusy( true );
		api.get( 'monitoring', { params: fresh ? { fresh: 1 } : {} } ).then( ( r ) => setData( r.data.data ) ).catch( () => setData( null ) ).finally( () => setBusy( false ) );
	};
	useEffect( () => { load( false ); }, [] );

	const d = data || {};
	const ssl = d.ssl || {};
	const dns = d.dns || {};
	const email = d.email || {};

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Monitoring', 'gemsecurity' ) }
				description={ __( 'Watches for the early-warning signs of trouble outside the request path: certificate expiry, DNS changes, downtime and email-auth gaps.', 'gemsecurity' ) }
				actions={ <Button variant="secondary" onClick={ () => load( true ) } loading={ busy }>{ __( 'Run checks now', 'gemsecurity' ) }</Button> }
			>
				<Toggle
					label={ __( 'Enable daily monitoring & alerts', 'gemsecurity' ) }
					checked={ form.monitoring_enabled }
					onChange={ ( v ) => setField( 'monitoring_enabled', v ) }
				/>
				{ form.monitoring_enabled && (
					<p className="gs-card__desc">
						{ __( 'Warnings go to the security email on the Notifications page, along with every other notification the plugin sends.', 'gemsecurity' ) }
					</p>
				) }
				<div className="gs-savebar gs-savebar--inline">
					<Button variant="secondary" onClick={ () => save() } loading={ saving } disabled={ ! dirty }>{ __( 'Save', 'gemsecurity' ) }</Button>
				</div>
			</Card>

			<Card title={ __( 'Status', 'gemsecurity' ) } description={ data ? `${ __( 'Last checked', 'gemsecurity' ) } ${ d.checked }` : '' }>
				{ ! data ? (
					<p className="gs-muted">{ __( 'Loading…', 'gemsecurity' ) }</p>
				) : (
					<ul className="gs-admins">
						<Row label={ __( 'Site reachable', 'gemsecurity' ) } ok={ d.health && d.health.up } value={ d.health ? `HTTP ${ d.health.code }` : '' } />
						<Row
							label={ __( 'TLS certificate', 'gemsecurity' ) }
							ok={ ssl.valid && ( ssl.days_left === null || ssl.days_left > 14 ) }
							tone={ ssl.valid ? ( ssl.days_left !== null && ssl.days_left <= 14 ? 'warning' : 'success' ) : 'danger' }
							value={ ssl.days_left !== undefined && ssl.days_left !== null ? `${ ssl.days_left } ${ __( 'days left', 'gemsecurity' ) }` : ( ssl.note || '' ) }
						/>
						<Row label={ __( 'DNS A record', 'gemsecurity' ) } ok={ ! dns.changed } tone={ dns.changed ? 'danger' : 'success' } value={ dns.ip || '' } />
						<Row label={ __( 'SPF record', 'gemsecurity' ) } ok={ !! email.spf } tone={ email.spf ? 'success' : 'warning' } />
						<Row label={ __( 'DMARC record', 'gemsecurity' ) } ok={ !! email.dmarc } tone={ email.dmarc ? 'success' : 'warning' } value={ email.dmarc_policy ? `p=${ email.dmarc_policy }` : '' } />
					</ul>
				) }
				<p className="gs-muted" style={ { marginTop: 10, fontSize: 12 } }>
					<Icon name="alert" size={ 13 } /> { __( 'DKIM is selector-specific and can’t be auto-detected; verify it with your email provider.', 'gemsecurity' ) }
				</p>
			</Card>
		</div>
	);
}
