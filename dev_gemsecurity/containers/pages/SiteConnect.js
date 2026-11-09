import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import { Card, Button, EmptyState } from '@Components/ui/Controls';
import { useToast } from '@Components/ui/Toast';

export default function SiteConnect() {
	const toast = useToast();
	const [ sites, setSites ] = useState( null );
	const [ signup, setSignup ] = useState( true );

	const load = () => api.get( 'connect/sites' ).then( ( r ) => { setSites( r.data.sites ); setSignup( r.data.allow_signup ); } ).catch( () => setSites( [] ) );
	useEffect( () => { load(); }, [] );

	const revoke = async ( id ) => {
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( __( 'Disconnect this site? It will stop seeing this customer\'s products until they connect again.', 'gemsecurity' ) ) ) {
			return;
		}
		try {
			await api.post( 'connect/sites/revoke', { id } );
			toast( __( 'Site disconnected.', 'gemsecurity' ), 'success' );
			load();
		} catch ( e ) {
			toast( __( 'Could not disconnect that site.', 'gemsecurity' ), 'error' );
		}
	};

	const toggleSignup = async () => {
		const r = await api.post( 'connect/signup', { allow: ! signup } );
		setSignup( r.data.allow_signup );
	};

	return (
		<>
		<Card title={ __( 'New customers', 'gemsecurity' ) }>
			<div style={ { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 } }>
				<span>{ signup ? __( 'People without an account can create one on the connection screen.', 'gemsecurity' ) : __( 'Only existing accounts can connect.', 'gemsecurity' ) }</span>
				<Button onClick={ toggleSignup }>{ signup ? __( 'Turn off', 'gemsecurity' ) : __( 'Turn on', 'gemsecurity' ) }</Button>
			</div>
		</Card>
		<Card title={ __( 'Connected sites', 'gemsecurity' ) }>
			{ sites && ! sites.length && <EmptyState title={ __( 'No sites connected yet', 'gemsecurity' ) } /> }
			{ ( sites || [] ).map( ( s ) => (
				<div key={ s.id } style={ { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, padding: '12px 0', borderTop: '1px solid var(--gemsec-border, #e4e7ec)' } }>
					<div>
						<strong>{ s.site }</strong>
						<div>{ s.user } · { new Date( s.created * 1000 ).toLocaleDateString() }</div>
					</div>
					<Button onClick={ () => revoke( s.id ) }>{ __( 'Disconnect', 'gemsecurity' ) }</Button>
				</div>
			) ) }
		</Card>
		</>
	);
}
