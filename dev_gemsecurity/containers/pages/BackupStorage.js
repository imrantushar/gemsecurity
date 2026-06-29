import React, { useState, useEffect, useCallback } from 'react';
import { __ } from '@wordpress/i18n';
import backupApi from '@Utils/backupApi';
import { useToast } from '@Components/ui/Toast';
import { Card, Button, Badge, Loading } from '@Components/ui/Controls';
import { isPro, ProBadge, upgradeUrl } from '@Components/ui/Pro';

const FREE_DRIVERS = [ 'local' ];

export default function BackupStorage() {
	const toast = useToast();
	const pro = isPro();
	const [ drivers, setDrivers ] = useState( null );
	const [ busy, setBusy ] = useState( '' );

	const load = useCallback( async () => {
		try {
			const { data } = await backupApi.get( 'storage' );
			// Response is keyed by driver; normalize to an array.
			const list = Array.isArray( data ) ? data : Object.values( data );
			setDrivers( list );
		} catch ( e ) {
			setDrivers( [] );
		}
	}, [] );

	useEffect( () => {
		load();
	}, [ load ] );

	const toggle = async ( d ) => {
		if ( ! FREE_DRIVERS.includes( d.key ) && ! pro ) {
			return;
		}
		setBusy( d.key );
		try {
			await backupApi.post( `storage/${ d.key }`, { enabled: ! d.enabled } );
			await load();
		} catch ( e ) {
			const msg = e?.response?.data?.message;
			toast( msg || __( 'Could not update storage.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	if ( drivers === null ) {
		return <div className="gs-page"><Loading /></div>;
	}

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Storage destinations', 'gemsecurity' ) }
				description={ __( 'Local storage is included. Cloud destinations are available in Pro.', 'gemsecurity' ) }
			>
				<table className="gs-table">
					<tbody>
						{ drivers.map( ( d ) => {
							const free = FREE_DRIVERS.includes( d.key );
							const locked = ! free && ! pro;
							return (
								<tr key={ d.key }>
									<td>
										<strong style={ { textTransform: 'capitalize' } }>{ d.label || d.key }</strong>
										{ locked && <ProBadge /> }
									</td>
									<td>
										{ d.connected
											? <Badge tone="success">{ __( 'Connected', 'gemsecurity' ) }</Badge>
											: <Badge tone="info">{ free ? __( 'Ready', 'gemsecurity' ) : __( 'Not configured', 'gemsecurity' ) }</Badge> }
										{ d.enabled && ' ' }
										{ d.enabled && <Badge tone="success">{ __( 'Enabled', 'gemsecurity' ) }</Badge> }
									</td>
									<td style={ { textAlign: 'right' } }>
										{ locked ? (
											<a className="gs-btn gs-btn--secondary" href={ upgradeUrl() } target="_blank" rel="noreferrer">
												{ __( 'Unlock in Pro', 'gemsecurity' ) }
											</a>
										) : (
											<Button variant="secondary" loading={ busy === d.key } onClick={ () => toggle( d ) }>
												{ d.enabled ? __( 'Disable', 'gemsecurity' ) : __( 'Enable', 'gemsecurity' ) }
											</Button>
										) }
									</td>
								</tr>
							);
						} ) }
					</tbody>
				</table>
				{ ! pro && (
					<p className="gs-card__desc" style={ { marginTop: 12 } }>
						{ __( 'Amazon S3, Backblaze B2, Cloudflare R2, Dropbox, Google Drive, OneDrive and FTP are unlocked with GemSecurity Pro.', 'gemsecurity' ) }
					</p>
				) }
			</Card>
		</div>
	);
}
