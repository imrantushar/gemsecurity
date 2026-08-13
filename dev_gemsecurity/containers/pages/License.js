import React, { useEffect, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api, { GS, sdkApi } from '@Utils/api';
import { upgradeUrl } from '@Components/ui/Pro';
import { Card, Field, TextInput, Toggle, Button, Badge } from '@Components/ui/Controls';
import { useToast } from '@Components/ui/Toast';

const STATUS_TONE = {
	active: 'success',
	valid: 'success',
	expired: 'warning',
	inactive: 'info',
	free: 'info',
};

/**
 * Settings > License. Renders one of two things depending on which
 * StoreEngine SDK client is actually active on this site (see
 * GemSecurity\StoreLicense / GemSecurityPro\StoreLicense on the PHP side):
 *
 * - GemSecurity Pro active: a real key-activation form talking to the SDK's
 *   own `storeengine-sdk/v1/gemsecurity-pro/license/*` routes.
 * - Free only: no key to activate, just the anonymous usage-tracking opt-in,
 *   proxied through this plugin's own `gemsecurity/v1/license/insights`.
 */
export default function LicenseCard() {
	const sdk = GS.SeSdk;

	// StoreLicense::load_sdk() failed (e.g. missing vendor/autoload.php) —
	// nothing localized at all. Fail quiet rather than show a broken card.
	if ( ! sdk ) {
		return null;
	}

	return sdkApi() ? <ProLicenseCard sdk={ sdk } /> : <FreeInsightsCard />;
}

function ProLicenseCard( { sdk } ) {
	const toast = useToast();
	const client = sdkApi();
	const [ key, setKey ] = useState( '' );
	const [ license, setLicense ] = useState( sdk.license || null );
	const [ busy, setBusy ] = useState( false );

	const status = license?.status || 'inactive';
	const isActive = 'active' === status || 'valid' === status;

	const activate = async () => {
		if ( ! key.trim() ) {
			toast( __( 'Enter a license key first.', 'gemsecurity' ), 'error' );
			return;
		}
		setBusy( true );
		try {
			const r = await client.post( 'license/activate', { license: key.trim() } );
			setLicense( r.data.license );
			setKey( '' );
			toast( r.data.message || __( 'License activated.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not activate license.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};

	const deactivate = async () => {
		setBusy( true );
		try {
			const r = await client.post( 'license/deactivate' );
			setLicense( r.data.license );
			toast( __( 'License deactivated.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not deactivate license.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};

	return (
		<Card
			title={ __( 'License', 'gemsecurity' ) }
			description={ __( 'Activate your GemSecurity Pro license key to enable automatic updates.', 'gemsecurity' ) }
		>
			<div className="gs-row" style={ { alignItems: 'flex-end' } }>
				<Field
					label={ __( 'License key', 'gemsecurity' ) }
					description={
						isActive
							? __( 'A license is active on this site.', 'gemsecurity' )
							: __( 'Paste the key from your purchase receipt or store dashboard.', 'gemsecurity' )
					}
				>
					<TextInput
						type={ isActive ? 'text' : 'password' }
						value={ isActive ? ( license?.license || '' ) : key }
						onChange={ ( e ) => setKey( e.target.value ) }
						placeholder="xxxx-xxxx-xxxx-xxxx"
						disabled={ isActive || busy }
					/>
				</Field>
				{ isActive ? (
					<Button variant="secondary" onClick={ deactivate } loading={ busy }>
						{ __( 'Deactivate', 'gemsecurity' ) }
					</Button>
				) : (
					<Button onClick={ activate } loading={ busy }>
						{ __( 'Activate', 'gemsecurity' ) }
					</Button>
				) }
			</div>

			<div className="gs-row" style={ { marginTop: 12, gap: 16, alignItems: 'center' } }>
				<Badge tone={ STATUS_TONE[ status ] || 'info' }>
					{ status.charAt( 0 ).toUpperCase() + status.slice( 1 ) }
				</Badge>
				{ license?.expires ? (
					<span>{ sprintf( /* translators: %s: expiry date */ __( 'Expires %s', 'gemsecurity' ), license.expires ) }</span>
				) : null }
				{ license?.limit ? (
					<span>
						{ sprintf(
							/* translators: 1: activation count, 2: activation limit */
							__( '%1$d / %2$d activations', 'gemsecurity' ),
							license.activations || 0,
							license.limit
						) }
					</span>
				) : null }
			</div>
		</Card>
	);
}

function FreeInsightsCard() {
	const toast = useToast();
	const [ status, setStatus ] = useState( null );
	const [ busy, setBusy ] = useState( false );

	useEffect( () => {
		api.get( 'license/insights' ).then( ( r ) => setStatus( r.data ) ).catch( () => {} );
	}, [] );

	const toggle = async ( allowed ) => {
		setBusy( true );
		try {
			const r = await api.post( 'license/insights', { opt_in: allowed } );
			setStatus( r.data );
		} catch ( e ) {
			toast( __( 'Could not update preference.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};

	return (
		<Card
			title={ __( 'License', 'gemsecurity' ) }
			description={ __( 'You’re running the free edition of GemSecurity — no license key needed.', 'gemsecurity' ) }
		>
			<div className="gs-row" style={ { alignItems: 'center', gap: 12, marginBottom: 12 } }>
				<Badge tone="info">{ __( 'Free Edition', 'gemsecurity' ) }</Badge>
				<a className="gs-btn gs-btn--secondary" href={ upgradeUrl() } target="_blank" rel="noreferrer">
					{ __( 'Upgrade to Pro', 'gemsecurity' ) }
				</a>
			</div>
			<Toggle
				label={ __( 'Share anonymous usage data', 'gemsecurity' ) }
				description={ __( 'Helps us prioritize what to build next. No personal data is collected.', 'gemsecurity' ) }
				checked={ !! status?.allowed }
				disabled={ busy || ! status }
				onChange={ toggle }
			/>
		</Card>
	);
}
