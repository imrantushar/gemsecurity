import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import { QRCodeSVG } from 'qrcode.react';
import api, { GS } from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, TextInput, Button, Badge, Loading } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';
import { useToast } from '@Components/ui/Toast';

function BackupCodes( { codes, onDone } ) {
	const download = () => {
		const blob = new Blob( [ codes.join( '\n' ) + '\n' ], { type: 'text/plain' } );
		const a = document.createElement( 'a' );
		a.href = URL.createObjectURL( blob );
		a.download = 'gemsecurity-backup-codes.txt';
		a.click();
	};
	return (
		<div className="gs-backup">
			<div className="gs-alert gs-alert--warning">
				<Icon name="alert" size={ 18 } />
				<span>{ __( 'Save these one-time backup codes now. Each works once if you lose access to your device. They will not be shown again.', 'gemsecurity' ) }</span>
			</div>
			<ul className="gs-backup__grid">
				{ codes.map( ( c ) => <li key={ c }><code>{ c }</code></li> ) }
			</ul>
			<div className="gs-row" style={ { gap: 10 } }>
				<Button variant="secondary" onClick={ download }>{ __( 'Download', 'gemsecurity' ) }</Button>
				<Button onClick={ onDone }>{ __( 'I have saved them', 'gemsecurity' ) }</Button>
			</div>
		</div>
	);
}

function MyTwoFactor() {
	const toast = useToast();
	const [ status, setStatus ] = useState( null );
	const [ setup, setSetup ] = useState( null ); // { secret, otpauth }
	const [ code, setCode ] = useState( '' );
	const [ busy, setBusy ] = useState( false );
	const [ backupCodes, setBackupCodes ] = useState( null );

	const loadStatus = () => api.get( '2fa' ).then( ( r ) => setStatus( r.data ) ).catch( () => setStatus( false ) );
	useEffect( () => { loadStatus(); }, [] );

	const startSetup = async () => {
		setBusy( true );
		try {
			const r = await api.post( '2fa/setup' );
			setSetup( r.data );
		} catch ( e ) {
			toast( __( 'Could not start setup.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};

	const activate = async () => {
		setBusy( true );
		try {
			const r = await api.post( '2fa/activate', { code } );
			setBackupCodes( r.data.backup_codes );
			setSetup( null );
			setCode( '' );
			await loadStatus();
			toast( __( 'Authenticator app enabled.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Invalid code.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};

	const enableEmail = async () => {
		setBusy( true );
		try {
			const r = await api.post( '2fa/enable-email' );
			setBackupCodes( r.data.backup_codes );
			await loadStatus();
			toast( __( 'Email verification enabled.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( __( 'Could not enable.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};

	const regenerate = async () => {
		setBusy( true );
		try {
			const r = await api.post( '2fa/backup-codes' );
			setBackupCodes( r.data.backup_codes );
			await loadStatus();
		} catch ( e ) {
			toast( __( 'Could not regenerate.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};

	const disable = async () => {
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( __( 'Disable two-factor for your account?', 'gemsecurity' ) ) ) {
			return;
		}
		setBusy( true );
		await api.post( '2fa/disable' );
		await loadStatus();
		setBusy( false );
		toast( __( 'Two-factor disabled.', 'gemsecurity' ), 'success' );
	};

	if ( status === null ) {
		return <Card title={ __( 'My two-factor', 'gemsecurity' ) }><Loading /></Card>;
	}
	if ( status === false ) {
		return <Card title={ __( 'My two-factor', 'gemsecurity' ) }>{ __( 'Failed to load.', 'gemsecurity' ) }</Card>;
	}

	if ( backupCodes ) {
		return (
			<Card title={ __( 'Your backup codes', 'gemsecurity' ) }>
				<BackupCodes codes={ backupCodes } onDone={ () => setBackupCodes( null ) } />
			</Card>
		);
	}

	if ( status.enabled ) {
		return (
			<Card title={ __( 'My two-factor', 'gemsecurity' ) }>
				<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'Two-factor is active on your account.', 'gemsecurity' ) }</p>
				<ul className="gs-kv">
					<li><span>{ __( 'Method', 'gemsecurity' ) }</span><Badge tone="info">{ status.method === 'totp' ? __( 'Authenticator app', 'gemsecurity' ) : __( 'Email code', 'gemsecurity' ) }</Badge></li>
					<li><span>{ __( 'Backup codes left', 'gemsecurity' ) }</span><strong>{ status.backup_remaining }</strong></li>
				</ul>
				<div className="gs-row" style={ { gap: 10, marginTop: 12 } }>
					<Button variant="secondary" onClick={ regenerate } loading={ busy }>{ __( 'Regenerate backup codes', 'gemsecurity' ) }</Button>
					<Button variant="danger" onClick={ disable } loading={ busy } disabled={ status.enforced }>
						{ __( 'Disable', 'gemsecurity' ) }
					</Button>
				</div>
				{ status.enforced && (
					<p className="gs-muted" style={ { marginTop: 8 } }>{ __( 'Two-factor is required for your role and cannot be disabled.', 'gemsecurity' ) }</p>
				) }
			</Card>
		);
	}

	// Not enabled — enrollment.
	return (
		<Card title={ __( 'My two-factor', 'gemsecurity' ) } description={ __( 'Protect your account with a second step at login.', 'gemsecurity' ) }>
			{ status.enforced && (
				<div className="gs-alert gs-alert--warning">
					<Icon name="alert" size={ 18 } />
					<span>{ __( 'Two-factor is required for your role. Until you set up an app, a code will be emailed to you at each login.', 'gemsecurity' ) }</span>
				</div>
			) }

			{ ! setup ? (
				<div className="gs-row" style={ { gap: 10 } }>
					<Button onClick={ startSetup } loading={ busy }><Icon name="smartphone" size={ 16 } /> { __( 'Set up authenticator app', 'gemsecurity' ) }</Button>
					<Button variant="secondary" onClick={ enableEmail } loading={ busy }><Icon name="mail" size={ 16 } /> { __( 'Use email codes instead', 'gemsecurity' ) }</Button>
				</div>
			) : (
				<div className="gs-2fa-setup">
					<ol className="gs-steps">
						<li>{ __( 'Scan this QR code with Google Authenticator, Authy or 1Password.', 'gemsecurity' ) }</li>
					</ol>
					<div className="gs-qr">
						<QRCodeSVG value={ setup.otpauth } size={ 168 } includeMargin />
					</div>
					<Field label={ __( 'Or enter this key manually', 'gemsecurity' ) }>
						<code className="gs-secret">{ setup.secret }</code>
					</Field>
					<Field label={ __( 'Enter the 6-digit code from your app', 'gemsecurity' ) }>
						<TextInput
							inputMode="numeric"
							maxLength={ 6 }
							placeholder="123456"
							value={ code }
							onChange={ ( e ) => setCode( e.target.value.replace( /\D/g, '' ) ) }
							style={ { maxWidth: 160, letterSpacing: '0.3em', fontSize: 18 } }
						/>
					</Field>
					<div className="gs-row" style={ { gap: 10 } }>
						<Button onClick={ activate } loading={ busy } disabled={ code.length !== 6 }>{ __( 'Verify & enable', 'gemsecurity' ) }</Button>
						<Button variant="secondary" onClick={ () => { setSetup( null ); setCode( '' ); } }>{ __( 'Cancel', 'gemsecurity' ) }</Button>
					</div>
				</div>
			) }
		</Card>
	);
}

const ENFORCE_KEYS = [ 'two_factor_enabled', 'two_factor_enforced_roles' ];

function Enforcement() {
	const { form, setField, save, saving, dirty } = useSettingsForm( ENFORCE_KEYS );
	const roles = GS.roles || {};
	const enforced = form.two_factor_enforced_roles || [];

	const toggleRole = ( slug, on ) => {
		const next = on ? [ ...new Set( [ ...enforced, slug ] ) ] : enforced.filter( ( r ) => r !== slug );
		setField( 'two_factor_enforced_roles', next );
	};

	return (
		<>
			<Card title={ __( 'Two-factor system', 'gemsecurity' ) } description={ __( 'Site-wide two-factor settings (administrators only).', 'gemsecurity' ) }>
				<Toggle
					label={ __( 'Enable two-factor authentication', 'gemsecurity' ) }
					description={ __( 'Turns the feature on for the whole site. Users still choose to enroll unless required below.', 'gemsecurity' ) }
					checked={ form.two_factor_enabled }
					onChange={ ( v ) => setField( 'two_factor_enabled', v ) }
				/>
			</Card>

			<Card title={ __( 'Require two-factor by role', 'gemsecurity' ) } description={ __( 'Selected roles must pass a second step at login. Users without an app get an emailed code automatically.', 'gemsecurity' ) }>
				<div className="gs-toggle-list">
					{ Object.entries( roles ).map( ( [ slug, name ] ) => (
						<Toggle
							key={ slug }
							label={ name }
							checked={ enforced.includes( slug ) }
							onChange={ ( v ) => toggleRole( slug, v ) }
							disabled={ ! form.two_factor_enabled }
						/>
					) ) }
				</div>
				<div className="gs-savebar">
					<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>{ __( 'Save changes', 'gemsecurity' ) }</Button>
				</div>
			</Card>
		</>
	);
}

export default function TwoFactor() {
	return (
		<div className="gs-page">
			<MyTwoFactor />
			<Enforcement />
		</div>
	);
}
