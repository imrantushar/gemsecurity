import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api, { GS } from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, TextInput, Select, Button, Loading, Badge } from '@Components/ui/Controls';
import SetupGuide from '@Components/ui/SetupGuide';
import TestCredentials from '@Components/ui/TestCredentials';
import Icon from '@Components/ui/Icon';
import { useToast } from '@Components/ui/Toast';

const PROVIDER_KEYS = ( p ) => [
	`social_${ p }_enabled`,
	`social_${ p }_client_id`,
	`social_${ p }_client_secret`,
];

const KEYS = [
	'social_login_enabled',
	'social_allow_registration',
	'social_link_by_email',
	'social_default_role',
	...[ 'google', 'facebook', 'github', 'twitter' ].flatMap( PROVIDER_KEYS ),
];

function ProviderCard( { provider, form, setField } ) {
	const { key, label, color } = provider;
	const enabled = form[ `social_${ key }_enabled` ];
	return (
		<Card>
			<div className="gs-provider">
				<span className="gs-provider__dot" style={ { background: color } } />
				<div className="gs-provider__head">
					<strong>{ label }</strong>
					{ enabled
						? <Badge tone="success">{ __( 'Enabled', 'gemsecurity' ) }</Badge>
						: <Badge tone="info">{ __( 'Off', 'gemsecurity' ) }</Badge> }
				</div>
				<Toggle checked={ enabled } onChange={ ( v ) => setField( `social_${ key }_enabled`, v ) } />
			</div>
			{ enabled && (
				<>
					{ /* Expanded on first setup: with no credentials saved yet,
					     the steps are the only thing that helps. */ }
					<SetupGuide
						id={ `social.${ key }` }
						defaultOpen={ ! form[ `social_${ key }_client_id` ] }
					/>
					<div className="gs-row">
						<Field label={ __( 'Client ID', 'gemsecurity' ) }>
							<TextInput value={ form[ `social_${ key }_client_id` ] ?? '' } onChange={ ( e ) => setField( `social_${ key }_client_id`, e.target.value ) } />
						</Field>
						<Field label={ __( 'Client secret', 'gemsecurity' ) }>
							<TextInput type="password" value={ form[ `social_${ key }_client_secret` ] ?? '' } onChange={ ( e ) => setField( `social_${ key }_client_secret`, e.target.value ) } />
						</Field>
					</div>
					<TestCredentials
						target="social"
						getValues={ () => ( {
							provider: key,
							client_id: form[ `social_${ key }_client_id` ] || '',
							client_secret: form[ `social_${ key }_client_secret` ] || '',
						} ) }
					/>
				</>
			) }
			{ enabled && key === 'twitter' && (
				<p className="gs-muted">{ __( 'Twitter rarely returns an email — accounts are created with a placeholder address you can change later.', 'gemsecurity' ) }</p>
			) }
		</Card>
	);
}

export default function SocialLogin() {
	const toast = useToast();
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const [ config, setConfig ] = useState( null );

	useEffect( () => {
		api.get( 'social' ).then( ( r ) => setConfig( r.data ) ).catch( () => setConfig( false ) );
	}, [] );

	const copyRedirect = () => {
		if ( config?.redirect_uri ) {
			navigator.clipboard?.writeText( config.redirect_uri );
			toast( __( 'Redirect URI copied.', 'gemsecurity' ), 'success' );
		}
	};

	if ( config === null ) {
		return <Loading />;
	}

	const roles = GS.roles || {};

	return (
		<div className="gs-page">
			<Card title={ __( 'Social login', 'gemsecurity' ) } description={ __( 'Let users sign in with their existing accounts.', 'gemsecurity' ) }>
				<Toggle
					label={ __( 'Enable social login', 'gemsecurity' ) }
					description={ __( 'Shows the configured provider buttons on the WordPress login form.', 'gemsecurity' ) }
					checked={ form.social_login_enabled }
					onChange={ ( v ) => setField( 'social_login_enabled', v ) }
				/>
				{ config && config.redirect_uri && (
					<Field
						label={ __( 'Authorized redirect URI', 'gemsecurity' ) }
						description={ __( 'Paste this exact URL into each provider’s OAuth app settings.', 'gemsecurity' ) }
					>
						<div className="gs-copyrow">
							<code className="gs-redirect">{ config.redirect_uri }</code>
							<Button variant="secondary" onClick={ copyRedirect }><Icon name="link" size={ 15 } /> { __( 'Copy', 'gemsecurity' ) }</Button>
						</div>
					</Field>
				) }
			</Card>

			<Card title={ __( 'Account behavior', 'gemsecurity' ) }>
				<Toggle
					label={ __( 'Allow new account registration', 'gemsecurity' ) }
					description={ __( 'Create a WordPress account when someone signs in with a provider for the first time.', 'gemsecurity' ) }
					checked={ form.social_allow_registration }
					onChange={ ( v ) => setField( 'social_allow_registration', v ) }
				/>
				<Toggle
					label={ __( 'Link to existing accounts by email', 'gemsecurity' ) }
					description={ __( 'If the provider email matches an existing user, link the accounts instead of creating a new one.', 'gemsecurity' ) }
					checked={ form.social_link_by_email }
					onChange={ ( v ) => setField( 'social_link_by_email', v ) }
				/>
				<Field label={ __( 'Default role for new accounts', 'gemsecurity' ) }>
					<Select
						value={ form.social_default_role || 'subscriber' }
						onChange={ ( e ) => setField( 'social_default_role', e.target.value ) }
						options={ Object.entries( roles ).map( ( [ slug, name ] ) => ( { value: slug, label: name } ) ) }
					/>
				</Field>
			</Card>

			{ ( config.providers || [] ).map( ( p ) => (
				<ProviderCard key={ p.key } provider={ p } form={ form } setField={ setField } />
			) ) }

			<div className="gs-savebar">
				<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>{ __( 'Save changes', 'gemsecurity' ) }</Button>
			</div>
		</div>
	);
}
