import React, { useEffect, useState, useCallback } from 'react';
import { __ } from '@wordpress/i18n';
import ReactSelect from 'react-select';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { COUNTRY_OPTIONS, countryName } from '@Utils/countries';
import { Card, Toggle, Field, Select, TextInput, Button, Badge, Loading } from '@Components/ui/Controls';
import TestCredentials from '@Components/ui/TestCredentials';
import Icon from '@Components/ui/Icon';
import { useToast } from '@Components/ui/Toast';

const KEYS = [
	'geo_enabled',
	'geo_whitelist_login_enabled',
	'geo_block_site_enabled',
	'geo_block_unknown',
	'geo_whitelist_block_admins',
	'geo_allowed_countries',
	'geo_user_lock_enabled',
	'geo_user_lock_action',
];

const toOptions = ( codes ) => ( codes || [] ).map( ( c ) => ( { value: c, label: `${ countryName( c ) } (${ c })` } ) );

/* ------------------------ Per-user assignment ------------------------ */

function PerUserLock() {
	const toast = useToast();
	const [ search, setSearch ] = useState( '' );
	const [ users, setUsers ] = useState( null );
	const [ drafts, setDrafts ] = useState( {} );
	const [ savingId, setSavingId ] = useState( 0 );

	const load = useCallback( ( q = '' ) => {
		setUsers( null );
		api.get( 'geo/users', { params: { search: q } } )
			.then( ( r ) => {
				setUsers( r.data.users );
				const d = {};
				r.data.users.forEach( ( u ) => { d[ u.id ] = u.countries; } );
				setDrafts( d );
			} )
			.catch( () => setUsers( [] ) );
	}, [] );

	useEffect( () => { load(); }, [ load ] );

	const saveUser = async ( u ) => {
		setSavingId( u.id );
		try {
			await api.post( 'geo/user', { user_id: u.id, countries: drafts[ u.id ] || [] } );
			toast( __( 'Saved.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( __( 'Could not save.', 'gemsecurity' ), 'error' );
		}
		setSavingId( 0 );
	};

	return (
		<>
			<div className="gs-geo-search">
				<TextInput
					placeholder={ __( 'Search a user by name or email…', 'gemsecurity' ) }
					value={ search }
					onChange={ ( e ) => setSearch( e.target.value ) }
					onKeyDown={ ( e ) => e.key === 'Enter' && load( search ) }
				/>
				<Button variant="secondary" onClick={ () => load( search ) }>{ __( 'Search', 'gemsecurity' ) }</Button>
			</div>
			<p className="gs-muted">{ __( 'Showing users with assigned countries; search to add countries to any user. A user with no assigned countries is not location-locked.', 'gemsecurity' ) }</p>

			{ users === null ? (
				<Loading />
			) : users.length === 0 ? (
				<p className="gs-muted">{ __( 'No matching users.', 'gemsecurity' ) }</p>
			) : (
				<ul className="gs-geo-users">
					{ users.map( ( u ) => (
						<li key={ u.id }>
							<div className="gs-geo-users__info">
								<strong>{ u.display_name }</strong> <span className="gs-muted">({ u.login })</span>
								<span className="gs-geo-users__email">{ u.email }</span>
							</div>
							<div className="gs-geo-users__pick">
								<ReactSelect
									isMulti
									className="gs-rs"
									classNamePrefix="gs-rs"
									options={ COUNTRY_OPTIONS }
									value={ toOptions( drafts[ u.id ] ) }
									onChange={ ( opts ) => setDrafts( ( d ) => ( { ...d, [ u.id ]: ( opts || [] ).map( ( o ) => o.value ) } ) ) }
									placeholder={ __( 'Allowed countries…', 'gemsecurity' ) }
									menuPortalTarget={ typeof document !== 'undefined' ? document.body : null }
									styles={ { menuPortal: ( base ) => ( { ...base, zIndex: 100000 } ) } }
								/>
								<Button onClick={ () => saveUser( u ) } loading={ savingId === u.id }>{ __( 'Save', 'gemsecurity' ) }</Button>
							</div>
						</li>
					) ) }
				</ul>
			) }
		</>
	);
}

/* ------------------------------- Page -------------------------------- */

export default function Geolocation() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const [ detected, setDetected ] = useState( null );

	useEffect( () => {
		api.get( 'geo/test' ).then( ( r ) => setDetected( r.data ) ).catch( () => setDetected( false ) );
	}, [] );

	return (
		<div className="gs-page">
			<Card title={ __( 'Geolocation access control', 'gemsecurity' ) } description={ __( 'Allow or block sign-ins based on the visitor’s country.', 'gemsecurity' ) }>
				<Toggle
					label={ __( 'Enable geolocation', 'gemsecurity' ) }
					description={ __( 'Master switch for every rule below.', 'gemsecurity' ) }
					checked={ form.geo_enabled }
					onChange={ ( v ) => setField( 'geo_enabled', v ) }
				/>
				{ /* The lookup runs from the server, so a firewalled host
				     silently resolves nobody — prove it works here. */ }
				<TestCredentials
					target="service"
					getValues={ () => ( { service: 'geolocation' } ) }
					label={ __( 'Test country lookup', 'gemsecurity' ) }
				/>
				{ detected && detected.country !== undefined && (
					<p className="gs-muted">
						{ __( 'Your current detected location:', 'gemsecurity' ) }{ ' ' }
						<Badge tone="info">{ detected.country ? `${ countryName( detected.country ) } (${ detected.country })` : __( 'unknown', 'gemsecurity' ) }</Badge>{ ' ' }
						<span>· { detected.ip }</span>
					</p>
				) }
				<div className="gs-alert gs-alert--warning">
					<Icon name="alert" size={ 18 } />
					<span>{ __( 'Locked out by a rule? Add define( \'GEMSEC_GEO_DISABLE\', true ); to wp-config.php to disable all geolocation gating.', 'gemsecurity' ) }</span>
				</div>
			</Card>

			<Card title={ __( 'Country whitelist', 'gemsecurity' ) } description={ __( 'Only the selected countries are allowed. Leave empty to allow all.', 'gemsecurity' ) }>
				<Field label={ __( 'Allowed countries', 'gemsecurity' ) }>
					<ReactSelect
						isMulti
						className="gs-rs"
						classNamePrefix="gs-rs"
						options={ COUNTRY_OPTIONS }
						value={ toOptions( form.geo_allowed_countries ) }
						onChange={ ( opts ) => setField( 'geo_allowed_countries', ( opts || [] ).map( ( o ) => o.value ) ) }
						placeholder={ __( 'Select countries…', 'gemsecurity' ) }
						isDisabled={ ! form.geo_enabled }
						menuPortalTarget={ typeof document !== 'undefined' ? document.body : null }
						styles={ { menuPortal: ( base ) => ( { ...base, zIndex: 100000 } ) } }
					/>
				</Field>
				<div className="gs-toggle-list">
					<Toggle label={ __( 'Block sign-in from other countries', 'gemsecurity' ) } description={ __( 'Reject logins from outside the allowed list.', 'gemsecurity' ) } checked={ form.geo_whitelist_login_enabled } onChange={ ( v ) => setField( 'geo_whitelist_login_enabled', v ) } disabled={ ! form.geo_enabled } />
					<Toggle label={ __( 'Block entire site from other countries', 'gemsecurity' ) } description={ __( 'Return a 403 for all visitors outside the allowed list (logged-in admins are exempt).', 'gemsecurity' ) } checked={ form.geo_block_site_enabled } onChange={ ( v ) => setField( 'geo_block_site_enabled', v ) } disabled={ ! form.geo_enabled } />
					<Toggle label={ __( 'Block when the country is unknown', 'gemsecurity' ) } description={ __( 'By default unknown/local IPs are allowed so you are never locked out. Turn on only if you are sure.', 'gemsecurity' ) } checked={ form.geo_block_unknown } onChange={ ( v ) => setField( 'geo_block_unknown', v ) } disabled={ ! form.geo_enabled } />
					<Toggle label={ __( 'Also apply the login block to administrators', 'gemsecurity' ) } description={ __( 'Off by default so an admin can always recover. Enabling this can lock out admins who travel.', 'gemsecurity' ) } checked={ form.geo_whitelist_block_admins } onChange={ ( v ) => setField( 'geo_whitelist_block_admins', v ) } disabled={ ! form.geo_enabled } />
				</div>
			</Card>

			<Card title={ __( 'Per-user location lock', 'gemsecurity' ) } description={ __( 'Restrict individual users to their own approved countries.', 'gemsecurity' ) }>
				<Toggle
					label={ __( 'Enable per-user location lock', 'gemsecurity' ) }
					checked={ form.geo_user_lock_enabled }
					onChange={ ( v ) => setField( 'geo_user_lock_enabled', v ) }
					disabled={ ! form.geo_enabled }
				/>
				<Field label={ __( 'When a user signs in from a new country', 'gemsecurity' ) }>
					<Select
						value={ form.geo_user_lock_action || 'verify' }
						onChange={ ( e ) => setField( 'geo_user_lock_action', e.target.value ) }
						options={ [
							{ value: 'verify', label: __( 'Email a verification code (recommended)', 'gemsecurity' ) },
							{ value: 'block', label: __( 'Block the login', 'gemsecurity' ) },
						] }
					/>
				</Field>
				{ form.geo_user_lock_enabled && <PerUserLock /> }
			</Card>

			<div className="gs-savebar" data-label={ __( 'Unsaved changes', 'gemsecurity' ) }>
				<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>{ __( 'Save changes', 'gemsecurity' ) }</Button>
			</div>
		</div>
	);
}
