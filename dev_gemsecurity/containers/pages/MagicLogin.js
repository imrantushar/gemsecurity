import React from 'react';
import { __ } from '@wordpress/i18n';
import { GS } from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, Select, MultiSelect, toOptions } from '@Components/ui/Controls';

const KEYS = [
	'magic_login_enabled',
	'magic_login_expiry',
	'magic_login_allow_admins',
	'magic_login_roles',
	'magic_login_require_2fa',
];

const EXPIRY_OPTIONS = [ 5, 10, 15, 30, 60 ].map( ( m ) => ( {
	value: String( m ),
	/* translators: %d: minutes. */
	label: `${ m } ${ __( 'minutes', 'gemsecurity' ) }`,
} ) );

export default function MagicLogin() {
	const { form, setField } = useSettingsForm( KEYS );
	const roles = GS.roles || {};
	const selected = Array.isArray( form.magic_login_roles ) ? form.magic_login_roles : [];

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Magic login', 'gemsecurity' ) }
				description={ __( 'Let users sign in without a password using a one-time link sent to their email.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Enable magic login', 'gemsecurity' ) }
					description={ __( 'Adds an “Email me a sign-in link” option to the login form.', 'gemsecurity' ) }
					checked={ !! form.magic_login_enabled }
					onChange={ ( v ) => setField( 'magic_login_enabled', v ) }
				/>
				<Field
					label={ __( 'Link validity', 'gemsecurity' ) }
					description={ __( 'A link works once and stops working after this long.', 'gemsecurity' ) }
				>
					<Select
						value={ String( form.magic_login_expiry || 10 ) }
						onChange={ ( e ) => setField( 'magic_login_expiry', parseInt( e.target.value, 10 ) ) }
						options={ EXPIRY_OPTIONS }
					/>
				</Field>
			</Card>

			<Card title={ __( 'Who can use it', 'gemsecurity' ) }>
				<Toggle
					label={ __( 'Allow administrators', 'gemsecurity' ) }
					description={ __( 'Off by default. Anyone who can read an administrator’s mailbox could sign in as them.', 'gemsecurity' ) }
					checked={ !! form.magic_login_allow_admins }
					onChange={ ( v ) => setField( 'magic_login_allow_admins', v ) }
				/>
				<Field
					label={ __( 'Limit to these roles', 'gemsecurity' ) }
					description={ __( 'Leave empty to allow every role (administrators still need the switch above).', 'gemsecurity' ) }
				>
					<MultiSelect
						options={ toOptions( roles ) }
						value={ selected }
						onChange={ ( next ) => setField( 'magic_login_roles', next ) }
						placeholder={ __( 'All roles', 'gemsecurity' ) }
					/>
				</Field>
			</Card>

			<Card title={ __( 'Two-factor', 'gemsecurity' ) }>
				<Toggle
					label={ __( 'Require two-factor after the link', 'gemsecurity' ) }
					description={ __( 'Users who have two-factor (or whose role requires it) are asked for their code after opening the link. Only applies while the Two-Factor system is on.', 'gemsecurity' ) }
					checked={ form.magic_login_require_2fa !== false }
					onChange={ ( v ) => setField( 'magic_login_require_2fa', v ) }
				/>
			</Card>
		</div>
	);
}
