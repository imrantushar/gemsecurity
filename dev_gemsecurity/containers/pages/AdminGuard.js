import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, Select, TextInput, Button, Loading, Badge } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';

const KEYS = [ 'admin_whitelist_enabled', 'admin_whitelist', 'rogue_admin_action', 'notify_on_rogue_admin' ];

export default function AdminGuard() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const [ admins, setAdmins ] = useState( null );
	const [ newEmail, setNewEmail ] = useState( '' );

	useEffect( () => {
		api.get( 'admins' ).then( ( r ) => setAdmins( r.data.admins ) ).catch( () => setAdmins( [] ) );
	}, [] );

	const whitelist = ( form.admin_whitelist || [] ).map( ( e ) => e.toLowerCase() );

	const inList = ( email ) => whitelist.includes( ( email || '' ).toLowerCase() );

	const toggleEmail = ( email, on ) => {
		const e = ( email || '' ).toLowerCase();
		const next = on ? [ ...new Set( [ ...whitelist, e ] ) ] : whitelist.filter( ( x ) => x !== e );
		setField( 'admin_whitelist', next );
	};

	const addEmail = () => {
		const e = newEmail.trim().toLowerCase();
		if ( e && ! whitelist.includes( e ) ) {
			setField( 'admin_whitelist', [ ...whitelist, e ] );
		}
		setNewEmail( '' );
	};

	// Whitelist emails that don't match any current administrator.
	const adminEmails = ( admins || [] ).map( ( a ) => a.email.toLowerCase() );
	const extraEmails = whitelist.filter( ( e ) => ! adminEmails.includes( e ) );

	// Safety: enabling the guard while the current user is not whitelisted.
	const currentAdmin = ( admins || [] ).find( ( a ) => a.is_current );
	const selfLockoutRisk =
		form.admin_whitelist_enabled && currentAdmin && ! inList( currentAdmin.email );

	return (
		<div className="gs-page">
			<Card>
				<div className="gs-callout">
					<Icon name="crown" size={ 20 } />
					<div>
						<strong>{ __( 'How the Admin Guard works', 'gemsecurity' ) }</strong>
						<p>
							{ __( 'When enabled, any administrator account whose email is not on the whitelist is automatically removed. A brand-new account that registers as an administrator is deleted; an existing user promoted to administrator is reverted (or deleted) per your chosen action. Your own account, user ID 1, the site-owner email and multisite super admins are always protected.', 'gemsecurity' ) }
						</p>
					</div>
				</div>
			</Card>

			<Card title={ __( 'Whitelist guard', 'gemsecurity' ) }>
				<Toggle
					label={ __( 'Enforce the administrator whitelist', 'gemsecurity' ) }
					description={ __( 'Auto-remove unapproved administrators.', 'gemsecurity' ) }
					checked={ form.admin_whitelist_enabled }
					onChange={ ( v ) => setField( 'admin_whitelist_enabled', v ) }
				/>

				{ selfLockoutRisk && (
					<div className="gs-alert gs-alert--warning">
						<Icon name="alert" size={ 18 } />
						<span>
							{ __( 'Your own administrator account is not on the whitelist. Add it below before saving, or you risk losing admin access.', 'gemsecurity' ) }
						</span>
					</div>
				) }

				<div className="gs-row">
					<Field
						label={ __( 'Action for promoted users', 'gemsecurity' ) }
						description={ __( 'What to do when an existing user is escalated to administrator without approval.', 'gemsecurity' ) }
					>
						<Select
							value={ form.rogue_admin_action || 'demote' }
							onChange={ ( e ) => setField( 'rogue_admin_action', e.target.value ) }
							options={ [
								{ value: 'demote', label: __( 'Demote to previous role (safer)', 'gemsecurity' ) },
								{ value: 'delete', label: __( 'Delete the account', 'gemsecurity' ) },
							] }
						/>
					</Field>
				</div>

				<Toggle
					label={ __( 'Email the site owner when a rogue admin is blocked', 'gemsecurity' ) }
					checked={ form.notify_on_rogue_admin }
					onChange={ ( v ) => setField( 'notify_on_rogue_admin', v ) }
				/>
			</Card>

			<Card
				title={ __( 'Approved administrators', 'gemsecurity' ) }
				description={ __( 'Check every administrator that should be allowed to keep their role.', 'gemsecurity' ) }
			>
				{ admins === null ? (
					<Loading />
				) : (
					<ul className="gs-admins">
						{ admins.map( ( a ) => (
							<li key={ a.id } className="gs-admins__row">
								<label className="gs-check">
									<input
										type="checkbox"
										checked={ inList( a.email ) }
										onChange={ ( e ) => toggleEmail( a.email, e.target.checked ) }
									/>
									<span className="gs-admins__info">
										<span className="gs-admins__name">
											{ a.display_name } <span className="gs-muted">({ a.login })</span>
											{ a.is_current && <Badge tone="info">{ __( 'You', 'gemsecurity' ) }</Badge> }
										</span>
										<span className="gs-admins__email">{ a.email }</span>
									</span>
								</label>
								{ inList( a.email ) ? (
									<Badge tone="success">{ __( 'Approved', 'gemsecurity' ) }</Badge>
								) : (
									<Badge tone="warning">{ __( 'Not approved', 'gemsecurity' ) }</Badge>
								) }
							</li>
						) ) }
					</ul>
				) }

				{ extraEmails.length > 0 && (
					<div className="gs-extra">
						<h4>{ __( 'Other approved emails', 'gemsecurity' ) }</h4>
						<div className="gs-chips">
							{ extraEmails.map( ( e ) => (
								<span key={ e } className="gs-chip">
									{ e }
									<button type="button" onClick={ () => toggleEmail( e, false ) }>×</button>
								</span>
							) ) }
						</div>
					</div>
				) }

				<div className="gs-addrow">
					<TextInput
						type="email"
						placeholder={ __( 'Pre-approve an email address…', 'gemsecurity' ) }
						value={ newEmail }
						onChange={ ( e ) => setNewEmail( e.target.value ) }
						onKeyDown={ ( e ) => e.key === 'Enter' && addEmail() }
					/>
					<Button variant="secondary" onClick={ addEmail }>{ __( 'Add', 'gemsecurity' ) }</Button>
				</div>
			</Card>

			<div className="gs-savebar">
				<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>
					{ __( 'Save changes', 'gemsecurity' ) }
				</Button>
			</div>
		</div>
	);
}
