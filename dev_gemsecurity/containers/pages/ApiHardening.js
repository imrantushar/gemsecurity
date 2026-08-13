import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, NumberInput, Field, Button, Badge, EmptyState } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';
import { useToast } from '@Components/ui/Toast';

const KEYS = [
	'rest_rate_limit_enabled',
	'rest_rate_limit_max',
	'rest_rate_limit_window',
	'app_pw_disabled',
	'app_pw_alert_on_create',
	'app_pw_max_age_days',
	'login_errors_generic',
];

/** Application-password inventory + revoke controls. */
function AppPasswords( { disabled } ) {
	const toast = useToast();
	const [ data, setData ] = useState( null );
	const [ busy, setBusy ] = useState( false );

	const load = () => {
		api.get( 'app-passwords' )
			.then( ( r ) => setData( r.data ) )
			.catch( () => setData( { supported: true, items: [] } ) );
	};
	useEffect( load, [] );

	const revoke = async ( payload, label ) => {
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( label ) ) {
			return;
		}
		setBusy( true );
		try {
			await api.post( 'app-passwords/revoke', payload );
			toast( __( 'Application password revoked.', 'gemsecurity' ), 'success' );
			load();
		} catch ( e ) {
			toast( __( 'Could not revoke.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};

	if ( data && data.supported === false ) {
		return (
			<Card title={ __( 'Application passwords', 'gemsecurity' ) }>
				<p className="gs-muted">{ __( 'Application passwords are not available on this site.', 'gemsecurity' ) }</p>
			</Card>
		);
	}

	const items = data ? data.items : [];

	return (
		<Card
			title={ __( 'Existing application passwords', 'gemsecurity' ) }
			description={ __( 'Application passwords authenticate the REST API and bypass two-factor. Review and revoke any you don’t recognise.', 'gemsecurity' ) }
			actions={
				items.length > 0 && ! disabled ? (
					<Button
						variant="danger"
						loading={ busy }
						onClick={ () => revoke( { all: true }, __( 'Revoke ALL application passwords for every user?', 'gemsecurity' ) ) }
					>
						{ __( 'Revoke all', 'gemsecurity' ) }
					</Button>
				) : null
			}
		>
			{ ! data ? (
				<p className="gs-muted">{ __( 'Loading…', 'gemsecurity' ) }</p>
			) : items.length === 0 ? (
				<EmptyState
					title={ __( 'No application passwords', 'gemsecurity' ) }
					description={ __( 'No user has created an application password yet.', 'gemsecurity' ) }
				/>
			) : (
				<table className="gs-table">
					<thead><tr>
						<th>{ __( 'User', 'gemsecurity' ) }</th>
						<th>{ __( 'Name', 'gemsecurity' ) }</th>
						<th>{ __( 'Created', 'gemsecurity' ) }</th>
						<th>{ __( 'Last used', 'gemsecurity' ) }</th>
						<th>{ __( 'Last IP', 'gemsecurity' ) }</th>
						<th />
					</tr></thead>
					<tbody>
						{ items.map( ( it ) => (
							<tr key={ it.user_id + it.uuid }>
								<td>{ it.user_login }</td>
								<td>{ it.name }</td>
								<td className="gs-nowrap">{ it.created || '—' }</td>
								<td className="gs-nowrap">{ it.last_used || __( 'never', 'gemsecurity' ) }</td>
								<td className="gs-nowrap">{ it.last_ip || '—' }</td>
								<td>
									<Button
										variant="danger"
										onClick={ () => revoke( { user_id: it.user_id, uuid: it.uuid }, __( 'Revoke this application password?', 'gemsecurity' ) ) }
									>
										{ __( 'Revoke', 'gemsecurity' ) }
									</Button>
								</td>
							</tr>
						) ) }
					</tbody>
				</table>
			) }
		</Card>
	);
}

export default function ApiHardening() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );

	return (
		<div className="gs-page">
			<Card
				title={ __( 'REST API', 'gemsecurity' ) }
				description={ __( 'The REST API is a common unauthenticated attack and recon surface. Rate-limit it for anonymous callers (logged-in administrators are never throttled).', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Rate-limit the REST API', 'gemsecurity' ) }
					description={ __( 'Throttle anonymous REST requests per IP.', 'gemsecurity' ) }
					checked={ form.rest_rate_limit_enabled }
					onChange={ ( v ) => setField( 'rest_rate_limit_enabled', v ) }
				/>
				{ form.rest_rate_limit_enabled && (
					<div className="gs-row">
						<Field label={ __( 'Max requests', 'gemsecurity' ) }>
							<NumberInput min="1" value={ form.rest_rate_limit_max ?? 120 } onChange={ ( e ) => setField( 'rest_rate_limit_max', Number( e.target.value ) ) } />
						</Field>
						<Field label={ __( 'Per window', 'gemsecurity' ) } suffix={ __( 'minutes', 'gemsecurity' ) }>
							<NumberInput min="1" value={ form.rest_rate_limit_window ?? 1 } onChange={ ( e ) => setField( 'rest_rate_limit_window', Number( e.target.value ) ) } />
						</Field>
					</div>
				) }
			</Card>

			<Card
				title={ __( 'Username enumeration', 'gemsecurity' ) }
				description={ __( 'Stop attackers from discovering valid usernames from the login form.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Generic login error messages', 'gemsecurity' ) }
					description={ __( 'Show one identical “username or password is incorrect” message instead of revealing which was wrong.', 'gemsecurity' ) }
					checked={ form.login_errors_generic }
					onChange={ ( v ) => setField( 'login_errors_generic', v ) }
				/>
			</Card>

			<Card
				title={ __( 'Application passwords', 'gemsecurity' ) }
				description={ __( 'Application passwords grant long-lived REST access and bypass two-factor. Govern them here.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Disable application passwords site-wide', 'gemsecurity' ) }
					description={ __( 'Turn the feature off entirely (also hides it from user profiles).', 'gemsecurity' ) }
					checked={ form.app_pw_disabled }
					onChange={ ( v ) => setField( 'app_pw_disabled', v ) }
				/>
				{ ! form.app_pw_disabled && (
					<>
						<Toggle
							label={ __( 'Email an alert when a new one is created', 'gemsecurity' ) }
							checked={ form.app_pw_alert_on_create }
							onChange={ ( v ) => setField( 'app_pw_alert_on_create', v ) }
						/>
						<Field
							label={ __( 'Auto-expire after', 'gemsecurity' ) }
							suffix={ __( 'days (0 = never)', 'gemsecurity' ) }
							description={ __( 'Application passwords older than this are deleted on the daily scan.', 'gemsecurity' ) }
						>
							<NumberInput min="0" value={ form.app_pw_max_age_days ?? 0 } onChange={ ( e ) => setField( 'app_pw_max_age_days', Number( e.target.value ) ) } />
						</Field>
					</>
				) }
			</Card>

			<div className="gs-savebar">
				<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>
					{ __( 'Save changes', 'gemsecurity' ) }
				</Button>
			</div>

			<AppPasswords disabled={ form.app_pw_disabled } />
		</div>
	);
}
