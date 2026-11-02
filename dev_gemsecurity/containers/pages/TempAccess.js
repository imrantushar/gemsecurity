import React, { useEffect, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { useToast } from '@Components/ui/Toast';
import { Card, Toggle, Field, Select, TextInput, Button, Badge, Loading, EmptyState } from '@Components/ui/Controls';

const KEYS = [ 'temp_access_notify_created', 'temp_access_notify_revoked' ];

const PRESET_LABELS = {
	'1h': __( '1 hour', 'gemsecurity' ),
	'6h': __( '6 hours', 'gemsecurity' ),
	'24h': __( '24 hours', 'gemsecurity' ),
	'7d': __( '7 days', 'gemsecurity' ),
	'30d': __( '30 days', 'gemsecurity' ),
};

const TONES = { active: 'success', expired: 'warning', revoked: 'danger' };

const STATUS_LABELS = {
	active: __( 'Active', 'gemsecurity' ),
	expired: __( 'Expired', 'gemsecurity' ),
	revoked: __( 'Revoked', 'gemsecurity' ),
};

const EVENT_LABELS = {
	created: __( 'Granted', 'gemsecurity' ),
	extended: __( 'Extended', 'gemsecurity' ),
	expired: __( 'Expired', 'gemsecurity' ),
	revoked: __( 'Revoked', 'gemsecurity' ),
};

/** Inline flex row for buttons and pickers. */
const ROW = { display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center', marginTop: '12px' };

const fmt = ( ts ) => ( ts ? new Date( ts * 1000 ).toLocaleString() : '' );

/** Options for a duration <Select>: the presets plus a custom date. */
const durationOptions = ( presets ) => [
	...presets.map( ( p ) => ( { value: p, label: PRESET_LABELS[ p ] || p } ) ),
	{ value: 'custom', label: __( 'Custom date and time…', 'gemsecurity' ) },
];

/** Duration picker: a preset, or a date/time converted to a unix time. */
function DurationPicker( { presets, value, onChange } ) {
	return (
		<>
			<Select
				value={ value.duration }
				onChange={ ( e ) => onChange( { ...value, duration: e.target.value } ) }
				options={ durationOptions( presets ) }
			/>
			{ value.duration === 'custom' && (
				<input
					type="datetime-local"
					className="gs-input"
					value={ value.local || '' }
					onChange={ ( e ) => {
						const ms = e.target.value ? new Date( e.target.value ).getTime() : 0;
						onChange( { ...value, local: e.target.value, expires_at: ms ? Math.floor( ms / 1000 ) : 0 } );
					} }
				/>
			) }
		</>
	);
}

/** Search existing users by name, login or email. */
function UserPicker( { value, onChange } ) {
	const [ term, setTerm ] = useState( '' );
	const [ results, setResults ] = useState( [] );

	useEffect( () => {
		if ( term.trim().length < 2 ) {
			setResults( [] );
			return undefined;
		}
		const t = setTimeout( () => {
			api.get( 'temp-access/users', { params: { search: term.trim() } } )
				.then( ( r ) => setResults( r.data.users || [] ) )
				.catch( () => setResults( [] ) );
		}, 250 );
		return () => clearTimeout( t );
	}, [ term ] );

	if ( value ) {
		return (
			<div style={ ROW }>
				<strong>{ value.name }</strong>
				<span className="gs-muted">{ value.email }</span>
				<Button variant="secondary" onClick={ () => onChange( null ) }>{ __( 'Change', 'gemsecurity' ) }</Button>
			</div>
		);
	}

	return (
		<>
			<TextInput
				value={ term }
				placeholder={ __( 'Search by name, username or email…', 'gemsecurity' ) }
				onChange={ ( e ) => setTerm( e.target.value ) }
			/>
			{ results.length > 0 && (
				<table className="gs-table">
					<tbody>
						{ results.map( ( u ) => (
							<tr key={ u.id }>
								<td>{ u.name }<div className="gs-muted">{ u.email }</div></td>
								<td className="gs-muted">{ u.roles.join( ', ' ) }</td>
								<td><Button variant="secondary" onClick={ () => onChange( u ) }>{ __( 'Choose', 'gemsecurity' ) }</Button></td>
							</tr>
						) ) }
					</tbody>
				</table>
			) }
			{ term.trim().length >= 2 && results.length === 0 && (
				<p className="gs-muted">{ __( 'No matching users. Add the person under Users → Add New first.', 'gemsecurity' ) }</p>
			) }
		</>
	);
}

const emptyForm = { role: '', duration: '24h', local: '', expires_at: 0, confirm_elevated: false };

function GrantForm( { data, onDone, onCancel } ) {
	const toast = useToast();
	const [ user, setUser ] = useState( null );
	const [ form, setForm ] = useState( emptyForm );
	const [ busy, setBusy ] = useState( false );
	const role = data.roles.find( ( r ) => r.slug === form.role );
	const elevated = !! ( role && role.elevated );

	const submit = async () => {
		setBusy( true );
		try {
			await api.post( 'temp-access', { ...form, user_id: user.id } );
			toast( __( 'Temporary access granted.', 'gemsecurity' ), 'success' );
			onDone();
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not grant access.', 'gemsecurity' ), 'error' );
		} finally {
			setBusy( false );
		}
	};

	return (
		<Card
			title={ __( 'Grant temporary access', 'gemsecurity' ) }
			description={ __( 'Pick a user who already has an account. They get the role you choose until the time is up, then their previous role is restored. Nothing is created and no sign-in link is sent.', 'gemsecurity' ) }
		>
			<Field label={ __( 'User', 'gemsecurity' ) }>
				<UserPicker value={ user } onChange={ setUser } />
			</Field>
			<Field label={ __( 'Role', 'gemsecurity' ) } description={ __( 'Grant the least access that gets the job done.', 'gemsecurity' ) }>
				<Select
					value={ form.role }
					onChange={ ( e ) => setForm( { ...form, role: e.target.value, confirm_elevated: false } ) }
					options={ [
						{ value: '', label: __( 'Choose a role…', 'gemsecurity' ) },
						...data.roles.map( ( r ) => ( {
							value: r.slug,
							label: r.elevated ? `${ r.name } — ${ __( 'full control', 'gemsecurity' ) }` : r.name,
						} ) ),
					] }
				/>
			</Field>
			{ elevated && (
				<div className="gs-alert gs-alert--warning">
					<strong>{ __( 'This role can change the site.', 'gemsecurity' ) }</strong>{ ' ' }
					{ __( 'It can install code, edit users and change settings. Only grant it to someone you trust completely, and keep the access short.', 'gemsecurity' ) }
					<Toggle
						label={ __( 'I understand and want to grant this role', 'gemsecurity' ) }
						checked={ form.confirm_elevated }
						onChange={ ( v ) => setForm( { ...form, confirm_elevated: v } ) }
					/>
				</div>
			) }
			<Field label={ __( 'Access lasts', 'gemsecurity' ) } description={ sprintf( /* translators: %d: days. */ __( 'At most %d days.', 'gemsecurity' ), data.max_days ) }>
				<DurationPicker presets={ data.presets } value={ form } onChange={ ( v ) => setForm( { ...form, ...v } ) } />
			</Field>
			<div style={ ROW }>
				<Button
					loading={ busy }
					disabled={ ! user || ! form.role || ( elevated && ! form.confirm_elevated ) || ( form.duration === 'custom' && ! form.expires_at ) }
					onClick={ submit }
				>
					{ __( 'Grant access', 'gemsecurity' ) }
				</Button>
				<Button variant="secondary" onClick={ onCancel }>{ __( 'Cancel', 'gemsecurity' ) }</Button>
			</div>
		</Card>
	);
}

function History( { item } ) {
	if ( ! item.history.length ) {
		return <p className="gs-muted">{ __( 'No activity yet.', 'gemsecurity' ) }</p>;
	}
	return (
		<table className="gs-table">
			<thead><tr>
				<th>{ __( 'When', 'gemsecurity' ) }</th>
				<th>{ __( 'Event', 'gemsecurity' ) }</th>
				<th>{ __( 'IP', 'gemsecurity' ) }</th>
			</tr></thead>
			<tbody>
				{ item.history.map( ( h, i ) => (
					<tr key={ i }>
						<td className="gs-nowrap">{ fmt( h.time ) }</td>
						<td>{ EVENT_LABELS[ h.event ] || h.event }</td>
						<td className="gs-nowrap">{ h.ip || '—' }</td>
					</tr>
				) ) }
			</tbody>
		</table>
	);
}

function ExtendForm( { data, item, onDone, onCancel } ) {
	const toast = useToast();
	const [ v, setV ] = useState( { duration: '24h', local: '', expires_at: 0 } );
	const [ busy, setBusy ] = useState( false );
	const go = async () => {
		setBusy( true );
		try {
			await api.post( 'temp-access/extend', { user_id: item.id, duration: v.duration, expires_at: v.expires_at } );
			toast( __( 'Access extended.', 'gemsecurity' ), 'success' );
			onDone();
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not extend access.', 'gemsecurity' ), 'error' );
		} finally {
			setBusy( false );
		}
	};
	return (
		<div style={ ROW }>
			<DurationPicker presets={ data.presets } value={ v } onChange={ setV } />
			<Button loading={ busy } disabled={ v.duration === 'custom' && ! v.expires_at } onClick={ go }>
				{ item.status === 'active' ? __( 'Extend', 'gemsecurity' ) : __( 'Reopen', 'gemsecurity' ) }
			</Button>
			<Button variant="secondary" onClick={ onCancel }>{ __( 'Cancel', 'gemsecurity' ) }</Button>
		</div>
	);
}

export default function TempAccess() {
	const { form, setField } = useSettingsForm( KEYS );
	const toast = useToast();
	const [ data, setData ] = useState( null );
	const [ creating, setCreating ] = useState( false );
	const [ open, setOpen ] = useState( 0 );
	const [ extending, setExtending ] = useState( 0 );
	const [ busyId, setBusyId ] = useState( 0 );

	const load = () => {
		api.get( 'temp-access' )
			.then( ( r ) => setData( r.data ) )
			.catch( ( e ) => {
				toast( e?.response?.data?.message || __( 'Could not load temporary access.', 'gemsecurity' ), 'error' );
				setData( { items: [], counts: { active: 0, expired: 0, revoked: 0 }, roles: [], presets: [], max_days: 90 } );
			} );
	};
	useEffect( load, [] );

	const revoke = async ( item ) => {
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( sprintf( /* translators: %s: email. */ __( 'Revoke access for %s now? Their previous role is restored and their sessions end immediately.', 'gemsecurity' ), item.email ) ) ) {
			return;
		}
		setBusyId( item.id );
		try {
			await api.post( 'temp-access/revoke', { user_id: item.id } );
			toast( __( 'Access revoked.', 'gemsecurity' ), 'success' );
			load();
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'That did not work.', 'gemsecurity' ), 'error' );
		} finally {
			setBusyId( 0 );
		}
	};

	if ( ! data ) {
		return <div className="gs-page"><Loading /></div>;
	}

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Temporary access', 'gemsecurity' ) }
				description={ __( 'Give an existing user a role for a limited time. It is taken back automatically — on expiry, or when you revoke it — and their sessions end at once.', 'gemsecurity' ) }
				actions={ ! creating && <Button onClick={ () => setCreating( true ) }>{ __( 'Grant access', 'gemsecurity' ) }</Button> }
			>
				<div style={ ROW }>
					{ [ 'active', 'expired', 'revoked' ].map( ( s ) => (
						<span key={ s }>
							<Badge tone={ TONES[ s ] }>{ STATUS_LABELS[ s ] }</Badge>{ ' ' }
							<strong>{ data.counts[ s ] || 0 }</strong>
						</span>
					) ) }
				</div>
			</Card>

			{ creating && (
				<GrantForm
					data={ data }
					onCancel={ () => setCreating( false ) }
					onDone={ () => {
						setCreating( false );
						load();
					} }
				/>
			) }

			<Card title={ __( 'Grants', 'gemsecurity' ) }>
				{ data.items.length === 0 ? (
					<EmptyState
						title={ __( 'No temporary access', 'gemsecurity' ) }
						description={ __( 'Grant a role to an existing user for a limited time.', 'gemsecurity' ) }
					/>
				) : (
					<table className="gs-table">
						<thead><tr>
							<th>{ __( 'User', 'gemsecurity' ) }</th>
							<th>{ __( 'Role granted', 'gemsecurity' ) }</th>
							<th>{ __( 'Status', 'gemsecurity' ) }</th>
							<th>{ __( 'Granted', 'gemsecurity' ) }</th>
							<th>{ __( 'Expires', 'gemsecurity' ) }</th>
							<th>{ __( 'Latest activity', 'gemsecurity' ) }</th>
							<th />
						</tr></thead>
						<tbody>
							{ data.items.map( ( it ) => (
								<React.Fragment key={ it.id }>
									<tr>
										<td>{ it.name }<div className="gs-muted">{ it.email }</div></td>
										<td>
											{ it.role_name }{ ' ' }
											{ it.elevated && <Badge tone="warning">{ __( 'full control', 'gemsecurity' ) }</Badge> }
											{ it.prev_roles.length > 0 && (
												<div className="gs-muted">{ sprintf( /* translators: %s: role names. */ __( 'was: %s', 'gemsecurity' ), it.prev_roles.join( ', ' ) ) }</div>
											) }
										</td>
										<td><Badge tone={ TONES[ it.status ] }>{ STATUS_LABELS[ it.status ] }</Badge></td>
										<td className="gs-nowrap">{ fmt( it.created ) }</td>
										<td className="gs-nowrap">{ fmt( it.status === 'revoked' ? it.revoked : it.expires ) }</td>
										<td>
											{ it.last_event ? (
												<>
													{ EVENT_LABELS[ it.last_event.event ] || it.last_event.event }
													<div className="gs-muted">{ fmt( it.last_event.time ) }</div>
												</>
											) : '—' }
										</td>
										<td style={ { minWidth: 200 } }>
											<Button variant="secondary" onClick={ () => setOpen( open === it.id ? 0 : it.id ) }>
												{ open === it.id ? __( 'Hide', 'gemsecurity' ) : __( 'View', 'gemsecurity' ) }
											</Button>{ ' ' }
											{ it.status !== 'revoked' && (
												<Button variant="secondary" disabled={ busyId === it.id } onClick={ () => setExtending( extending === it.id ? 0 : it.id ) }>
													{ it.status === 'active' ? __( 'Extend', 'gemsecurity' ) : __( 'Reopen', 'gemsecurity' ) }
												</Button>
											) }{ ' ' }
											{ it.status === 'active' && (
												<Button variant="danger" loading={ busyId === it.id } onClick={ () => revoke( it ) }>
													{ __( 'Revoke', 'gemsecurity' ) }
												</Button>
											) }
										</td>
									</tr>
									{ extending === it.id && (
										<tr>
											<td colSpan={ 7 }>
												<ExtendForm
													data={ data }
													item={ it }
													onCancel={ () => setExtending( 0 ) }
													onDone={ () => { setExtending( 0 ); load(); } }
												/>
											</td>
										</tr>
									) }
									{ open === it.id && (
										<tr>
											<td colSpan={ 7 }>
												<p className="gs-muted">
													{ sprintf(
														/* translators: 1: username, 2: who granted it. */
														__( 'Username %1$s · granted by %2$s', 'gemsecurity' ),
														it.login,
														it.created_by || '—'
													) }
												</p>
												<History item={ it } />
											</td>
										</tr>
									) }
								</React.Fragment>
							) ) }
						</tbody>
					</table>
				) }
			</Card>

			<Card
				title={ __( 'Email me when…', 'gemsecurity' ) }
				description={ __( 'Notices go to the security notification address.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Access is granted', 'gemsecurity' ) }
					checked={ form.temp_access_notify_created !== false }
					onChange={ ( v ) => setField( 'temp_access_notify_created', v ) }
				/>
				<Toggle
					label={ __( 'Access is revoked', 'gemsecurity' ) }
					checked={ form.temp_access_notify_revoked !== false }
					onChange={ ( v ) => setField( 'temp_access_notify_revoked', v ) }
				/>
			</Card>
		</div>
	);
}
