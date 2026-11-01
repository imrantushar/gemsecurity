import React, { useEffect, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { useToast } from '@Components/ui/Toast';
import { Card, Toggle, Field, Select, TextInput, Button, Badge, Loading, EmptyState } from '@Components/ui/Controls';

const KEYS = [ 'temp_access_notify_created', 'temp_access_notify_used', 'temp_access_notify_revoked' ];

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
	created: __( 'Created', 'gemsecurity' ),
	link_sent: __( 'Link emailed', 'gemsecurity' ),
	link_regenerated: __( 'Link regenerated', 'gemsecurity' ),
	login: __( 'Signed in', 'gemsecurity' ),
	link_failed: __( 'Failed link attempt', 'gemsecurity' ),
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

const emptyForm = { email: '', role: '', duration: '24h', local: '', expires_at: 0, send_email: true, confirm_elevated: false };

function CreateForm( { data, onDone, onCancel } ) {
	const toast = useToast();
	const [ form, setForm ] = useState( emptyForm );
	const [ busy, setBusy ] = useState( false );
	const role = data.roles.find( ( r ) => r.slug === form.role );
	const elevated = !! ( role && role.elevated );

	const submit = async () => {
		setBusy( true );
		try {
			const { data: res } = await api.post( 'temp-access', form );
			toast( res.emailed ? __( 'Temporary access created and emailed.', 'gemsecurity' ) : __( 'Temporary access created.', 'gemsecurity' ), 'success' );
			onDone( { link: res.link, email: form.email } );
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not create the account.', 'gemsecurity' ), 'error' );
		} finally {
			setBusy( false );
		}
	};

	return (
		<Card
			title={ __( 'Create temporary access', 'gemsecurity' ) }
			description={ __( 'A new account is created with the role you pick. An address that already belongs to a user is refused — existing accounts are never changed.', 'gemsecurity' ) }
		>
			<Field label={ __( 'Email address', 'gemsecurity' ) }>
				<TextInput
					type="email"
					value={ form.email }
					placeholder="developer@example.com"
					onChange={ ( e ) => setForm( { ...form, email: e.target.value } ) }
				/>
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
			<Toggle
				label={ __( 'Email the access link to this address', 'gemsecurity' ) }
				description={ __( 'You can also copy the link after the account is created.', 'gemsecurity' ) }
				checked={ form.send_email }
				onChange={ ( v ) => setForm( { ...form, send_email: v } ) }
			/>
			{ ! data.https && (
				<p className="gs-muted">{ __( 'Your site is not served over HTTPS, so this link would travel unencrypted. Enable HTTPS before sharing it.', 'gemsecurity' ) }</p>
			) }
			<div style={ ROW }>
				<Button
					loading={ busy }
					disabled={ ! form.email || ! form.role || ( elevated && ! form.confirm_elevated ) || ( form.duration === 'custom' && ! form.expires_at ) }
					onClick={ submit }
				>
					{ __( 'Create access', 'gemsecurity' ) }
				</Button>
				<Button variant="secondary" onClick={ onCancel }>{ __( 'Cancel', 'gemsecurity' ) }</Button>
			</div>
		</Card>
	);
}

/** The one place a raw link is ever shown. */
function LinkReveal( { reveal, onClose } ) {
	const toast = useToast();
	const copy = async () => {
		try {
			await navigator.clipboard.writeText( reveal.link );
			toast( __( 'Link copied.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( __( 'Copy failed — select the link and copy it manually.', 'gemsecurity' ), 'error' );
		}
	};
	return (
		<Card
			title={ sprintf( /* translators: %s: email. */ __( 'Access link for %s', 'gemsecurity' ), reveal.email ) }
			description={ __( 'This link works once and is shown only now — it is not stored. Anyone who opens it first gets the access, so send it privately.', 'gemsecurity' ) }
			actions={ <Button variant="secondary" onClick={ onClose }>{ __( 'Done', 'gemsecurity' ) }</Button> }
		>
			<input
				readOnly
				className="gs-input"
				style={ { width: '100%' } }
				value={ reveal.link }
				onFocus={ ( e ) => e.target.select() }
			/>
			<div style={ ROW }>
				<Button onClick={ copy }>{ __( 'Copy link', 'gemsecurity' ) }</Button>
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
	const [ reveal, setReveal ] = useState( null );
	const [ open, setOpen ] = useState( 0 );
	const [ extending, setExtending ] = useState( 0 );
	const [ busyId, setBusyId ] = useState( 0 );

	const load = () => {
		api.get( 'temp-access' )
			.then( ( r ) => setData( r.data ) )
			.catch( ( e ) => {
				toast( e?.response?.data?.message || __( 'Could not load temporary access.', 'gemsecurity' ), 'error' );
				setData( { items: [], counts: { active: 0, expired: 0, revoked: 0 }, roles: [], presets: [], https: true, max_days: 90 } );
			} );
	};
	useEffect( load, [] );

	const act = async ( item, path, payload, success, confirmText ) => {
		// eslint-disable-next-line no-alert
		if ( confirmText && ! window.confirm( confirmText ) ) {
			return null;
		}
		setBusyId( item.id );
		try {
			const { data: res } = await api.post( `temp-access/${ path }`, { user_id: item.id, ...payload } );
			toast( success, 'success' );
			load();
			return res;
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'That did not work.', 'gemsecurity' ), 'error' );
			return null;
		} finally {
			setBusyId( 0 );
		}
	};

	const regenerate = async ( item ) => {
		const res = await act(
			item,
			'regenerate',
			{ send_email: false },
			__( 'New link generated.', 'gemsecurity' ),
			__( 'Generate a new link? The current one will stop working immediately.', 'gemsecurity' )
		);
		if ( res && res.link ) {
			setReveal( { link: res.link, email: item.email } );
		}
	};

	if ( ! data ) {
		return <div className="gs-page"><Loading /></div>;
	}

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Temporary access', 'gemsecurity' ) }
				description={ __( 'Give a developer or support person a real account that stops working on its own — no shared passwords. Sign-in is by a single-use link; expiry and revocation end every session at once.', 'gemsecurity' ) }
				actions={ ! creating && <Button onClick={ () => { setCreating( true ); setReveal( null ); } }>{ __( 'Create temporary access', 'gemsecurity' ) }</Button> }
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

			{ reveal && <LinkReveal reveal={ reveal } onClose={ () => setReveal( null ) } /> }

			{ creating && (
				<CreateForm
					data={ data }
					onCancel={ () => setCreating( false ) }
					onDone={ ( r ) => {
						setCreating( false );
						setReveal( r );
						load();
					} }
				/>
			) }

			<Card title={ __( 'Accounts', 'gemsecurity' ) }>
				{ data.items.length === 0 ? (
					<EmptyState
						title={ __( 'No temporary accounts', 'gemsecurity' ) }
						description={ __( 'Create one to give someone time-limited access.', 'gemsecurity' ) }
					/>
				) : (
					<table className="gs-table">
						<thead><tr>
							<th>{ __( 'Email', 'gemsecurity' ) }</th>
							<th>{ __( 'Role', 'gemsecurity' ) }</th>
							<th>{ __( 'Status', 'gemsecurity' ) }</th>
							<th>{ __( 'Created', 'gemsecurity' ) }</th>
							<th>{ __( 'Expires', 'gemsecurity' ) }</th>
							<th>{ __( 'Last login', 'gemsecurity' ) }</th>
							<th>{ __( 'Latest activity', 'gemsecurity' ) }</th>
							<th />
						</tr></thead>
						<tbody>
							{ data.items.map( ( it ) => (
								<React.Fragment key={ it.id }>
									<tr>
										<td>{ it.email }</td>
										<td>
											{ it.role_name }{ ' ' }
											{ it.elevated && <Badge tone="warning">{ __( 'full control', 'gemsecurity' ) }</Badge> }
										</td>
										<td>
											<Badge tone={ TONES[ it.status ] }>{ STATUS_LABELS[ it.status ] }</Badge>
											{ it.link_pending && <div className="gs-muted">{ __( 'link not used yet', 'gemsecurity' ) }</div> }
										</td>
										<td className="gs-nowrap">{ fmt( it.created ) }</td>
										<td className="gs-nowrap">{ fmt( it.status === 'revoked' ? it.revoked : it.expires ) }</td>
										<td className="gs-nowrap">{ it.last_login ? fmt( it.last_login ) : __( 'never', 'gemsecurity' ) }</td>
										<td>
											{ it.last_event ? (
												<>
													{ EVENT_LABELS[ it.last_event.event ] || it.last_event.event }
													<div className="gs-muted">{ fmt( it.last_event.time ) }</div>
												</>
											) : '—' }
										</td>
										<td style={ { minWidth: 220 } }>
											<Button variant="secondary" onClick={ () => setOpen( open === it.id ? 0 : it.id ) }>
												{ open === it.id ? __( 'Hide', 'gemsecurity' ) : __( 'View', 'gemsecurity' ) }
											</Button>{ ' ' }
											{ it.status !== 'revoked' && (
												<Button variant="secondary" disabled={ busyId === it.id } onClick={ () => setExtending( extending === it.id ? 0 : it.id ) }>
													{ it.status === 'active' ? __( 'Extend', 'gemsecurity' ) : __( 'Reopen', 'gemsecurity' ) }
												</Button>
											) }{ ' ' }
											{ it.status === 'active' && (
												<Button variant="secondary" loading={ busyId === it.id } onClick={ () => regenerate( it ) }>
													{ __( 'Regenerate link', 'gemsecurity' ) }
												</Button>
											) }{ ' ' }
											{ it.status !== 'revoked' && (
												<Button
													variant="danger"
													loading={ busyId === it.id }
													onClick={ () => act(
														it,
														'revoke',
														{},
														__( 'Access revoked.', 'gemsecurity' ),
														sprintf( /* translators: %s: email. */ __( 'Revoke access for %s now? Their sessions end immediately.', 'gemsecurity' ), it.email )
													) }
												>
													{ __( 'Revoke', 'gemsecurity' ) }
												</Button>
											) }
										</td>
									</tr>
									{ extending === it.id && (
										<tr>
											<td colSpan={ 8 }>
												<ExtendForm
													data={ data }
													item={ it }
													onCancel={ () => setExtending( 0 ) }
													onDone={ () => { setExtending( 0 ); load(); } }
												/>
												{ it.status === 'expired' && (
													<p className="gs-muted">{ __( 'After reopening, use “Regenerate link” — the old link and sessions are gone.', 'gemsecurity' ) }</p>
												) }
											</td>
										</tr>
									) }
									{ open === it.id && (
										<tr>
											<td colSpan={ 8 }>
												<p className="gs-muted">
													{ sprintf(
														/* translators: 1: username, 2: creator, 3: number of sign-ins. */
														__( 'Username %1$s · created by %2$s · %3$d sign-in(s)', 'gemsecurity' ),
														it.login,
														it.created_by || '—',
														it.logins
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
					label={ __( 'Access is created', 'gemsecurity' ) }
					checked={ form.temp_access_notify_created !== false }
					onChange={ ( v ) => setField( 'temp_access_notify_created', v ) }
				/>
				<Toggle
					label={ __( 'A link is used for the first time', 'gemsecurity' ) }
					checked={ form.temp_access_notify_used !== false }
					onChange={ ( v ) => setField( 'temp_access_notify_used', v ) }
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
