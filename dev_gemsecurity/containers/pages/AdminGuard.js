import React, { useEffect, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api from '@Utils/api';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, Select, TextInput, Button, Loading, Badge } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';

const KEYS = [
	'admin_whitelist_enabled',
	'admin_whitelist',
	'rogue_admin_action',
	'notify_on_rogue_admin',
	'hidden_admin_detection',
	'notify_on_hidden_admin',
];

export default function AdminGuard() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );
	const [ admins, setAdmins ] = useState( null );
	const [ audit, setAudit ] = useState( null );
	const [ newEmail, setNewEmail ] = useState( '' );
	const [ busyId, setBusyId ] = useState( 0 );
	// Sweep of administrators that already exist — previewed before it runs,
	// because the configured action may be "delete".
	const [ sweep, setSweep ] = useState( null );
	const [ sweeping, setSweeping ] = useState( '' );

	useEffect( () => {
		api.get( 'admins' )
			.then( ( r ) => {
				setAdmins( r.data.admins );
				setAudit( r.data.audit );
			} )
			.catch( () => setAdmins( [] ) );
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

	// Remove (delete/demote) a hidden, suspicious or unapproved administrator.
	const removeAdmin = ( admin, action ) => {
		const verb = action === 'delete' ? __( 'delete', 'gemsecurity' ) : __( 'demote', 'gemsecurity' );
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( sprintf(
			/* translators: 1: action verb, 2: username. */
			__( 'Are you sure you want to %1$s the administrator "%2$s"? This cannot be undone.', 'gemsecurity' ),
			verb,
			admin.login
		) ) ) {
			return;
		}
		setBusyId( admin.id );
		api.post( 'admins/remove', { user_id: admin.id, action } )
			.then( ( r ) => {
				setAdmins( r.data.admins );
				setAudit( r.data.audit );
			} )
			.catch( ( err ) => {
				// eslint-disable-next-line no-alert
				window.alert( err?.response?.data?.message || __( 'Could not remove that administrator.', 'gemsecurity' ) );
			} )
			.finally( () => setBusyId( 0 ) );
	};

	// Reusable Demote / Delete controls for a flagged account.
	const RemoveActions = ( { admin } ) => (
		admin.protected ? (
			<span className="gs-muted">{ __( 'Protected account', 'gemsecurity' ) }</span>
		) : (
			<span className="gs-admins__actions">
				<Button
					variant="secondary"
					loading={ busyId === admin.id }
					disabled={ busyId !== 0 }
					onClick={ () => removeAdmin( admin, 'demote' ) }
				>
					{ __( 'Demote', 'gemsecurity' ) }
				</Button>
				<Button
					variant="danger"
					loading={ busyId === admin.id }
					disabled={ busyId !== 0 }
					onClick={ () => removeAdmin( admin, 'delete' ) }
				>
					{ __( 'Delete', 'gemsecurity' ) }
				</Button>
			</span>
		)
	);

	// Whitelist emails that don't match any current administrator.
	const adminEmails = ( admins || [] ).map( ( a ) => a.email.toLowerCase() );
	const extraEmails = whitelist.filter( ( e ) => ! adminEmails.includes( e ) );

	// Safety: enabling the guard while the current user is not whitelisted.
	const currentAdmin = ( admins || [] ).find( ( a ) => a.is_current );
	const selfLockoutRisk =
		form.admin_whitelist_enabled && currentAdmin && ! inList( currentAdmin.email );

	const hiddenAdmins = ( admins || [] ).filter( ( a ) => a.hidden );
	// Suspicious but not already listed as hidden.
	const suspiciousAdmins = ( admins || [] ).filter( ( a ) => a.suspicious && ! a.hidden );
	const allClear = audit && hiddenAdmins.length === 0 && suspiciousAdmins.length === 0 && ! audit.mismatch;

	const previewSweep = async () => {
		setSweeping( 'preview' );
		try {
			const { data } = await api.get( 'admins/sweep' );
			setSweep( data );
		} catch ( e ) {
			setSweep( null );
		}
		setSweeping( '' );
	};

	const runSweep = async () => {
		setSweeping( 'run' );
		try {
			const { data } = await api.post( 'admins/sweep', {} );
			setSweep( { ...data, done: true } );
			if ( Array.isArray( data.admins ) ) {
				setAdmins( data.admins );
			}
			if ( data.audit ) {
				setAudit( data.audit );
			}
		} catch ( e ) {
			// Leave the preview on screen; the error surfaces below.
		}
		setSweeping( '' );
	};

	return (
		<div className="gs-page">
			{ /* Critical: administrators concealed from the Users screen. */ }
			{ hiddenAdmins.length > 0 && (
				<Card className="gs-breach">
					<div className="gs-alert gs-alert--danger">
						<Icon name="alert" size={ 20 } />
						<div>
							<strong>{ __( 'Hidden administrator detected', 'gemsecurity' ) }</strong>
							<p>
								{ audit && sprintf(
									/* translators: 1: database admin count, 2: count visible in wp-admin. */
									__( 'Your database contains %1$d administrator account(s) but only %2$d are visible on the WordPress Users screen. An account that is present but hidden from the list is a strong sign the site has been compromised — malicious code is filtering it out so it cannot be removed the normal way.', 'gemsecurity' ),
									audit.raw_count,
									audit.visible_count
								) }
							</p>
						</div>
					</div>

					<ul className="gs-admins gs-admins--hidden">
						{ hiddenAdmins.map( ( a ) => (
							<li key={ a.id } className="gs-admins__row gs-admins__row--hidden">
								<span className="gs-admins__info">
									<span className="gs-admins__name">
										{ a.display_name } <span className="gs-muted">({ a.login })</span>
										<Badge tone="danger">{ __( 'Hidden', 'gemsecurity' ) }</Badge>
										{ a.protected && <Badge tone="info">{ __( 'Protected', 'gemsecurity' ) }</Badge> }
									</span>
									<span className="gs-admins__email">
										{ a.email } · { sprintf( __( 'ID %d', 'gemsecurity' ), a.id ) } · { sprintf( __( 'registered %s', 'gemsecurity' ), a.registered ) }
									</span>
								</span>
								<RemoveActions admin={ a } />
							</li>
						) ) }
					</ul>

					<p className="gs-breach__hint">
						{ __( 'After removing the account, run a full malware scan (Malware Scan detects the code that hides admins) and rotate every administrator password — the entry point that created this account is likely still present.', 'gemsecurity' ) }
					</p>
				</Card>
			) }

			{ /* Warning: accounts that look planted even if not proven hidden. */ }
			{ suspiciousAdmins.length > 0 && (
				<Card className="gs-breach gs-breach--warn">
					<div className="gs-alert gs-alert--warning">
						<Icon name="alert" size={ 20 } />
						<div>
							<strong>{ __( 'Suspicious administrator account', 'gemsecurity' ) }</strong>
							<p>
								{ __( 'These administrator accounts have hallmarks of an injected back-door (for example a non-routable e-mail address). Review each one — if you do not recognise it, remove it and run a malware scan.', 'gemsecurity' ) }
							</p>
						</div>
					</div>

					<ul className="gs-admins gs-admins--hidden">
						{ suspiciousAdmins.map( ( a ) => (
							<li key={ a.id } className="gs-admins__row gs-admins__row--hidden">
								<span className="gs-admins__info">
									<span className="gs-admins__name">
										{ a.display_name } <span className="gs-muted">({ a.login })</span>
										<Badge tone="warning">{ __( 'Suspicious', 'gemsecurity' ) }</Badge>
										{ a.protected && <Badge tone="info">{ __( 'Protected', 'gemsecurity' ) }</Badge> }
									</span>
									<span className="gs-admins__email">
										{ a.email }{ a.suspicious_reason ? ` · ${ a.suspicious_reason }` : '' }
									</span>
								</span>
								<RemoveActions admin={ a } />
							</li>
						) ) }
					</ul>
				</Card>
			) }

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

				<Field
					label={ __( 'Existing administrators', 'gemsecurity' ) }
					description={ __( 'The whitelist is swept hourly, and whenever you change it, so unapproved accounts that never sign in are removed too. Check what that would affect here.', 'gemsecurity' ) }
				>
					<div className="gs-addrow">
						<Button variant="secondary" onClick={ previewSweep } loading={ sweeping === 'preview' }>
							{ __( 'Check for unapproved admins', 'gemsecurity' ) }
						</Button>
						{ sweep && ! sweep.done && sweep.removed && sweep.removed.length > 0 && (
							<Button variant="danger" onClick={ runSweep } loading={ sweeping === 'run' }>
								{ 'delete' === sweep.action
									? __( 'Delete them now', 'gemsecurity' )
									: __( 'Demote them now', 'gemsecurity' ) }
							</Button>
						) }
					</div>
				</Field>

				{ sweep && ! sweep.ran && (
					<div className="gs-alert gs-alert--warning">
						<Icon name="alert" size={ 18 } />
						<span>{ __( 'The sweep does not run while the whitelist is empty or the guard is off — otherwise every administrator would count as unapproved.', 'gemsecurity' ) }</span>
					</div>
				) }

				{ sweep && sweep.ran && (
					<div className={ `gs-alert gs-alert--${ sweep.removed.length ? 'warning' : 'info' }` }>
						<Icon name={ sweep.removed.length ? 'alert' : 'check' } size={ 18 } />
						<span>
							{ sweep.done
								? sprintf(
									/* translators: 1: count, 2: demoted|deleted */
									__( '%1$d unapproved administrator(s) %2$s.', 'gemsecurity' ),
									sweep.removed.length,
									'delete' === sweep.action ? __( 'deleted', 'gemsecurity' ) : __( 'demoted', 'gemsecurity' )
								)
								: sprintf(
									/* translators: 1: checked, 2: count, 3: delete|demote */
									__( 'Checked %1$d administrator(s): %2$d not on the whitelist and would be %3$s.', 'gemsecurity' ),
									sweep.checked,
									sweep.removed.length,
									'delete' === sweep.action ? __( 'deleted', 'gemsecurity' ) : __( 'demoted', 'gemsecurity' )
								) }
							{ sweep.removed.length > 0 && (
								<> { sweep.removed.map( ( u ) => u.login ).join( ', ' ) }</>
							) }
							{ sweep.protected && sweep.protected.length > 0 && (
								<>
									{ ' · ' }
									{ sprintf(
										/* translators: %s: comma-separated usernames */
										__( 'Protected, never removed: %s', 'gemsecurity' ),
										sweep.protected.map( ( u ) => u.login ).join( ', ' )
									) }
								</>
							) }
						</span>
					</div>
				) }
			</Card>

			<Card
				title={ __( 'Hidden administrator detection', 'gemsecurity' ) }
				description={ __( 'Reconciles the real administrator list in the database against what the Users screen shows, exposing back-door accounts that malware hides with a query filter.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Detect hidden administrators', 'gemsecurity' ) }
					description={ __( 'Runs on the daily scan, when the Users screen is opened, and whenever this page is loaded.', 'gemsecurity' ) }
					checked={ form.hidden_admin_detection }
					onChange={ ( v ) => setField( 'hidden_admin_detection', v ) }
				/>
				<Toggle
					label={ __( 'Email the site owner when a hidden admin is detected', 'gemsecurity' ) }
					checked={ form.notify_on_hidden_admin }
					onChange={ ( v ) => setField( 'notify_on_hidden_admin', v ) }
				/>
				{ allClear && (
					<div className="gs-ok">
						<Icon name="check" size={ 18 } />
						<span>
							{ sprintf(
								/* translators: %d: administrator count. */
								__( 'All %d administrator account(s) are accounted for — none are hidden or suspicious.', 'gemsecurity' ),
								audit.raw_count
							) }
						</span>
					</div>
				) }
			</Card>

			<Card
				title={ __( 'Approved administrators', 'gemsecurity' ) }
				description={ __( 'Check every administrator that should be allowed to keep their role. Unapproved accounts you do not recognise can be removed directly.', 'gemsecurity' ) }
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
											{ a.hidden && <Badge tone="danger">{ __( 'Hidden', 'gemsecurity' ) }</Badge> }
											{ a.suspicious && ! a.hidden && <Badge tone="warning">{ __( 'Suspicious', 'gemsecurity' ) }</Badge> }
										</span>
										<span className="gs-admins__email">{ a.email }</span>
									</span>
								</label>
								<span className="gs-admins__trailing">
									{ inList( a.email ) ? (
										<Badge tone="success">{ __( 'Approved', 'gemsecurity' ) }</Badge>
									) : (
										<Badge tone="warning">{ __( 'Not approved', 'gemsecurity' ) }</Badge>
									) }
									{ ! inList( a.email ) && ! a.protected && ! a.hidden && ! a.suspicious && (
										<Button
											variant="secondary"
											loading={ busyId === a.id }
											disabled={ busyId !== 0 }
											onClick={ () => removeAdmin( a, 'delete' ) }
										>
											{ __( 'Delete', 'gemsecurity' ) }
										</Button>
									) }
								</span>
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
