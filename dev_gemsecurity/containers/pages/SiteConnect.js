import React, { useEffect, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api from '@Utils/api';
import { Card, Button, Toggle, TextInput, Field, EmptyState, Loading, Badge } from '@Components/ui/Controls';
import { useToast } from '@Components/ui/Toast';

/**
 * Site Connect + Single Sign-On admin page.
 *
 * Four cards, top to bottom:
 *   New customers        — whether a visitor without an account may create one on the connection screen.
 *   Customer connections — read-only tokens other apps/sites hold for a customer here (one-time code flow).
 *   Single sign-on sites — WordPress-to-WordPress pairings this site makes (out) or accepts (in).
 *   Who can use SSO      — which roles may sign in through a connected site, with a safety nudge on privileged roles.
 */
export default function SiteConnect() {
	const toast = useToast();

	// Customer connections (one-time code flow)
	const [ sites, setSites ] = useState( null );
	const [ signup, setSignup ] = useState( true );

	// SSO pairings
	const [ sso, setSso ] = useState( null ); // { connections: [...], roles: [...] }
	const [ addOpen, setAddOpen ] = useState( false );

	const loadCustomerSites = () =>
		api.get( 'connect/sites' )
			.then( ( r ) => { setSites( r.data.sites ); setSignup( r.data.allow_signup ); } )
			.catch( () => setSites( [] ) );

	const loadSso = () =>
		api.get( 'sso/status' )
			.then( ( r ) => setSso( r.data ) )
			.catch( () => setSso( { connections: [], roles: [] } ) );

	useEffect( () => { loadCustomerSites(); loadSso(); }, [] );

	/* -------------------------------------------------------------------- */
	/* Customer connections                                                  */
	/* -------------------------------------------------------------------- */

	const revokeCustomer = async ( id ) => {
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( __( 'Disconnect this site? It will stop seeing this customer\'s products until they connect again.', 'gemsecurity' ) ) ) {
			return;
		}
		try {
			await api.post( 'connect/sites/revoke', { id } );
			toast( __( 'Site disconnected.', 'gemsecurity' ), 'success' );
			loadCustomerSites();
		} catch ( e ) {
			toast( __( 'Could not disconnect that site.', 'gemsecurity' ), 'error' );
		}
	};

	const toggleSignup = async () => {
		const r = await api.post( 'connect/signup', { allow: ! signup } );
		setSignup( r.data.allow_signup );
	};

	/* -------------------------------------------------------------------- */
	/* SSO pairings                                                          */
	/* -------------------------------------------------------------------- */

	const removeSso = async ( id ) => {
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( __( 'Remove this connection? Sign-in through it will stop at once.', 'gemsecurity' ) ) ) {
			return;
		}
		try {
			await api.post( 'sso/remove', { id } );
			toast( __( 'Connection removed.', 'gemsecurity' ), 'success' );
			loadSso();
		} catch ( e ) {
			toast( __( 'Could not remove that connection.', 'gemsecurity' ), 'error' );
		}
	};

	const toggleRole = async ( role, enabled ) => {
		const nextRoles = ( sso?.roles || [] ).map( ( r ) => ( r.role === role ? { ...r, enabled } : r ) );
		setSso( { ...sso, roles: nextRoles } );

		try {
			const r = await api.post( 'sso/roles', { roles: nextRoles.filter( ( x ) => x.enabled ).map( ( x ) => x.role ) } );
			setSso( { ...sso, roles: r.data.roles } );
		} catch ( e ) {
			toast( __( 'Could not save that change.', 'gemsecurity' ), 'error' );
			loadSso();
		}
	};

	/* -------------------------------------------------------------------- */

	return (
		<div className="gs-page">
			<Card title={ __( 'New customers', 'gemsecurity' ) }>
				<div className="gsc-admin__inline">
					<span>{ signup ? __( 'People without an account can create one on the connection screen.', 'gemsecurity' ) : __( 'Only existing accounts can connect.', 'gemsecurity' ) }</span>
					<Button variant="secondary" onClick={ toggleSignup }>{ signup ? __( 'Turn off', 'gemsecurity' ) : __( 'Turn on', 'gemsecurity' ) }</Button>
				</div>
			</Card>

			<Card title={ __( 'Customer connections', 'gemsecurity' ) } description={ __( 'Apps and sites holding a read-only token for one of this site\'s customers.', 'gemsecurity' ) }>
				{ sites === null && <Loading /> }
				{ sites && sites.length === 0 && <EmptyState title={ __( 'No sites connected yet', 'gemsecurity' ) } /> }
				{ sites && sites.length > 0 && (
					<div className="gsc-admin__list">
						{ sites.map( ( s ) => (
							<ConnectionRow
								key={ s.id }
								title={ s.site }
								sub={ `${ s.user } · ${ new Date( s.created * 1000 ).toLocaleDateString() }` }
								right={ <Button variant="secondary" onClick={ () => revokeCustomer( s.id ) }>{ __( 'Disconnect', 'gemsecurity' ) }</Button> }
							/>
						) ) }
					</div>
				) }
			</Card>

			<Card
				title={ __( 'Single sign-on sites', 'gemsecurity' ) }
				description={ __( 'Other sites your customers can sign in to without a second password. Each side keeps its own account; this just links them.', 'gemsecurity' ) }
				actions={ <Button onClick={ () => setAddOpen( true ) }>{ __( 'Add connection', 'gemsecurity' ) }</Button> }
			>
				{ sso === null && <Loading /> }
				{ sso && sso.connections.length === 0 && (
					<EmptyState
						title={ __( 'No connections yet', 'gemsecurity' ) }
						description={ __( 'Pair this site with another to let one set of customers sign in to both.', 'gemsecurity' ) }
					/>
				) }
				{ sso && sso.connections.length > 0 && (
					<div className="gsc-admin__list">
						{ sso.connections.map( ( c ) => (
							<ConnectionRow
								key={ c.id }
								title={ c.name || c.url }
								sub={ (
									<>
										<Badge tone={ c.direction === 'in' ? 'info' : 'success' }>
											{ c.direction === 'in' ? __( 'Accepts sign-ins', 'gemsecurity' ) : __( 'Sends customers', 'gemsecurity' ) }
										</Badge>
										{ ' · ' }
										{ sprintf( __( 'Added %s', 'gemsecurity' ), new Date( c.created * 1000 ).toLocaleDateString() ) }
									</>
								) }
								right={ <Button variant="secondary" onClick={ () => removeSso( c.id ) }>{ __( 'Remove', 'gemsecurity' ) }</Button> }
							/>
						) ) }
					</div>
				) }
			</Card>

			<Card title={ __( 'Who can use single sign-on', 'gemsecurity' ) } description={ __( 'Choose which roles may sign in through a connected site. A role must be on at BOTH ends for a user to pass through.', 'gemsecurity' ) }>
				{ sso === null && <Loading /> }
				{ sso?.roles && (
					<div className="gsc-admin__list">
						{ sso.roles.map( ( r ) => (
							<div key={ r.role } className="gsc-admin__row">
								<div className="gsc-admin__row-main">
									<div className="gsc-admin__row-title">
										<strong>{ r.name }</strong>
										{ r.sensitive && <Badge tone="warning">{ __( 'Can manage this site', 'gemsecurity' ) }</Badge> }
									</div>
									<div className="gsc-admin__row-sub">
										{ r.sensitive
											? __( 'A compromised partner site could sign in as anyone with this role. Off by default.', 'gemsecurity' )
											: __( 'Safe to leave on for customer-only roles.', 'gemsecurity' ) }
									</div>
								</div>
								<Toggle checked={ !! r.enabled } onChange={ ( v ) => toggleRole( r.role, v ) } />
							</div>
						) ) }
					</div>
				) }
			</Card>

			{ addOpen && (
				<AddConnectionModal
					onClose={ () => setAddOpen( false ) }
					onAdded={ () => { setAddOpen( false ); loadSso(); } }
					toast={ toast }
				/>
			) }
		</div>
	);
}

function ConnectionRow( { title, sub, right } ) {
	return (
		<div className="gsc-admin__row">
			<div className="gsc-admin__row-main">
				<div className="gsc-admin__row-title"><strong>{ title }</strong></div>
				<div className="gsc-admin__row-sub">{ sub }</div>
			</div>
			{ right }
		</div>
	);
}

/**
 * Two-step pairing: one site creates a code, the other pastes it. Either end can start.
 */
function AddConnectionModal( { onClose, onAdded, toast } ) {
	const [ tab, setTab ] = useState( 'create' );
	const [ url, setUrl ] = useState( '' );
	const [ code, setCode ] = useState( '' );
	const [ generated, setGenerated ] = useState( '' );
	const [ busy, setBusy ] = useState( false );

	useEffect( () => {
		const onKey = ( e ) => e.key === 'Escape' && onClose();
		document.addEventListener( 'keydown', onKey );
		return () => document.removeEventListener( 'keydown', onKey );
	}, [ onClose ] );

	const create = async ( e ) => {
		e.preventDefault();
		setBusy( true );
		try {
			const r = await api.post( 'sso/pair', { site_url: url } );
			setGenerated( r.data.code );
			toast( __( 'Pairing code ready — paste it on the other site.', 'gemsecurity' ), 'success' );
		} catch ( err ) {
			toast( err?.response?.data?.message || __( 'Could not create a code.', 'gemsecurity' ), 'error' );
		} finally {
			setBusy( false );
		}
	};

	const accept = async ( e ) => {
		e.preventDefault();
		setBusy( true );
		try {
			await api.post( 'sso/connect', { code: code.trim() } );
			toast( __( 'Connected.', 'gemsecurity' ), 'success' );
			onAdded();
		} catch ( err ) {
			toast( err?.response?.data?.message || __( 'Could not accept that code.', 'gemsecurity' ), 'error' );
		} finally {
			setBusy( false );
		}
	};

	const copy = () => {
		navigator.clipboard?.writeText( generated );
		toast( __( 'Code copied.', 'gemsecurity' ), 'success' );
	};

	return (
		<div className="gs-modal" role="dialog" aria-modal="true" aria-label={ __( 'Add connection', 'gemsecurity' ) } onMouseDown={ ( e ) => e.target === e.currentTarget && onClose() }>
			<div className="gs-modal__box gs-modal__box--sm">
				<div className="gs-modal__head">
					<strong>{ __( 'Connect another site', 'gemsecurity' ) }</strong>
					<button type="button" className="gs-modal__x" onClick={ onClose } aria-label={ __( 'Close', 'gemsecurity' ) }>×</button>
				</div>

				<div className="gsc-admin__tabs">
					<TabButton active={ tab === 'create' } onClick={ () => { setTab( 'create' ); setGenerated( '' ); } }>{ __( 'Create a code', 'gemsecurity' ) }</TabButton>
					<TabButton active={ tab === 'paste' } onClick={ () => setTab( 'paste' ) }>{ __( 'Paste a code', 'gemsecurity' ) }</TabButton>
				</div>

				{ tab === 'create' && ! generated && (
					<form className="gs-modal__form" onSubmit={ create }>
						<p className="gs-modal__note">
							{ __( 'Enter the address of the other site. You will get a one-time code to paste on that site to finish the pairing.', 'gemsecurity' ) }
						</p>
						<Field label={ __( 'Other site address', 'gemsecurity' ) }>
							<TextInput type="url" required value={ url } onChange={ ( e ) => setUrl( e.target.value ) } placeholder="https://support.example.com" />
						</Field>
						<div className="gs-modal__foot">
							<Button variant="secondary" type="button" onClick={ onClose }>{ __( 'Cancel', 'gemsecurity' ) }</Button>
							<Button type="submit" loading={ busy }>{ __( 'Create code', 'gemsecurity' ) }</Button>
						</div>
					</form>
				) }

				{ tab === 'create' && generated && (
					<div className="gs-modal__form">
						<p className="gs-modal__note">
							{ __( 'Copy this code, open the other site\'s Site Connect page, pick "Paste a code" and paste it in. This code is shown only once.', 'gemsecurity' ) }
						</p>
						<textarea readOnly value={ generated } rows={ 4 } className="gsc-admin__code" />
						<div className="gs-modal__foot">
							<Button variant="secondary" type="button" onClick={ onClose }>{ __( 'Done', 'gemsecurity' ) }</Button>
							<Button type="button" onClick={ copy }>{ __( 'Copy code', 'gemsecurity' ) }</Button>
						</div>
					</div>
				) }

				{ tab === 'paste' && (
					<form className="gs-modal__form" onSubmit={ accept }>
						<p className="gs-modal__note">
							{ __( 'Paste the code the other site gave you. This site will check the other end, then save the pairing.', 'gemsecurity' ) }
						</p>
						<Field label={ __( 'Pairing code', 'gemsecurity' ) }>
							<textarea required value={ code } onChange={ ( e ) => setCode( e.target.value ) } rows={ 4 } className="gsc-admin__code" />
						</Field>
						<div className="gs-modal__foot">
							<Button variant="secondary" type="button" onClick={ onClose }>{ __( 'Cancel', 'gemsecurity' ) }</Button>
							<Button type="submit" loading={ busy }>{ __( 'Connect', 'gemsecurity' ) }</Button>
						</div>
					</form>
				) }
			</div>
		</div>
	);
}

function TabButton( { active, children, ...props } ) {
	return (
		<button type="button" className={ `gsc-admin__tab${ active ? ' gsc-admin__tab--active' : '' }` } { ...props }>
			{ children }
		</button>
	);
}
