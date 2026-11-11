import React, { useEffect, useRef, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api, { GS } from '@Utils/api';
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
	const [ editing, setEditing ] = useState( null ); // the connection being edited

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
								right={ (
									<>
										<Button variant="secondary" onClick={ () => setEditing( c ) }>{ __( 'Edit', 'gemsecurity' ) }</Button>
										{ ' ' }
										<Button variant="secondary" onClick={ () => removeSso( c.id ) }>{ __( 'Remove', 'gemsecurity' ) }</Button>
									</>
								) }
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
					onAdded={ ( close ) => { if ( close ) { setAddOpen( false ); } loadSso(); } }
					toast={ toast }
				/>
			) }

			{ editing && (
				<EditConnectionModal
					connection={ editing }
					onClose={ () => setEditing( null ) }
					onSaved={ () => { setEditing( null ); loadSso(); } }
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

/** Read the public parts of a pairing code (site address + chosen title/logo) without trusting it. */
function decodeCode( raw ) {
	try {
		const b64 = raw.trim().replace( /-/g, '+' ).replace( /_/g, '/' );
		const data = JSON.parse( window.atob( b64 + '==='.slice( ( b64.length + 3 ) % 4 ) ) );
		return data && typeof data.url === 'string' && /^[a-f0-9]{64}$/.test( data.secret || '' ) ? data : null;
	} catch ( e ) {
		return null;
	}
}

const siteHost = () => {
	try {
		return new URL( GS.home_url || window.location.origin ).host;
	} catch ( e ) {
		return window.location.host;
	}
};

/** Exactly what the login button on the other site will look like. */
function ButtonPreview( { title, logo } ) {
	const name = ( title || '' ).trim() || siteHost();
	return (
		<div className="gsc-pair__preview">
			<span className="gsc-pair__preview-label">{ __( 'Login button preview', 'gemsecurity' ) }</span>
			<span className="gsc-pair__btn">
				{ logo ? <img src={ logo } alt="" /> : <span className="gsc-pair__btn-mono">{ name.charAt( 0 ).toUpperCase() }</span> }
				<span>{ sprintf( /* translators: %s: site name. */ __( 'Log in with %s', 'gemsecurity' ), name ) }</span>
			</span>
		</div>
	);
}

/** Upload (or remove) a logo. Shows the current image, a drop zone, and the size/type rules. */
function LogoPicker( { value, onChange, toast } ) {
	const input = useRef( null );
	const [ busy, setBusy ] = useState( false );
	const [ drag, setDrag ] = useState( false );
	const [ byUrl, setByUrl ] = useState( false );

	const upload = async ( file ) => {
		if ( ! file ) {
			return;
		}
		if ( ! /^image\/(png|jpe?g|gif|webp)$/.test( file.type ) ) {
			toast( __( 'Use a PNG, JPG, GIF or WebP image.', 'gemsecurity' ), 'error' );
			return;
		}
		if ( file.size > 1024 * 1024 ) {
			toast( __( 'The logo must be 1 MB or smaller.', 'gemsecurity' ), 'error' );
			return;
		}
		const form = new window.FormData();
		form.append( 'logo', file );
		setBusy( true );
		try {
			const r = await api.post( 'sso/logo', form, { headers: { 'Content-Type': 'multipart/form-data' } } );
			onChange( r.data.url );
		} catch ( err ) {
			toast( err?.response?.data?.message || __( 'Could not upload that image.', 'gemsecurity' ), 'error' );
		} finally {
			setBusy( false );
			if ( input.current ) {
				input.current.value = '';
			}
		}
	};

	return (
		<div
			className={ `gsc-pair__logo${ drag ? ' is-drag' : '' }` }
			onDragOver={ ( e ) => { e.preventDefault(); setDrag( true ); } }
			onDragLeave={ () => setDrag( false ) }
			onDrop={ ( e ) => { e.preventDefault(); setDrag( false ); upload( e.dataTransfer.files?.[ 0 ] ); } }
		>
			<div className="gsc-pair__logo-thumb">
				{ value ? <img src={ value } alt="" /> : <span aria-hidden="true">+</span> }
			</div>
			<div className="gsc-pair__logo-body">
				<div className="gsc-pair__logo-actions">
					<Button variant="secondary" type="button" loading={ busy } onClick={ () => input.current?.click() }>
						{ value ? __( 'Replace', 'gemsecurity' ) : __( 'Upload logo', 'gemsecurity' ) }
					</Button>
					{ value && <Button variant="secondary" type="button" onClick={ () => onChange( '' ) }>{ __( 'Remove', 'gemsecurity' ) }</Button> }
				</div>
				{ byUrl ? (
					<TextInput type="url" value={ value } onChange={ ( e ) => onChange( e.target.value ) } placeholder="https://example.com/logo.png" />
				) : (
					<span className="gsc-pair__hint">{ __( 'Square PNG, JPG or WebP, up to 1 MB. Drop a file here or upload.', 'gemsecurity' ) }</span>
				) }
				<button type="button" className="gsc-pair__link" onClick={ () => setByUrl( ! byUrl ) }>
					{ byUrl ? __( 'Upload a file instead', 'gemsecurity' ) : __( 'Use an image address instead', 'gemsecurity' ) }
				</button>
			</div>
			<input ref={ input } type="file" accept="image/png,image/jpeg,image/gif,image/webp" hidden onChange={ ( e ) => upload( e.target.files?.[ 0 ] ) } />
		</div>
	);
}

function Steps( { steps, current } ) {
	return (
		<ol className="gsc-pair__steps">
			{ steps.map( ( label, i ) => (
				<li key={ label } className={ i < current ? 'is-done' : i === current ? 'is-current' : '' }>
					<span className="gsc-pair__step-dot">{ i < current ? '✓' : i + 1 }</span>
					<span>{ label }</span>
				</li>
			) ) }
		</ol>
	);
}

/**
 * Pairing wizard. Either end can start:
 *   Share this site  → address of the other site → title + logo for the login button → one-time code.
 *   Use a code       → paste → see who it connects to and how the button will look → connect.
 */
function AddConnectionModal( { onClose, onAdded, toast } ) {
	const [ mode, setMode ] = useState( null ); // null | 'create' | 'paste'
	const [ step, setStep ] = useState( 0 );
	const [ url, setUrl ] = useState( '' );
	const [ title, setTitle ] = useState( GS.site_name || '' );
	const [ logo, setLogo ] = useState( GS.site_icon || '' );
	const [ code, setCode ] = useState( '' );
	const [ generated, setGenerated ] = useState( '' );
	const [ copied, setCopied ] = useState( false );
	const [ busy, setBusy ] = useState( false );
	const [ error, setError ] = useState( '' );

	useEffect( () => {
		const onKey = ( e ) => e.key === 'Escape' && onClose();
		document.addEventListener( 'keydown', onKey );
		return () => document.removeEventListener( 'keydown', onKey );
	}, [ onClose ] );

	const urlOk = /^https?:\/\/[^\s/]+\.[^\s]+$/i.test( url.trim() ) || /^https?:\/\/localhost/i.test( url.trim() );
	const decoded = code.trim() ? decodeCode( code ) : null;

	const generate = async () => {
		setBusy( true );
		setError( '' );
		try {
			const r = await api.post( 'sso/pair', { site_url: url.trim(), label: title.trim(), icon: logo } );
			setGenerated( r.data.code );
			setStep( 2 );
			onAdded( false );
		} catch ( err ) {
			setError( err?.response?.data?.message || __( 'Could not create a code.', 'gemsecurity' ) );
		} finally {
			setBusy( false );
		}
	};

	const accept = async ( e ) => {
		e.preventDefault();
		setBusy( true );
		setError( '' );
		try {
			await api.post( 'sso/connect', { code: code.trim() } );
			toast( __( 'Connected. The login button is live.', 'gemsecurity' ), 'success' );
			onAdded( true );
		} catch ( err ) {
			setError( err?.response?.data?.message || __( 'Could not accept that code.', 'gemsecurity' ) );
		} finally {
			setBusy( false );
		}
	};

	const copy = () => {
		navigator.clipboard?.writeText( generated );
		setCopied( true );
		window.setTimeout( () => setCopied( false ), 2000 );
	};

	const back = () => {
		setError( '' );
		if ( step > 0 && ! generated ) {
			setStep( step - 1 );
		} else {
			setMode( null );
			setStep( 0 );
		}
	};

	const heading = { null: __( 'Add a single sign-on connection', 'gemsecurity' ), create: __( 'Share this site\'s sign-in', 'gemsecurity' ), paste: __( 'Connect with a pairing code', 'gemsecurity' ) }[ String( mode ) ];

	return (
		<div className="gs-modal" role="dialog" aria-modal="true" aria-label={ heading } onMouseDown={ ( e ) => e.target === e.currentTarget && onClose() }>
			<div className="gs-modal__box gs-modal__box--sm gsc-pair">
				<div className="gs-modal__head">
					<strong>{ heading }</strong>
					<button type="button" className="gs-modal__x" onClick={ onClose } aria-label={ __( 'Close', 'gemsecurity' ) }>×</button>
				</div>

				{ mode === null && (
					<div className="gs-modal__form">
						<p className="gs-modal__note">{ __( 'A connection lets customers who have an account on one site sign in to the other with one click. Start on whichever site you are on now.', 'gemsecurity' ) }</p>
						<button type="button" className="gsc-pair__choice" onClick={ () => setMode( 'create' ) }>
							<span className="gsc-pair__choice-icon" aria-hidden="true">↗</span>
							<span>
								<strong>{ __( 'Customers sign in with this site', 'gemsecurity' ) }</strong>
								<span>{ __( 'This site holds the customer accounts. Set the button title and logo, then get a code for the other site.', 'gemsecurity' ) }</span>
							</span>
						</button>
						<button type="button" className="gsc-pair__choice" onClick={ () => setMode( 'paste' ) }>
							<span className="gsc-pair__choice-icon" aria-hidden="true">⇣</span>
							<span>
								<strong>{ __( 'I have a pairing code', 'gemsecurity' ) }</strong>
								<span>{ __( 'Another site gave you a code. Paste it here to add its login button to this site.', 'gemsecurity' ) }</span>
							</span>
						</button>
					</div>
				) }

				{ mode === 'create' && (
					<>
						<Steps steps={ [ __( 'Other site', 'gemsecurity' ), __( 'Branding', 'gemsecurity' ), __( 'Pairing code', 'gemsecurity' ) ] } current={ step } />

						{ step === 0 && (
							<form className="gs-modal__form" onSubmit={ ( e ) => { e.preventDefault(); if ( urlOk ) { setStep( 1 ); } } }>
								<Field label={ __( 'Address of the other site', 'gemsecurity' ) } description={ __( 'The site where customers will see the login button, e.g. your support or community site.', 'gemsecurity' ) }>
									<TextInput type="url" required autoFocus value={ url } onChange={ ( e ) => setUrl( e.target.value ) } placeholder="https://support.example.com" />
								</Field>
								<div className="gs-modal__foot">
									<Button variant="secondary" type="button" onClick={ back }>{ __( 'Back', 'gemsecurity' ) }</Button>
									<Button type="submit" disabled={ ! urlOk }>{ __( 'Continue', 'gemsecurity' ) }</Button>
								</div>
							</form>
						) }

						{ step === 1 && (
							<form className="gs-modal__form" onSubmit={ ( e ) => { e.preventDefault(); generate(); } }>
								<Field label={ __( 'Connection title', 'gemsecurity' ) } description={ __( 'Shown on the other site\'s button as "Log in with …".', 'gemsecurity' ) }>
									<TextInput required maxLength={ 60 } autoFocus value={ title } onChange={ ( e ) => setTitle( e.target.value ) } placeholder={ siteHost() } />
								</Field>
								<Field label={ __( 'Logo', 'gemsecurity' ) }>
									<LogoPicker value={ logo } onChange={ setLogo } toast={ toast } />
								</Field>
								<ButtonPreview title={ title } logo={ logo } />
								{ error && <div className="gsc-pair__error">{ error }</div> }
								<div className="gs-modal__foot">
									<Button variant="secondary" type="button" onClick={ back }>{ __( 'Back', 'gemsecurity' ) }</Button>
									<Button type="submit" loading={ busy } disabled={ ! title.trim() }>{ __( 'Generate code', 'gemsecurity' ) }</Button>
								</div>
							</form>
						) }

						{ step === 2 && (
							<div className="gs-modal__form">
								<div className="gsc-pair__success">{ sprintf( /* translators: %s: site address. */ __( 'Connection to %s created. Finish it on that site.', 'gemsecurity' ), url.trim() ) }</div>
								<div className="gsc-pair__codebox">
									<textarea readOnly value={ generated } rows={ 4 } className="gsc-admin__code" onFocus={ ( e ) => e.target.select() } />
									<Button type="button" onClick={ copy }>{ copied ? __( 'Copied ✓', 'gemsecurity' ) : __( 'Copy code', 'gemsecurity' ) }</Button>
								</div>
								<ol className="gsc-pair__howto">
									<li>{ sprintf( /* translators: %s: site address. */ __( 'Open GemSecurity → Site Connect on %s.', 'gemsecurity' ), url.trim() ) }</li>
									<li>{ __( 'Click Add connection, then "I have a pairing code".', 'gemsecurity' ) }</li>
									<li>{ __( 'Paste this code and click Connect.', 'gemsecurity' ) }</li>
								</ol>
								<p className="gsc-pair__warn">{ __( 'Treat this code like a password: it is shown only once and contains the connection secret. Close without copying and you will need to remove the connection and start again.', 'gemsecurity' ) }</p>
								<div className="gs-modal__foot">
									<Button type="button" onClick={ onClose }>{ __( 'Done', 'gemsecurity' ) }</Button>
								</div>
							</div>
						) }
					</>
				) }

				{ mode === 'paste' && (
					<form className="gs-modal__form" onSubmit={ accept }>
						<Field label={ __( 'Pairing code', 'gemsecurity' ) } description={ __( 'This site checks the other end before saving anything.', 'gemsecurity' ) }>
							<textarea required autoFocus value={ code } onChange={ ( e ) => { setCode( e.target.value ); setError( '' ); } } rows={ 4 } className="gsc-admin__code" placeholder={ __( 'Paste the code here', 'gemsecurity' ) } />
						</Field>
						{ code.trim() && ! decoded && <div className="gsc-pair__error">{ __( 'This does not look like a pairing code. Copy it again from the other site.', 'gemsecurity' ) }</div> }
						{ decoded && (
							<>
								<div className="gsc-pair__peer">
									{ sprintf( /* translators: %s: site address. */ __( 'Customers of %s will be able to sign in here.', 'gemsecurity' ), decoded.url ) }
								</div>
								<ButtonPreview title={ decoded.label || ( () => { try { return new URL( decoded.url ).host; } catch ( x ) { return decoded.url; } } )() } logo={ decoded.icon || '' } />
								<span className="gsc-pair__hint">{ __( 'You can change the title and logo later with Edit.', 'gemsecurity' ) }</span>
							</>
						) }
						{ error && <div className="gsc-pair__error">{ error }</div> }
						<div className="gs-modal__foot">
							<Button variant="secondary" type="button" onClick={ back }>{ __( 'Back', 'gemsecurity' ) }</Button>
							<Button type="submit" loading={ busy } disabled={ ! decoded }>{ __( 'Connect', 'gemsecurity' ) }</Button>
						</div>
					</form>
				) }
			</div>
		</div>
	);
}

/**
 * Override the login button's label and icon for one pairing. Empty fields clear the override and fall back
 * to the paired site's own title and site icon (as it reported through /sso/ping).
 */
function EditConnectionModal( { connection, onClose, onSaved, toast } ) {
	const [ label, setLabel ] = useState( connection.label || '' );
	const [ icon, setIcon ] = useState( connection.icon_override || '' );
	const [ busy, setBusy ] = useState( false );

	useEffect( () => {
		const onKey = ( e ) => e.key === 'Escape' && onClose();
		document.addEventListener( 'keydown', onKey );
		return () => document.removeEventListener( 'keydown', onKey );
	}, [ onClose ] );

	const save = async ( e ) => {
		e.preventDefault();
		setBusy( true );
		try {
			await api.post( 'sso/connection/update', { id: connection.id, label, icon } );
			toast( __( 'Login button updated.', 'gemsecurity' ), 'success' );
			onSaved();
		} catch ( err ) {
			toast( err?.response?.data?.message || __( 'Could not save those changes.', 'gemsecurity' ), 'error' );
		} finally {
			setBusy( false );
		}
	};

	const previewName = ( label || connection.name || connection.url ).trim();
	const previewIcon = icon || connection.icon_source || '';

	return (
		<div className="gs-modal" role="dialog" aria-modal="true" aria-label={ __( 'Edit login button', 'gemsecurity' ) } onMouseDown={ ( e ) => e.target === e.currentTarget && onClose() }>
			<div className="gs-modal__box gs-modal__box--sm gsc-pair">
				<div className="gs-modal__head">
					<strong>{ __( 'Login button', 'gemsecurity' ) }</strong>
					<button type="button" className="gs-modal__x" onClick={ onClose } aria-label={ __( 'Close', 'gemsecurity' ) }>×</button>
				</div>

				<form className="gs-modal__form" onSubmit={ save }>
					<p className="gs-modal__note">
						{ __( 'Override how this connection appears on the login screen. Leave either field empty to use the other site\'s own title and icon.', 'gemsecurity' ) }
					</p>

					<Field label={ __( 'Connection title', 'gemsecurity' ) } description={ __( 'Shown as "Log in with …". Leave empty to use the other site\'s name.', 'gemsecurity' ) }>
						<TextInput
							value={ label }
							onChange={ ( e ) => setLabel( e.target.value ) }
							placeholder={ connection.name || connection.url }
						/>
					</Field>

					<Field label={ __( 'Logo', 'gemsecurity' ) } description={ connection.icon_source ? __( 'Remove to fall back to the other site\'s own icon.', 'gemsecurity' ) : '' }>
						<LogoPicker value={ icon } onChange={ setIcon } toast={ toast } />
					</Field>

					<ButtonPreview title={ previewName } logo={ previewIcon } />

					<div className="gs-modal__foot">
						<Button variant="secondary" type="button" onClick={ onClose }>{ __( 'Cancel', 'gemsecurity' ) }</Button>
						<Button type="submit" loading={ busy }>{ __( 'Save', 'gemsecurity' ) }</Button>
					</div>
				</form>
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
