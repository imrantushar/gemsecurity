import React, { useEffect, useMemo, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api, { GS } from '@Utils/api';
import Icon from '@Components/ui/Icon';
import { Card, Badge, Toggle, Button, Loading } from '@Components/ui/Controls';
import { ProBadge, isPro, upgradeUrl } from '@Components/ui/Pro';

/* Friendly, ordered category buckets for the manager grid. */
const CATEGORIES = [
	{ key: 'core', label: __( 'Core', 'gemsecurity' ) },
	{ key: 'firewall', label: __( 'Firewall & threats', 'gemsecurity' ) },
	{ key: 'access', label: __( 'Login & access', 'gemsecurity' ) },
	{ key: 'scanning', label: __( 'Scanning', 'gemsecurity' ) },
	{ key: 'logging', label: __( 'Logging', 'gemsecurity' ) },
	{ key: 'maintenance', label: __( 'Maintenance', 'gemsecurity' ) },
];

export default function Modules() {
	const [ modules, setModules ] = useState(
		Array.isArray( GS.modules ) ? GS.modules : []
	);
	const [ loading, setLoading ] = useState( ! modules.length );
	const [ savingId, setSavingId ] = useState( null );
	const [ error, setError ] = useState( null );
	// Set once a toggle succeeds — the WP menu + REST are registered server-side,
	// so a reload is needed for the change to fully take effect.
	const [ pendingReload, setPendingReload ] = useState( false );

	// Refresh authoritative state from the server on mount.
	useEffect( () => {
		let alive = true;
		api.get( 'modules' )
			.then( ( r ) => {
				if ( alive && Array.isArray( r.data?.modules ) ) {
					setModules( r.data.modules );
				}
			} )
			.catch( () => {} )
			.finally( () => alive && setLoading( false ) );
		return () => {
			alive = false;
		};
	}, [] );

	const grouped = useMemo( () => {
		const map = {};
		modules.forEach( ( m ) => {
			( map[ m.category ] = map[ m.category ] || [] ).push( m );
		} );
		return map;
	}, [ modules ] );

	const activeCount = modules.filter( ( m ) => m.active ).length;

	const toggle = async ( mod, next ) => {
		setError( null );
		setSavingId( mod.id );
		// Optimistic update.
		setModules( ( prev ) =>
			prev.map( ( m ) => ( m.id === mod.id ? { ...m, active: next } : m ) )
		);
		try {
			const r = await api.post( 'modules', { id: mod.id, active: next } );
			if ( Array.isArray( r.data?.modules ) ) {
				setModules( r.data.modules );
			}
			setPendingReload( true );
		} catch ( e ) {
			// Roll back on failure.
			setModules( ( prev ) =>
				prev.map( ( m ) => ( m.id === mod.id ? { ...m, active: ! next } : m ) )
			);
			setError(
				e?.response?.data?.message ||
					__( 'Could not update the module. Please try again.', 'gemsecurity' )
			);
		} finally {
			setSavingId( null );
		}
	};

	if ( loading ) {
		return <Loading label={ __( 'Loading modules…', 'gemsecurity' ) } />;
	}

	return (
		<div className="gs-page gs-modules">
			<Card
				title={ __( 'Security modules', 'gemsecurity' ) }
				description={ __(
					'Turn features on or off. Only active modules load their admin pages, settings and background code — activate just what this site needs.',
					'gemsecurity'
				) }
				actions={
					<Badge tone="info">
						{ /* translators: %1$d active, %2$d total. */ }
						{ activeCount +
							' / ' +
							modules.length +
							' ' +
							__( 'active', 'gemsecurity' ) }
					</Badge>
				}
			>
				{ error && <div className="gs-notice gs-notice--error">{ error }</div> }
				{ pendingReload && (
					<div className="gs-notice gs-notice--info">
						{ __(
							'Module changes are saved. Reload the page to apply the updated menu and features.',
							'gemsecurity'
						) }
						<Button
							variant="secondary"
							onClick={ () => window.location.reload() }
							style={ { marginLeft: 12 } }
						>
							{ __( 'Reload now', 'gemsecurity' ) }
						</Button>
					</div>
				) }
			</Card>

			{ CATEGORIES.map( ( cat ) => {
				const items = grouped[ cat.key ];
				if ( ! items || ! items.length ) {
					return null;
				}
				return (
					<div key={ cat.key } className="gs-modules__group">
						<h3 className="gs-modules__group-title">{ cat.label }</h3>
						<div className="gs-modules__grid">
							{ items.map( ( mod ) => (
								<ModuleCard
									key={ mod.id }
									mod={ mod }
									saving={ savingId === mod.id }
									onToggle={ toggle }
								/>
							) ) }
						</div>
					</div>
				);
			} ) }
		</div>
	);
}

function ModuleCard( { mod, saving, onToggle } ) {
	const proLockedOff = mod.is_pro && ! isPro();

	let control;
	if ( mod.core ) {
		control = <Badge tone="success">{ __( 'Always on', 'gemsecurity' ) }</Badge>;
	} else if ( proLockedOff ) {
		control = (
			<a className="gs-modules__upsell" href={ upgradeUrl() } target="_blank" rel="noreferrer">
				{ __( 'Upgrade', 'gemsecurity' ) }
			</a>
		);
	} else {
		control = (
			<Toggle
				checked={ mod.active }
				disabled={ saving }
				onChange={ ( v ) => onToggle( mod, v ) }
			/>
		);
	}

	return (
		<div
			className={ `gs-module-card ${ mod.active ? 'is-active' : '' } ${
				proLockedOff ? 'is-locked' : ''
			}` }
		>
			<div className="gs-module-card__icon">
				<Icon name={ mod.icon } size={ 20 } />
			</div>
			<div className="gs-module-card__body">
				<div className="gs-module-card__head">
					<span className="gs-module-card__title">{ mod.title }</span>
					{ mod.is_pro && ! isPro() && <ProBadge /> }
				</div>
				<p className="gs-module-card__desc">{ mod.desc }</p>
			</div>
			<div className="gs-module-card__control">{ control }</div>
		</div>
	);
}
