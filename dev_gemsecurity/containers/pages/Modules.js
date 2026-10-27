import React, { useEffect, useMemo, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api from '@Utils/api';
import { pageUrl, useModules, setModules, getModules } from '@Utils/nav';
import Icon from '@Components/ui/Icon';
import { Toggle, Loading } from '@Components/ui/Controls';
import useNavigate from '@Utils/useGuardedNavigate';
import { useToast } from '@Components/ui/Toast';
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
	// The module list lives in the shared nav store, so every toggle here is
	// reflected in the plugin nav and the WordPress admin menu right away.
	const modules = useModules();
	const [ loading, setLoading ] = useState( ! modules.length );
	const [ savingId, setSavingId ] = useState( null );
	const [ query, setQuery ] = useState( '' );
	const toast = useToast();

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
		setSavingId( mod.id );
		// Optimistic update. A non-core module's menu entry follows its
		// activation, so `visible` moves with it until the server confirms.
		setModules(
			getModules().map( ( m ) =>
				m.id === mod.id
					? { ...m, active: next, visible: m.core ? true : next }
					: m
			)
		);
		try {
			const r = await api.post( 'modules', { id: mod.id, active: next } );
			if ( Array.isArray( r.data?.modules ) ) {
				setModules( r.data.modules );
			}
			toast(
				next
					// translators: %s: module name, e.g. "Firewall".
					? sprintf( __( '%s activated — its menu is now available.', 'gemsecurity' ), mod.title )
					// translators: %s: module name, e.g. "Firewall".
					: sprintf( __( '%s deactivated — removed from the menu.', 'gemsecurity' ), mod.title ),
				'success'
			);
		} catch ( e ) {
			// Roll back on failure.
			setModules(
				getModules().map( ( m ) =>
					m.id === mod.id
						? { ...m, active: ! next, visible: m.core ? true : ! next }
						: m
				)
			);
			toast(
				e?.response?.data?.message ||
					__( 'Could not update the module. Please try again.', 'gemsecurity' ),
				'error'
			);
		} finally {
			setSavingId( null );
		}
	};

	if ( loading ) {
		return <Loading label={ __( 'Loading modules…', 'gemsecurity' ) } />;
	}

	const q = query.trim().toLowerCase();
	const matches = ( m ) => ! q || ( m.title + ' ' + ( m.desc || '' ) ).toLowerCase().includes( q );
	const pct = modules.length ? ( activeCount / modules.length ) * 100 : 0;

	return (
		<div className="gs-page gs-modules">
			<section className="gs-modules__head">
				<div className="gs-modules__head-text">
					<h2>{ __( 'Security modules', 'gemsecurity' ) }</h2>
					<p>
						{ __(
							'Turn features on or off. Inactive modules don’t load their pages, settings or background code — keep only what this site needs.',
							'gemsecurity'
						) }
					</p>
				</div>
				<div className="gs-modules__progress">
					<div>
						<span>{ __( 'Active', 'gemsecurity' ) }</span>
						<strong>{ sprintf( /* translators: 1: active, 2: total */ __( '%1$d of %2$d', 'gemsecurity' ), activeCount, modules.length ) }</strong>
					</div>
					<i><b style={ { width: `${ pct }%` } } /></i>
				</div>
				<label className="gs-modules__search">
					<Icon name="radar" size={ 16 } />
					<input
						type="search"
						value={ query }
						placeholder={ __( 'Search modules', 'gemsecurity' ) }
						onChange={ ( e ) => setQuery( e.target.value ) }
					/>
				</label>
			</section>

			{ CATEGORIES.map( ( cat ) => {
				const all = grouped[ cat.key ];
				if ( ! all || ! all.length ) {
					return null;
				}
				const items = all.filter( matches );
				if ( ! items.length ) {
					return null;
				}
				const on = all.filter( ( m ) => m.active ).length;
				return (
					<div key={ cat.key } className="gs-modules__group">
						<h3 className="gs-modules__group-title">
							{ cat.label }
							<span>
								{ cat.key === 'core'
									? __( 'Always on', 'gemsecurity' )
									: sprintf( /* translators: 1: active, 2: total */ __( '%1$d of %2$d on', 'gemsecurity' ), on, all.length ) }
							</span>
						</h3>
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
	const navigate = useNavigate();
	const proLockedOff = mod.is_pro && ! isPro();

	let control;
	if ( mod.core ) {
		control = (
			<span className="gs-module-card__always"><Icon name="lock" size={ 12 } />{ __( 'Always on', 'gemsecurity' ) }</span>
		);
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

	const href = mod.page_slug ? pageUrl( mod.page_slug ) : null;
	const status = mod.core
		? __( 'Active · Core', 'gemsecurity' )
		: mod.active ? __( 'Active', 'gemsecurity' ) : __( 'Off', 'gemsecurity' );

	return (
		<div
			className={ `gs-module-card ${ mod.active ? 'is-active' : '' } ${
				proLockedOff ? 'is-locked' : ''
			}` }
		>
			<div className="gs-module-card__top">
				<div className="gs-module-card__icon">
					<Icon name={ mod.icon } size={ 20 } />
				</div>
				<div className="gs-module-card__control">{ control }</div>
			</div>
			<div className="gs-module-card__body">
				<div className="gs-module-card__head">
					<span className="gs-module-card__title">{ mod.title }</span>
					{ mod.is_pro && ! isPro() && <ProBadge /> }
				</div>
				<p className="gs-module-card__desc">{ mod.desc }</p>
			</div>
			<div className="gs-module-card__foot">
				<span className={ `gs-module-card__status ${ mod.active ? 'is-on' : '' }` }>{ status }</span>
				{ mod.active && href && (
					<a
						href={ href }
						className="gs-module-card__cfg"
						onClick={ ( e ) => {
							if ( e.metaKey || e.ctrlKey || e.shiftKey || e.altKey ) {
								return;
							}
							e.preventDefault();
							navigate( href );
						} }
					>
						{ __( 'Configure', 'gemsecurity' ) }
						<Icon name="arrow-right" size={ 14 } />
					</a>
				) }
			</div>
		</div>
	);
}
