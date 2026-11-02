import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { __ } from '@wordpress/i18n';
import Icon from '@Components/ui/Icon';
import { isPro, ProBadge } from '@Components/ui/Pro';
import { useNavGroups, pageUrl } from '@Utils/nav';

const MORE = '__more';
// Matches `gap` on .gs-topnav; used when summing tab widths to see what fits.
const GAP = 4;

/**
 * Topbar navigation: one tab per module group. A group with several visible
 * modules opens a dropdown listing them; a single-module group is a plain link.
 *
 * The bar never wraps. It shows as many tabs as fit the available width and
 * tucks the rest into a trailing "More" dropdown, so the count adapts to the
 * screen size (and to the WP sidebar being expanded or folded).
 *
 * @param {Object}   props
 * @param {string}   props.current  Active page slug.
 * @param {Function} props.onNavigate Called with an admin href for client-side routing.
 */
export default function TopNav( { current, onNavigate } ) {
	const groups = useNavGroups();
	const [ open, setOpen ] = useState( null );
	// How many leading groups stay in the bar; the rest go under "More".
	const [ fit, setFit ] = useState( groups.length );
	const ref = useRef( null );
	const measureRef = useRef( null );

	// Close on outside click / Escape.
	useEffect( () => {
		if ( ! open ) {
			return undefined;
		}
		const onDown = ( e ) => {
			if ( ref.current && ! ref.current.contains( e.target ) ) {
				setOpen( null );
			}
		};
		const onKey = ( e ) => e.key === 'Escape' && setOpen( null );
		document.addEventListener( 'mousedown', onDown );
		document.addEventListener( 'keydown', onKey );
		return () => {
			document.removeEventListener( 'mousedown', onDown );
			document.removeEventListener( 'keydown', onKey );
		};
	}, [ open ] );

	// Work out how many tabs fit. A hidden, unwrapped copy of every tab (plus
	// the More button, last) supplies natural widths independent of what is
	// currently shown.
	useLayoutEffect( () => {
		const box = ref.current;
		const meas = measureRef.current;
		if ( ! box || ! meas ) {
			return undefined;
		}
		const compute = () => {
			const widths = Array.from( meas.children ).map( ( el ) => el.offsetWidth );
			const moreW = widths.pop() || 0;
			const avail = box.clientWidth;
			const total = widths.reduce( ( s, w ) => s + w, 0 ) + GAP * Math.max( 0, widths.length - 1 );
			if ( total <= avail ) {
				setFit( widths.length );
				return;
			}
			let used = moreW;
			let n = 0;
			for ( const w of widths ) {
				if ( used + GAP + w > avail ) {
					break;
				}
				used += GAP + w;
				n++;
			}
			setFit( n );
		};
		compute();
		if ( typeof ResizeObserver === 'undefined' ) {
			return undefined;
		}
		const ro = new ResizeObserver( compute );
		ro.observe( box );
		return () => ro.disconnect();
	}, [ groups ] );

	// Same modifier-click handling as the sub-nav: new tab/window stays native.
	const go = ( e, href ) => {
		if ( e.metaKey || e.ctrlKey || e.shiftKey || e.altKey ) {
			return;
		}
		e.preventDefault();
		setOpen( null );
		onNavigate( href );
	};

	const shown = groups.slice( 0, fit );
	const overflow = groups.slice( fit );
	const tabClass = ( active ) => `gs-topnav__tab ${ active ? 'is-active' : '' }`;
	const isActiveGroup = ( g ) => g.items.some( ( i ) => i.key === current );

	const renderItem = ( item ) => {
		const href = pageUrl( item.key );
		return (
			<a
				key={ item.key }
				href={ href }
				role="menuitem"
				className={ `gs-topnav__item ${ item.key === current ? 'is-active' : '' }` }
				onClick={ ( e ) => go( e, href ) }
			>
				<Icon name={ item.icon } size={ 16 } />
				<span>{ item.label }</span>
				{ item.isPro && ! isPro() && <ProBadge /> }
			</a>
		);
	};

	// Tab body shared by the live bar and the hidden measuring copy.
	const renderTab = ( g, interactive ) => {
		const cls = tabClass( interactive && isActiveGroup( g ) );
		if ( g.items.length === 1 ) {
			const href = pageUrl( g.lead );
			return (
				<a
					key={ g.id }
					href={ href }
					className={ cls }
					{ ...( interactive ? { onClick: ( e ) => go( e, href ) } : { tabIndex: -1 } ) }
				>
					<Icon name={ g.icon } size={ 16 } />
					<span>{ g.title }</span>
				</a>
			);
		}
		const expanded = interactive && open === g.id;
		return (
			<div key={ g.id } className={ `gs-topnav__group ${ expanded ? 'is-open' : '' }` }>
				<button
					type="button"
					className={ cls }
					aria-haspopup="true"
					aria-expanded={ expanded }
					tabIndex={ interactive ? undefined : -1 }
					onClick={ interactive ? () => setOpen( expanded ? null : g.id ) : undefined }
				>
					<Icon name={ g.icon } size={ 16 } />
					<span>{ g.title }</span>
					<Icon name="chevron" size={ 14 } />
				</button>
				{ expanded && (
					<div className="gs-topnav__menu" role="menu">
						{ g.items.map( renderItem ) }
					</div>
				) }
			</div>
		);
	};

	const moreLabel = __( 'More', 'gemsecurity' );
	const moreOpen = open === MORE;

	return (
		<nav className="gs-topnav" ref={ ref }>
			{ shown.map( ( g ) => renderTab( g, true ) ) }

			{ overflow.length > 0 && (
				<div className={ `gs-topnav__group ${ moreOpen ? 'is-open' : '' }` }>
					<button
						type="button"
						className={ tabClass( overflow.some( isActiveGroup ) ) }
						aria-haspopup="true"
						aria-expanded={ moreOpen }
						onClick={ () => setOpen( moreOpen ? null : MORE ) }
					>
						<Icon name="grid" size={ 16 } />
						<span>{ moreLabel }</span>
						<Icon name="chevron" size={ 14 } />
					</button>
					{ moreOpen && (
						<div className="gs-topnav__menu gs-topnav__menu--end" role="menu">
							{ overflow.map( ( g ) =>
								g.items.length === 1 ? (
									renderItem( { ...g.items[ 0 ], label: g.title, icon: g.icon } )
								) : (
									<React.Fragment key={ g.id }>
										<span className="gs-topnav__heading">{ g.title }</span>
										{ g.items.map( renderItem ) }
									</React.Fragment>
								)
							) }
						</div>
					) }
				</div>
			) }

			{ /* Hidden copy used only to measure natural tab widths. */ }
			<div className="gs-topnav__measure" ref={ measureRef } aria-hidden="true">
				{ groups.map( ( g ) => renderTab( g, false ) ) }
				<div className="gs-topnav__group">
					<button type="button" className={ tabClass( false ) } tabIndex={ -1 }>
						<Icon name="grid" size={ 16 } />
						<span>{ moreLabel }</span>
						<Icon name="chevron" size={ 14 } />
					</button>
				</div>
			</div>
		</nav>
	);
}
