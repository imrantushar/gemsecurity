import React, { useEffect, useRef, useState } from 'react';
import Icon from '@Components/ui/Icon';
import { isPro, ProBadge } from '@Components/ui/Pro';
import { useNavGroups, pageUrl } from '@Utils/nav';

/**
 * Topbar navigation: one tab per module group. A group with several visible
 * modules opens a dropdown listing them; a single-module group is a plain link.
 *
 * @param {Object}   props
 * @param {string}   props.current  Active page slug.
 * @param {Function} props.onNavigate Called with an admin href for client-side routing.
 */
export default function TopNav( { current, onNavigate } ) {
	const groups = useNavGroups();
	const [ open, setOpen ] = useState( null );
	const ref = useRef( null );

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

	// Same modifier-click handling as the sub-nav: new tab/window stays native.
	const go = ( e, href ) => {
		if ( e.metaKey || e.ctrlKey || e.shiftKey || e.altKey ) {
			return;
		}
		e.preventDefault();
		setOpen( null );
		onNavigate( href );
	};

	return (
		<nav className="gs-topnav" ref={ ref }>
			{ groups.map( ( g ) => {
				const isActive = g.items.some( ( i ) => i.key === current );
				const cls = `gs-topnav__tab ${ isActive ? 'is-active' : '' }`;

				if ( g.items.length === 1 ) {
					const href = pageUrl( g.lead );
					return (
						<a key={ g.id } href={ href } className={ cls } onClick={ ( e ) => go( e, href ) }>
							<Icon name={ g.icon } size={ 16 } />
							<span>{ g.title }</span>
						</a>
					);
				}

				const expanded = open === g.id;
				return (
					<div key={ g.id } className={ `gs-topnav__group ${ expanded ? 'is-open' : '' }` }>
						<button
							type="button"
							className={ cls }
							aria-haspopup="true"
							aria-expanded={ expanded }
							onClick={ () => setOpen( expanded ? null : g.id ) }
						>
							<Icon name={ g.icon } size={ 16 } />
							<span>{ g.title }</span>
							<Icon name="chevron" size={ 14 } />
						</button>
						{ expanded && (
							<div className="gs-topnav__menu" role="menu">
								{ g.items.map( ( item ) => {
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
								} ) }
							</div>
						) }
					</div>
				);
			} ) }
		</nav>
	);
}
