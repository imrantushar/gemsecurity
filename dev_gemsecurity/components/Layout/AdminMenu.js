import React, { useLayoutEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router-dom';
import { __ } from '@wordpress/i18n';
import useNavigate from '@Utils/useGuardedNavigate';
import { useActivePage, useNavGroups, pageUrl } from '@Utils/nav';

const SLUG = 'gemsecurity';

// Groups whose pages are listed as a sub-menu under the group in the WP
// sidebar, rather than as tabs inside the page.
export const NESTED_GROUPS = [ 'settings' ];

/**
 * The GemSecurity entry of the native WordPress admin sidebar, rendered by
 * React so every click is a client-side route change instead of a full page
 * load. It is portaled into the server-rendered top-level <li>, replacing the
 * static markup (mirrors GemCRM's AdminMenu).
 */
export default function AdminMenu() {
	const navigate = useNavigate();
	const page = useActivePage();
	const groups = useNavGroups();
	const [ host, setHost ] = useState( null );

	useLayoutEffect( () => {
		const el = document.getElementById( `toplevel_page_${ SLUG }` );
		if ( el ) {
			el.innerHTML = '';
			setHost( el );
		}
	}, [] );

	if ( ! host ) {
		return null;
	}

	// Modified clicks (new tab/window) keep native behavior; the rest route
	// client-side through the unsaved-changes guard.
	const go = ( to ) => ( e ) => {
		if ( e.metaKey || e.ctrlKey || e.shiftKey || e.altKey ) {
			return;
		}
		e.preventDefault();
		navigate( to );
	};

	const title = __( 'GemSecurity', 'gemsecurity' );
	const topUrl = pageUrl( SLUG );

	return createPortal(
		<>
			<Link
				to={ topUrl }
				onClick={ go( topUrl ) }
				className={ `wp-has-submenu wp-has-current-submenu wp-menu-open menu-top toplevel_page_${ SLUG } menu-top-first menu-top-last` }
				aria-haspopup="false"
			>
				<div className="wp-menu-arrow"><div /></div>
				<div className="wp-menu-image dashicons-before dashicons-shield" aria-hidden="true"><br /></div>
				<div className="wp-menu-name">{ title }</div>
			</Link>
			<ul className="wp-submenu wp-submenu-wrap">
				<li className="wp-submenu-head" aria-hidden="true">{ title }</li>
				{ groups.map( ( g, i ) => {
					const url = pageUrl( g.lead );
					const current = g.items.some( ( item ) => item.key === page );
					const cls = [ i === 0 ? 'wp-first-item' : '', current ? 'current' : '' ].filter( Boolean ).join( ' ' );
					// The group entry itself opens the lead page, so the sub-menu lists
					// only the other pages (Settings → Notifications), never a duplicate.
					const children = g.items.filter( ( item ) => item.key !== g.lead );
					const nested = NESTED_GROUPS.includes( g.id ) && children.length > 0;
					return (
						<li key={ g.id } className={ `${ cls }${ nested ? ' gemsec-has-flyout' : '' }`.trim() }>
							<Link
								to={ url }
								onClick={ go( url ) }
								className={ cls }
								aria-current={ g.lead === page ? 'page' : undefined }
							>
								{ g.title }
							</Link>
							{ nested && (
								// Active group keeps its pages expanded inline; others fly out on hover.
								<ul className={ `wp-submenu${ current ? '' : ' gemsec-submenu-flyout' }` }>
									{ children.map( ( item ) => {
										const to = pageUrl( item.key );
										return (
											<li key={ item.key } className={ item.key === page ? 'current' : '' }>
												<Link
													to={ to }
													onClick={ go( to ) }
													aria-current={ item.key === page ? 'page' : undefined }
												>
													{ item.label }
												</Link>
											</li>
										);
									} ) }
								</ul>
							) }
						</li>
					);
				} ) }
			</ul>
		</>,
		host
	);
}
