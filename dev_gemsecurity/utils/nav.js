import { useCallback, useMemo, useSyncExternalStore } from 'react';
import { useLocation } from 'react-router-dom';
import { GS } from '@Utils/api';

const SLUG = 'gemsecurity';

/**
 * Live module store.
 *
 * The server localizes the module registry as `GS.modules`. That snapshot is
 * only accurate for the request that rendered the page, so toggling a module
 * on the Modules page would otherwise leave a stale menu behind until a
 * reload. Keeping the list in a tiny subscribable store lets every consumer
 * (nav, page gate) re-render the moment activation changes.
 */
let modules = Array.isArray( GS.modules ) ? GS.modules : [];
const listeners = new Set();

/** Current module list (never mutated in place — replaced wholesale). */
export function getModules() {
	return modules;
}

/**
 * Replace the module list and notify subscribers. Also mirrors the change back
 * onto `GS.modules` and into the WordPress admin sidebar, which is rendered
 * server-side and would otherwise keep showing deactivated modules.
 *
 * @param {Array} next Module descriptors from the /modules REST response.
 */
export function setModules( next ) {
	if ( ! Array.isArray( next ) ) {
		return;
	}
	modules = next;
	GS.modules = next;
	syncAdminMenu( next );
	listeners.forEach( ( fn ) => fn() );
}

function subscribe( fn ) {
	listeners.add( fn );
	return () => listeners.delete( fn );
}

/** Reactive module list. */
export function useModules() {
	return useSyncExternalStore( subscribe, getModules, getModules );
}

/** Map module descriptors to nav items; only *visible* modules appear. */
function toNavItems( list ) {
	return list
		.filter( ( m ) => m.visible )
		.map( ( m ) => ( {
			key: m.page_slug,
			label: m.title,
			icon: m.icon,
			isPro: !! m.is_pro,
			active: !! m.active,
		} ) );
}

/** Reactive nav items, keyed by the ?page= slug WordPress uses. */
export function useNavItems() {
	const list = useModules();
	return useMemo( () => toNavItems( list ), [ list ] );
}

/**
 * Rebuild GemSecurity's entries in the native WordPress admin sidebar so they
 * match the current activation state.
 *
 * WordPress prints that submenu in PHP on page load: an inactive module has no
 * `<li>` in the DOM at all, so activating one has to *create* its item (hiding
 * alone only ever covers the deactivate direction). Items are (re)inserted in
 * registry order so the menu looks exactly as a fresh page load would render
 * it, and deactivated ones are removed outright.
 *
 * @param {Array} list Module descriptors, in registry order.
 */
export function syncAdminMenu( list ) {
	const adminMenu = document.getElementById( 'adminmenu' );
	if ( ! adminMenu ) {
		return;
	}

	// `page=` is the last query arg, so ends-with is an exact slug match:
	// "page=gemsecurity" never matches "page=gemsecurity-firewall".
	const topLink = adminMenu.querySelector( `a[href$="page=${ SLUG }"]` );
	const submenu = topLink?.closest( 'li' )?.querySelector( '.wp-submenu' );
	if ( ! submenu ) {
		return;
	}

	// Lookups stay scoped to the submenu: the top-level `<a>` points at the
	// dashboard slug too, and matching it would drag the whole top-level menu
	// item into its own submenu.
	const subLinkFor = ( slug ) =>
		submenu.querySelector( `a[href$="page=${ slug }"]` );

	// Walk the registry in order, keeping a cursor on the last item placed so
	// every visible module lands in its registry position.
	let cursor = submenu.querySelector( '.wp-submenu-head' );

	list.forEach( ( m ) => {
		if ( ! m.page_slug ) {
			return;
		}
		const existing = subLinkFor( m.page_slug )?.closest( 'li' );

		if ( ! m.visible ) {
			if ( existing ) {
				existing.remove();
			}
			return;
		}

		const item = existing || buildMenuItem( m );
		if ( cursor ) {
			cursor.after( item );
		} else {
			submenu.prepend( item );
		}
		cursor = item;
	} );
}

/** A submenu `<li>` matching what PHP would have printed for this module. */
function buildMenuItem( mod ) {
	const li = document.createElement( 'li' );
	const a = document.createElement( 'a' );
	a.href = pageUrl( mod.page_slug );
	a.textContent = mod.title;

	// Mirror the PRO pill the menu prints for Pro-gated items (see Admin\Menu).
	if ( mod.is_pro && ! GS.is_pro ) {
		const pill = document.createElement( 'span' );
		pill.className = 'gemsec-pro-pill';
		pill.textContent = 'PRO';
		a.append( ' ', pill );
	}

	li.appendChild( a );
	return li;
}

/** Base admin path used for client-side router links, e.g. "/wp-admin/". */
export const ROUTE_PATH = GS.route_path || '/wp-admin/';

/**
 * Current page slug from the live URL (non-reactive). Used for the initial
 * render before the router context is available.
 */
export function getCurrentPage() {
	const params = new URLSearchParams( window.location.search );
	return params.get( 'page' ) || SLUG;
}

/**
 * Reactive active page slug — re-renders on client-side navigation.
 * Reads the ?page= query from the react-router location.
 */
export function useActivePage() {
	const location = useLocation();
	const params = new URLSearchParams( location.search );
	return params.get( 'page' ) || SLUG;
}

/** Reactive lookup of a single module descriptor by its page slug. */
export function useModuleBySlug( slug ) {
	const list = useModules();
	const find = useCallback(
		( items ) => items.find( ( m ) => m.page_slug === slug ),
		[ slug ]
	);
	return useMemo( () => find( list ), [ find, list ] );
}

/**
 * Router link target for a nav key: a real WordPress admin URL
 * (path + ?page=) so it stays bookmarkable and server-resolvable, but
 * react-router navigates to it client-side without a reload.
 */
export function pageUrl( key ) {
	return `${ ROUTE_PATH }admin.php?page=${ key }`;
}

/** Extract the ?page= slug from any admin href (or null). */
export function pageFromHref( href ) {
	try {
		return new URL( href, window.location.origin ).searchParams.get( 'page' );
	} catch ( e ) {
		return null;
	}
}
