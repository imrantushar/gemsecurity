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
			group: m.group || 'settings',
		} ) );
}

const GROUPS = Array.isArray( GS.groups ) ? GS.groups : [];

/**
 * Nav items bucketed by group, in group order. Empty groups are dropped;
 * `lead` is the page a group link opens (its first visible module).
 *
 * @param {Array} items Output of toNavItems().
 */
function toNavGroups( items ) {
	return GROUPS.map( ( g ) => {
		const groupItems = items.filter( ( i ) => i.group === g.id );
		return {
			...g,
			items: groupItems,
			// Mirrors Registry::visible_groups(): prefer the page named after the group.
			lead: ( groupItems.find( ( i ) => i.key === `${ SLUG }-${ g.id }` ) || groupItems[ 0 ] )?.key,
		};
	} ).filter( ( g ) => g.items.length );
}

/** Reactive grouped nav: [{ id, title, icon, lead, items }]. */
export function useNavGroups() {
	const items = useNavItems();
	return useMemo( () => toNavGroups( items ), [ items ] );
}

/** Reactive nav items, keyed by the ?page= slug WordPress uses. */
export function useNavItems() {
	const list = useModules();
	return useMemo( () => toNavItems( list ), [ list ] );
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
