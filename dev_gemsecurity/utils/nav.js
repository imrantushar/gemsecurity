import { useLocation } from 'react-router-dom';
import { GS } from '@Utils/api';

const SLUG = 'gemsecurity';

/**
 * The plugin navigation, derived from the module registry the server localizes
 * as `GS.modules`. Only *visible* modules appear (core + Pro always; other
 * modules only when active), so deactivating a module removes its nav item.
 * Each item's `key` maps to the ?page= slug used by WordPress.
 */
export const MODULES = Array.isArray( GS.modules ) ? GS.modules : [];

export const NAV_ITEMS = MODULES
	.filter( ( m ) => m.visible )
	.map( ( m ) => ( {
		key: m.page_slug,
		label: m.title,
		icon: m.icon,
		isPro: !! m.is_pro,
		active: !! m.active,
	} ) );

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
