import { __ } from '@wordpress/i18n';
import { useLocation } from 'react-router-dom';
import { GS } from '@Utils/api';

const SLUG = 'gemsecurity';

/**
 * The plugin navigation. `key` maps to the ?page= slug used by WordPress.
 */
export const NAV_ITEMS = [
	{ key: SLUG, label: __( 'Dashboard', 'gemsecurity' ), icon: 'grid' },
	{ key: `${ SLUG }-firewall`, label: __( 'Firewall', 'gemsecurity' ), icon: 'shield' },
	{ key: `${ SLUG }-login-security`, label: __( 'Login Security', 'gemsecurity' ), icon: 'lock' },
	{ key: `${ SLUG }-two-factor`, label: __( 'Two-Factor', 'gemsecurity' ), icon: 'key' },
	{ key: `${ SLUG }-social-login`, label: __( 'Social Login', 'gemsecurity' ), icon: 'users' },
	{ key: `${ SLUG }-geolocation`, label: __( 'Geolocation', 'gemsecurity' ), icon: 'globe' },
	{ key: `${ SLUG }-admin-guard`, label: __( 'Admin Guard', 'gemsecurity' ), icon: 'crown' },
	{ key: `${ SLUG }-scanner`, label: __( 'Scanner', 'gemsecurity' ), icon: 'radar' },
	{ key: `${ SLUG }-logs`, label: __( 'Logs', 'gemsecurity' ), icon: 'list' },
	{ key: `${ SLUG }-settings`, label: __( 'Settings', 'gemsecurity' ), icon: 'cog' },
];

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
