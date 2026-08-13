import { useCallback, useEffect, useState } from 'react';

/**
 * Light/dark theme handling for the GemSecurity admin UI.
 *
 * The theme is applied as a `data-theme` attribute on the plugin wrapper
 * (#gemsecuritywrap), which flips the CSS custom properties defined in
 * backend.scss. The choice is persisted per-browser in localStorage; if the
 * user has never chosen, we follow the OS preference.
 */

const STORAGE_KEY = 'gemsecurity_theme';

/** The plugin root element the scoped styles (and CSS vars) live on. */
function root() {
	return document.getElementById( 'gemsecuritywrap' );
}

/** Resolve the initial theme: stored choice → OS preference → light. */
export function getInitialTheme() {
	try {
		const stored = window.localStorage.getItem( STORAGE_KEY );
		if ( stored === 'light' || stored === 'dark' ) {
			return stored;
		}
	} catch ( e ) {
		// localStorage may be unavailable (privacy mode) — fall through.
	}
	if ( window.matchMedia && window.matchMedia( '(prefers-color-scheme: dark)' ).matches ) {
		return 'dark';
	}
	return 'light';
}

/** Apply a theme to the wrapper and persist the choice. */
export function applyTheme( theme ) {
	const el = root();
	if ( el ) {
		el.setAttribute( 'data-theme', theme );
	}
	try {
		window.localStorage.setItem( STORAGE_KEY, theme );
	} catch ( e ) {
		// Ignore persistence failures.
	}
}

/**
 * React hook: returns the current theme and a toggle function.
 * Applies the resolved theme on mount so the attribute is always present.
 */
export function useThemeMode() {
	const [ theme, setTheme ] = useState( getInitialTheme );

	useEffect( () => {
		applyTheme( theme );
	}, [ theme ] );

	const toggle = useCallback( () => {
		setTheme( ( t ) => ( t === 'dark' ? 'light' : 'dark' ) );
	}, [] );

	return { theme, toggle };
}
