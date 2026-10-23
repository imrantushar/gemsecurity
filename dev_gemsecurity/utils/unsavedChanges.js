import { useSyncExternalStore } from 'react';

/**
 * App-wide registry of settings forms with unsaved edits.
 *
 * Every useSettingsForm instance registers its dirty state plus save/discard
 * callbacks here, so one global save bar can save everything on the page and
 * one leave guard can stop navigation that would throw edits away — no page
 * has to wire either up itself.
 */

const FORMS     = new Map(); // id → { dirty, save, discard }
const LISTENERS = new Set();
let pending     = null;      // { proceed } while the leave dialog is open
let snapshot    = { dirty: false, count: 0, pending: null };

let dirtyHref = null; // URL the unsaved edits belong to (for Back/Forward)

function emit() {
	let count = 0;
	FORMS.forEach( ( f ) => { if ( f.dirty ) count++; } );
	snapshot = { dirty: count > 0, count, pending };
	dirtyHref = snapshot.dirty ? ( dirtyHref || window.location.href ) : null;
	LISTENERS.forEach( ( fn ) => fn() );
}

function subscribe( fn ) {
	LISTENERS.add( fn );
	return () => LISTENERS.delete( fn );
}

export function registerForm( id, entry ) {
	const prev = FORMS.get( id );
	FORMS.set( id, entry );
	if ( ! prev || prev.dirty !== entry.dirty ) {
		emit();
	}
}

export function unregisterForm( id ) {
	if ( FORMS.delete( id ) ) {
		emit();
	}
}

export function hasUnsaved() {
	return snapshot.dirty;
}

/** Save every dirty form. Resolves true only if all of them saved. */
export async function saveAll() {
	const dirty = [ ...FORMS.values() ].filter( ( f ) => f.dirty );
	const results = await Promise.all( dirty.map( ( f ) => f.save() ) );
	return results.every( ( ok ) => ok !== false );
}

export function discardAll() {
	FORMS.forEach( ( f ) => { if ( f.dirty ) f.discard(); } );
}

/**
 * Run `proceed` now if nothing is unsaved; otherwise open the leave dialog
 * and run it only once the user saves or discards.
 */
export function guardLeave( proceed ) {
	if ( ! snapshot.dirty ) {
		proceed();
		return;
	}
	pending = { proceed };
	emit();
}

export async function resolveLeave( choice ) {
	const p = pending;
	if ( ! p ) {
		return;
	}
	if ( choice === 'save' ) {
		const ok = await saveAll();
		if ( ! ok ) {
			return; // keep the dialog open; the save toast explains why
		}
	} else if ( choice === 'discard' ) {
		discardAll();
	}
	pending = null;
	emit();
	if ( choice !== 'stay' ) {
		p.proceed();
	}
}

export function useUnsaved() {
	return useSyncExternalStore( subscribe, () => snapshot );
}

// Real page loads (reload, typed URL, closing the tab) can only get the
// browser's own prompt. Links we can see are routed through guardLeave below.
let bypassUnload = false;
window.addEventListener( 'beforeunload', ( e ) => {
	if ( snapshot.dirty && ! bypassUnload ) {
		e.preventDefault();
		e.returnValue = '';
	}
} );

/** Full-page navigation that skips the native prompt (already confirmed). */
export function leaveTo( href ) {
	bypassUnload = true;
	window.location.href = href;
}

// Browser Back/Forward. This module loads before the router mounts, so this
// listener runs first and can hide the event from it: put the URL back, ask,
// and replay the history step only once the user saves or discards.
const pageOf = ( href ) => new URL( href ).searchParams.get( 'page' );
let replaying = false;
window.addEventListener( 'popstate', ( e ) => {
	if ( replaying ) {
		replaying = false;
		return;
	}
	if ( ! snapshot.dirty || ! dirtyHref ) {
		return;
	}
	const target = window.location.href;
	// Tab/query changes within the same page keep the forms mounted.
	if ( pageOf( target ) === pageOf( dirtyHref ) ) {
		dirtyHref = target;
		return;
	}
	e.stopImmediatePropagation();
	const from = dirtyHref;
	window.history.pushState( window.history.state, '', from );
	guardLeave( () => {
		replaying = true;
		window.history.back();
	} );
} );

// Intercept ordinary links outside the app (WP sidebar, admin bar, in-page
// anchors to other admin screens) so they get our dialog, not the browser's.
document.addEventListener( 'click', ( e ) => {
	if ( ! snapshot.dirty || e.defaultPrevented || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey ) {
		return;
	}
	const a = e.target.closest?.( 'a[href]' );
	if ( ! a || a.target === '_blank' || a.hasAttribute( 'download' ) ) {
		return;
	}
	const href = a.getAttribute( 'href' );
	if ( ! href || href.startsWith( '#' ) || href.startsWith( 'javascript:' ) ) {
		return;
	}
	e.preventDefault();
	guardLeave( () => leaveTo( a.href ) );
} );
