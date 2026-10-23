import { useState, useEffect, useMemo, useRef, useId } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { saveSettings } from '@Redux/settingsSlice';
import { useToast } from '@Components/ui/Toast';
import { registerForm, unregisterForm } from '@Utils/unsavedChanges';
import { isInstantSetting } from '@Utils/instantSettings';
import { __ } from '@wordpress/i18n';

const same = ( a, b ) => JSON.stringify( a ) === JSON.stringify( b );

/*
 * Unsaved drafts survive a reload. Browsers only allow their own generic
 * "Leave site?" prompt on reload, and some (or an automated reload) skip it,
 * so instead of relying on it the draft is kept per tab in sessionStorage and
 * offered back when the page loads again. Storage can throw (private mode,
 * blocked site data) — then this quietly does nothing.
 */
const DRAFT_TTL = 60 * 60 * 1000;

function readDraft( key ) {
	try {
		const raw = window.sessionStorage.getItem( key );
		if ( ! raw ) {
			return null;
		}
		const d = JSON.parse( raw );
		return d && d.at && Date.now() - d.at < DRAFT_TTL ? d.fields : null;
	} catch ( e ) {
		return null;
	}
}

function writeDraft( key, fields ) {
	try {
		if ( fields ) {
			window.sessionStorage.setItem( key, JSON.stringify( { at: Date.now(), fields } ) );
		} else {
			window.sessionStorage.removeItem( key );
		}
	} catch ( e ) {}
}

/**
 * Local draft form bound to a subset of the global settings.
 *
 * Two kinds of field:
 *  - Instant (see instantSettings.js): master on/off switches. setField saves
 *    them straight away, on their own, without touching other drafts.
 *  - Draft: everything else. Edits stay local, the global save bar appears,
 *    and leaving the page asks first (unsavedChanges.js).
 *
 * @param {string[]} keys Setting keys this page manages.
 */
export default function useSettingsForm( keys ) {
	const dispatch = useDispatch();
	const toast = useToast();
	const id = useId();
	const { data, saving } = useSelector( ( s ) => s.settings );

	// Depend on what the keys *are*, not on the identity of the array holding
	// them. A caller passing an inline literal — `useSettingsForm( [ 'a', 'b' ] )`
	// — hands over a new array on every render, which made `initial` new every
	// render, which made the effect below setState on every render: an infinite
	// update loop that froze the whole admin, not just that page. Callers should
	// not have to know that, so the hook is responsible for it.
	const signature = ( keys || [] ).join( '\u0000' );

	const initial = useMemo( () => {
		const o = {};
		( keys || [] ).forEach( ( k ) => {
			o[ k ] = data ? data[ k ] : undefined;
		} );
		return o;
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [ data, signature ] );

	const [ form, setForm ] = useState( initial );
	const prevInitial = useRef( initial );
	const draftKey = useMemo(
		() => 'gemsecurity-draft:' + ( new URLSearchParams( window.location.search ).get( 'page' ) || '' ) + ':' + signature,
		// eslint-disable-next-line react-hooks/exhaustive-deps
		[ signature ]
	);

	// Settings changed underneath us (an instant toggle, a one-click fix from
	// the score popover, another form's save). Take the new value only for
	// fields the user has not edited, so their unsaved drafts survive.
	useEffect( () => {
		const prev = prevInitial.current;
		prevInitial.current = initial;
		setForm( ( f ) => {
			const next = { ...initial };
			Object.keys( f ).forEach( ( k ) => {
				if ( ! same( f[ k ], prev[ k ] ) ) {
					next[ k ] = f[ k ];
				}
			} );
			return next;
		} );
	}, [ initial ] );

	// Once settings have loaded, bring back a draft left by a reload.
	const restored = useRef( false );
	useEffect( () => {
		if ( ! data || restored.current ) {
			return;
		}
		restored.current = true;
		const draft = readDraft( draftKey );
		if ( ! draft ) {
			return;
		}
		const fields = {};
		Object.keys( draft ).forEach( ( k ) => {
			if ( k in initial && ! isInstantSetting( k ) && ! same( draft[ k ], initial[ k ] ) ) {
				fields[ k ] = draft[ k ];
			}
		} );
		if ( ! Object.keys( fields ).length ) {
			writeDraft( draftKey, null );
			return;
		}
		setForm( ( f ) => ( { ...f, ...fields } ) );
		toast( __( 'Restored your unsaved changes from before the page reloaded.', 'gemsecurity' ), 'warning', {
			action: { label: __( 'Discard', 'gemsecurity' ), onClick: () => discardRef.current() },
		} );
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [ data ] );

	const persist = async ( partial, message, source = 'save' ) => {
		try {
			await dispatch( saveSettings( { settings: partial, source } ) ).unwrap();
			if ( message ) {
				toast( message, 'success' );
			}
			return true;
		} catch ( e ) {
			toast( __( 'Could not save settings.', 'gemsecurity' ), 'error' );
			return false;
		}
	};

	const setField = ( key, value ) => {
		setForm( ( f ) => ( { ...f, [ key ]: value } ) );
		if ( isInstantSetting( key ) && typeof value === 'boolean' ) {
			persist(
				{ [ key ]: value },
				value ? __( 'Turned on and saved.', 'gemsecurity' ) : __( 'Turned off and saved.', 'gemsecurity' ),
				'instant'
			).then( ( ok ) => {
				if ( ! ok ) {
					// Roll the switch back so it shows what is really saved.
					setForm( ( f ) => ( { ...f, [ key ]: ! value } ) );
				}
			} );
		}
	};

	// Instant switches are saved as they flip, so they never count as unsaved.
	const dirty = useMemo(
		() => Object.keys( form ).some( ( k ) => ! isInstantSetting( k ) && ! same( form[ k ], initial[ k ] ) ),
		[ form, initial ]
	);

	// Only send what changed, so saving one page never rewrites a value
	// another form or the score popover set a moment ago.
	const changedFields = () => {
		const changed = {};
		Object.keys( form ).forEach( ( k ) => {
			if ( ! isInstantSetting( k ) && ! same( form[ k ], initial[ k ] ) ) {
				changed[ k ] = form[ k ];
			}
		} );
		return changed;
	};

	const save = async ( extra = {} ) => {
		const ok = await persist( { ...changedFields(), ...extra }, __( 'Settings saved.', 'gemsecurity' ) );
		if ( ok ) {
			writeDraft( draftKey, null );
		}
		return ok;
	};

	// Clear the stored draft right here, not in an effect: Discard & leave
	// unmounts the page before an effect would get to run.
	const discard = () => {
		writeDraft( draftKey, null );
		setForm( initial );
	};

	// Mirror the draft to storage while there is one. Skipped until the
	// restore above has had its chance, so the empty first render cannot
	// wipe the draft it is about to restore.
	useEffect( () => {
		if ( restored.current ) {
			writeDraft( draftKey, dirty ? changedFields() : null );
		}
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [ form, dirty, draftKey ] );

	// Keep the global registry current. Refs keep the callbacks fresh without
	// re-registering on every keystroke.
	const saveRef = useRef( save );
	const discardRef = useRef( discard );
	saveRef.current = save;
	discardRef.current = discard;
	useEffect( () => {
		registerForm( id, {
			dirty,
			save: () => saveRef.current(),
			discard: () => discardRef.current(),
		} );
	}, [ id, dirty ] );
	useEffect( () => () => unregisterForm( id ), [ id ] );

	return { form, setField, setForm, save, discard, saving, dirty, settings: data };
}
