import { useState, useEffect, useMemo, useRef, useId } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { saveSettings } from '@Redux/settingsSlice';
import { useToast } from '@Components/ui/Toast';
import { registerForm, unregisterForm } from '@Utils/unsavedChanges';
import { isInstantSetting } from '@Utils/instantSettings';
import { __ } from '@wordpress/i18n';

const same = ( a, b ) => JSON.stringify( a ) === JSON.stringify( b );

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
	const save = ( extra = {} ) => {
		const changed = {};
		Object.keys( form ).forEach( ( k ) => {
			if ( ! isInstantSetting( k ) && ! same( form[ k ], initial[ k ] ) ) {
				changed[ k ] = form[ k ];
			}
		} );
		return persist( { ...changed, ...extra }, __( 'Settings saved.', 'gemsecurity' ) );
	};

	const discard = () => setForm( initial );

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
