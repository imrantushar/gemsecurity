import { useState, useEffect, useMemo } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { saveSettings } from '@Redux/settingsSlice';
import { useToast } from '@Components/ui/Toast';
import { __ } from '@wordpress/i18n';

/**
 * Local draft form bound to a subset of the global settings.
 *
 * @param {string[]} keys Setting keys this page manages.
 */
export default function useSettingsForm( keys ) {
	const dispatch = useDispatch();
	const toast = useToast();
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

	useEffect( () => {
		setForm( initial );
	}, [ initial ] );

	const setField = ( key, value ) => setForm( ( f ) => ( { ...f, [ key ]: value } ) );

	const dirty = useMemo(
		() => JSON.stringify( form ) !== JSON.stringify( initial ),
		[ form, initial ]
	);

	const save = async ( extra = {} ) => {
		try {
			await dispatch( saveSettings( { ...form, ...extra } ) ).unwrap();
			toast( __( 'Settings saved.', 'gemsecurity' ), 'success' );
		} catch ( e ) {
			toast( __( 'Could not save settings.', 'gemsecurity' ), 'error' );
		}
	};

	return { form, setField, setForm, save, saving, dirty, settings: data };
}
