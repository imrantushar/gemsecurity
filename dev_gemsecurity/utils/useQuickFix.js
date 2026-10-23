import { useState } from 'react';
import { useDispatch } from 'react-redux';
import { __, sprintf, _n } from '@wordpress/i18n';
import { saveSettings } from '@Redux/settingsSlice';
import { useToast } from '@Components/ui/Toast';

/**
 * One-click score fixes: switch boolean settings on, with an Undo toast.
 * Shared by the topbar score popover and the in-page score tips.
 */
export default function useQuickFix() {
	const dispatch = useDispatch();
	const toast = useToast();
	const [ fixing, setFixing ] = useState( {} );

	const fix = ( keys ) => {
		const on = Object.fromEntries( keys.map( ( k ) => [ k, true ] ) );
		const off = Object.fromEntries( keys.map( ( k ) => [ k, false ] ) );
		setFixing( ( f ) => ( { ...f, ...on } ) );
		return dispatch( saveSettings( { settings: on, source: 'quick_fix' } ) )
			.unwrap()
			.then( () => {
				toast(
					sprintf(
						/* translators: %d: number of settings */
						_n( '%d setting turned on.', '%d settings turned on.', keys.length, 'gemsecurity' ),
						keys.length
					),
					'success',
					{
						action: {
							label: __( 'Undo', 'gemsecurity' ),
							onClick: () => dispatch( saveSettings( { settings: off, source: 'undo' } ) ),
						},
					}
				);
			} )
			.catch( () => toast( __( 'Could not save. Open the setting\'s page and try again.', 'gemsecurity' ), 'error' ) )
			.finally( () => setFixing( ( f ) => {
				const next = { ...f };
				keys.forEach( ( k ) => delete next[ k ] );
				return next;
			} ) );
	};

	return { fix, fixing, busy: Object.keys( fixing ).length > 0 };
}
