import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { guardLeave } from '@Utils/unsavedChanges';

/**
 * Drop-in for react-router's useNavigate that asks before leaving a page
 * with unsaved settings. Same-page navigations (tab/query changes on the
 * current ?page=) go straight through — the forms stay mounted.
 */
export default function useGuardedNavigate() {
	const navigate = useNavigate();
	return useCallback( ( to, opts ) => {
		if ( typeof to === 'number' ) {
			guardLeave( () => navigate( to ) );
			return;
		}
		const target = new URL( String( to ), window.location.href ).searchParams.get( 'page' );
		const current = new URLSearchParams( window.location.search ).get( 'page' );
		if ( target && target === current ) {
			navigate( to, opts );
			return;
		}
		guardLeave( () => navigate( to, opts ) );
	}, [ navigate ] );
}
