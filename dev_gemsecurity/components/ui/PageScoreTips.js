import React, { useEffect, useState } from 'react';
import { __, sprintf, _n } from '@wordpress/i18n';
import api from '@Utils/api';
import Icon from '@Components/ui/Icon';
import useQuickFix from '@Utils/useQuickFix';

// A check fixed by a different setting (e.g. "debug.log is public" → turn on
// core-file protection) names it in fix_key.
const settingOf = ( c ) => c.fix_key || c.key;

/**
 * Lightweight in-page coach: on every module page, read the security score
 * assessment and show the failing posture checks whose fix lives on THIS page.
 *
 * Rationale: the Dashboard already lists every failing check, but once a user
 * clicks through to a module page they lose that context — they can see the
 * toggles but not which ones move the score. This component carries the
 * assessment with them, so each page can say "turn on A, B, C to gain +N
 * points" without them having to context-switch back to the dashboard.
 *
 * One `/score` fetch per page load; cached in-module across remounts within
 * the same session. Hidden on pages the dashboard already covers (dashboard,
 * modules, settings) and when the current page has nothing to improve.
 */

// Pages where this banner adds nothing because they ARE the overview.
const SKIP_PAGES = new Set( [
	'gemsecurity',
	'gemsecurity-modules',
	'gemsecurity-settings',
	'gemsecurity-notifications',
	'gemsecurity-logs',
	'gemsecurity-setup',
] );

let CACHED  = null;
let LOADING = null;
const SUBS  = new Set();

export function loadScore() {
	if ( CACHED ) {
		return Promise.resolve( CACHED );
	}
	if ( LOADING ) {
		return LOADING;
	}
	LOADING = api.get( 'score' )
		.then( ( r ) => { CACHED = r.data; return CACHED; } )
		.catch( () => ( { checks: [], threats: [], score: null, grade: null } ) )
		.finally( () => { LOADING = null; } );
	return LOADING;
}

/** Force a refetch; notifies subscribers so topbar/tips refresh on next render. */
export function refreshScoreTips() {
	CACHED = null;
	SUBS.forEach( ( fn ) => fn() );
}

/** Subscribe to invalidation events (returns unsubscribe). */
export function onScoreInvalidated( fn ) {
	SUBS.add( fn );
	return () => SUBS.delete( fn );
}

export default function PageScoreTips( { page } ) {
	const { fix, fixing, busy } = useQuickFix();
	const [ data, setData ] = useState( CACHED );
	const [ dismissed, setDismissed ] = useState( false );

	useEffect( () => {
		if ( SKIP_PAGES.has( page ) ) {
			return;
		}
		let cancelled = false;
		const refetch = () => loadScore().then( ( d ) => {
			if ( ! cancelled ) {
				setData( d );
			}
		} );
		refetch();
		const unsub = onScoreInvalidated( refetch );
		return () => { cancelled = true; unsub(); };
	}, [ page ] );

	if ( SKIP_PAGES.has( page ) || ! data || ! Array.isArray( data.checks ) ) {
		return null;
	}

	// Posture checks that fail AND whose fix is configured on this page.
	const pageUrl = `admin.php?page=${ page }`;
	const tips = data.checks.filter( ( c ) =>
		c.status !== 'pass' &&
		c.action &&
		typeof c.action.url === 'string' &&
		c.action.url.indexOf( pageUrl ) !== -1
	);

	if ( tips.length === 0 || dismissed ) {
		return null;
	}

	const quickKeys = tips.filter( ( c ) => c.quick ).map( settingOf ).filter( ( k, i, a ) => a.indexOf( k ) === i );
	const gain = tips.reduce( ( sum, c ) => sum + ( c.weight || 0 ), 0 );
	const score = typeof data.score === 'number' ? data.score : null;

	return (
		<aside className="gs-score-tips" role="region" aria-label={ __( 'Score suggestions for this page', 'gemsecurity' ) }>
			<div className="gs-score-tips__head">
				<span className="gs-score-tips__icon"><Icon name="zap" size={ 16 } /></span>
				<div className="gs-score-tips__title">
					<strong>
						{ score !== null
							? sprintf(
								/* translators: 1 points gain, 2 current score */
								__( 'Boost your score by +%1$d points (currently %2$d)', 'gemsecurity' ),
								gain, score
							)
							: sprintf(
								/* translators: %d: points gain */
								__( 'Boost your score by +%d points', 'gemsecurity' ),
								gain
							)
						}
					</strong>
					<span>
						{ sprintf(
							/* translators: %d: number of settings */
							_n(
								'Enable %d setting below to raise your security grade.',
								'Enable %d settings below to raise your security grade.',
								tips.length, 'gemsecurity'
							),
							tips.length
						) }
					</span>
				</div>
				{ quickKeys.length > 1 && (
					<button type="button" className="gs-score-tips__fixall" onClick={ () => fix( quickKeys ) } disabled={ busy }>
						{ sprintf(
							/* translators: %d: number of settings */
							__( 'Fix all %d', 'gemsecurity' ),
							quickKeys.length
						) }
					</button>
				) }
				<button
					type="button"
					className="gs-score-tips__close"
					onClick={ () => setDismissed( true ) }
					aria-label={ __( 'Hide suggestions', 'gemsecurity' ) }
					title={ __( 'Hide for now — they come back on reload once anything changes.', 'gemsecurity' ) }
				>
					<Icon name="close" size={ 14 } />
				</button>
			</div>
			<ul className="gs-score-tips__list">
				{ tips.map( ( c ) => (
					<li key={ c.key }>
						<span className="gs-score-tips__dot" />
						<span className="gs-score-tips__row">
							<strong>{ c.label }</strong>
							<span>{ c.fix }</span>
						</span>
						<span className="gs-score-tips__weight">
							{ sprintf( /* translators: %d: weight */ __( '+%d', 'gemsecurity' ), c.weight || 0 ) }
						</span>
						{ c.quick && (
							<button
								type="button"
								className="gs-score-tips__fix"
								onClick={ () => fix( [ settingOf( c ) ] ) }
								disabled={ !! fixing[ settingOf( c ) ] }
							>
								{ fixing[ settingOf( c ) ] ? __( 'Fixing…', 'gemsecurity' ) : __( 'Fix', 'gemsecurity' ) }
							</button>
						) }
					</li>
				) ) }
			</ul>
		</aside>
	);
}
