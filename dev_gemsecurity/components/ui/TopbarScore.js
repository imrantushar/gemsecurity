import React, { useEffect, useRef, useState } from 'react';
import { __, sprintf, _n } from '@wordpress/i18n';
import Icon from '@Components/ui/Icon';
import useQuickFix from '@Utils/useQuickFix';

// A check fixed by a different setting (e.g. "debug.log is public" → turn on
// core-file protection) names it in fix_key.
const settingOf = ( c ) => c.fix_key || c.key;
import { loadScore, onScoreInvalidated } from '@Components/ui/PageScoreTips';

/**
 * A compact score chip in the topbar. Click to open a popover listing every
 * failing posture check and active threat, with a direct link to the page
 * that resolves each one. Hovering shows the grade in a tooltip.
 *
 * Reuses the /score fetch cached by PageScoreTips so the two don't
 * double-request. On settings-save the cache is busted and both this chip
 * and the in-page tips refresh together.
 */
export default function TopbarScore( { onNavigate } ) {
	const [ data, setData ]   = useState( null );
	const [ open, setOpen ]   = useState( false );
	const { fix, fixing, busy } = useQuickFix();
	const btnRef              = useRef( null );
	const popRef              = useRef( null );

	useEffect( () => {
		let cancelled = false;
		const refetch = () => {
			loadScore().then( ( d ) => {
				if ( ! cancelled ) {
					setData( d );
				}
			} );
		};
		refetch();
		const unsub = onScoreInvalidated( refetch );
		return () => { cancelled = true; unsub(); };
	}, [] );

	// Close on outside click / Esc.
	useEffect( () => {
		if ( ! open ) {
			return;
		}
		const onDocClick = ( e ) => {
			if ( popRef.current && ! popRef.current.contains( e.target ) &&
				btnRef.current && ! btnRef.current.contains( e.target ) ) {
				setOpen( false );
			}
		};
		const onKey = ( e ) => {
			if ( e.key === 'Escape' ) {
				setOpen( false );
			}
		};
		document.addEventListener( 'mousedown', onDocClick );
		document.addEventListener( 'keydown', onKey );
		return () => {
			document.removeEventListener( 'mousedown', onDocClick );
			document.removeEventListener( 'keydown', onKey );
		};
	}, [ open ] );

	if ( ! data || typeof data.score !== 'number' ) {
		return null;
	}

	const score   = data.score;
	const grade   = data.grade || scoreToGrade( score );
	const tone    = scoreTone( score );
	const checks  = Array.isArray( data.checks ) ? data.checks : [];
	const threats = Array.isArray( data.threats ) ? data.threats : [];
	const failing = checks.filter( ( c ) => c.status !== 'pass' );
	const gain    = failing.reduce( ( s, c ) => s + ( c.weight || 0 ), 0 );

	const handleFix = ( key ) => fix( [ key ] );

	const quickKeys = failing.filter( ( c ) => c.quick ).map( settingOf ).filter( ( k, i, a ) => a.indexOf( k ) === i );
	const handleFixAll = () => quickKeys.length && fix( quickKeys );

	const handleGo = ( url ) => {
		if ( ! url ) {
			return;
		}
		setOpen( false );
		if ( onNavigate ) {
			onNavigate( url );
		} else {
			window.location.href = url;
		}
	};

	return (
		<div className="gs-topbar__score-wrap">
			<button
				ref={ btnRef }
				type="button"
				className={ `gs-topbar__score is-${ tone } ${ open ? 'is-open' : '' }` }
				onClick={ () => setOpen( ( v ) => ! v ) }
				aria-expanded={ open }
				aria-haspopup="dialog"
				title={ sprintf(
					/* translators: 1 score, 2 grade */
					__( 'Security score %1$d (grade %2$s). Click to see what needs attention.', 'gemsecurity' ),
					score, grade
				) }
			>
				<i className="gs-topbar__score-dot" />
				<span className="gs-topbar__score-num">{ sprintf( /* translators: %d: score */ __( 'Score %d', 'gemsecurity' ), score ) }</span>
				<span className="gs-topbar__score-grade">· { scoreLabel( score ) }</span>
			</button>
			{ open && (
				<div ref={ popRef } className="gs-score-pop" role="dialog" aria-label={ __( 'Security score', 'gemsecurity' ) }>
					<header className="gs-score-pop__head">
						<div className={ `gs-score-pop__badge is-${ tone }` }>
							<strong>{ score }</strong>
							<span>{ grade }</span>
						</div>
						<div className="gs-score-pop__title">
							<strong>{ __( 'Security score', 'gemsecurity' ) }</strong>
							{ gain > 0
								? <span>{ sprintf(
										/* translators: 1 points to gain, 2 count of items */
										_n(
											'+%1$d points available across %2$d check',
											'+%1$d points available across %2$d checks',
											failing.length, 'gemsecurity'
										),
										gain, failing.length
									) }</span>
								: <span>{ __( 'Every posture check is passing.', 'gemsecurity' ) }</span>
							}
						</div>
						<button
							type="button"
							className="gs-score-pop__close"
							onClick={ () => setOpen( false ) }
							aria-label={ __( 'Close', 'gemsecurity' ) }
						>
							<Icon name="close" size={ 14 } />
						</button>
					</header>

					{ threats.length > 0 && (
						<section className="gs-score-pop__section">
							<h4><Icon name="alert" size={ 14 } />{ __( 'Active issues', 'gemsecurity' ) }</h4>
							<ul>
								{ threats.map( ( t ) => (
									<li key={ t.key } className={ `is-${ t.severity }` }>
										<span className="gs-score-pop__dot" />
										<span className="gs-score-pop__row">
											<strong>{ t.label }</strong>
											<span>{ t.fix }</span>
										</span>
										{ t.action && (
											<button
												type="button"
												className="gs-score-pop__go"
												onClick={ () => handleGo( t.action.url ) }
											>
												{ t.action.label || __( 'Open', 'gemsecurity' ) }
											</button>
										) }
									</li>
								) ) }
							</ul>
						</section>
					) }

					{ failing.length > 0 ? (
						<section className="gs-score-pop__section">
							<h4>
								<Icon name="zap" size={ 14 } />{ __( 'To fix', 'gemsecurity' ) }
								{ quickKeys.length > 1 && (
									<button
										type="button"
										className="gs-score-pop__fixall"
										onClick={ handleFixAll }
										disabled={ busy }
									>
										{ sprintf(
											/* translators: %d: number of settings */
											__( 'Fix all %d', 'gemsecurity' ),
											quickKeys.length
										) }
									</button>
								) }
							</h4>
							<ul>
								{ failing.map( ( c ) => (
									<li key={ c.key }>
										<span className="gs-score-pop__dot is-off" />
										<span className="gs-score-pop__row">
											<strong>{ c.label }</strong>
											<span>{ c.fix }</span>
										</span>
										<span className="gs-score-pop__weight">
											{ sprintf( /* translators: %d: weight */ __( '+%d', 'gemsecurity' ), c.weight || 0 ) }
										</span>
										{ c.quick ? (
											<button
												type="button"
												className="gs-score-pop__go is-fix"
												onClick={ () => handleFix( settingOf( c ) ) }
												disabled={ !! fixing[ settingOf( c ) ] }
												title={ __( 'Turn this setting on now', 'gemsecurity' ) }
											>
												{ fixing[ settingOf( c ) ] ? __( 'Fixing…', 'gemsecurity' ) : __( 'Fix', 'gemsecurity' ) }
											</button>
										) : c.action && (
											<button
												type="button"
												className="gs-score-pop__go"
												onClick={ () => handleGo( c.action.url ) }
											>
												{ c.action.label || __( 'Open', 'gemsecurity' ) }
											</button>
										) }
									</li>
								) ) }
							</ul>
						</section>
					) : threats.length === 0 && (
						<div className="gs-score-pop__empty">
							<Icon name="check" size={ 18 } />
							<span>{ __( "You're all set — every check is passing.", 'gemsecurity' ) }</span>
						</div>
					) }
				</div>
			) }
		</div>
	);
}

function scoreToGrade( p ) {
	if ( p >= 90 ) return 'A';
	if ( p >= 75 ) return 'B';
	if ( p >= 60 ) return 'C';
	if ( p >= 40 ) return 'D';
	return 'F';
}

function scoreLabel( p ) {
	if ( p >= 75 ) return __( 'Good', 'gemsecurity' );
	if ( p >= 50 ) return __( 'Fair', 'gemsecurity' );
	return __( 'At risk', 'gemsecurity' );
}

function scoreTone( p ) {
	if ( p >= 75 ) return 'good';
	if ( p >= 60 ) return 'ok';
	if ( p >= 40 ) return 'warn';
	return 'bad';
}
