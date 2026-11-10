import React, { useEffect, useMemo, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api from '@Utils/api';
import { Button, Badge, Loading } from '@Components/ui/Controls';
import { useToast } from '@Components/ui/Toast';
import { isPro, ProBadge, UpgradeButton } from '@Components/ui/Pro';

/**
 * Line diff (longest common subsequence). Core files are well under a few
 * thousand lines; anything bigger falls back to showing the lines unpaired
 * rather than freezing the tab.
 */
function diffLines( a, b ) {
	const A = a.split( '\n' );
	const B = b.split( '\n' );
	if ( A.length * B.length > 4000000 ) {
		return [ ...A.map( ( t ) => ( { t, k: 'del' } ) ), ...B.map( ( t ) => ( { t, k: 'add' } ) ) ];
	}
	const L = Array.from( { length: A.length + 1 }, () => new Uint32Array( B.length + 1 ) );
	for ( let i = A.length - 1; i >= 0; i-- ) {
		for ( let j = B.length - 1; j >= 0; j-- ) {
			L[ i ][ j ] = A[ i ] === B[ j ] ? L[ i + 1 ][ j + 1 ] + 1 : Math.max( L[ i + 1 ][ j ], L[ i ][ j + 1 ] );
		}
	}
	const out = [];
	let i = 0;
	let j = 0;
	while ( i < A.length && j < B.length ) {
		if ( A[ i ] === B[ j ] ) {
			out.push( { t: A[ i ], k: 'same' } );
			i++;
			j++;
		} else if ( L[ i + 1 ][ j ] >= L[ i ][ j + 1 ] ) {
			out.push( { t: A[ i++ ], k: 'del' } );
		} else {
			out.push( { t: B[ j++ ], k: 'add' } );
		}
	}
	while ( i < A.length ) {
		out.push( { t: A[ i++ ], k: 'del' } );
	}
	while ( j < B.length ) {
		out.push( { t: B[ j++ ], k: 'add' } );
	}
	return out;
}

/** Show changed lines with two lines of context either side. */
function collapse( rows ) {
	const keep = new Array( rows.length ).fill( false );
	rows.forEach( ( r, i ) => {
		if ( r.k !== 'same' ) {
			for ( let n = Math.max( 0, i - 2 ); n <= Math.min( rows.length - 1, i + 2 ); n++ ) {
				keep[ n ] = true;
			}
		}
	} );
	const out = [];
	let hidden = 0;
	rows.forEach( ( r, i ) => {
		if ( keep[ i ] ) {
			if ( hidden ) {
				out.push( { k: 'gap', t: sprintf( /* translators: %d: unchanged lines. */ __( '… %d unchanged lines …', 'gemsecurity' ), hidden ) } );
				hidden = 0;
			}
			out.push( r );
		} else {
			hidden++;
		}
	} );
	if ( hidden ) {
		out.push( { k: 'gap', t: sprintf( /* translators: %d: unchanged lines. */ __( '… %d unchanged lines …', 'gemsecurity' ), hidden ) } );
	}
	return out;
}

/**
 * Popup for one flagged file: what differs from the official copy.
 *
 * Free: modified WordPress core files, view only.
 * Pro:  any flagged file with an official copy (core, WordPress.org plugins
 *       and themes), plus Restore original / Mark as safe.
 *
 * @param {Object}   props
 * @param {string}   props.file    Root-relative (or absolute) path.
 * @param {Function} props.onClose
 * @param {Function} props.onFixed Called with the fresh scan result (or nothing).
 */
export default function CoreFileModal( { file, onClose, onFixed } ) {
	const toast = useToast();
	const pro = isPro();
	const [ info, setInfo ] = useState( null );
	const [ error, setError ] = useState( '' );
	const [ busy, setBusy ] = useState( '' );

	useEffect( () => {
		api.get( pro ? 'pro/compare' : 'scan/core-file', { params: { file } } )
			.then( ( r ) => setInfo( r.data ) )
			.catch( ( e ) => setError( e?.response?.data?.message || __( 'Could not load this file.', 'gemsecurity' ) ) );
	}, [ file, pro ] );

	useEffect( () => {
		const onKey = ( e ) => e.key === 'Escape' && onClose();
		document.addEventListener( 'keydown', onKey );
		return () => document.removeEventListener( 'keydown', onKey );
	}, [ onClose ] );

	const rows = useMemo( () => {
		if ( ! info || ! info.original ) {
			return null;
		}
		return collapse( diffLines( info.original, info.current ) );
	}, [ info ] );

	const changed = rows ? rows.filter( ( r ) => r.k === 'add' || r.k === 'del' ).length : 0;

	const restore = async () => {
		const warn = info.verified
			? __( 'Replace this file with the official copy? The current file is moved to quarantine first, so this can be undone.', 'gemsecurity' )
			: __( 'No checksum is published for this copy, so it could not be verified — it still comes directly from WordPress.org. Replace the file? The current one is moved to quarantine first.', 'gemsecurity' );
		// eslint-disable-next-line no-alert
		if ( ! window.confirm( warn ) ) {
			return;
		}
		setBusy( 'restore' );
		try {
			const { data } = await api.post( 'pro/compare/restore', { file: info.file } );
			toast( __( 'Official copy restored. The previous file is in quarantine.', 'gemsecurity' ), 'success' );
			onFixed && onFixed( data.result );
			onClose();
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not restore the file.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const markSafe = async () => {
		setBusy( 'safe' );
		try {
			await api.post( 'safe-files', { path: info.file } );
			toast( __( 'Marked as safe. It will be flagged again if it changes.', 'gemsecurity' ), 'success' );
			// No result: the caller re-scans in its own way.
			onFixed && onFixed( null );
			onClose();
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not mark that file.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const source = info && info.type && info.type !== 'unknown'
		? ( info.type === 'core' ? `WordPress ${ info.version }` : `${ info.slug } ${ info.version } (${ info.type })` )
		: ( info && info.version ? `WordPress ${ info.version }` : '' );

	// Rendered in place, not in a portal: the plugin's styles and dark theme are
	// scoped to its own wrapper, which a portal on <body> would sit outside of.
	return (
		<div className="gs-modal" role="dialog" aria-modal="true" aria-label={ file } onMouseDown={ ( e ) => e.target === e.currentTarget && onClose() }>
			<div className="gs-modal__box">
				<div className="gs-modal__head">
					<div>
						<strong>{ info?.file || file }</strong>
						{ source && <span className="gs-muted"> · { source }</span> }
						{ info && info.original && ( info.verified
							? <> <Badge tone="success">{ __( 'Verified copy', 'gemsecurity' ) }</Badge></>
							: pro && <> <Badge tone="warning">{ __( 'Unverified copy', 'gemsecurity' ) }</Badge></> ) }
						{ info?.safe && <> <Badge tone="info">{ __( 'Marked safe', 'gemsecurity' ) }</Badge></> }
					</div>
					<button type="button" className="gs-modal__x" onClick={ onClose } aria-label={ __( 'Close', 'gemsecurity' ) }>×</button>
				</div>

				<div className="gs-modal__body">
					{ error && <p className="gs-alert gs-alert--danger">{ error }</p> }
					{ ! info && ! error && <Loading /> }

					{ info && (
						<>
							{ ! info.exists && <p><Badge tone="warning">{ __( 'Missing', 'gemsecurity' ) }</Badge> { __( 'This file is not on your site.', 'gemsecurity' ) }</p> }
							{ info.binary && <p className="gs-alert gs-alert--warning">{ __( 'This is a binary file, so no line-by-line comparison is shown.', 'gemsecurity' ) }</p> }
							{ info.original_error && <p className="gs-alert gs-alert--warning">{ info.original_error }</p> }
							{ rows && rows.length === 0 && <p className="gs-ok">{ __( 'This file matches the official copy exactly — it is safe.', 'gemsecurity' ) }</p> }
							{ rows && rows.length > 0 && (
								<>
									<p className="gs-muted">
										{ sprintf( /* translators: %d: changed lines. */ __( '%d changed line(s).', 'gemsecurity' ), changed ) }{ ' ' }
										{ __( 'Red (+) lines are in your file but not in the official copy; green (−) lines are in the official copy but missing from yours.', 'gemsecurity' ) }
									</p>
									<pre className="gs-diff">
										{ rows.map( ( r, i ) => (
											<div key={ i } className={ `gs-diff__row gs-diff__row--${ r.k }` }>
												<span className="gs-diff__mark">{ { add: '+', del: '-', same: ' ', gap: '' }[ r.k ] }</span>{ r.t }
											</div>
										) ) }
									</pre>
								</>
							) }
							{ ! pro && (
								<p className="gs-muted">
									<ProBadge /> { __( 'Compare plugin and theme files too, restore the official copy in one click, or accept a reviewed change as safe.', 'gemsecurity' ) }
								</p>
							) }
						</>
					) }
				</div>

				{ info && (
					<div className="gs-modal__foot">
						{ pro && info.can_restore && (
							<Button onClick={ restore } loading={ busy === 'restore' } disabled={ !! busy }>
								{ info.exists ? __( 'Restore original', 'gemsecurity' ) : __( 'Restore missing file', 'gemsecurity' ) }
							</Button>
						) }
						{ pro && info.can_mark_safe && ! info.safe && (
							<Button variant="secondary" onClick={ markSafe } loading={ busy === 'safe' } disabled={ !! busy }>
								{ info.identical ? __( 'Mark as safe', 'gemsecurity' ) : __( 'Accept changes as safe', 'gemsecurity' ) }
							</Button>
						) }
						{ ! pro && <UpgradeButton>{ __( 'Unlock restore & mark safe', 'gemsecurity' ) }</UpgradeButton> }
						<Button variant="secondary" onClick={ onClose }>{ __( 'Close', 'gemsecurity' ) }</Button>
					</div>
				) }
			</div>
		</div>
	);
}
