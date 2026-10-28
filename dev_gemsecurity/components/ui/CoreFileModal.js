import React, { useEffect, useMemo, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api from '@Utils/api';
import { Button, Badge, Loading } from '@Components/ui/Controls';
import { useToast } from '@Components/ui/Toast';

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
 * Popup for one flagged core file: what differs from the official release,
 * with a one-click restore and, where the site allows file editing, an editor.
 *
 * @param {Object}   props
 * @param {string}   props.file    Root-relative path.
 * @param {Function} props.onClose
 * @param {Function} props.onFixed Called with the fresh scan result.
 */
export default function CoreFileModal( { file, onClose, onFixed } ) {
	const toast = useToast();
	const [ info, setInfo ] = useState( null );
	const [ error, setError ] = useState( '' );
	const [ editing, setEditing ] = useState( false );
	const [ draft, setDraft ] = useState( '' );
	const [ busy, setBusy ] = useState( false );

	useEffect( () => {
		api.get( 'scan/core-file', { params: { file } } )
			.then( ( r ) => {
				setInfo( r.data );
				setDraft( r.data.current );
			} )
			.catch( ( e ) => setError( e?.response?.data?.message || __( 'Could not load this file.', 'gemsecurity' ) ) );
	}, [ file ] );

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

	const run = async ( body, done ) => {
		setBusy( true );
		try {
			const { data } = await api.post( 'scan/core-file', { file, ...body } );
			toast( done, 'success' );
			onFixed( data.result );
			onClose();
		} catch ( e ) {
			toast( e?.response?.data?.message || __( 'Could not update the file.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};

	const restore = () => {
		// eslint-disable-next-line no-alert
		if ( window.confirm( __( 'Replace this file with the official WordPress copy? The current file is backed up first.', 'gemsecurity' ) ) ) {
			run( { action: 'restore' }, __( 'Original file restored.', 'gemsecurity' ) );
		}
	};

	// Rendered in place, not in a portal: the plugin's styles and dark theme are
	// scoped to its own wrapper, which a portal on <body> would sit outside of.
	return (
		<div className="gs-modal" role="dialog" aria-modal="true" aria-label={ file } onMouseDown={ ( e ) => e.target === e.currentTarget && onClose() }>
			<div className="gs-modal__box">
				<div className="gs-modal__head">
					<div>
						<strong>{ file }</strong>
						{ info && <span className="gs-muted"> · WordPress { info.version }</span> }
					</div>
					<button type="button" className="gs-modal__x" onClick={ onClose } aria-label={ __( 'Close', 'gemsecurity' ) }>×</button>
				</div>

				<div className="gs-modal__body">
					{ error && <p className="gs-alert gs-alert--danger">{ error }</p> }
					{ ! info && ! error && <Loading /> }

					{ info && ! editing && (
						<>
							{ ! info.exists && <p><Badge tone="warning">{ __( 'Missing', 'gemsecurity' ) }</Badge> { __( 'This core file is not on your site.', 'gemsecurity' ) }</p> }
							{ info.original_error && <p className="gs-alert gs-alert--warning">{ info.original_error }</p> }
							{ rows && rows.length === 0 && <p className="gs-ok">{ __( 'This file now matches the official copy.', 'gemsecurity' ) }</p> }
							{ rows && rows.length > 0 && (
								<>
									<p className="gs-muted">
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
						</>
					) }

					{ info && editing && (
						<>
							<p className="gs-muted">{ __( 'Edit the file directly. A backup of the current version is kept first. A syntax error here can take your whole site down.', 'gemsecurity' ) }</p>
							<textarea
								className="gs-input gs-textarea gs-modal__editor"
								value={ draft }
								onChange={ ( e ) => setDraft( e.target.value ) }
								spellCheck={ false }
							/>
						</>
					) }
				</div>

				{ info && (
					<div className="gs-modal__foot">
						{ ! editing ? (
							<>
								{ info.original && <Button onClick={ restore } loading={ busy }>{ __( 'Restore original', 'gemsecurity' ) }</Button> }
								{ info.can_edit
									? <Button variant="secondary" onClick={ () => setEditing( true ) }>{ __( 'Edit file', 'gemsecurity' ) }</Button>
									: <span className="gs-muted">{ __( 'Editing is off (file editor disabled in Firewall settings).', 'gemsecurity' ) }</span> }
							</>
						) : (
							<>
								<Button onClick={ () => run( { action: 'save', content: draft }, __( 'File saved.', 'gemsecurity' ) ) } loading={ busy }>{ __( 'Save file', 'gemsecurity' ) }</Button>
								<Button variant="secondary" onClick={ () => { setEditing( false ); setDraft( info.current ); } }>{ __( 'Cancel', 'gemsecurity' ) }</Button>
							</>
						) }
						<Button variant="secondary" onClick={ onClose }>{ __( 'Close', 'gemsecurity' ) }</Button>
					</div>
				) }
			</div>
		</div>
	);
}
