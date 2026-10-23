import React, { createContext, useContext, useCallback, useEffect, useRef, useState } from 'react';

const ToastContext = createContext( () => {} );

export function useToast() {
	return useContext( ToastContext );
}

let idCounter = 0;

/** How long a toast stays up. One with an action (e.g. Undo) gets longer. */
const LIFETIME = 4000;
const ACTION_LIFETIME = 15000;

export function ToastProvider( { children } ) {
	const [ toasts, setToasts ] = useState( [] );

	const remove = useCallback( ( id ) => {
		setToasts( ( list ) => list.filter( ( t ) => t.id !== id ) );
	}, [] );

	const push = useCallback(
		// opts.action = { label, onClick } adds a button (e.g. Undo).
		( message, type = 'success', opts = {} ) => {
			const id = ++idCounter;
			setToasts( ( list ) => [ ...list, { id, message, type, action: opts.action } ] );
		},
		[]
	);

	return (
		<ToastContext.Provider value={ push }>
			{ children }
			<div className="gs-toasts" role="status" aria-live="polite">
				{ toasts.map( ( t ) => (
					<Toast key={ t.id } toast={ t } onClose={ () => remove( t.id ) } />
				) ) }
			</div>
		</ToastContext.Provider>
	);
}

/**
 * A single toast. Its timer pauses while hovered or focused, so an Undo
 * button never disappears from under the pointer; a bar shows time left.
 */
function Toast( { toast, onClose } ) {
	const total = toast.action ? ACTION_LIFETIME : LIFETIME;
	const [ paused, setPaused ] = useState( false );
	const left = useRef( total );
	const started = useRef( Date.now() );

	useEffect( () => {
		if ( paused ) {
			left.current -= Date.now() - started.current;
			return;
		}
		started.current = Date.now();
		const timer = setTimeout( onClose, Math.max( 0, left.current ) );
		return () => clearTimeout( timer );
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [ paused ] );

	return (
		<div
			className={ `gs-toast gs-toast--${ toast.type } ${ paused ? 'is-paused' : '' }` }
			onClick={ toast.action ? undefined : onClose }
			onMouseEnter={ () => setPaused( true ) }
			onMouseLeave={ () => setPaused( false ) }
			onFocus={ () => setPaused( true ) }
			onBlur={ () => setPaused( false ) }
		>
			{ toast.message }
			{ toast.action && (
				<button
					type="button"
					className="gs-toast__action"
					onClick={ ( e ) => {
						e.stopPropagation();
						onClose();
						toast.action.onClick();
					} }
				>
					{ toast.action.label }
				</button>
			) }
			{ toast.action && (
				<span className="gs-toast__timer" style={ { animationDuration: `${ total }ms` } } />
			) }
		</div>
	);
}
