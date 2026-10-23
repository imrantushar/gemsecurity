import React, { createContext, useContext, useCallback, useState } from 'react';

const ToastContext = createContext( () => {} );

export function useToast() {
	return useContext( ToastContext );
}

let idCounter = 0;

export function ToastProvider( { children } ) {
	const [ toasts, setToasts ] = useState( [] );

	const remove = useCallback( ( id ) => {
		setToasts( ( list ) => list.filter( ( t ) => t.id !== id ) );
	}, [] );

	const push = useCallback(
		// opts.action = { label, onClick } adds a button (e.g. Undo) and keeps
		// the toast up longer so there is time to use it.
		( message, type = 'success', opts = {} ) => {
			const id = ++idCounter;
			setToasts( ( list ) => [ ...list, { id, message, type, action: opts.action } ] );
			setTimeout( () => remove( id ), opts.action ? 8000 : 4000 );
		},
		[ remove ]
	);

	return (
		<ToastContext.Provider value={ push }>
			{ children }
			<div className="gs-toasts">
				{ toasts.map( ( t ) => (
					<div key={ t.id } className={ `gs-toast gs-toast--${ t.type }` } onClick={ () => remove( t.id ) }>
						{ t.message }
						{ t.action && (
							<button
								type="button"
								className="gs-toast__action"
								onClick={ ( e ) => {
									e.stopPropagation();
									remove( t.id );
									t.action.onClick();
								} }
							>
								{ t.action.label }
							</button>
						) }
					</div>
				) ) }
			</div>
		</ToastContext.Provider>
	);
}
