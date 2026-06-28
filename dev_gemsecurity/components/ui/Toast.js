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
		( message, type = 'success' ) => {
			const id = ++idCounter;
			setToasts( ( list ) => [ ...list, { id, message, type } ] );
			setTimeout( () => remove( id ), 4000 );
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
					</div>
				) ) }
			</div>
		</ToastContext.Provider>
	);
}
