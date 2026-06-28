import React from 'react';
import { createRoot } from 'react-dom/client';
import { Provider } from 'react-redux';
import { BrowserRouter as Router } from 'react-router-dom';
import store from '@Redux/store';
import App from '@Containers/App';
import { ToastProvider } from '@Components/ui/Toast';
import './backend.scss';

document.addEventListener( 'DOMContentLoaded', () => {
	const container = document.getElementById( 'gemsecuritywrap' );
	if ( ! container ) {
		return;
	}

	container.innerHTML = '';
	const root = createRoot( container );
	root.render(
		<Provider store={ store }>
			<Router future={ { v7_startTransition: true, v7_relativeSplatPath: true } }>
				<ToastProvider>
					<App />
				</ToastProvider>
			</Router>
		</Provider>
	);
} );
