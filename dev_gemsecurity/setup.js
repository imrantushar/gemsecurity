import React from 'react';
import { createRoot } from 'react-dom/client';
import SetupWizard from '@Containers/SetupWizard';
import { applyTheme, getInitialTheme } from '@Utils/theme';
import './backend.scss';
import './setup.scss';

document.addEventListener( 'DOMContentLoaded', () => {
	const container = document.getElementById( 'gemsecuritywrap' );
	if ( ! container ) {
		return;
	}
	applyTheme( getInitialTheme() );
	createRoot( container ).render( <SetupWizard /> );
} );
