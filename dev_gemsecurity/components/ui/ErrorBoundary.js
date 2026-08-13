import React from 'react';
import { __ } from '@wordpress/i18n';

/**
 * Page-level error boundary.
 *
 * Contains a render/lifecycle crash in a single page so it can't take down the
 * whole SPA (and, critically, the navigation). The boundary is keyed by the
 * active page in App, so moving to another page automatically resets it.
 */
export default class ErrorBoundary extends React.Component {
	constructor( props ) {
		super( props );
		this.state = { error: null };
	}

	static getDerivedStateFromError( error ) {
		return { error };
	}

	componentDidCatch( error, info ) {
		// Surface it for debugging without breaking the app.
		// eslint-disable-next-line no-console
		console.error( 'GemSecurity page error:', error, info );
	}

	render() {
		if ( this.state.error ) {
			return (
				<div className="gs-page">
					<div className="gs-card">
						<div className="gs-card__body">
							<div className="gs-empty">
								<h4>{ __( 'Something went wrong on this page', 'gemsecurity' ) }</h4>
								<p>
									{ __(
										'This page hit an unexpected error. Other sections still work — pick another item from the menu, or reload to try again.',
										'gemsecurity'
									) }
								</p>
								<p className="gs-muted" style={ { marginTop: 8, fontSize: 12 } }>
									{ String( this.state.error?.message || this.state.error ) }
								</p>
								<button
									type="button"
									className="gs-btn gs-btn--secondary"
									style={ { marginTop: 14 } }
									onClick={ () => window.location.reload() }
								>
									{ __( 'Reload', 'gemsecurity' ) }
								</button>
							</div>
						</div>
					</div>
				</div>
			);
		}
		return this.props.children;
	}
}
