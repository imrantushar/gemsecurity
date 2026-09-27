import React, { useEffect, useRef } from 'react';
import { __ } from '@wordpress/i18n';
import Icon from '@Components/ui/Icon';
import { Loading } from '@Components/ui/Controls';
import { useDoc } from '@Utils/docs';

/**
 * Slide-over help panel for the page you are on: what the module does, how to
 * set it up, and what to watch out for. Content comes from PHP (Modules\Docs)
 * so it stays translatable and extendable.
 *
 * @param {boolean}  open    Whether the drawer is showing.
 * @param {Function} onClose Close handler.
 * @param {string}   slug    Page slug to document.
 * @param {string}   title   Fallback heading while the guide loads.
 */
export default function HelpDrawer( { open, onClose, slug, title } ) {
	const panel = useRef( null );
	const { doc, loading } = useDoc( slug, open );

	// Escape closes; focus moves into the panel so keyboard users are not left
	// behind on the button that opened it.
	useEffect( () => {
		if ( ! open ) {
			return;
		}
		const onKey = ( e ) => {
			if ( e.key === 'Escape' ) {
				onClose();
			}
		};
		document.addEventListener( 'keydown', onKey );
		panel.current?.focus();
		return () => document.removeEventListener( 'keydown', onKey );
	}, [ open, onClose ] );

	if ( ! open ) {
		return null;
	}

	return (
		<div className="gs-help">
			<div
				className="gs-help__scrim"
				onClick={ onClose }
				role="presentation"
			/>
			<aside
				className="gs-help__panel"
				ref={ panel }
				tabIndex={ -1 }
				role="dialog"
				aria-modal="true"
				aria-label={ __( 'Help', 'gemsecurity' ) }
			>
				<header className="gs-help__head">
					<h2 className="gs-help__title">
						{ ( doc && doc.title ) || title || __( 'Help', 'gemsecurity' ) }
					</h2>
					<button
						type="button"
						className="gs-help__close"
						onClick={ onClose }
						aria-label={ __( 'Close help', 'gemsecurity' ) }
					>
						<Icon name="close" size={ 18 } />
					</button>
				</header>

				<div className="gs-help__body">
					{ loading && <Loading label={ __( 'Loading guide…', 'gemsecurity' ) } /> }

					{ ! loading && ! doc && (
						<p className="gs-muted">
							{ __(
								'No guide for this page yet. Each card on the page describes what its settings do.',
								'gemsecurity'
							) }
						</p>
					) }

					{ doc && (
						<>
							<p className="gs-help__summary">{ doc.summary }</p>
							<Section
								icon="check"
								title={ __( 'What it does', 'gemsecurity' ) }
								items={ doc.does }
							/>
							<Section
								icon="cog"
								title={ __( 'How to set it up', 'gemsecurity' ) }
								items={ doc.setup }
								ordered
							/>
							<Section
								icon="alert"
								title={ __( 'Good to know', 'gemsecurity' ) }
								items={ doc.notes }
								tone="warning"
							/>
						</>
					) }
				</div>
			</aside>
		</div>
	);
}

function Section( { icon, title, items, ordered, tone } ) {
	if ( ! items || ! items.length ) {
		return null;
	}
	const List = ordered ? 'ol' : 'ul';
	return (
		<section className={ `gs-help__section ${ tone ? `is-${ tone }` : '' }` }>
			<h3 className="gs-help__section-title">
				<Icon name={ icon } size={ 15 } />
				{ title }
			</h3>
			<List className="gs-help__list">
				{ items.map( ( item, i ) => (
					<li key={ i }>{ item }</li>
				) ) }
			</List>
		</section>
	);
}
