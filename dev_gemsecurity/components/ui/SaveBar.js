import React, { useEffect, useRef, useState } from 'react';
import { __, sprintf, _n } from '@wordpress/i18n';
import { Button } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';
import { useUnsaved, saveAll, discardAll, resolveLeave } from '@Utils/unsavedChanges';

/**
 * The one save control for every settings page. Appears, docked to the
 * bottom of the content area, as soon as any form on the page has unsaved
 * edits; saves or discards all of them together. Instant switches never
 * show it — they save as they flip.
 */
export default function SaveBar() {
	const { dirty, count } = useUnsaved();
	const [ saving, setSaving ] = useState( false );

	// Ctrl/Cmd+S saves from anywhere on the page.
	useEffect( () => {
		const onKey = ( e ) => {
			if ( dirty && ( e.metaKey || e.ctrlKey ) && e.key.toLowerCase() === 's' ) {
				e.preventDefault();
				onSave();
			}
		};
		document.addEventListener( 'keydown', onKey );
		return () => document.removeEventListener( 'keydown', onKey );
	} );

	const onSave = async () => {
		setSaving( true );
		await saveAll();
		setSaving( false );
	};

	if ( ! dirty ) {
		return null;
	}

	return (
		<div className="gs-globalsave" role="region" aria-label={ __( 'Unsaved changes', 'gemsecurity' ) }>
			<span className="gs-globalsave__label">
				<span className="gs-globalsave__dot" />
				{ count > 1
					? sprintf(
						/* translators: %d: number of sections */
						_n( 'Unsaved changes in %d section', 'Unsaved changes in %d sections', count, 'gemsecurity' ),
						count
					)
					: __( 'You have unsaved changes', 'gemsecurity' ) }
			</span>
			<div className="gs-globalsave__actions">
				<Button variant="secondary" onClick={ discardAll } disabled={ saving }>
					{ __( 'Discard', 'gemsecurity' ) }
				</Button>
				<Button onClick={ onSave } loading={ saving }>
					{ __( 'Save changes', 'gemsecurity' ) }
				</Button>
			</div>
		</div>
	);
}

/** Modal shown when leaving a page with unsaved edits. */
export function LeaveDialog() {
	const { pending } = useUnsaved();
	const [ saving, setSaving ] = useState( false );
	const saveRef = useRef( null );

	useEffect( () => {
		if ( ! pending ) {
			return;
		}
		saveRef.current?.focus();
		const onKey = ( e ) => {
			if ( e.key === 'Escape' ) {
				resolveLeave( 'stay' );
			}
		};
		document.addEventListener( 'keydown', onKey );
		return () => document.removeEventListener( 'keydown', onKey );
	}, [ pending ] );

	if ( ! pending ) {
		return null;
	}

	const onSave = async () => {
		setSaving( true );
		await resolveLeave( 'save' );
		setSaving( false );
	};

	return (
		<div className="gs-leave" onMouseDown={ ( e ) => e.target === e.currentTarget && resolveLeave( 'stay' ) }>
			<div className="gs-leave__box" role="alertdialog" aria-modal="true" aria-labelledby="gs-leave-title" aria-describedby="gs-leave-desc">
				<span className="gs-leave__icon"><Icon name="alert" size={ 20 } /></span>
				<h2 id="gs-leave-title">{ __( 'You have unsaved changes', 'gemsecurity' ) }</h2>
				<p id="gs-leave-desc">
					{ __( 'If you leave this page now, the changes you made will be lost. Save them first?', 'gemsecurity' ) }
				</p>
				<div className="gs-leave__actions">
					<Button variant="secondary" onClick={ () => resolveLeave( 'stay' ) } disabled={ saving }>
						{ __( 'Stay on page', 'gemsecurity' ) }
					</Button>
					<Button variant="danger" onClick={ () => resolveLeave( 'discard' ) } disabled={ saving }>
						{ __( 'Discard & leave', 'gemsecurity' ) }
					</Button>
					<Button ref={ saveRef } onClick={ onSave } loading={ saving }>
						{ __( 'Save & leave', 'gemsecurity' ) }
					</Button>
				</div>
			</div>
		</div>
	);
}
