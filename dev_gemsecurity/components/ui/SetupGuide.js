import React, { useState } from 'react';
import { __ } from '@wordpress/i18n';
import Icon from '@Components/ui/Icon';
import { useGuide } from '@Utils/docs';

/**
 * Inline "where does this value come from?" panel.
 *
 * A field label can say what a setting is, but not where to fetch an OAuth
 * client ID or a CAPTCHA secret. This renders the steps for that, collapsed by
 * default so it never gets in the way of someone who already knows, next to
 * the fields it describes.
 *
 * Content comes from PHP (Modules\Docs::guides), so it stays translatable and
 * add-ons can register their own through `gemsecurity/docs_guides`.
 *
 * @param {string} id           Guide id, e.g. "social.google".
 * @param {string} defaultOpen  Start expanded (for a first-run empty state).
 */
export default function SetupGuide( { id, defaultOpen = false } ) {
	const guide = useGuide( id );
	const [ open, setOpen ] = useState( defaultOpen );

	// Nothing registered for this id (or still loading) — render nothing rather
	// than an empty box.
	if ( ! guide ) {
		return null;
	}

	return (
		<div className={ `gs-guide ${ open ? 'is-open' : '' }` }>
			<button
				type="button"
				className="gs-guide__toggle"
				onClick={ () => setOpen( ! open ) }
				aria-expanded={ open }
			>
				<Icon name="help" size={ 15 } />
				<span>{ guide.title }</span>
				<Icon
					name="chevron"
					size={ 15 }
					className="gs-guide__chevron"
					aria-hidden="true"
				/>
			</button>

			{ open && (
				<div className="gs-guide__body">
					<ol className="gs-guide__steps">
						{ ( guide.steps || [] ).map( ( step, i ) => (
							<li key={ i }>{ step }</li>
						) ) }
					</ol>

					{ !! ( guide.notes || [] ).length && (
						<ul className="gs-guide__notes">
							{ guide.notes.map( ( note, i ) => (
								<li key={ i }>
									<Icon name="alert" size={ 13 } />
									<span>{ note }</span>
								</li>
							) ) }
						</ul>
					) }

					{ guide.link && guide.link.url && (
						<a
							className="gs-guide__link"
							href={ guide.link.url }
							target="_blank"
							rel="noreferrer noopener"
						>
							<Icon name="link" size={ 14 } />
							{ guide.link.label || __( 'Open provider console', 'gemsecurity' ) }
						</a>
					) }
				</div>
			) }
		</div>
	);
}
