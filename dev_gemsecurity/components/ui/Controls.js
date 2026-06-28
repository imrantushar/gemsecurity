import React from 'react';

/* ------------------------------------------------------------------ */
/* Card                                                                */
/* ------------------------------------------------------------------ */

export function Card( { title, description, actions, children, className = '' } ) {
	return (
		<div className={ `gs-card ${ className }` }>
			{ ( title || actions ) && (
				<div className="gs-card__head">
					<div>
						{ title && <h3 className="gs-card__title">{ title }</h3> }
						{ description && <p className="gs-card__desc">{ description }</p> }
					</div>
					{ actions && <div className="gs-card__actions">{ actions }</div> }
				</div>
			) }
			<div className="gs-card__body">{ children }</div>
		</div>
	);
}

/* ------------------------------------------------------------------ */
/* Button                                                              */
/* ------------------------------------------------------------------ */

export function Button( { variant = 'primary', loading, children, ...props } ) {
	return (
		<button
			className={ `gs-btn gs-btn--${ variant } ${ loading ? 'is-loading' : '' }` }
			disabled={ loading || props.disabled }
			{ ...props }
		>
			{ loading && <span className="gs-spinner" /> }
			{ children }
		</button>
	);
}

/* ------------------------------------------------------------------ */
/* Toggle (switch)                                                     */
/* ------------------------------------------------------------------ */

export function Toggle( { label, description, checked, onChange, disabled } ) {
	return (
		<label className={ `gs-toggle ${ disabled ? 'is-disabled' : '' }` }>
			<span className="gs-toggle__text">
				{ label && <span className="gs-toggle__label">{ label }</span> }
				{ description && <span className="gs-toggle__desc">{ description }</span> }
			</span>
			<span className={ `gs-switch ${ checked ? 'is-on' : '' }` }>
				<input
					type="checkbox"
					checked={ !! checked }
					disabled={ disabled }
					onChange={ ( e ) => onChange( e.target.checked ) }
				/>
				<span className="gs-switch__track">
					<span className="gs-switch__thumb" />
				</span>
			</span>
		</label>
	);
}

/* ------------------------------------------------------------------ */
/* Field (text / number / select)                                     */
/* ------------------------------------------------------------------ */

export function Field( { label, description, suffix, children } ) {
	return (
		<div className="gs-field">
			{ label && <label className="gs-field__label">{ label }</label> }
			<div className="gs-field__control">
				{ children }
				{ suffix && <span className="gs-field__suffix">{ suffix }</span> }
			</div>
			{ description && <p className="gs-field__desc">{ description }</p> }
		</div>
	);
}

export function TextInput( props ) {
	return <input className="gs-input" { ...props } />;
}

export function NumberInput( props ) {
	return <input type="number" className="gs-input gs-input--number" { ...props } />;
}

export function Select( { options, ...props } ) {
	return (
		<select className="gs-input gs-select" { ...props }>
			{ options.map( ( o ) => (
				<option key={ o.value } value={ o.value }>
					{ o.label }
				</option>
			) ) }
		</select>
	);
}

/* ------------------------------------------------------------------ */
/* List input (textarea-backed list of emails / IPs)                   */
/* ------------------------------------------------------------------ */

export function ListInput( { value, onChange, placeholder, rows = 5 } ) {
	const text = Array.isArray( value ) ? value.join( '\n' ) : value || '';
	return (
		<textarea
			className="gs-input gs-textarea"
			rows={ rows }
			placeholder={ placeholder }
			value={ text }
			onChange={ ( e ) =>
				onChange(
					e.target.value
						.split( /[\r\n,]+/ )
						.map( ( v ) => v.trim() )
						.filter( Boolean )
				)
			}
		/>
	);
}

/* ------------------------------------------------------------------ */
/* Badge                                                               */
/* ------------------------------------------------------------------ */

export function Badge( { tone = 'info', children } ) {
	return <span className={ `gs-badge gs-badge--${ tone }` }>{ children }</span>;
}

/* ------------------------------------------------------------------ */
/* Empty / loading states                                              */
/* ------------------------------------------------------------------ */

export function Loading( { label = 'Loading…' } ) {
	return (
		<div className="gs-loading">
			<span className="gs-spinner gs-spinner--lg" />
			<span>{ label }</span>
		</div>
	);
}

export function EmptyState( { title, description } ) {
	return (
		<div className="gs-empty">
			<h4>{ title }</h4>
			{ description && <p>{ description }</p> }
		</div>
	);
}
