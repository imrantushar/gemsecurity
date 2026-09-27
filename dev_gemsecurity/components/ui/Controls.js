import React, { useEffect, useState } from 'react';
import ReactSelect from 'react-select';
import Icon from '@Components/ui/Icon';

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
/* Collapsible (accordion section)                                     */
/* ------------------------------------------------------------------ */

/**
 * A Card whose body folds away behind its header.
 *
 * For pages that stack many result panels: the header keeps the title and a
 * status summary in view, so a section that found nothing costs one row
 * instead of a screenful and only the ones that matter are opened.
 *
 * Uncontrolled by default — pass `open` + `onToggle` to drive it from a
 * parent. `syncKey` re-applies `defaultOpen` when it changes, which is how a
 * fresh set of results re-opens whichever sections now carry findings.
 */
export function Collapsible( {
	id,
	title,
	description,
	badge,
	actions,
	defaultOpen = false,
	open: openProp,
	onToggle,
	syncKey,
	children,
	className = '',
} ) {
	const [ selfOpen, setSelfOpen ] = useState( defaultOpen );
	const controlled = undefined !== openProp;
	const open = controlled ? openProp : selfOpen;

	// eslint-disable-next-line react-hooks/exhaustive-deps
	useEffect( () => setSelfOpen( defaultOpen ), [ defaultOpen, syncKey ] );

	const toggle = () => ( controlled ? onToggle( ! open ) : setSelfOpen( ! open ) );

	return (
		<div id={ id } className={ `gs-card gs-collapse ${ open ? 'is-open' : '' } ${ className }` }>
			<div className="gs-collapse__head">
				<h3 className="gs-collapse__heading">
					<button
						type="button"
						className="gs-collapse__toggle"
						aria-expanded={ open }
						onClick={ toggle }
					>
						<Icon name="chevron" size={ 16 } className="gs-collapse__chevron" />
						<span>{ title }</span>
					</button>
				</h3>
				<div className="gs-collapse__trailing">
					{ badge }
					{ open && actions ? <div className="gs-card__actions">{ actions }</div> : null }
				</div>
			</div>
			{ open && (
				<div className="gs-card__body">
					{ description && <p className="gs-card__desc gs-collapse__desc">{ description }</p> }
					{ children }
				</div>
			) }
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
/* Multi-select                                                        */
/* ------------------------------------------------------------------ */

/** Turn a `{ slug: label }` map — how roles arrive from PHP — into options. */
export function toOptions( map ) {
	return Object.entries( map || {} ).map( ( [ value, label ] ) => ( { value, label } ) );
}

/**
 * Pick several values from a long list.
 *
 * `value` and `onChange` deal in a plain array of option values rather than
 * react-select's option objects, because that is what every caller stores. A
 * stored value with no matching option — a role a plugin has since removed —
 * still shows as its own chip, so saving cannot quietly drop it.
 *
 * The menu renders in place rather than through a portal on `document.body`:
 * the theme's custom properties are defined on the plugin wrapper, so a
 * portalled menu falls out of the dark theme. Nothing here clips overflow, so
 * there is nothing for a portal to escape.
 */
export function MultiSelect( { options, value, onChange, placeholder, disabled, inputId } ) {
	const selected = ( Array.isArray( value ) ? value : [] ).map(
		( v ) => options.find( ( o ) => o.value === v ) || { value: v, label: v }
	);

	return (
		<ReactSelect
			isMulti
			inputId={ inputId }
			className="gs-rs"
			classNamePrefix="gs-rs"
			options={ options }
			value={ selected }
			onChange={ ( opts ) => onChange( ( opts || [] ).map( ( o ) => o.value ) ) }
			placeholder={ placeholder }
			isDisabled={ disabled }
			closeMenuOnSelect={ false }
			hideSelectedOptions={ false }
		/>
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

export function Badge( { tone = 'info', className = '', children } ) {
	return <span className={ `gs-badge gs-badge--${ tone } ${ className }` }>{ children }</span>;
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
