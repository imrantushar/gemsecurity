import React from 'react';
import { __ } from '@wordpress/i18n';
import { GS } from '@Utils/api';
import Icon from '@Components/ui/Icon';

/* ------------------------------------------------------------------ */
/* Pro state helpers — single source of truth comes from PHP via the   */
/* GemSecurityGlobal payload (Helper::get_pro_features / is_pro_active).*/
/* ------------------------------------------------------------------ */

/** Is the Pro addon active (and licensed)? */
export function isPro() {
	return !! GS.is_pro;
}

/** Map of pro feature key => { title, desc }. */
export function proFeatures() {
	return GS.pro_features || {};
}

/** Is this page/section key a Pro-only feature? */
export function isProFeature( key ) {
	return Object.prototype.hasOwnProperty.call( proFeatures(), key );
}

/** Should this key be locked right now (Pro feature + Pro inactive)? */
export function isLocked( key ) {
	return isProFeature( key ) && ! isPro();
}

/** Upgrade/pricing URL. */
export function upgradeUrl() {
	return GS.upgrade_url || 'https://kodezen.com/';
}

/* ------------------------------------------------------------------ */
/* ProBadge — small inline "PRO" pill.                                 */
/* ------------------------------------------------------------------ */

export function ProBadge( { className = '' } ) {
	return (
		<span className={ `gs-pro-badge ${ className }` }>
			{ __( 'PRO', 'gemsecurity' ) }
		</span>
	);
}

/* ------------------------------------------------------------------ */
/* UpgradeButton                                                       */
/* ------------------------------------------------------------------ */

export function UpgradeButton( { children } ) {
	return (
		<a
			className="gs-btn gs-btn--primary"
			href={ upgradeUrl() }
			target="_blank"
			rel="noreferrer"
		>
			{ children || __( 'Upgrade to Pro', 'gemsecurity' ) }
		</a>
	);
}

/* ------------------------------------------------------------------ */
/* ProGate — renders children when Pro is active; otherwise shows the  */
/* feature behind a frosted upgrade overlay.                           */
/* ------------------------------------------------------------------ */

export function ProGate( { title, description, children } ) {
	if ( isPro() ) {
		return children;
	}

	return (
		<div className="gs-pro-gate">
			<div className="gs-pro-gate__preview" aria-hidden="true" inert="">
				{ children }
			</div>
			<div className="gs-pro-gate__overlay">
				<div className="gs-pro-gate__card">
					<span className="gs-pro-gate__mark">
						<Icon name="lock" size={ 24 } />
					</span>
					<ProBadge />
					<h3 className="gs-pro-gate__title">
						{ title || __( 'This is a Pro feature', 'gemsecurity' ) }
					</h3>
					{ description && (
						<p className="gs-pro-gate__desc">{ description }</p>
					) }
					<UpgradeButton />
				</div>
			</div>
		</div>
	);
}

/**
 * ProSection — convenience wrapper to lock an individual settings block on
 * an otherwise-free page. Renders a header with a PRO badge, then gates the
 * body. Sprinkle around any block you want to reserve for Pro.
 */
export function ProSection( { title, description, children } ) {
	if ( isPro() ) {
		return children;
	}

	return (
		<div className="gs-pro-gate gs-pro-gate--compact">
			<div className="gs-pro-gate__preview" aria-hidden="true" inert="">
				{ children }
			</div>
			<div className="gs-pro-gate__overlay">
				<div className="gs-pro-gate__card">
					<span className="gs-pro-gate__mark">
						<Icon name="lock" size={ 20 } />
					</span>
					<div className="gs-pro-gate__body">
						<h3 className="gs-pro-gate__title">
							{ title || __( 'This is a Pro feature', 'gemsecurity' ) }
							<ProBadge />
						</h3>
						{ description && (
							<p className="gs-pro-gate__desc">{ description }</p>
						) }
					</div>
					<UpgradeButton />
				</div>
			</div>
		</div>
	);
}
