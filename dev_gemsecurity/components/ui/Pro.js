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
/* ProGate — renders children only when the Pro add-on is active.     */
/* Nothing is rendered for features this plugin does not contain.      */
/* ------------------------------------------------------------------ */

export function ProGate( { title, description, children } ) {
	if ( ! isPro() ) {
		return null;
	}
	return children;
}

/**
 * ProSection — wrapper for a settings block that exists only in the Pro
 * add-on: rendered when Pro is active, absent otherwise.
 */
export function ProSection( { title, description, children } ) {
	if ( isPro() ) {
		return children;
	}

	// Nothing is shown for features this plugin does not contain.
	return null;
}

