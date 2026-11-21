import { useLocation } from 'react-router-dom';
import { __ } from '@wordpress/i18n';

export const SETTINGS_PAGE = 'gemsecurity-settings';

/** Sections of the Settings page, shown as a sub-menu under Settings. */
export function getSettingsTabs( pro ) {
	return [
		{ id: 'general', label: __( 'General', 'gemsecurity' ), icon: 'cog' },
		{ id: 'compliance', label: __( 'Compliance & SIEM', 'gemsecurity' ), icon: 'shield' },
		{ id: 'maintenance', label: __( 'Maintenance', 'gemsecurity' ), icon: 'lock' },
		...( pro ? [ { id: 'portability', label: __( 'Import / export', 'gemsecurity' ), icon: 'layers' } ] : [] ),
	];
}

/** Active section, read from `?tab=` so the sub-menu and the page stay in sync. */
export function useSettingsTab() {
	const { search } = useLocation();
	return new URLSearchParams( search ).get( 'tab' ) || 'general';
}
