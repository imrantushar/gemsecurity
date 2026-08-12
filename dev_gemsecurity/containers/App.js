import React, { useEffect } from 'react';
import { __ } from '@wordpress/i18n';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import { fetchSettings } from '@Redux/settingsSlice';
import { useActivePage, NAV_ITEMS, MODULES, pageUrl } from '@Utils/nav';
import { Loading, EmptyState, Button } from '@Components/ui/Controls';
import { isLocked, isPro, proFeatures, ProBadge, ProGate } from '@Components/ui/Pro';
import ErrorBoundary from '@Components/ui/ErrorBoundary';
import Icon from '@Components/ui/Icon';
import { useThemeMode } from '@Utils/theme';

import Dashboard from '@Containers/pages/Dashboard';
import ModulesPage from '@Containers/pages/Modules';
import Firewall from '@Containers/pages/Firewall';
import ThreatDefense from '@Containers/pages/ThreatDefense';
import LoginSecurity from '@Containers/pages/LoginSecurity';
import TwoFactor from '@Containers/pages/TwoFactor';
import SocialLogin from '@Containers/pages/SocialLogin';
import Geolocation from '@Containers/pages/Geolocation';
import AdminGuard from '@Containers/pages/AdminGuard';
import Scanner from '@Containers/pages/Scanner';
import Logs from '@Containers/pages/Logs';
import Backup from '@Containers/pages/Backup';
import ProTools from '@Containers/pages/ProTools';
import Settings from '@Containers/pages/Settings';

const PAGES = {
	gemsecurity: Dashboard,
	'gemsecurity-modules': ModulesPage,
	'gemsecurity-firewall': Firewall,
	'gemsecurity-threats': ThreatDefense,
	'gemsecurity-login-security': LoginSecurity,
	'gemsecurity-two-factor': TwoFactor,
	'gemsecurity-social-login': SocialLogin,
	'gemsecurity-geolocation': Geolocation,
	'gemsecurity-admin-guard': AdminGuard,
	'gemsecurity-scanner': Scanner,
	// Legacy alias — the malware scanner is now a tab inside Scanner.
	'gemsecurity-malware': Scanner,
	'gemsecurity-logs': Logs,
	'gemsecurity-backup': Backup,
	'gemsecurity-pro-tools': ProTools,
	'gemsecurity-settings': Settings,
};

export default function App() {
	const dispatch = useDispatch();
	const navigate = useNavigate();
	const { theme, toggle } = useThemeMode();
	const { data, loading } = useSelector( ( s ) => s.settings );
	const page = useActivePage();

	useEffect( () => {
		dispatch( fetchSettings() );
	}, [ dispatch ] );

	// Scroll to top on route change for a fresh-page feel.
	useEffect( () => {
		const el = document.querySelector( '.gs-content' );
		if ( el ) {
			el.scrollTo?.( 0, 0 );
		}
		window.scrollTo?.( 0, 0 );
	}, [ page ] );

	// The malware scanner is now a tab inside Scanner — resolve the old slug.
	const resolvedPage = page === 'gemsecurity-malware' ? 'gemsecurity-scanner' : page;
	const PageComponent = PAGES[ resolvedPage ] || Dashboard;
	const navItem = NAV_ITEMS.find( ( i ) => i.key === resolvedPage );
	const locked = isLocked( resolvedPage );
	const feature = proFeatures()[ resolvedPage ] || {};

	// A module the user has turned off: its page is unreachable. Show a prompt
	// to re-activate it rather than a broken/empty page.
	const module = MODULES.find( ( m ) => m.page_slug === resolvedPage );
	const inactive = module && ! module.visible;

	const renderPage = () => {
		if ( loading && ! data ) {
			return <Loading />;
		}
		if ( inactive ) {
			return (
				<div className="gs-page">
					<EmptyState
						title={ __( 'This module is turned off', 'gemsecurity' ) }
						description={ __( 'Activate it from the Modules page to use this feature.', 'gemsecurity' ) }
					/>
					<div style={ { marginTop: 16 } }>
						<Button onClick={ () => navigate( pageUrl( 'gemsecurity-modules' ) ) }>
							{ __( 'Go to Modules', 'gemsecurity' ) }
						</Button>
					</div>
				</div>
			);
		}
		if ( locked ) {
			return (
				<ProGate title={ feature.title } description={ feature.desc }>
					<PageComponent />
				</ProGate>
			);
		}
		return <PageComponent />;
	};

	return (
		<div className="gs-app">
			<main className="gs-main">
				<header className="gs-topbar">
					<div className="gs-topbar__inner">
						<div className="gs-topbar__left">
							<span className="gs-topbar__logo" aria-hidden="true">
								<Icon name="shield" size={ 20 } />
							</span>
							<h1 className="gs-topbar__title">
								{ navItem ? navItem.label : 'GemSecurity' }
								{ locked && <ProBadge /> }
							</h1>
						</div>
						<button
							type="button"
							className="gs-topbar__theme"
							onClick={ toggle }
							aria-label={ theme === 'dark' ? __( 'Switch to light mode', 'gemsecurity' ) : __( 'Switch to dark mode', 'gemsecurity' ) }
							title={ theme === 'dark' ? __( 'Switch to light mode', 'gemsecurity' ) : __( 'Switch to dark mode', 'gemsecurity' ) }
						>
							<Icon name={ theme === 'dark' ? 'sun' : 'moon' } size={ 18 } />
						</button>
					</div>
				</header>
				<div className="gs-shell">
					<nav className="gs-subnav">
						{ NAV_ITEMS.map( ( item ) => {
							const href = pageUrl( item.key );
							return (
								<a
									key={ item.key }
									href={ href }
									className={ `gs-subnav__item ${ item.key === resolvedPage ? 'is-active' : '' }` }
									onClick={ ( e ) => {
										// Let modifier-clicks (new tab/window) behave normally;
										// otherwise route client-side. No e.button gate — some
										// environments don't report button===0 reliably, which
										// would silently swallow the click.
										if ( e.metaKey || e.ctrlKey || e.shiftKey || e.altKey ) {
											return;
										}
										e.preventDefault();
										navigate( href );
									} }
								>
									<Icon name={ item.icon } size={ 17 } />
									<span>{ item.label }</span>
									{ item.isPro && ! isPro() && <ProBadge /> }
								</a>
							);
						} ) }
					</nav>
					<div className="gs-content">
						<ErrorBoundary key={ resolvedPage }>
							{ renderPage() }
						</ErrorBoundary>
					</div>
				</div>
			</main>
		</div>
	);
}
