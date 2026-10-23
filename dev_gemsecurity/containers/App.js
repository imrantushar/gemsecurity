import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import { fetchSettings } from '@Redux/settingsSlice';
import { useActivePage, useNavItems, useNavGroups, useModuleBySlug, pageUrl, pageFromHref, syncAdminMenu, getModules } from '@Utils/nav';
import TopNav from '@Components/Layout/TopNav';
import { Loading, EmptyState, Button } from '@Components/ui/Controls';
import { isLocked, isPro, proFeatures, ProBadge, ProGate } from '@Components/ui/Pro';
import ErrorBoundary from '@Components/ui/ErrorBoundary';
import Icon from '@Components/ui/Icon';
import HelpDrawer from '@Components/ui/HelpDrawer';
import PageScoreTips from '@Components/ui/PageScoreTips';
import TopbarScore from '@Components/ui/TopbarScore';
import { useThemeMode } from '@Utils/theme';

import Dashboard from '@Containers/pages/Dashboard';
import ModulesPage from '@Containers/pages/Modules';
import Firewall from '@Containers/pages/Firewall';
import ThreatDefense from '@Containers/pages/ThreatDefense';
import VirtualPatch from '@Containers/pages/VirtualPatch';
import LoginSecurity from '@Containers/pages/LoginSecurity';
import Captcha from '@Containers/pages/Captcha';
import TwoFactor from '@Containers/pages/TwoFactor';
import SocialLogin from '@Containers/pages/SocialLogin';
import Geolocation from '@Containers/pages/Geolocation';
import AdminGuard from '@Containers/pages/AdminGuard';
import ApiHardening from '@Containers/pages/ApiHardening';
import AntiSpam from '@Containers/pages/AntiSpam';
import Scanner from '@Containers/pages/Scanner';
import PluginGuard from '@Containers/pages/PluginGuard';
import PaymentIntegrity from '@Containers/pages/PaymentIntegrity';
import IncidentResponse from '@Containers/pages/IncidentResponse';
import Logs from '@Containers/pages/Logs';
import Monitoring from '@Containers/pages/Monitoring';
import Notifications from '@Containers/pages/Notifications';
import Settings from '@Containers/pages/Settings';

const PAGES = {
	gemsecurity: Dashboard,
	'gemsecurity-modules': ModulesPage,
	'gemsecurity-firewall': Firewall,
	'gemsecurity-threats': ThreatDefense,
	'gemsecurity-virtual-patch': VirtualPatch,
	'gemsecurity-plugin-guard': PluginGuard,
	'gemsecurity-login-security': LoginSecurity,
	'gemsecurity-captcha': Captcha,
	'gemsecurity-two-factor': TwoFactor,
	'gemsecurity-social-login': SocialLogin,
	'gemsecurity-geolocation': Geolocation,
	'gemsecurity-admin-guard': AdminGuard,
	'gemsecurity-api-hardening': ApiHardening,
	'gemsecurity-anti-spam': AntiSpam,
	'gemsecurity-scanner': Scanner,
	'gemsecurity-payment-integrity': PaymentIntegrity,
	'gemsecurity-incident-response': IncidentResponse,
	// Legacy alias — the malware scanner is now a tab inside Scanner.
	'gemsecurity-malware': Scanner,
	'gemsecurity-logs': Logs,
	'gemsecurity-monitoring': Monitoring,
	'gemsecurity-notifications': Notifications,
	'gemsecurity-settings': Settings,
};

export default function App() {
	const dispatch = useDispatch();
	const navigate = useNavigate();
	const { theme, toggle } = useThemeMode();
	const { data, loading } = useSelector( ( s ) => s.settings );
	const page = useActivePage();
	const [ helpOpen, setHelpOpen ] = useState( false );

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
		// Keep the WP sidebar's group highlight in step with client-side routing.
		syncAdminMenu( getModules() );
	}, [ page ] );

	// The malware scanner is now a tab inside Scanner — resolve the old slug.
	const resolvedPage = page === 'gemsecurity-malware' ? 'gemsecurity-scanner' : page;
	const PageComponent = PAGES[ resolvedPage ] || Dashboard;
	const navItems = useNavItems();
	const navItem = navItems.find( ( i ) => i.key === resolvedPage );
	// Side nav lists only the current group's pages; the topbar switches groups.
	const groupItems = useNavGroups().find( ( g ) => g.items.some( ( i ) => i.key === resolvedPage ) )?.items || [];
	const locked = isLocked( resolvedPage );
	const feature = proFeatures()[ resolvedPage ] || {};

	// A module the user has turned off: its page is unreachable. Show a prompt
	// to re-activate it rather than a broken/empty page.
	const module = useModuleBySlug( resolvedPage );
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
						<div className="gs-topbar__nav">
							<TopNav current={ resolvedPage } onNavigate={ navigate } />
						</div>
						<div className="gs-topbar__actions">
							<TopbarScore
								onNavigate={ ( url ) => {
									// Server-rendered URL — route client-side if it is
									// one of our pages so we don't do a full reload.
									const slug = pageFromHref( url );
									if ( slug && PAGES[ slug ] ) {
										navigate( pageUrl( slug ) );
									} else {
										window.location.href = url;
									}
								} }
							/>
							<a
								className="gs-topbar__action"
								href={ pageUrl( 'gemsecurity-setup' ) }
								aria-label={ __( 'Setup wizard', 'gemsecurity' ) }
								title={ __( 'Setup wizard', 'gemsecurity' ) }
							>
								<Icon name="zap" size={ 18 } />
							</a>
							<button
								type="button"
								className="gs-topbar__action"
								onClick={ () => setHelpOpen( true ) }
								aria-label={ __( 'How this page works', 'gemsecurity' ) }
								title={ __( 'How this page works', 'gemsecurity' ) }
							>
								<Icon name="help" size={ 18 } />
							</button>
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
					</div>
				</header>
				<div className="gs-shell">
					{ groupItems.length > 1 && (
					<nav className="gs-subnav">
						{ groupItems.map( ( item ) => {
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
					) }
					<div className="gs-content">
						<PageScoreTips page={ resolvedPage } />
						<ErrorBoundary key={ resolvedPage }>
							{ renderPage() }
						</ErrorBoundary>
					</div>
				</div>
			</main>
			<HelpDrawer
				open={ helpOpen }
				onClose={ () => setHelpOpen( false ) }
				slug={ resolvedPage }
				title={ navItem ? navItem.label : 'GemSecurity' }
			/>
		</div>
	);
}
