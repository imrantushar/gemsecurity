import React, { useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import { fetchSettings } from '@Redux/settingsSlice';
import { useActivePage, NAV_ITEMS, pageUrl, pageFromHref } from '@Utils/nav';
import { Loading } from '@Components/ui/Controls';
import { isLocked, proFeatures, ProBadge, ProGate } from '@Components/ui/Pro';

import Dashboard from '@Containers/pages/Dashboard';
import Firewall from '@Containers/pages/Firewall';
import ThreatDefense from '@Containers/pages/ThreatDefense';
import LoginSecurity from '@Containers/pages/LoginSecurity';
import TwoFactor from '@Containers/pages/TwoFactor';
import SocialLogin from '@Containers/pages/SocialLogin';
import Geolocation from '@Containers/pages/Geolocation';
import AdminGuard from '@Containers/pages/AdminGuard';
import Scanner from '@Containers/pages/Scanner';
import Logs from '@Containers/pages/Logs';
import MalwareScan from '@Containers/pages/MalwareScan';
import ProTools from '@Containers/pages/ProTools';
import Settings from '@Containers/pages/Settings';
import Transfer from '@Containers/pages/Transfer';

const PAGES = {
	gemsecurity: Dashboard,
	'gemsecurity-firewall': Firewall,
	'gemsecurity-threats': ThreatDefense,
	'gemsecurity-login-security': LoginSecurity,
	'gemsecurity-two-factor': TwoFactor,
	'gemsecurity-social-login': SocialLogin,
	'gemsecurity-geolocation': Geolocation,
	'gemsecurity-admin-guard': AdminGuard,
	'gemsecurity-scanner': Scanner,
	'gemsecurity-malware': MalwareScan,
	'gemsecurity-logs': Logs,
	'gemsecurity-pro-tools': ProTools,
	'gemsecurity-settings': Settings,
	'gemsecurity-transfer': Transfer,
};

const PAGE_KEYS = Object.keys( PAGES );

/**
 * Make the native WordPress sidebar (left admin menu) navigate client-side:
 * intercept clicks on our submenu links and route them, and keep the active
 * highlight in sync as the in-app route changes — no page reloads.
 */
function useWpMenuSync( page ) {
	const navigate = useNavigate();

	// Intercept native menu clicks once.
	useEffect( () => {
		const root = document.getElementById( 'toplevel_page_gemsecurity' );
		if ( ! root ) {
			return undefined;
		}
		const onClick = ( e ) => {
			const link = e.target.closest( 'a' );
			if ( ! link ) {
				return;
			}
			const slug = pageFromHref( link.getAttribute( 'href' ) || '' );
			if ( slug && PAGE_KEYS.includes( slug ) ) {
				e.preventDefault();
				navigate( pageUrl( slug ) );
			}
		};
		root.addEventListener( 'click', onClick );
		return () => root.removeEventListener( 'click', onClick );
	}, [ navigate ] );

	// Keep the WP menu highlight in sync with the active route.
	useEffect( () => {
		const root = document.getElementById( 'toplevel_page_gemsecurity' );
		if ( ! root ) {
			return;
		}
		root.querySelectorAll( '.wp-submenu li' ).forEach( ( li ) => {
			const link = li.querySelector( 'a' );
			const slug = link ? pageFromHref( link.getAttribute( 'href' ) || '' ) : null;
			const active = slug === page;
			li.classList.toggle( 'current', active );
			if ( link ) {
				if ( active ) {
					link.classList.add( 'current' );
					link.setAttribute( 'aria-current', 'page' );
				} else {
					link.classList.remove( 'current' );
					link.removeAttribute( 'aria-current' );
				}
			}
		} );
	}, [ page ] );
}

export default function App() {
	const dispatch = useDispatch();
	const { data, loading } = useSelector( ( s ) => s.settings );
	const page = useActivePage();

	useWpMenuSync( page );

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

	const PageComponent = PAGES[ page ] || Dashboard;
	const navItem = NAV_ITEMS.find( ( i ) => i.key === page );
	const locked = isLocked( page );
	const feature = proFeatures()[ page ] || {};

	const renderPage = () => {
		if ( loading && ! data ) {
			return <Loading />;
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
		<div className="gs-app gs-app--nosidebar">
			<main className="gs-main">
				<header className="gs-topbar">
					<h1 className="gs-topbar__title">
						{ navItem ? navItem.label : 'GemSecurity' }
						{ locked && <ProBadge /> }
					</h1>
				</header>
				<div className="gs-content">
					{ renderPage() }
				</div>
			</main>
		</div>
	);
}
