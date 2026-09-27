import React from 'react';
import { Link } from 'react-router-dom';
import Icon from '@Components/ui/Icon';
import { useNavItems, useActivePage, pageUrl } from '@Utils/nav';

export default function Sidebar() {
	const current = useActivePage();
	const navItems = useNavItems();

	return (
		<aside className="gs-sidebar">
			<div className="gs-brand">
				<span className="gs-brand__mark">
					<Icon name="shield" size={ 22 } />
				</span>
				<span className="gs-brand__name">GemSecurity</span>
			</div>
			<nav className="gs-nav">
				{ navItems.map( ( item ) => (
					<Link
						key={ item.key }
						to={ pageUrl( item.key ) }
						className={ `gs-nav__item ${ current === item.key ? 'is-active' : '' }` }
					>
						<Icon name={ item.icon } size={ 18 } />
						<span>{ item.label }</span>
					</Link>
				) ) }
			</nav>
			<div className="gs-sidebar__foot">
				v{ ( window.GemSecurityGlobal || {} ).version || '1.0.0' }
			</div>
		</aside>
	);
}
