import React, { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import { Card, Loading, Badge } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';

const SEVERITY_TONE = { info: 'info', notice: 'info', warning: 'warning', critical: 'danger' };

function ScoreRing( { score, grade } ) {
	const r = 52;
	const c = 2 * Math.PI * r;
	const offset = c - ( score / 100 ) * c;
	const tone = score >= 75 ? '#16a34a' : score >= 50 ? '#d97706' : '#dc2626';
	return (
		<div className="gs-score">
			<svg width="140" height="140" viewBox="0 0 140 140">
				<circle cx="70" cy="70" r={ r } fill="none" stroke="#e5e7eb" strokeWidth="12" />
				<circle
					cx="70"
					cy="70"
					r={ r }
					fill="none"
					stroke={ tone }
					strokeWidth="12"
					strokeDasharray={ c }
					strokeDashoffset={ offset }
					strokeLinecap="round"
					transform="rotate(-90 70 70)"
				/>
				<text x="70" y="64" textAnchor="middle" className="gs-score__num">{ score }</text>
				<text x="70" y="88" textAnchor="middle" className="gs-score__grade" fill={ tone }>{ grade }</text>
			</svg>
			<span className="gs-score__caption">{ __( 'Security score', 'gemsecurity' ) }</span>
		</div>
	);
}

const STAT_META = [
	{ key: 'logins_24h', label: __( 'Logins (24h)', 'gemsecurity' ), icon: 'lock' },
	{ key: 'failed_logins_24h', label: __( 'Failed logins (24h)', 'gemsecurity' ), icon: 'alert' },
	{ key: 'lockouts_7d', label: __( 'Lockouts (7d)', 'gemsecurity' ), icon: 'shield' },
	{ key: 'blocks_7d', label: __( 'Blocked requests (7d)', 'gemsecurity' ), icon: 'shield' },
	{ key: 'rogue_admins_7d', label: __( 'Rogue admins stopped (7d)', 'gemsecurity' ), icon: 'crown' },
	{ key: 'critical_7d', label: __( 'Critical events (7d)', 'gemsecurity' ), icon: 'alert' },
];

export default function Dashboard() {
	const [ data, setData ] = useState( null );

	useEffect( () => {
		api.get( 'dashboard' ).then( ( r ) => setData( r.data ) ).catch( () => setData( false ) );
	}, [] );

	if ( data === null ) {
		return <Loading />;
	}
	if ( data === false ) {
		return <Card title={ __( 'Dashboard', 'gemsecurity' ) }>{ __( 'Failed to load.', 'gemsecurity' ) }</Card>;
	}

	const maxTrend = Math.max( 1, ...data.trend.map( ( t ) => t.count ) );

	return (
		<div className="gs-dashboard">
			<div className="gs-grid gs-grid--hero">
				<Card className="gs-card--score">
					<div className="gs-hero">
						<ScoreRing score={ data.security_score.score } grade={ data.security_score.grade } />
						<div className="gs-hero__protections">
							<h3>{ __( 'Protection status', 'gemsecurity' ) }</h3>
							<ul className="gs-checklist">
								{ data.protections.map( ( p ) => (
									<li key={ p.key } className={ p.enabled ? 'is-on' : 'is-off' }>
										<Icon name={ p.enabled ? 'check' : 'alert' } size={ 15 } />
										<span>{ p.label }</span>
									</li>
								) ) }
							</ul>
						</div>
					</div>
				</Card>
			</div>

			<div className="gs-grid gs-grid--stats">
				{ STAT_META.map( ( s ) => (
					<div key={ s.key } className="gs-stat">
						<span className="gs-stat__icon"><Icon name={ s.icon } size={ 18 } /></span>
						<span className="gs-stat__value">{ data.counts[ s.key ] ?? 0 }</span>
						<span className="gs-stat__label">{ s.label }</span>
					</div>
				) ) }
			</div>

			<div className="gs-grid gs-grid--2">
				<Card title={ __( 'Activity (last 7 days)', 'gemsecurity' ) }>
					<div className="gs-bars">
						{ data.trend.map( ( t ) => (
							<div key={ t.date } className="gs-bars__col" title={ `${ t.date }: ${ t.count }` }>
								<div className="gs-bars__bar" style={ { height: `${ ( t.count / maxTrend ) * 100 }%` } } />
								<span className="gs-bars__label">{ t.date.slice( 5 ) }</span>
							</div>
						) ) }
					</div>
				</Card>

				<Card title={ __( 'Recent events', 'gemsecurity' ) }>
					{ data.recent.length === 0 ? (
						<p className="gs-muted">{ __( 'No events yet.', 'gemsecurity' ) }</p>
					) : (
						<ul className="gs-events">
							{ data.recent.map( ( e ) => (
								<li key={ e.id }>
									<Badge tone={ SEVERITY_TONE[ e.severity ] || 'info' }>{ e.severity }</Badge>
									<span className="gs-events__msg">{ e.message }</span>
									<span className="gs-events__time">{ e.created_at }</span>
								</li>
							) ) }
						</ul>
					) }
				</Card>
			</div>

			{ data.last_scan && (
				<Card title={ __( 'Last scan', 'gemsecurity' ) }>
					<p>
						<Badge tone={ data.last_scan.status === 'clean' ? 'success' : 'warning' }>
							{ data.last_scan.status === 'clean' ? __( 'Clean', 'gemsecurity' ) : __( 'Issues found', 'gemsecurity' ) }
						</Badge>{ ' ' }
						{ data.last_scan.issue_count } { __( 'issue(s)', 'gemsecurity' ) } · { data.last_scan.scanned_at }
					</p>
				</Card>
			) }
		</div>
	);
}
