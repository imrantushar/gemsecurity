import React, { useEffect, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import useNavigate from '@Utils/useGuardedNavigate';
import api from '@Utils/api';
import { Card, Loading, Badge } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';
import { pageFromHref, pageUrl } from '@Utils/nav';

const SEVERITY_TONE = { info: 'info', notice: 'info', warning: 'warning', critical: 'danger' };

function ScoreRing( { score, grade } ) {
	const r = 52;
	const c = 2 * Math.PI * r;
	const offset = c - ( score / 100 ) * c;
	const tone = score >= 75 ? 'var(--gs-success)' : score >= 50 ? 'var(--gs-warning)' : 'var(--gs-danger)';
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
	{ key: 'bots_blocked_24h', label: __( 'Bots blocked (24h)', 'gemsecurity' ), icon: 'zap' },
	{ key: 'rogue_admins_7d', label: __( 'Rogue admins stopped (7d)', 'gemsecurity' ), icon: 'crown' },
	{ key: 'banned_ips', label: __( 'Banned IPs', 'gemsecurity' ), icon: 'zap' },
	{ key: 'vulnerabilities', label: __( 'Known vulnerabilities', 'gemsecurity' ), icon: 'bug' },
	{ key: 'critical_7d', label: __( 'Critical events (7d)', 'gemsecurity' ), icon: 'alert' },
];

/**
 * The link that turns a finding into something you can act on.
 *
 * Every row used to state a problem and a fix and then leave you to work out
 * which page to open. The destination comes from the server, which resolves it
 * through the module registry — so a finding whose module is switched off
 * points at the Modules manager rather than at a page that does not exist.
 */
function ActionLink( { action } ) {
	const navigate = useNavigate();

	if ( ! action || ! action.url ) {
		return null;
	}

	return (
		<a
			className="gs-actionlist__go"
			href={ action.url }
			onClick={ ( e ) => {
				// Modifier-clicks keep their normal open-in-new-tab behaviour.
				if ( e.metaKey || e.ctrlKey || e.shiftKey || e.altKey ) {
					return;
				}
				const slug = pageFromHref( action.url );
				if ( ! slug ) {
					return;
				}
				e.preventDefault();
				navigate( pageUrl( slug ) );
			} }
		>
			{ action.label }
			<Icon name="arrow-right" size={ 14 } />
		</a>
	);
}

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
	const posture = data.posture || { threats: [], checks: [], summary: { passed: 0, failed: 0, threats: 0 } };
	const failingChecks = posture.checks.filter( ( c ) => c.status === 'fail' );
	const allClear = posture.threats.length === 0 && failingChecks.length === 0;
	const attentionCount = posture.threats.length + failingChecks.length;

	const score = data.security_score.score;
	const status =
		score >= 75
			? { tone: 'good', label: __( 'Good', 'gemsecurity' ) }
			: score >= 50
			? { tone: 'warn', label: __( 'Fair', 'gemsecurity' ) }
			: { tone: 'bad', label: __( 'Needs attention', 'gemsecurity' ) };

	return (
		<div className="gs-dashboard">
			<div className="gs-grid gs-grid--hero">
				<Card className="gs-card--score">
					<div className="gs-hero">
						<div className="gs-hero__score">
							<ScoreRing score={ score } grade={ data.security_score.grade } />
							<span className={ `gs-hero__status gs-hero__status--${ status.tone }` }>
								{ status.label }
							</span>
							<p className="gs-hero__count">
								{ sprintf(
									/* translators: 1: active protections, 2: total protections. */
									__( '%1$d of %2$d protections active', 'gemsecurity' ),
									posture.summary.passed,
									posture.summary.passed + posture.summary.failed
								) }
							</p>
						</div>
						<div className="gs-hero__protections">
							<div className="gs-hero__protections-head">
								<h3>{ __( 'What needs your attention', 'gemsecurity' ) }</h3>
								{ ! allClear && <Badge tone="danger">{ attentionCount }</Badge> }
							</div>
							{ allClear ? (
								<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'No active threats and every recommended protection is on. Nicely done.', 'gemsecurity' ) }</p>
							) : (
								<ul className="gs-actionlist">
									{ posture.threats.map( ( t ) => (
										<li key={ t.key } className="gs-actionlist__item is-threat">
											<Badge tone={ t.severity === 'critical' ? 'danger' : 'warning' }>{ t.severity }</Badge>
											<div>
												<strong>{ t.label }</strong>
												<span className="gs-actionlist__fix">{ t.fix }</span>
											</div>
											<ActionLink action={ t.action } />
										</li>
									) ) }
									{ failingChecks.map( ( c ) => (
										<li key={ c.key } className="gs-actionlist__item is-todo">
											<Icon name="alert" size={ 15 } />
											<div>
												<strong>{ c.label }</strong>
												<span className="gs-actionlist__fix">{ c.fix }</span>
											</div>
											<ActionLink action={ c.action } />
										</li>
									) ) }
								</ul>
							) }
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
