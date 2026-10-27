import React, { useEffect, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import useNavigate from '@Utils/useGuardedNavigate';
import api from '@Utils/api';
import useQuickFix from '@Utils/useQuickFix';
import { Card, Loading, Badge } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';
import { pageFromHref, pageUrl } from '@Utils/nav';

// Where each dashboard number is explained / acted on.
const METRIC_PAGE = {
	logins_24h: 'gemsecurity-logs',
	failed_logins_24h: 'gemsecurity-login-security',
	lockouts_7d: 'gemsecurity-login-security',
	rogue_admins_7d: 'gemsecurity-admin-guard',
	vulnerabilities: 'gemsecurity-scanner',
	critical_7d: 'gemsecurity-logs',
	blocks_7d: 'gemsecurity-threats',
	bots_blocked_24h: 'gemsecurity-threats',
	banned_ips: 'gemsecurity-threats',
};

const SEVERITY_TONE = { info: 'info', notice: 'info', warning: 'warning', critical: 'danger' };

function ScoreRing( { score, grade } ) {
	const r = 52;
	const c = 2 * Math.PI * r;
	const offset = c - ( score / 100 ) * c;
	const tone = score >= 75 ? 'var(--gs-success)' : score >= 50 ? '#F97316' : 'var(--gs-danger)';
	return (
		<div className="gs-score">
			<svg width="168" height="168" viewBox="0 0 140 140">
				<circle cx="70" cy="70" r={ r } fill="none" stroke="var(--gs-line)" strokeWidth="12" />
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
				<text x="70" y="88" textAnchor="middle" className="gs-score__grade">{ __( 'of 100', 'gemsecurity' ) }</text>
			</svg>
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

function DashAction( { action, primary, verb } ) {
	const navigate = useNavigate();
	if ( ! action || ! action.url ) {
		return null;
	}
	return (
		<a
			className={ `gs-dash__btn ${ primary ? 'is-primary' : '' }` }
			href={ action.url }
			onClick={ ( e ) => {
				if ( e.metaKey || e.ctrlKey || e.shiftKey || e.altKey ) {
					return;
				}
				const slug = pageFromHref( action.url );
				if ( slug ) {
					e.preventDefault();
					navigate( pageUrl( slug ) );
				}
			} }
		>
			{ verb || action.label }
		</a>
	);
}

export default function Dashboard() {
	const [ data, setData ] = useState( null );
	const [ showAll, setShowAll ] = useState( false );
	const { fix, fixing, busy } = useQuickFix();
	const navigate = useNavigate();

	const load = () => api.get( 'dashboard' ).then( ( r ) => setData( r.data ) ).catch( () => setData( false ) );
	useEffect( () => {
		load();
	}, [] );

	// One-click fix straight from the list, then refresh so the row disappears.
	const quickFix = ( key ) => fix( [ key ] ).then( load );

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

	const attention = [
		...posture.threats.map( ( t ) => ( { key: t.key, label: t.label, fix: t.fix, action: t.action, severity: t.severity === 'critical' ? 'high' : 'medium', threat: true } ) ),
		...failingChecks.map( ( c ) => ( { key: c.key, label: c.label, fix: c.fix, action: c.action, severity: c.severity || 'low', threat: false, quickKey: c.quick ? ( c.fix_key || c.key ) : null } ) ),
	];
	const quickKeys = [ ...new Set( attention.filter( ( a ) => a.quickKey ).map( ( a ) => a.quickKey ) ) ];
	const shown = showAll ? attention : attention.slice( 0, 4 );
	const total = posture.summary.passed + posture.summary.failed;
	const n = ( k ) => data.counts[ k ] ?? 0;
	const GROUPS = [
		{
			id: 'access', title: __( 'Access', 'gemsecurity' ), icon: 'lock', quiet: n( 'failed_logins_24h' ) + n( 'lockouts_7d' ) === 0,
			items: [ [ 'logins_24h', __( 'Logins', 'gemsecurity' ), '24h' ], [ 'failed_logins_24h', __( 'Failed logins', 'gemsecurity' ), '24h' ], [ 'lockouts_7d', __( 'Lockouts', 'gemsecurity' ), '7d' ] ],
		},
		{
			id: 'threats', title: __( 'Threats', 'gemsecurity' ), icon: 'bug', quiet: n( 'rogue_admins_7d' ) + n( 'vulnerabilities' ) + n( 'critical_7d' ) === 0,
			items: [ [ 'rogue_admins_7d', __( 'Rogue admins', 'gemsecurity' ), '7d' ], [ 'vulnerabilities', __( 'Vulnerabilities', 'gemsecurity' ), __( 'Now', 'gemsecurity' ) ], [ 'critical_7d', __( 'Critical events', 'gemsecurity' ), '7d' ] ],
		},
		{
			id: 'firewall', title: __( 'Firewall', 'gemsecurity' ), icon: 'shield', quiet: n( 'blocks_7d' ) + n( 'bots_blocked_24h' ) === 0,
			items: [ [ 'blocks_7d', __( 'Blocked requests', 'gemsecurity' ), '7d' ], [ 'bots_blocked_24h', __( 'Bots blocked', 'gemsecurity' ), '24h' ], [ 'banned_ips', __( 'Banned IPs', 'gemsecurity' ), __( 'Total', 'gemsecurity' ) ] ],
		},
	];
	const dayLabel = ( t, i ) => ( i === data.trend.length - 1 ? __( 'Today', 'gemsecurity' ) : new Date( t.date + 'T00:00:00' ).toLocaleDateString( undefined, { month: 'short', day: 'numeric' } ) );

	return (
		<div className="gs-dashboard gs-dash">
			<section className="gs-dash__hero">
				<div className="gs-dash__score">
					<ScoreRing score={ score } grade={ data.security_score.grade } />
					<div className="gs-dash__score-title">
						<strong>{ __( 'Security score', 'gemsecurity' ) }</strong>
						<span className={ `gs-dash__grade gs-dash__grade--${ status.tone }` }>
							{ sprintf( /* translators: 1: grade letter, 2: status */ __( 'Grade %1$s · %2$s', 'gemsecurity' ), data.security_score.grade, status.label ) }
						</span>
					</div>
					<div className="gs-dash__protect">
						<div><span>{ __( 'Protections active', 'gemsecurity' ) }</span><strong>{ sprintf( /* translators: 1: active, 2: total */ __( '%1$d of %2$d', 'gemsecurity' ), posture.summary.passed, total ) }</strong></div>
						<i><b style={ { width: `${ total ? ( posture.summary.passed / total ) * 100 : 0 }%` } } /></i>
					</div>
					{ quickKeys.length > 0 && (
						<button type="button" className="gs-dash__fix" onClick={ () => fix( quickKeys ).then( load ) } disabled={ busy }>
							{ busy ? __( 'Fixing…', 'gemsecurity' ) : sprintf( /* translators: %d: number of issues */ __( 'Fix %d issues', 'gemsecurity' ), quickKeys.length ) }
						</button>
					) }
				</div>
				<div className="gs-dash__attention">
					<header>
						<h3>{ __( 'What needs your attention', 'gemsecurity' ) }</h3>
						{ ! allClear && <span className="gs-dash__open">{ sprintf( /* translators: %d: count */ __( '%d open', 'gemsecurity' ), attentionCount ) }</span> }
						{ ! allClear && <span className="gs-dash__sorted">{ __( 'Sorted by risk', 'gemsecurity' ) }</span> }
						{ attention.length > 4 && (
							<button type="button" className="gs-dash__viewall" onClick={ () => setShowAll( ! showAll ) }>
								{ showAll ? __( 'Show less', 'gemsecurity' ) : sprintf( /* translators: %d: count */ __( 'View all %d', 'gemsecurity' ), attention.length ) }
								<Icon name="arrow-right" size={ 14 } />
							</button>
						) }
					</header>
					{ allClear ? (
						<p className="gs-ok"><Icon name="check" size={ 16 } /> { __( 'No active threats and every recommended protection is on. Nicely done.', 'gemsecurity' ) }</p>
					) : (
						<ul>
							{ shown.map( ( a, i ) => (
								<li key={ a.key } className={ `gs-dash__item gs-dash__item--${ a.severity } ${ i === 0 && a.severity === 'high' ? 'is-top' : '' }` }>
									<span className="gs-dash__item-icon"><Icon name={ a.threat ? 'shield' : 'lock' } size={ 18 } /></span>
									<div>
										<strong>{ a.label }<em>{ a.severity === 'high' ? __( 'High', 'gemsecurity' ) : a.severity === 'medium' ? __( 'Medium', 'gemsecurity' ) : __( 'Low', 'gemsecurity' ) }</em></strong>
										<span>{ a.fix }</span>
									</div>
									{ a.quickKey ? (
										<button
											type="button"
											className="gs-dash__btn"
											onClick={ () => quickFix( a.quickKey ) }
											disabled={ !! fixing[ a.quickKey ] }
										>
											{ fixing[ a.quickKey ] ? __( 'Enabling…', 'gemsecurity' ) : __( 'Enable', 'gemsecurity' ) }
										</button>
									) : (
										<DashAction action={ a.action } primary={ i === 0 && a.severity === 'high' } verb={ /scanner/.test( a.action?.url || '' ) && a.threat ? __( 'Run scan', 'gemsecurity' ) : a.threat ? __( 'Review', 'gemsecurity' ) : __( 'Enable', 'gemsecurity' ) } />
									) }
								</li>
							) ) }
						</ul>
					) }
				</div>
			</section>

			<div className="gs-dash__groups">
				{ GROUPS.map( ( g ) => (
					<section key={ g.id } className="gs-dash__group">
						<header>
							<span className="gs-dash__group-icon"><Icon name={ g.icon } size={ 18 } /></span>
							<h3>{ g.title }</h3>
							<span className={ `gs-dash__quiet ${ g.quiet ? '' : 'is-active' }` }>
								{ g.quiet && <Icon name="check" size={ 12 } /> }
								{ g.quiet ? __( 'All quiet', 'gemsecurity' ) : __( 'Activity', 'gemsecurity' ) }
							</span>
						</header>
						<div className="gs-dash__metrics">
							{ g.items.map( ( [ key, label, period ] ) => {
								const href = pageUrl( METRIC_PAGE[ key ] || 'gemsecurity-logs' );
								return (
									<a
										key={ key }
										href={ href }
										onClick={ ( e ) => {
											if ( e.metaKey || e.ctrlKey || e.shiftKey || e.altKey ) {
												return;
											}
											e.preventDefault();
											navigate( href );
										} }
									>
										<strong>{ n( key ) }</strong>
										<span>{ label } <small>{ period }</small></span>
									</a>
								);
							} ) }
						</div>
					</section>
				) ) }
			</div>

			<div className="gs-dash__lower">
				<section className="gs-dash__panel">
					<header>
						<div><h3>{ __( 'Activity', 'gemsecurity' ) }</h3><p>{ __( 'Security events, last 7 days', 'gemsecurity' ) }</p></div>
						<span className="gs-dash__legend"><i />{ __( 'Events', 'gemsecurity' ) }</span>
					</header>
					<div className="gs-dash__bars">
						{ data.trend.map( ( t, i ) => (
							<div key={ t.date } className={ `gs-dash__bar ${ i === data.trend.length - 1 ? 'is-today' : '' }` } title={ `${ t.date }: ${ t.count }` }>
								<div className="gs-dash__bar-track"><b style={ { height: `${ Math.max( 3, ( t.count / maxTrend ) * 100 ) }%` } } /></div>
								<span>{ dayLabel( t, i ) }</span>
							</div>
						) ) }
					</div>
				</section>

				<section className="gs-dash__panel">
					<header>
						<div><h3>{ __( 'Recent events', 'gemsecurity' ) }</h3><p>{ __( 'What changed on your site', 'gemsecurity' ) }</p></div>
					</header>
					<ul className="gs-dash__events">
						{ data.recent.slice( 0, 5 ).map( ( e ) => (
							<li key={ e.id }>
								<Badge tone={ SEVERITY_TONE[ e.severity ] || 'info' }>{ e.severity }</Badge>
								<span className="gs-events__msg">{ e.message }</span>
								<span className="gs-events__time">{ e.created_at }</span>
							</li>
						) ) }
						<li className="gs-dash__events-end"><Icon name="check" size={ 14 } />{ __( 'That’s everything from the last 7 days.', 'gemsecurity' ) }</li>
					</ul>
				</section>
			</div>
		</div>
	);
}
