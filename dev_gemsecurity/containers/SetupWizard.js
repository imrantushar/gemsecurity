import React, { useMemo, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api, { GS } from '@Utils/api';
import { Button, Toggle, Field, TextInput, Select } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';
import Logo from '@Components/ui/Logo';
import { isPro, ProBadge } from '@Components/ui/Pro';
import { useThemeMode } from '@Utils/theme';

/* ------------------------------------------------------------------ */
/* Protection levels                                                   */
/* ------------------------------------------------------------------ */

const BASE = {
	firewall_enabled: true,
	login_attempts_enabled: true,
	login_honeypot_enabled: true,
	antispam_enabled: true,
	audit_log_enabled: true,
	vuln_scan_enabled: true,
};

const STANDARD = {
	...BASE,
	waf_enabled: true,
	rate_limit_enabled: true,
	block_bad_bots: true,
	block_author_enumeration: true,
	hide_wp_version: true,
	security_headers_enabled: true,
	file_watcher_enabled: true,
};

const LEVELS = [
	{
		id: 'essential',
		icon: 'shield',
		title: __( 'Essential', 'gemsecurity' ),
		desc: __( 'Light-touch protection that never gets in anyone’s way.', 'gemsecurity' ),
		points: [
			__( 'Firewall & login attempt limits', 'gemsecurity' ),
			__( 'Comment spam blocking', 'gemsecurity' ),
			__( 'Activity log + vulnerability checks', 'gemsecurity' ),
		],
		settings: BASE,
		modules: ( m ) => [ 'firewall', 'login-security', 'anti-spam', 'scanner' ].includes( m.id ),
	},
	{
		id: 'recommended',
		icon: 'zap',
		title: __( 'Recommended', 'gemsecurity' ),
		desc: __( 'The best balance of safety and compatibility for most sites.', 'gemsecurity' ),
		points: [
			__( 'Everything in Essential', 'gemsecurity' ),
			__( 'Web application firewall + rate limiting', 'gemsecurity' ),
			__( 'Bad-bot blocking & security headers', 'gemsecurity' ),
			__( 'File change monitoring', 'gemsecurity' ),
		],
		settings: STANDARD,
		modules: ( m ) => m.recommended || m.id === 'threats',
		best: true,
	},
	{
		id: 'maximum',
		icon: 'lock',
		title: __( 'Maximum', 'gemsecurity' ),
		desc: __( 'Locks things down tight. Best for sites with few editors.', 'gemsecurity' ),
		points: [
			__( 'Everything in Recommended', 'gemsecurity' ),
			__( 'XML-RPC off, file editing disabled', 'gemsecurity' ),
			__( '404 throttling & AI crawler blocking', 'gemsecurity' ),
			__( 'Strong password policy + two-factor', 'gemsecurity' ),
		],
		settings: {
			...STANDARD,
			throttle_404_enabled: true,
			block_ai_crawlers: true,
			xmlrpc_disabled: true,
			disable_file_editing: true,
			password_policy_enabled: true,
		},
		modules: ( m ) => m.recommended || [ 'threats', 'two-factor', 'virtual-patch', 'monitoring' ].includes( m.id ),
	},
];

const STEPS = [
	{ id: 'welcome', label: __( 'Welcome', 'gemsecurity' ) },
	{ id: 'questions', label: __( 'A few questions', 'gemsecurity' ) },
	{ id: 'features', label: __( 'Review features', 'gemsecurity' ) },
	{ id: 'alerts', label: __( 'Alerts', 'gemsecurity' ) },
	{ id: 'done', label: __( 'All set', 'gemsecurity' ) },
];

/* ------------------------------------------------------------------ */
/* Questionnaire                                                       */
/* ------------------------------------------------------------------ */
/*
 * Five concrete questions, each mapped to a `recommendation` fragment that
 * the recommender merges. Keeping the mapping declarative here means the
 * logic for "what does this answer actually DO" lives next to the answer
 * copy — one place to read and tune.
 *
 * `settings` entries flip boolean feature flags on; `modules` entries name
 * a module to switch on by id. Pro-only modules are still named; the
 * module list filters Pro ones out automatically when Pro isn't active, so
 * a free install can't trip the recommender into enabling something it
 * can't boot.
 */
const QUESTIONS = [
	{
		id: 'site_kind',
		label: __( 'What kind of site is this?', 'gemsecurity' ),
		help: __( 'This tells us what\'s worth protecting the most.', 'gemsecurity' ),
		options: [
			{
				id: 'blog',
				icon: 'list',
				title: __( 'Blog or portfolio', 'gemsecurity' ),
				desc: __( 'Content I publish; readers mostly read.', 'gemsecurity' ),
				rec: { level: 'essential' },
			},
			{
				id: 'business',
				icon: 'grid',
				title: __( 'Business site', 'gemsecurity' ),
				desc: __( 'Marketing, services, lead forms.', 'gemsecurity' ),
				rec: { level: 'recommended', settings: { security_headers_enabled: true, hide_wp_version: true } },
			},
			{
				id: 'store',
				icon: 'zap',
				title: __( 'Online store', 'gemsecurity' ),
				desc: __( 'I sell products or subscriptions.', 'gemsecurity' ),
				rec: {
					level: 'recommended',
					modules: [ 'two-factor', 'payment-integrity' ],
					settings: { rate_limit_enabled: true, security_headers_enabled: true, payment_integrity_enabled: true },
				},
			},
			{
				id: 'membership',
				icon: 'users',
				title: __( 'Membership, courses or community', 'gemsecurity' ),
				desc: __( 'People sign up and log in to use it.', 'gemsecurity' ),
				rec: {
					level: 'recommended',
					modules: [ 'captcha', 'two-factor' ],
					settings: { password_policy_enabled: true, rate_limit_enabled: true },
				},
			},
			{
				id: 'agency',
				icon: 'layers',
				title: __( 'Agency or multi-client site', 'gemsecurity' ),
				desc: __( 'I manage this for someone else.', 'gemsecurity' ),
				rec: {
					level: 'maximum',
					modules: [ 'plugin-guard', 'admin-guard', 'monitoring' ],
				},
			},
		],
	},
	{
		id: 'logins',
		label: __( 'Who else logs in?', 'gemsecurity' ),
		help: __( 'Login surface is where most sites get hit.', 'gemsecurity' ),
		options: [
			{
				id: 'only_me',
				icon: 'crown',
				title: __( 'Only me', 'gemsecurity' ),
				desc: __( 'I am the only account.', 'gemsecurity' ),
				rec: { modules: [ 'two-factor', 'admin-guard' ] },
			},
			{
				id: 'small_team',
				icon: 'users',
				title: __( 'A small team', 'gemsecurity' ),
				desc: __( 'A handful of editors or staff.', 'gemsecurity' ),
				rec: {
					modules: [ 'two-factor', 'admin-guard' ],
					settings: { password_policy_enabled: true, admin_session_timeout_enabled: true },
				},
			},
			{
				id: 'public',
				icon: 'globe',
				title: __( 'Members and customers can register', 'gemsecurity' ),
				desc: __( 'The public can create accounts.', 'gemsecurity' ),
				rec: {
					modules: [ 'captcha', 'two-factor', 'admin-guard' ],
					settings: {
						antispam_heuristics: true,
						rate_limit_enabled: true,
						password_policy_enabled: true,
						login_errors_generic: true,
					},
				},
			},
		],
	},
	{
		id: 'incidents',
		label: __( 'Has anything suspicious happened lately?', 'gemsecurity' ),
		help: __( 'If yes, we turn on tighter detection and threat intel.', 'gemsecurity' ),
		options: [
			{
				id: 'calm',
				icon: 'check',
				title: __( 'All quiet — nothing I\'ve noticed', 'gemsecurity' ),
				desc: __( 'Standard protection is a good fit.', 'gemsecurity' ),
				rec: {},
			},
			{
				id: 'noisy',
				icon: 'alert',
				title: __( 'Spam, brute-force or odd traffic', 'gemsecurity' ),
				desc: __( 'Comment spam, login attempts, bursts.', 'gemsecurity' ),
				rec: {
					modules: [ 'threats' ],
					settings: {
						waf_enabled: true,
						rate_limit_enabled: true,
						block_bad_bots: true,
						throttle_404_enabled: true,
						login_errors_generic: true,
					},
				},
			},
			{
				id: 'hacked',
				icon: 'shield',
				title: __( 'Been hacked before, or files look changed', 'gemsecurity' ),
				desc: __( 'Lock it down and watch files closely.', 'gemsecurity' ),
				rec: {
					level: 'maximum',
					modules: [ 'threats', 'virtual-patch', 'incident-response', 'plugin-guard', 'payment-integrity' ],
					settings: {
						waf_enabled: true,
						block_bad_bots: true,
						throttle_404_enabled: true,
						xmlrpc_disabled: true,
						disable_file_editing: true,
						file_watcher_enabled: true,
						hidden_admin_detection: true,
					},
				},
			},
		],
	},
	{
		id: 'traffic',
		label: __( 'Where does your traffic come from?', 'gemsecurity' ),
		help: __( 'Shapes bot blocking and country rules.', 'gemsecurity' ),
		options: [
			{
				id: 'global',
				icon: 'globe',
				title: __( 'Global audience', 'gemsecurity' ),
				desc: __( 'Visitors from anywhere.', 'gemsecurity' ),
				rec: {},
			},
			{
				id: 'countries',
				icon: 'grid',
				title: __( 'A few specific countries', 'gemsecurity' ),
				desc: __( 'I can keep others out safely.', 'gemsecurity' ),
				rec: { modules: [ 'geolocation' ], settings: { geo_enabled: true } },
			},
			{
				id: 'bots',
				icon: 'bot',
				title: __( 'Mostly bots and scrapers lately', 'gemsecurity' ),
				desc: __( 'Hungry crawlers, AI bots, scanners.', 'gemsecurity' ),
				rec: {
					settings: {
						block_bad_bots: true,
						block_ai_crawlers: true,
						verify_search_bots: true,
						throttle_404_enabled: true,
					},
				},
			},
		],
	},
	{
		id: 'strictness',
		label: __( 'If a real visitor got blocked once, how bad is that?', 'gemsecurity' ),
		help: __( 'Tunes how aggressively we enforce rules.', 'gemsecurity' ),
		options: [
			{
				id: 'gentle',
				icon: 'help',
				title: __( 'Terrible — be gentle', 'gemsecurity' ),
				desc: __( 'Protect, but never risk breaking anything.', 'gemsecurity' ),
				rec: { settings: { throttle_404_enabled: false } },
			},
			{
				id: 'balanced',
				icon: 'cog',
				title: __( 'Balanced is fine', 'gemsecurity' ),
				desc: __( 'The recommended default.', 'gemsecurity' ),
				rec: {},
			},
			{
				id: 'strict',
				icon: 'lock',
				title: __( 'Fine — lock it down', 'gemsecurity' ),
				desc: __( 'I\'ll handle the odd false positive.', 'gemsecurity' ),
				rec: {
					level: 'maximum',
					settings: {
						throttle_404_enabled: true,
						xmlrpc_disabled: true,
						disable_file_editing: true,
						block_author_enumeration: true,
						disable_user_rest: true,
					},
				},
			},
		],
	},
];

/**
 * Fold the question answers into a single {level, settings, moduleIds}
 * recommendation. Later answers can override earlier ones (strictness=strict
 * promotes to maximum even if site_kind=blog said essential).
 */
function recommendFromAnswers( answers ) {
	let levelId  = 'recommended';
	let settings = {};
	let moduleIds = new Set();

	// Rank so a "harder" level answer wins over a softer one.
	const rank = { essential: 0, recommended: 1, maximum: 2 };

	for ( const q of QUESTIONS ) {
		const picked = q.options.find( ( o ) => o.id === answers[ q.id ] );
		if ( ! picked ) {
			continue;
		}
		const rec = picked.rec || {};
		if ( rec.level && rank[ rec.level ] > rank[ levelId ] ) {
			levelId = rec.level;
		}
		if ( rec.settings ) {
			settings = { ...settings, ...rec.settings };
		}
		for ( const id of ( rec.modules || [] ) ) {
			moduleIds.add( id );
		}
	}

	return { levelId, settingsFromQuestions: settings, forcedModules: moduleIds };
}

/** Build the full module map from a level + the questionnaire's forced-on ids. */
function modulesForRecommendation( level, forcedModules ) {
	const map = modulesFor( level );
	for ( const id of forcedModules ) {
		const m = allModules().find( ( x ) => x.id === id );
		if ( m && ( ! m.is_pro || isPro() ) ) {
			map[ id ] = true;
		}
	}
	return map;
}

const allModules = () => ( Array.isArray( GS.modules ) ? GS.modules : [] ).filter( ( m ) => ! m.core );
const groupList = () => ( Array.isArray( GS.groups ) ? GS.groups : [] );

/** Module selection a level implies; Pro modules only when Pro is active. */
function modulesFor( level ) {
	const map = {};
	allModules().forEach( ( m ) => {
		map[ m.id ] = ( ! m.is_pro || isPro() ) && level.modules( m );
	} );
	return map;
}

/* ------------------------------------------------------------------ */
/* Wizard                                                              */
/* ------------------------------------------------------------------ */

export default function SetupWizard() {
	const { theme, toggle } = useThemeMode();
	const [ step, setStep ] = useState( 0 );
	const [ answers, setAnswers ] = useState( {} );

	// Derived from answers; the Features step may override `modules` after.
	const { levelId, settingsFromQuestions, forcedModules } = useMemo(
		() => recommendFromAnswers( answers ),
		[ answers ]
	);
	const level = LEVELS.find( ( l ) => l.id === levelId );

	const [ modules, setModules ] = useState( () => modulesFor( level ) );
	const [ userTouchedModules, setUserTouchedModules ] = useState( false );
	const [ alerts, setAlerts ] = useState( {
		alerts_enabled: true,
		alert_to_email: GS.admin_email || '',
		alert_min_severity: 'warning',
		digest_enabled: true,
	} );
	const [ saving, setSaving ] = useState( false );
	const [ error, setError ] = useState( '' );

	// When answers change, refresh the pre-filled module map — unless the
	// user has started hand-picking features on the next step.
	const applyAnswer = ( qid, oid ) => {
		const nextAnswers = { ...answers, [ qid ]: oid };
		setAnswers( nextAnswers );
		if ( ! userTouchedModules ) {
			const { levelId: nextLevel, forcedModules: nextForced } = recommendFromAnswers( nextAnswers );
			setModules( modulesForRecommendation( LEVELS.find( ( l ) => l.id === nextLevel ), nextForced ) );
		}
	};
	const changeModules = ( next ) => {
		setUserTouchedModules( true );
		setModules( next );
	};
	const answeredCount = Object.keys( answers ).length;

	const enabledCount = Object.values( modules ).filter( Boolean ).length;
	const next = () => setStep( ( s ) => Math.min( s + 1, STEPS.length - 1 ) );
	const back = () => setStep( ( s ) => Math.max( s - 1, 0 ) );

	const finish = async () => {
		setSaving( true );
		setError( '' );
		try {
			await api.post( 'settings', { settings: { ...level.settings, ...settingsFromQuestions, ...alerts } } );
			// Only touch modules whose state actually changes.
			for ( const m of allModules() ) {
				const want = !! modules[ m.id ];
				if ( want !== !! m.active && ( ! m.is_pro || isPro() ) ) {
					await api.post( 'modules', { id: m.id, active: want } );
				}
			}
			await api.post( 'setup', { status: 'completed' } );
			next();
		} catch ( e ) {
			setError( e?.response?.data?.message || __( 'Something went wrong while saving. Please try again.', 'gemsecurity' ) );
		} finally {
			setSaving( false );
		}
	};

	const skip = async () => {
		try {
			await api.post( 'setup', { status: 'skipped' } );
		} finally {
			window.location.href = GS.dashboard;
		}
	};

	const current = STEPS[ step ].id;

	if ( current === 'done' ) {
		return (
			<div className="gs-wizard gs-wizard--done">
				<header className="gs-done__bar">
					<span className="gs-done__brand"><span className="gs-done__logo"><Logo size={ 22 } /></span>GemSecurity</span>
					<span className="gs-done__step">
						{ sprintf( /* translators: 1: step, 2: total */ __( 'Step %1$d of %2$d', 'gemsecurity' ), STEPS.length, STEPS.length ) }
						<em><i />{ __( 'Setup complete', 'gemsecurity' ) }</em>
					</span>
				</header>
				<DoneStep level={ level } count={ enabledCount } total={ allModules().length } alerts={ alerts } digest={ alerts.digest_enabled } onEdit={ setStep } />
			</div>
		);
	}

	return (
		<div className="gs-wizard">
			<aside className="gs-wizard__rail">
				<div className="gs-wizard__brand">
					<span className="gs-wizard__logo"><Logo size={ 24 } /></span>
					<span>GemSecurity</span>
				</div>
				<ol className="gs-wizard__steps">
					{ STEPS.map( ( s, i ) => (
						<li
							key={ s.id }
							className={ `${ i === step ? 'is-current' : '' } ${ i < step ? 'is-done' : '' }` }
						>
							<span className="gs-wizard__dot">
								{ i < step ? <Icon name="check" size={ 14 } /> : i + 1 }
							</span>
							<span className="gs-wizard__step-label">{ s.label }</span>
							{ i === step && <span className="gs-wizard__now">{ __( 'Now', 'gemsecurity' ) }</span> }
						</li>
					) ) }
				</ol>
				<p className="gs-wizard__rail-foot">
					<Icon name="refresh" size={ 18 } />
					<span>{ __( 'You can change every choice later from the GemSecurity settings.', 'gemsecurity' ) }</span>
				</p>
			</aside>

			<main className="gs-wizard__main">
				<div className="gs-wizard__top">
					<span className="gs-wizard__count">
						{ sprintf( /* translators: 1: step, 2: total */ __( 'Step %1$d of %2$d', 'gemsecurity' ), step + 1, STEPS.length ) }
						<span className="gs-wizard__count-sep">·</span>
						<span className="gs-wizard__count-name">{ STEPS[ step ].label }</span>
					</span>
					<div className="gs-wizard__top-actions">
						<button type="button" className="gs-topbar__theme" onClick={ toggle } aria-label={ __( 'Toggle dark mode', 'gemsecurity' ) }>
							<Icon name={ theme === 'dark' ? 'sun' : 'moon' } size={ 18 } />
						</button>
						{ current !== 'done' && (
							<button type="button" className="gs-wizard__skip" onClick={ skip }>
								{ __( 'Skip setup', 'gemsecurity' ) }
							</button>
						) }
					</div>
				</div>
				<div className="gs-wizard__progress"><span style={ { width: `${ ( ( step + 1 ) / STEPS.length ) * 100 }%` } } /></div>

				<div className="gs-wizard__body" key={ current }>
					{ current === 'welcome' && <Welcome /> }
					{ current === 'questions' && (
						<QuestionsStep
							answers={ answers }
							onAnswer={ applyAnswer }
							recommendedLevel={ level }
						/>
					) }
					{ current === 'features' && <FeaturesStep value={ modules } onChange={ changeModules } level={ level } /> }
					{ current === 'alerts' && <AlertsStep value={ alerts } onChange={ setAlerts } /> }
					{ current === 'done' && <DoneStep level={ level } count={ enabledCount } alerts={ alerts } /> }
					{ error && <div className="gs-wizard__error">{ error }</div> }
				</div>

				{ current !== 'done' && (
					<div className="gs-wizard__foot">
						{ step > 0 ? (
							<Button variant="secondary" onClick={ back } disabled={ saving }>
								{ __( 'Back', 'gemsecurity' ) }
							</Button>
						) : (
							<span className="gs-wizard__hint">
								<Icon name="clock" size={ 18 } />
								<span>
									{ __( 'About', 'gemsecurity' ) } <strong>{ __( '1 minute', 'gemsecurity' ) }</strong>
									<span className="gs-wizard__count-sep">·</span>
									{ __( 'Nothing is applied until you confirm', 'gemsecurity' ) }
								</span>
							</span>
						) }
						{ current === 'alerts' ? (
							<Button onClick={ finish } loading={ saving }>
								{ __( 'Finish setup', 'gemsecurity' ) }
							</Button>
						) : (
							<Button
								onClick={ next }
								disabled={ current === 'questions' && answeredCount < QUESTIONS.length }
							>
								{ current === 'welcome'
									? <>{ __( 'Let’s get started', 'gemsecurity' ) }<Icon name="arrow-right" size={ 18 } /></>
									: current === 'questions'
										? sprintf(
											/* translators: 1 answered, 2 total */
											__( 'Continue (%1$d/%2$d)', 'gemsecurity' ),
											answeredCount, QUESTIONS.length
										)
										: __( 'Continue', 'gemsecurity' ) }
							</Button>
						) }
					</div>
				) }
			</main>
		</div>
	);
}

/* ------------------------------------------------------------------ */
/* Steps                                                               */
/* ------------------------------------------------------------------ */

function Welcome() {
	const items = [
		{ icon: 'shield', title: __( 'Block attacks', 'gemsecurity' ), desc: __( 'Firewall, brute-force and bot protection.', 'gemsecurity' ) },
		{ icon: 'radar', title: __( 'Find problems', 'gemsecurity' ), desc: __( 'Malware, vulnerability and file-change scans.', 'gemsecurity' ) },
		{ icon: 'bell', title: __( 'Stay informed', 'gemsecurity' ), desc: __( 'Alerts the moment something needs you.', 'gemsecurity' ) },
	];
	return (
		<div className="gs-wizard__welcome">
			<div className="gs-wizard__hero-icon"><Icon name="shield" size={ 40 } /></div>
			<h1>{ __( 'Let’s secure your website', 'gemsecurity' ) }</h1>
			<span className="gs-wizard__site-chip">
				<i className="gs-wizard__live-dot" />
				{ ( GS.site_url || '' ).replace( /^https?:\/\//, '' ).replace( /\/$/, '' ) }
			</span>
			<p className="gs-wizard__lead">
				{ __( 'Answer a few quick questions and GemSecurity will switch on the right protection for you.', 'gemsecurity' ) }{ ' ' }
				<strong>{ __( 'It takes about a minute.', 'gemsecurity' ) }</strong>
			</p>
			<div className="gs-wizard__features">
				{ items.map( ( i ) => (
					<div key={ i.title } className="gs-wizard__feature">
						<span className="gs-wizard__feature-icon"><Icon name={ i.icon } size={ 20 } /></span>
						<strong>{ i.title }</strong>
						<span>{ i.desc }</span>
					</div>
				) ) }
			</div>
		</div>
	);
}

function StepHead( { title, desc } ) {
	return (
		<header className="gs-wizard__head">
			<h2>{ title }</h2>
			<p>{ desc }</p>
		</header>
	);
}

function QuestionsStep( { answers, onAnswer, recommendedLevel } ) {
	const answered = Object.keys( answers ).length;
	const total    = QUESTIONS.length;

	return (
		<>
			<StepHead
				title={ __( 'A few questions about your site', 'gemsecurity' ) }
				desc={ __( 'Your answers switch on the right protection — we show the summary before anything is saved.', 'gemsecurity' ) }
			/>

			<div className="gs-wizard__questions">
				{ QUESTIONS.map( ( q, idx ) => (
					<section key={ q.id } className="gs-question" aria-labelledby={ `gs-q-${ q.id }` }>
						<header className="gs-question__head">
							<span className="gs-question__num">{ idx + 1 }</span>
							<div>
								<h3 id={ `gs-q-${ q.id }` }>{ q.label }</h3>
								{ q.help && <p className="gs-question__help">{ q.help }</p> }
							</div>
						</header>
						<div className="gs-question__options" role="radiogroup" aria-labelledby={ `gs-q-${ q.id }` }>
							{ q.options.map( ( o ) => {
								const selected = answers[ q.id ] === o.id;
								return (
									<button
										type="button"
										key={ o.id }
										role="radio"
										aria-checked={ selected }
										className={ `gs-option ${ selected ? 'is-selected' : '' }` }
										onClick={ () => onAnswer( q.id, o.id ) }
									>
										<span className="gs-option__icon"><Icon name={ o.icon } size={ 18 } /></span>
										<span className="gs-option__text">
											<strong>{ o.title }</strong>
											<span>{ o.desc }</span>
										</span>
										<span className="gs-option__radio" aria-hidden="true" />
									</button>
								);
							} ) }
						</div>
					</section>
				) ) }
			</div>

			<aside className={ `gs-wizard__recommendation ${ answered === total ? 'is-ready' : '' }` } aria-live="polite">
				{ answered < total ? (
					<p>{ sprintf(
						/* translators: 1 answered, 2 total */
						__( '%1$d of %2$d answered — your recommendation appears here.', 'gemsecurity' ),
						answered, total
					) }</p>
				) : (
					<>
						<span className="gs-wizard__rec-tag"><Icon name="shield" size={ 14 } />{ __( 'Recommended for you', 'gemsecurity' ) }</span>
						<strong>{ recommendedLevel.title }</strong>
						<p>{ recommendedLevel.desc }</p>
					</>
				) }
			</aside>
		</>
	);
}

function FeaturesStep( { value, onChange, level } ) {
	const grouped = useMemo( () => groupList()
		.map( ( g ) => ( { ...g, items: allModules().filter( ( m ) => m.group === g.id ) } ) )
		.filter( ( g ) => g.items.length ), [] );

	const enabled = Object.values( value ).filter( Boolean ).length;

	return (
		<>
			<StepHead
				title={ __( 'Review your features', 'gemsecurity' ) }
				desc={ __( 'We pre-selected features based on your answers. Tweak anything you like — only switched-on features load, so your site stays fast.', 'gemsecurity' ) }
			/>
			<div className="gs-wizard__rec-banner" role="status">
				<Icon name={ level.icon } size={ 18 } />
				<span>
					<strong>{ level.title }</strong>
					{ ' · ' }
					{ sprintf(
						/* translators: %d: features enabled */
						__( '%d features switched on', 'gemsecurity' ),
						enabled
					) }
				</span>
			</div>
			<div className="gs-wizard__groups">
				{ grouped.map( ( g ) => (
					<section key={ g.id } className="gs-wizard__group">
						<h3><Icon name={ g.icon } size={ 16 } />{ g.title }</h3>
						<div className="gs-wizard__modules">
							{ g.items.map( ( m ) => {
								const locked = m.is_pro && ! isPro();
								const on = !! value[ m.id ];
								return (
									<label key={ m.id } className={ `gs-module-pick ${ on ? 'is-on' : '' } ${ locked ? 'is-locked' : '' }` }>
										<input
											type="checkbox"
											checked={ on }
											disabled={ locked }
											onChange={ ( e ) => onChange( { ...value, [ m.id ]: e.target.checked } ) }
										/>
										<span className="gs-module-pick__icon"><Icon name={ m.icon } size={ 18 } /></span>
										<span className="gs-module-pick__text">
											<strong>{ m.title } { locked && <ProBadge /> }</strong>
											<span>{ m.desc }</span>
										</span>
										<span className="gs-module-pick__check"><Icon name="check" size={ 14 } /></span>
									</label>
								);
							} ) }
						</div>
					</section>
				) ) }
			</div>
		</>
	);
}

function AlertsStep( { value, onChange } ) {
	const set = ( k ) => ( v ) => onChange( { ...value, [ k ]: v } );
	return (
		<>
			<StepHead
				title={ __( 'Where should we send alerts?', 'gemsecurity' ) }
				desc={ __( 'Get an email when GemSecurity blocks something serious or finds a problem.', 'gemsecurity' ) }
			/>
			<div className="gs-wizard__panel">
				<Toggle
					label={ __( 'Email me security alerts', 'gemsecurity' ) }
					description={ __( 'Lockouts, malware findings, file changes and more.', 'gemsecurity' ) }
					checked={ value.alerts_enabled }
					onChange={ set( 'alerts_enabled' ) }
				/>
				{ value.alerts_enabled && (
					<>
						<Field label={ __( 'Send alerts to', 'gemsecurity' ) }>
							<TextInput
								type="email"
								value={ value.alert_to_email }
								onChange={ ( e ) => set( 'alert_to_email' )( e.target.value ) }
								placeholder="you@example.com"
							/>
						</Field>
						<Field label={ __( 'Alert me about', 'gemsecurity' ) }>
							<Select
								value={ value.alert_min_severity }
								onChange={ ( e ) => set( 'alert_min_severity' )( e.target.value ) }
								options={ [
									{ value: 'critical', label: __( 'Critical issues only', 'gemsecurity' ) },
									{ value: 'warning', label: __( 'Warnings and critical issues', 'gemsecurity' ) },
									{ value: 'notice', label: __( 'Everything', 'gemsecurity' ) },
								] }
							/>
						</Field>
					</>
				) }
				<Toggle
					label={ __( 'Weekly security summary', 'gemsecurity' ) }
					description={ __( 'One short email a week with what was blocked and what needs attention.', 'gemsecurity' ) }
					checked={ value.digest_enabled }
					onChange={ set( 'digest_enabled' ) }
				/>
			</div>
		</>
	);
}

function DoneStep( { level, count, total, alerts, digest, onEdit } ) {
	const url = ( slug ) => `${ GS.admin_url }admin.php?page=${ slug }`;
	const host = ( GS.site_url || '' ).replace( /^https?:\/\//, '' ).replace( /\/$/, '' );
	const rows = [
		{ icon: 'shield', label: __( 'Protection level', 'gemsecurity' ), value: level.title, action: __( 'Change', 'gemsecurity' ), go: () => onEdit( 1 ) },
		{ icon: 'grid', label: __( 'Features switched on', 'gemsecurity' ), value: sprintf( /* translators: 1: on, 2: total */ __( '%1$d of %2$d', 'gemsecurity' ), count, total ), action: __( 'View', 'gemsecurity' ), go: () => ( window.location.href = url( 'gemsecurity-modules' ) ) },
		{ icon: 'bell', label: __( 'Alerts sent to', 'gemsecurity' ), value: alerts.alerts_enabled && alerts.alert_to_email ? alerts.alert_to_email : __( 'Email alerts are off', 'gemsecurity' ), action: __( 'Edit', 'gemsecurity' ), go: () => onEdit( 3 ) },
	];
	const next = [
		{ tone: 'on', title: __( 'Firewall & login protection', 'gemsecurity' ), sub: __( 'Active now', 'gemsecurity' ) },
		{ tone: 'warn', title: __( 'First full scan', 'gemsecurity' ), sub: __( 'Not run yet · about 4 min', 'gemsecurity' ) },
		{ tone: digest ? 'on' : 'off', title: __( 'Weekly security digest', 'gemsecurity' ), sub: digest ? __( 'Every Monday, by email', 'gemsecurity' ) : __( 'Off', 'gemsecurity' ) },
	];
	return (
		<div className="gs-done">
			<div className="gs-done__hero">
				<svg width="56" height="56" viewBox="0 0 24 24" aria-hidden="true">
					<path fill="currentColor" d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z" />
					<path fill="none" stroke="#fff" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" d="m9 12 2 2 4-4" />
				</svg>
			</div>
			<h1>{ __( 'Your site is protected', 'gemsecurity' ) } <span aria-hidden="true">🎉</span></h1>
			<p className="gs-done__lead">{ __( 'GemSecurity is now watching', 'gemsecurity' ) }</p>
			<span className="gs-wizard__site-chip"><i className="gs-wizard__live-dot" />{ host }</span>

			<section className="gs-done__card">
				<h3>{ __( 'What we set up', 'gemsecurity' ) }</h3>
				{ rows.map( ( r ) => (
					<div key={ r.label } className="gs-done__row">
						<span className="gs-done__row-icon"><Icon name={ r.icon } size={ 18 } /></span>
						<div><small>{ r.label }</small><strong>{ r.value }</strong></div>
						<button type="button" onClick={ r.go }>{ r.action }</button>
					</div>
				) ) }
			</section>

			<section className="gs-done__card">
				<h3>{ __( 'What happens next', 'gemsecurity' ) }</h3>
				{ next.map( ( n ) => (
					<div key={ n.title } className="gs-done__row gs-done__row--next">
						<i className={ `gs-done__dot is-${ n.tone }` } />
						<div><strong>{ n.title }</strong><small>{ n.sub }</small></div>
					</div>
				) ) }
			</section>

			<div className="gs-done__actions">
				<Button onClick={ () => ( window.location.href = url( 'gemsecurity-scanner' ) ) }>
					<Icon name="refresh" size={ 18 } />{ __( 'Run first scan', 'gemsecurity' ) }
				</Button>
				<Button variant="secondary" onClick={ () => ( window.location.href = GS.dashboard ) }>
					{ __( 'Go to dashboard', 'gemsecurity' ) }<Icon name="arrow-right" size={ 18 } />
				</Button>
			</div>
			<p className="gs-done__note">{ __( 'You can change any of this later in Settings.', 'gemsecurity' ) }</p>
		</div>
	);
}
