import React, { useMemo, useState } from 'react';
import { __, sprintf } from '@wordpress/i18n';
import api, { GS } from '@Utils/api';
import { Button, Toggle, Field, TextInput, Select } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';
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
	{ id: 'level', label: __( 'Protection level', 'gemsecurity' ) },
	{ id: 'features', label: __( 'Features', 'gemsecurity' ) },
	{ id: 'alerts', label: __( 'Alerts', 'gemsecurity' ) },
	{ id: 'done', label: __( 'All set', 'gemsecurity' ) },
];

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
	const [ levelId, setLevelId ] = useState( 'recommended' );
	const level = LEVELS.find( ( l ) => l.id === levelId );
	const [ modules, setModules ] = useState( () => modulesFor( level ) );
	const [ alerts, setAlerts ] = useState( {
		alerts_enabled: true,
		alert_to_email: GS.admin_email || '',
		alert_min_severity: 'warning',
		digest_enabled: true,
	} );
	const [ saving, setSaving ] = useState( false );
	const [ error, setError ] = useState( '' );

	const pickLevel = ( id ) => {
		setLevelId( id );
		setModules( modulesFor( LEVELS.find( ( l ) => l.id === id ) ) );
	};

	const enabledCount = Object.values( modules ).filter( Boolean ).length;
	const next = () => setStep( ( s ) => Math.min( s + 1, STEPS.length - 1 ) );
	const back = () => setStep( ( s ) => Math.max( s - 1, 0 ) );

	const finish = async () => {
		setSaving( true );
		setError( '' );
		try {
			await api.post( 'settings', { settings: { ...level.settings, ...alerts } } );
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

	return (
		<div className="gs-wizard">
			<aside className="gs-wizard__rail">
				<div className="gs-wizard__brand">
					<span className="gs-wizard__logo"><Icon name="shield" size={ 22 } /></span>
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
							<span>{ s.label }</span>
						</li>
					) ) }
				</ol>
				<p className="gs-wizard__rail-foot">
					{ __( 'You can change every choice later from the GemSecurity settings.', 'gemsecurity' ) }
				</p>
			</aside>

			<main className="gs-wizard__main">
				<div className="gs-wizard__top">
					<span className="gs-wizard__count">
						{ sprintf( /* translators: 1: step, 2: total */ __( 'Step %1$d of %2$d', 'gemsecurity' ), step + 1, STEPS.length ) }
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
				<div className="gs-wizard__progress"><span style={ { width: `${ ( step / ( STEPS.length - 1 ) ) * 100 }%` } } /></div>

				<div className="gs-wizard__body" key={ current }>
					{ current === 'welcome' && <Welcome /> }
					{ current === 'level' && <LevelStep value={ levelId } onChange={ pickLevel } /> }
					{ current === 'features' && <FeaturesStep value={ modules } onChange={ setModules } /> }
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
						) : <span /> }
						{ current === 'alerts' ? (
							<Button onClick={ finish } loading={ saving }>
								{ __( 'Finish setup', 'gemsecurity' ) }
							</Button>
						) : (
							<Button onClick={ next }>
								{ current === 'welcome' ? __( 'Let’s get started', 'gemsecurity' ) : __( 'Continue', 'gemsecurity' ) }
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
		{ icon: 'mail', title: __( 'Stay informed', 'gemsecurity' ), desc: __( 'Alerts the moment something needs you.', 'gemsecurity' ) },
	];
	return (
		<div className="gs-wizard__welcome">
			<div className="gs-wizard__hero-icon"><Icon name="shield" size={ 40 } /></div>
			<h1>{ GS.site_name
				? sprintf( /* translators: %s: site name */ __( 'Let’s secure %s', 'gemsecurity' ), GS.site_name )
				: __( 'Let’s secure your site', 'gemsecurity' ) }</h1>
			<p className="gs-wizard__lead">
				{ __( 'Answer three quick questions and GemSecurity will switch on the right protection for you. It takes about a minute.', 'gemsecurity' ) }
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

function LevelStep( { value, onChange } ) {
	return (
		<>
			<StepHead
				title={ __( 'How much protection do you want?', 'gemsecurity' ) }
				desc={ __( 'Pick a starting point. You can fine-tune each feature on the next step.', 'gemsecurity' ) }
			/>
			<div className="gs-wizard__levels" role="radiogroup">
				{ LEVELS.map( ( l ) => (
					<button
						type="button"
						key={ l.id }
						role="radio"
						aria-checked={ value === l.id }
						className={ `gs-level ${ value === l.id ? 'is-selected' : '' }` }
						onClick={ () => onChange( l.id ) }
					>
						{ l.best && <span className="gs-level__tag">{ __( 'Recommended', 'gemsecurity' ) }</span> }
						<span className="gs-level__icon"><Icon name={ l.icon } size={ 22 } /></span>
						<strong className="gs-level__title">{ l.title }</strong>
						<span className="gs-level__desc">{ l.desc }</span>
						<ul>
							{ l.points.map( ( p ) => (
								<li key={ p }><Icon name="check" size={ 14 } />{ p }</li>
							) ) }
						</ul>
						<span className="gs-level__radio" />
					</button>
				) ) }
			</div>
		</>
	);
}

function FeaturesStep( { value, onChange } ) {
	const grouped = useMemo( () => groupList()
		.map( ( g ) => ( { ...g, items: allModules().filter( ( m ) => m.group === g.id ) } ) )
		.filter( ( g ) => g.items.length ), [] );

	return (
		<>
			<StepHead
				title={ __( 'Choose your features', 'gemsecurity' ) }
				desc={ __( 'We’ve pre-selected features for your protection level. Only switched-on features load, so your site stays fast.', 'gemsecurity' ) }
			/>
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

function DoneStep( { level, count, alerts } ) {
	const url = ( slug ) => `${ GS.admin_url }admin.php?page=${ slug }`;
	return (
		<div className="gs-wizard__welcome gs-wizard__done">
			<div className="gs-wizard__hero-icon is-success"><Icon name="check" size={ 40 } /></div>
			<h1>{ __( 'Your site is protected', 'gemsecurity' ) }</h1>
			<p className="gs-wizard__lead">{ __( 'GemSecurity is now watching over your site. Here’s what we set up:', 'gemsecurity' ) }</p>
			<ul className="gs-wizard__summary">
				<li><Icon name="shield" size={ 16 } />{ sprintf( /* translators: %s: level name */ __( '%s protection level', 'gemsecurity' ), level.title ) }</li>
				<li><Icon name="layers" size={ 16 } />{ sprintf( /* translators: %d: count */ __( '%d features switched on', 'gemsecurity' ), count ) }</li>
				<li><Icon name="mail" size={ 16 } />{ alerts.alerts_enabled && alerts.alert_to_email
					? sprintf( /* translators: %s: email */ __( 'Alerts go to %s', 'gemsecurity' ), alerts.alert_to_email )
					: __( 'Email alerts are off', 'gemsecurity' ) }</li>
			</ul>
			<div className="gs-wizard__done-actions">
				<Button onClick={ () => ( window.location.href = GS.dashboard ) }>
					{ __( 'Go to dashboard', 'gemsecurity' ) }
				</Button>
				<Button variant="secondary" onClick={ () => ( window.location.href = url( 'gemsecurity-scanner' ) ) }>
					{ __( 'Run my first scan', 'gemsecurity' ) }
				</Button>
			</div>
		</div>
	);
}
