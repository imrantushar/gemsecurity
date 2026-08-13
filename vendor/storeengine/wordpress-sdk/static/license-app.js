/* global wp */
/**
 * StoreEngine SDK License + Updates panel.
 *
 * Boots once per host plugin from SE_License_SDK_License::render_license_page().
 * Reads its config from a `window.seSdkLicenseAppConfig_{slug}` object the
 * PHP side injects via wp_localize_script.
 *
 * Uses wp.element (React + ReactDOM that ships with WordPress) — no build
 * step, runs as plain JS in every WP admin from 5.3+.
 *
 * Visual language mirrors the legacy license-form.php: centered cards with
 * soft shadow, slate palette, 4px radius, the host's --se-sdk-primary-color.
 */
( function ( wp ) {
	if ( ! wp || ! wp.element ) {
		return;
	}

	const { createElement: h, useState, useEffect, useCallback, Fragment, render } = wp.element;
	const { __, sprintf } = ( wp.i18n || { __: ( s ) => s, sprintf: ( s ) => s } );

	function api( config, path, opts ) {
		opts = opts || {};
		const url = config.restUrl + path.replace( /^\//, '' );

		return fetch( url, {
			method: opts.method || 'GET',
			headers: {
				'Content-Type': 'application/json',
				'X-WP-Nonce': config.nonce,
				Accept: 'application/json',
			},
			credentials: 'same-origin',
			body: opts.body ? JSON.stringify( opts.body ) : undefined,
		} ).then( async ( res ) => {
			const data = await res.json().catch( () => ( {} ) );
			if ( ! res.ok ) {
				const err = new Error( data.message || res.statusText );
				err.code = data.code;
				err.data = data.data || {};
				err.status = res.status;
				err.log = ( data.data && data.data.log ) || null;
				throw err;
			}
			return data;
		} );
	}

	function timeAgo( unix ) {
		if ( ! unix ) {
			return __( 'never', 'storeengine-sdk' );
		}
		const seconds = Math.max( 0, Math.floor( Date.now() / 1000 - unix ) );
		if ( seconds < 60 ) return __( 'just now', 'storeengine-sdk' );
		if ( seconds < 3600 ) return sprintf( /* translators: %d: minutes */ __( '%d min ago', 'storeengine-sdk' ), Math.floor( seconds / 60 ) );
		if ( seconds < 86400 ) return sprintf( __( '%d hr ago', 'storeengine-sdk' ), Math.floor( seconds / 3600 ) );
		return sprintf( __( '%d days ago', 'storeengine-sdk' ), Math.floor( seconds / 86400 ) );
	}

	function compareVersions( a, b ) {
		const pa = String( a ).split( '.' ).map( ( n ) => parseInt( n, 10 ) || 0 );
		const pb = String( b ).split( '.' ).map( ( n ) => parseInt( n, 10 ) || 0 );
		const len = Math.max( pa.length, pb.length );
		for ( let i = 0; i < len; i++ ) {
			const ai = pa[ i ] || 0;
			const bi = pb[ i ] || 0;
			if ( ai !== bi ) return ai < bi ? -1 : 1;
		}
		return 0;
	}

	function refreshIcon() {
		return h( 'svg', { xmlns: 'http://www.w3.org/2000/svg', viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 2, strokeLinecap: 'round', strokeLinejoin: 'round' },
			h( 'polyline', { points: '23 4 23 10 17 10' } ),
			h( 'polyline', { points: '1 20 1 14 7 14' } ),
			h( 'path', { d: 'M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15' } )
		);
	}

	function checkIcon() {
		return h( 'svg', { className: 'se-sdk-btn-icon', viewBox: '0 0 20 20', fill: 'none', xmlns: 'http://www.w3.org/2000/svg', 'aria-hidden': true },
			h( 'path', { fill: 'currentColor', d: 'M17.5 9.99992C17.5 5.85778 14.1421 2.49992 10 2.49992C5.85787 2.49992 2.50001 5.85778 2.50001 9.99992C2.50001 14.1421 5.85787 17.4999 10 17.4999C14.1421 17.4999 17.5 14.1421 17.5 9.99992ZM11.9108 7.74406C12.2363 7.41862 12.7638 7.41862 13.0892 7.74406C13.4146 8.0695 13.4146 8.59701 13.0892 8.92244L9.75587 12.2558C9.43043 12.5812 8.90292 12.5812 8.57748 12.2558L6.91082 10.5891C6.58538 10.2637 6.58538 9.73616 6.91082 9.41072C7.23625 9.08529 7.76377 9.08529 8.0892 9.41072L9.16668 10.4882L11.9108 7.74406Z' } )
		);
	}

	/* =========================================================
	   Update status hero — top card, "Installed → Latest"
	   ========================================================= */
	function StatusHero( props ) {
		const { state, onCheckNow, checking } = props;
		const updateAvailable = !! state.update_available;

		return h( 'div', { className: 'se-sdk-card' },
			h( 'div', { className: 'se-sdk-hero' },
				h( 'div', { className: 'se-sdk-hero-versions' },
					h( 'div', { className: 'se-sdk-version-block' },
						h( 'span', { className: 'se-sdk-version-label' }, __( 'Installed', 'storeengine-sdk' ) ),
						h( 'span', { className: 'se-sdk-version-value' }, state.current_version || '—' )
					),
					updateAvailable && h( 'span', { className: 'se-sdk-hero-arrow', 'aria-hidden': true }, '→' ),
					updateAvailable && h( 'div', { className: 'se-sdk-version-block' },
						h( 'span', { className: 'se-sdk-version-label' }, __( 'Latest', 'storeengine-sdk' ) ),
						h( 'span', { className: 'se-sdk-version-value is-latest' }, state.latest_version || '—' )
					)
				),
				h( 'div', { className: 'se-sdk-hero-actions' },
					h( 'span', { className: 'se-sdk-checked-at' },
						sprintf( __( 'Checked %s', 'storeengine-sdk' ), timeAgo( state.last_checked_at ) )
					),
					h( 'button', {
						type: 'button',
						className: 'se-sdk-btn se-sdk-btn-secondary',
						onClick: onCheckNow,
						disabled: checking,
					}, checking ? __( 'Checking…', 'storeengine-sdk' ) : __( 'Check for updates', 'storeengine-sdk' ) )
				)
			)
		);
	}

	/* =========================================================
	   Update available banner (above license card when relevant)
	   ========================================================= */
	function UpdateBanner( props ) {
		const { state, installing, installLog, onInstall } = props;

		if ( ! state.update_available ) {
			return null;
		}

		return h( 'div', { className: 'se-sdk-banner se-sdk-banner-update' },
			h( 'div', { className: 'se-sdk-banner-message' },
				h( 'div', { className: 'se-sdk-banner-title' },
					sprintf( __( 'Version %s is available', 'storeengine-sdk' ), state.latest_version )
				),
				state.changelog
					? h( 'p', { className: 'se-sdk-banner-sub' }, state.changelog )
					: h( 'p', { className: 'se-sdk-banner-sub' },
						__( 'Click update to install the latest release. Your settings and data stay intact.', 'storeengine-sdk' ) )
			),
			h( 'div', { className: 'se-sdk-banner-actions' },
				h( 'button', {
					type: 'button',
					className: 'se-sdk-btn',
					onClick: () => onInstall( null ),
					disabled: installing,
				}, installing
					? __( 'Installing…', 'storeengine-sdk' )
					: sprintf( __( 'Update to %s', 'storeengine-sdk' ), state.latest_version )
				)
			),
			installing && installLog.length > 0 && h( 'div', { className: 'se-sdk-install-progress' },
				h( 'div', { className: 'se-sdk-progress-track' }, h( 'div', { className: 'se-sdk-progress-fill' } ) ),
				h( InstallLog, { messages: installLog } )
			)
		);
	}

	function InstallLog( props ) {
		const { messages } = props;
		if ( ! messages || messages.length === 0 ) {
			return null;
		}
		return h( 'details', { className: 'se-sdk-log-drawer' },
			h( 'summary', null, sprintf( __( 'Install log (%d entries)', 'storeengine-sdk' ), messages.length ) ),
			h( 'ul', { className: 'se-sdk-log-list' },
				messages.map( ( m, i ) =>
					h( 'li', { key: i, className: 'se-sdk-log-' + m.level },
						h( 'span', { className: 'se-sdk-log-level' }, m.level ),
						h( 'span', { className: 'se-sdk-log-msg' }, m.message )
					)
				)
			)
		);
	}

	/* =========================================================
	   Rollback shortcut banner (only when previous_version known)
	   ========================================================= */
	function RollbackBanner( props ) {
		const { state, installing, onRollback } = props;
		if ( ! state.previous_version ) return null;

		return h( 'div', { className: 'se-sdk-banner se-sdk-banner-rollback' },
			h( 'div', { className: 'se-sdk-banner-message' },
				h( 'div', { className: 'se-sdk-banner-title' },
					sprintf( __( 'Quick rollback to v%s', 'storeengine-sdk' ), state.previous_version )
				),
				h( 'p', { className: 'se-sdk-banner-sub' },
					__( "If the latest update isn't working out, you can return to your previously installed version with one click.", 'storeengine-sdk' )
				)
			),
			h( 'div', { className: 'se-sdk-banner-actions' },
				h( 'button', {
					type: 'button',
					className: 'se-sdk-btn se-sdk-btn-secondary',
					onClick: () => onRollback( state.previous_version ),
					disabled: installing,
				}, sprintf( __( 'Roll back to v%s', 'storeengine-sdk' ), state.previous_version ) )
			)
		);
	}

	/* =========================================================
	   License card — mirrors the legacy license-form.php layout
	   ========================================================= */
	function LicenseCard( props ) {
		const { config, license, state, onActivate, onDeactivate, onCheckLicense, busy, error } = props;
		const [ keyDraft, setKeyDraft ] = useState( '' );

		const active = license && license.status === 'active';
		// Server already masks via get_public_data() → mask_string(). Render as-is.
		const maskedKey = license && license.license ? license.license : '';

		const heroTitle = active
			? sprintf( __( '%s is active on this site.', 'storeengine-sdk' ), config.packageName )
			: sprintf( __( 'Activate %s', 'storeengine-sdk' ), config.packageName );

		const heroSub = active
			? __( 'You\'re receiving updates, security fixes and priority support.', 'storeengine-sdk' )
			: __( 'Activate your license to unlock automatic updates, priority support, and all premium features.', 'storeengine-sdk' );

		return h( 'div', { className: 'se-sdk-card' },
			h( 'div', { className: 'se-sdk-license-hero' },
				h( 'h2', { className: 'se-sdk-license-hero-title' }, heroTitle ),
				h( 'p', { className: 'se-sdk-license-hero-sub' }, heroSub ),
				h( 'form', {
					className: 'se-sdk-license-form',
					onSubmit: ( e ) => {
						e.preventDefault();
						if ( active ) return;
						if ( keyDraft.trim() ) onActivate( keyDraft.trim() );
					},
				},
					h( 'div', { className: 'se-sdk-license-row' },
						h( 'input', {
							className: 'se-sdk-license-input',
							type: 'text',
							placeholder: __( 'Enter your license key to activate', 'storeengine-sdk' ),
							value: active ? maskedKey : keyDraft,
							readOnly: active,
							onChange: ( e ) => setKeyDraft( e.target.value ),
							disabled: busy,
							spellCheck: false,
							autoComplete: 'off',
						} ),
						active
							? h( Fragment, null,
								h( 'button', {
									type: 'button',
									className: 'se-sdk-btn se-sdk-btn-danger',
									onClick: onDeactivate,
									disabled: busy,
								}, busy ? __( 'Working…', 'storeengine-sdk' ) : __( 'Deactivate License', 'storeengine-sdk' ) ),
								config.storeDashboardUrl && h( 'a', {
									className: 'se-sdk-btn',
									href: config.storeDashboardUrl,
									target: '_blank',
									rel: 'noopener noreferrer',
								}, __( 'Manage License', 'storeengine-sdk' ) )
							)
							: h( 'button', {
								type: 'submit',
								className: 'se-sdk-btn',
								disabled: busy || ! keyDraft.trim(),
							}, busy ? __( 'Activating…', 'storeengine-sdk' ) : h( Fragment, null,
								checkIcon(),
								h( 'span', null, __( 'Activate License', 'storeengine-sdk' ) )
							) )
					),
					! active && config.purchaseUrl && h( 'p', { className: 'se-sdk-purchase-prompt' },
						__( "Don't have a license key? ", 'storeengine-sdk' ),
						h( 'a', { href: config.purchaseUrl, target: '_blank', rel: 'noopener noreferrer' },
							__( 'Purchase one here', 'storeengine-sdk' )
						)
					),
					error && h( 'div', { className: 'se-sdk-error' }, error )
				)
			),
			active && h( StatsRow, { license, state, onCheckLicense, checking: busy } )
		);
	}

	function StatsRow( props ) {
		const { license, state, onCheckLicense, checking } = props;
		const remaining = license.unlimited
			? '∞'
			: ( license.remaining !== undefined ? license.remaining : ( license.limit - license.activations ) );
		const usage = license.unlimited
			? __( 'Unlimited', 'storeengine-sdk' )
			: sprintf( __( '%1$s of %2$s', 'storeengine-sdk' ), remaining, license.limit );

		// License "updated_at" comes back as an ISO/MySQL string from
		// get_public_data(); turn it into a unix timestamp for timeAgo().
		const licenseCheckedUnix = license.updated_at
			? Math.floor( Date.parse( license.updated_at.replace( ' ', 'T' ) + 'Z' ) / 1000 )
			: null;

		const autoUpdateOn = !! state.auto_update_enabled;

		return h( 'div', { className: 'se-sdk-stats' },
			h( 'div', { className: 'se-sdk-stat' },
				h( 'span', { className: 'se-sdk-stat-label' }, __( 'Status', 'storeengine-sdk' ) ),
				h( 'span', { className: 'se-sdk-stat-value' },
					h( 'span', { className: 'se-sdk-pill se-sdk-pill-ok' }, __( 'Active', 'storeengine-sdk' ) )
				)
			),
			h( 'div', { className: 'se-sdk-stat' },
				h( 'span', { className: 'se-sdk-stat-label' }, __( 'Last Checked', 'storeengine-sdk' ) ),
				h( 'span', { className: 'se-sdk-stat-value' },
					timeAgo( licenseCheckedUnix ),
					h( 'button', {
						type: 'button',
						className: 'se-sdk-refresh-link',
						onClick: onCheckLicense,
						disabled: checking,
						title: __( 'Check license status now', 'storeengine-sdk' ),
						'aria-label': __( 'Check license status now', 'storeengine-sdk' ),
					}, refreshIcon() )
				)
			),
			h( 'div', { className: 'se-sdk-stat' },
				h( 'span', { className: 'se-sdk-stat-label' }, __( 'Expires', 'storeengine-sdk' ) ),
				h( 'span', { className: 'se-sdk-stat-value' }, license.expires || __( 'N/A', 'storeengine-sdk' ) )
			),
			h( 'div', { className: 'se-sdk-stat' },
				h( 'span', { className: 'se-sdk-stat-label' }, __( 'Activations Remaining', 'storeengine-sdk' ) ),
				h( 'span', { className: 'se-sdk-stat-value' }, usage )
			),
			h( 'div', { className: 'se-sdk-stat' },
				h( 'span', { className: 'se-sdk-stat-label' }, __( 'WP Auto-update', 'storeengine-sdk' ) ),
				h( 'span', { className: 'se-sdk-stat-value' },
					h( 'span', {
						className: 'se-sdk-pill ' + ( autoUpdateOn ? 'se-sdk-pill-ok' : 'se-sdk-pill' ),
						title: autoUpdateOn
							? __( "WordPress will auto-install updates for this plugin (toggled on the Plugins screen).", 'storeengine-sdk' )
							: __( 'Toggle auto-update from WordPress→Plugins.', 'storeengine-sdk' ),
					}, autoUpdateOn ? __( 'Enabled', 'storeengine-sdk' ) : __( 'Disabled', 'storeengine-sdk' ) )
				)
			)
		);
	}

	/* =========================================================
	   Version history
	   ========================================================= */
	function VersionsTable( props ) {
		const { versions, loading, installing, onInstall, current, onRefresh, refreshing, error } = props;
		const [ confirming, setConfirming ] = useState( null );

		const header = h( 'div', { className: 'se-sdk-card-header' },
			h( 'div', null,
				h( 'h2', null, __( 'Version history', 'storeengine-sdk' ) ),
				h( 'p', { className: 'se-sdk-card-subtitle' },
					__( 'Install or roll back to any released version of this plugin.', 'storeengine-sdk' )
				)
			),
			h( 'button', {
				type: 'button',
				className: 'se-sdk-btn se-sdk-btn-secondary',
				onClick: onRefresh,
				disabled: refreshing || loading,
				title: __( 'Re-fetch the version list from the license server.', 'storeengine-sdk' ),
			}, refreshing ? __( 'Refreshing…', 'storeengine-sdk' ) : __( 'Refresh', 'storeengine-sdk' ) )
		);

		const body = ( inner ) => h( 'div', { className: 'se-sdk-card' },
			header,
			h( 'div', { className: 'se-sdk-card-body' }, inner )
		);

		if ( loading ) {
			return body( h( 'p', { className: 'se-sdk-empty-state' }, __( 'Loading version history…', 'storeengine-sdk' ) ) );
		}

		if ( ! versions || versions.length === 0 ) {
			if ( error && error.code === 'sdk-server-version-list-unsupported' ) {
				return body( h( 'div', { className: 'se-sdk-empty-state se-sdk-empty-state-soft' },
					h( 'p', null, h( 'strong', null, __( "The license server doesn't support version history yet.", 'storeengine-sdk' ) ) ),
					h( 'p', null, error.message ),
					h( 'p', null, __( 'Status updates above still work — they use the older /check-update endpoint. The Refresh button retries once the server is upgraded.', 'storeengine-sdk' ) )
				) );
			}

			if ( error ) {
				return body( h( 'div', { className: 'se-sdk-empty-state se-sdk-empty-state-soft' },
					h( 'p', null, h( 'strong', null, __( 'Could not load version history.', 'storeengine-sdk' ) ) ),
					h( 'p', null, error.message )
				) );
			}

			return body( h( 'div', { className: 'se-sdk-empty-state' },
				h( 'p', null, h( 'strong', null, __( 'No versions are available to install or roll back to yet.', 'storeengine-sdk' ) ) ),
				h( 'p', null, __( "Once the vendor publishes additional released versions on the license server, they'll appear here with Install and Roll back buttons.", 'storeengine-sdk' ) )
			) );
		}

		const onlyCurrent = versions.length === 1 && versions[ 0 ].is_current;

		return h( 'div', { className: 'se-sdk-card' },
			header,
			onlyCurrent && h( 'div', { className: 'se-sdk-card-body' },
				h( 'div', { className: 'se-sdk-empty-state se-sdk-empty-state-soft' },
					h( 'p', null, __( "You're on the only released version. Roll back will become available once an earlier release is published.", 'storeengine-sdk' ) )
				)
			),
			h( 'div', { className: 'se-sdk-versions-table-wrap' },
				h( 'table', { className: 'se-sdk-versions-table' },
					h( 'thead', null,
						h( 'tr', null,
							h( 'th', null, __( 'Version', 'storeengine-sdk' ) ),
							h( 'th', null, __( 'Status', 'storeengine-sdk' ) ),
							h( 'th', null, __( 'Released', 'storeengine-sdk' ) ),
							h( 'th', { className: 'se-sdk-col-actions' }, '' )
						)
					),
					h( 'tbody', null,
						versions.map( ( v ) =>
							h( Fragment, { key: v.id },
								h( 'tr', null,
									h( 'td', null,
										h( 'code', null, v.version ),
										v.is_current && ' ',
										v.is_current && h( 'span', { className: 'se-sdk-pill se-sdk-pill-current' }, __( 'current', 'storeengine-sdk' ) )
									),
									h( 'td', null,
										h( 'span', { className: 'se-sdk-pill se-sdk-pill-' + v.status }, v.status )
									),
									h( 'td', null, v.deployed_at || '—' ),
									h( 'td', { className: 'se-sdk-col-actions' },
										v.is_current
											? h( 'span', { style: { color: '#738496', fontSize: 12 } }, __( 'Installed', 'storeengine-sdk' ) )
											: ( ! v.allow_rollback && current && compareVersions( v.version, current ) < 0 )
												? h( 'span', { style: { color: '#b26200', fontSize: 12 }, title: __( 'Vendor disabled rollback to this version.', 'storeengine-sdk' ) }, __( 'Rollback blocked', 'storeengine-sdk' ) )
												: h( 'button', {
													type: 'button',
													className: 'se-sdk-btn se-sdk-btn-secondary',
													onClick: () => {
														if ( v.breaking_changes ) {
															setConfirming( v );
														} else {
															onInstall( v.version );
														}
													},
													disabled: installing,
												}, ( current && compareVersions( v.version, current ) < 0 )
													? __( 'Roll back', 'storeengine-sdk' )
													: __( 'Install', 'storeengine-sdk' ) )
									)
								),
								confirming && confirming.id === v.id && h( 'tr', { className: 'se-sdk-confirm-row' },
									h( 'td', { colSpan: 4 },
										h( 'div', { className: 'se-sdk-confirm-box' },
											h( 'strong', null, __( '⚠ Breaking changes', 'storeengine-sdk' ) ),
											h( 'p', null, confirming.breaking_changes ),
											h( 'div', { className: 'se-sdk-confirm-actions' },
												h( 'button', {
													type: 'button',
													className: 'se-sdk-btn',
													onClick: () => {
														const version = confirming.version;
														setConfirming( null );
														onInstall( version );
													},
												}, __( 'I understand, continue', 'storeengine-sdk' ) ),
												h( 'button', {
													type: 'button',
													className: 'se-sdk-btn se-sdk-btn-secondary',
													onClick: () => setConfirming( null ),
												}, __( 'Cancel', 'storeengine-sdk' ) )
											)
										)
									)
								)
							)
						)
					)
				)
			)
		);
	}

	/* =========================================================
	   Settings card
	   Note: server endpoint /settings/auto-update-window + storage
	   still exist for a future scheduled-update feature, but the
	   UI is hidden until a window parser + cron are wired in.
	   ========================================================= */
	function SettingsCard( props ) {
		const { state, onBeta, savingBeta } = props;

		return h( 'div', { className: 'se-sdk-card' },
			h( 'div', { className: 'se-sdk-card-header' },
				h( 'div', null,
					h( 'h2', null, __( 'Update preferences', 'storeengine-sdk' ) ),
					h( 'p', { className: 'se-sdk-card-subtitle' },
						__( 'Tune how this site receives updates from the license server.', 'storeengine-sdk' )
					)
				)
			),
			h( 'div', { className: 'se-sdk-card-body' },
				h( 'div', { className: 'se-sdk-setting-row' },
					h( 'label', { className: 'se-sdk-toggle' },
						h( 'input', {
							type: 'checkbox',
							checked: !! state.beta_enabled,
							onChange: ( e ) => onBeta( e.target.checked ),
							disabled: savingBeta,
						} ),
						h( 'span', { className: 'se-sdk-setting-label' }, __( 'Receive beta updates', 'storeengine-sdk' ) )
					),
					h( 'p', { className: 'se-sdk-setting-help' },
						__( 'Includes pre-release versions tagged as beta on the license server.', 'storeengine-sdk' )
					)
				)
			)
		);
	}

	/* =========================================================
	   App root
	   ========================================================= */
	function App( props ) {
		const { config } = props;
		const [ state, setState ] = useState( null );
		const [ versions, setVersions ] = useState( null );
		const [ versionsLoading, setVersionsLoading ] = useState( true );
		const [ versionsError, setVersionsError ] = useState( null );
		const [ checking, setChecking ] = useState( false );
		const [ installing, setInstalling ] = useState( false );
		const [ installLog, setInstallLog ] = useState( [] );
		const [ licenseBusy, setLicenseBusy ] = useState( false );
		const [ licenseError, setLicenseError ] = useState( null );
		const [ savingBeta, setSavingBeta ] = useState( false );
		const [ toast, setToast ] = useState( null );

		const refreshStatus = useCallback( () => {
			return api( config, 'updates/status' ).then( setState );
		}, [ config ] );

		const refreshVersions = useCallback( () => {
			setVersionsLoading( true );
			setVersionsError( null );
			return api( config, 'updates/versions' )
				.then( ( res ) => setVersions( res && res.versions ? res.versions : [] ) )
				.catch( ( err ) => {
					setVersions( [] );
					setVersionsError( { code: err.code, message: err.message } );
				} )
				.finally( () => setVersionsLoading( false ) );
		}, [ config ] );

		const refreshLicense = useCallback( () => {
			if ( config.isFree ) return Promise.resolve();
			return api( config, 'license/status' ).then( ( lic ) => {
				setState( ( s ) => Object.assign( {}, s || {}, { license: lic } ) );
			} );
		}, [ config ] );

		useEffect( () => {
			refreshStatus().catch( () => setState( {} ) );
			if ( ! config.isFree ) refreshLicense();
			refreshVersions();
		}, [ refreshStatus, refreshLicense, refreshVersions, config.isFree ] );

		const showToast = useCallback( ( msg, kind ) => {
			setToast( { msg, kind: kind || 'info' } );
			setTimeout( () => setToast( null ), 4000 );
		}, [] );

		const handleCheckNow = useCallback( () => {
			setChecking( true );
			api( config, 'updates/check-now', { method: 'POST' } )
				.then( ( fresh ) => {
					setState( fresh );
					showToast( fresh.update_available
						? sprintf( __( 'Update available: v%s', 'storeengine-sdk' ), fresh.latest_version )
						: __( "You're up to date.", 'storeengine-sdk' ),
					'success' );
				} )
				.catch( ( err ) => showToast( err.message, 'error' ) )
				.finally( () => setChecking( false ) );
		}, [ config, showToast ] );

		const handleInstall = useCallback( ( version ) => {
			setInstalling( true );
			setInstallLog( [ { level: 'info', message: __( 'Starting…', 'storeengine-sdk' ), time: Date.now() / 1000 } ] );
			api( config, 'updates/install', { method: 'POST', body: version ? { version } : {} } )
				.then( ( res ) => {
					setInstallLog( res.log || [] );
					showToast(
						res.is_rollback
							? sprintf( __( 'Rolled back to v%s', 'storeengine-sdk' ), res.target_version )
							: sprintf( __( 'Installed v%s', 'storeengine-sdk' ), res.target_version ),
						'success'
					);
					setTimeout( () => window.location.reload(), 1500 );
				} )
				.catch( ( err ) => {
					if ( err.log ) setInstallLog( err.log );
					showToast( err.message, 'error' );
					refreshStatus();
				} )
				.finally( () => setInstalling( false ) );
		}, [ config, showToast, refreshStatus ] );

		const handleActivate = useCallback( ( licenseKey ) => {
			setLicenseBusy( true );
			setLicenseError( null );
			api( config, 'license/activate', { method: 'POST', body: { license: licenseKey } } )
				.then( ( res ) => {
					setState( ( s ) => Object.assign( {}, s || {}, { license: res.license } ) );
					showToast( res.message || __( 'License activated.', 'storeengine-sdk' ), 'success' );
					refreshVersions();
				} )
				.catch( ( err ) => setLicenseError( err.message ) )
				.finally( () => setLicenseBusy( false ) );
		}, [ config, showToast, refreshVersions ] );

		const handleDeactivate = useCallback( () => {
			if ( ! window.confirm( __( 'Deactivate this license on this site?', 'storeengine-sdk' ) ) ) return;
			setLicenseBusy( true );
			setLicenseError( null );
			api( config, 'license/deactivate', { method: 'POST' } )
				.then( ( res ) => {
					setState( ( s ) => Object.assign( {}, s || {}, { license: res.license } ) );
					showToast( res.message || __( 'License deactivated.', 'storeengine-sdk' ), 'success' );
				} )
				.catch( ( err ) => setLicenseError( err.message ) )
				.finally( () => setLicenseBusy( false ) );
		}, [ config, showToast ] );

		const handleCheckLicense = useCallback( () => {
			setLicenseBusy( true );
			api( config, 'license/status?force=true' )
				.then( ( lic ) => {
					setState( ( s ) => Object.assign( {}, s || {}, { license: lic } ) );
					showToast( __( 'License re-checked.', 'storeengine-sdk' ), 'success' );
				} )
				.catch( ( err ) => showToast( err.message, 'error' ) )
				.finally( () => setLicenseBusy( false ) );
		}, [ config, showToast ] );

		const handleBeta = useCallback( ( enabled ) => {
			setSavingBeta( true );
			api( config, 'settings/beta-channel', { method: 'POST', body: { enabled } } )
				.then( () => {
					setState( ( s ) => Object.assign( {}, s || {}, { beta_enabled: enabled } ) );
					refreshStatus();
				} )
				.catch( ( err ) => showToast( err.message, 'error' ) )
				.finally( () => setSavingBeta( false ) );
		}, [ config, refreshStatus, showToast ] );

		if ( ! state ) {
			return h( 'div', { className: 'se-sdk-loading' }, __( 'Loading…', 'storeengine-sdk' ) );
		}

		return h( 'div', { className: 'se-sdk-app' },
			toast && h( 'div', { className: 'se-sdk-toast se-sdk-toast-' + toast.kind }, toast.msg ),

			h( StatusHero, { state, onCheckNow: handleCheckNow, checking } ),

			h( UpdateBanner, { state, installing, installLog, onInstall: handleInstall } ),
			h( RollbackBanner, { state, installing, onRollback: handleInstall } ),

			! config.isFree && h( LicenseCard, {
				config,
				license: state.license || config.initialLicense,
				state,
				onActivate: handleActivate,
				onDeactivate: handleDeactivate,
				onCheckLicense: handleCheckLicense,
				busy: licenseBusy,
				error: licenseError,
			} ),

			h( VersionsTable, {
				versions,
				loading: versionsLoading,
				installing,
				onInstall: handleInstall,
				current: state.current_version,
				onRefresh: refreshVersions,
				refreshing: versionsLoading,
				error: versionsError,
			} ),

			h( SettingsCard, {
				state,
				onBeta: handleBeta,
				savingBeta,
			} )
		);
	}

	function boot() {
		const configs = Object.keys( window ).filter( ( k ) => k.indexOf( 'seSdkLicenseAppConfig_' ) === 0 );
		configs.forEach( ( key ) => {
			const config = window[ key ];
			const mount = document.getElementById( config.mountId );
			if ( ! mount ) return;
			render( h( App, { config } ), mount );
		} );
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', boot );
	} else {
		boot();
	}
}( window.wp ) );
