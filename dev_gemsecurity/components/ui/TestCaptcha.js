import React, { useCallback, useRef, useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import Icon from '@Components/ui/Icon';
import { Button } from '@Components/ui/Controls';

/**
 * End-to-end CAPTCHA key test.
 *
 * A wrong CAPTCHA secret rejects every login on the site, so these keys need
 * to be provable *before* they are saved. There is no server-side dry run:
 * Google and hCaptcha answer a dummy token with `invalid-input-response`
 * whether the secret is right or wrong, so only a real widget token proves
 * the pair. This renders the actual widget with the entered site key (a bad
 * site key fails right here, in the browser, exactly as it would on the login
 * form) and sends the resulting token to the server to be verified against the
 * secret.
 *
 * @param {string} provider  recaptcha_v2 | recaptcha_v3 | hcaptcha | turnstile
 * @param {string} siteKey   Site key from the form (unsaved).
 * @param {string} secretKey Secret key from the form (unsaved).
 */

/* Explicit-render script per provider. v3 needs the site key in the URL. */
const SCRIPT = {
	recaptcha_v2: () => 'https://www.google.com/recaptcha/api.js?render=explicit',
	recaptcha_v3: ( key ) =>
		`https://www.google.com/recaptcha/api.js?render=${ encodeURIComponent( key ) }`,
	hcaptcha: () => 'https://js.hcaptcha.com/1/api.js?render=explicit',
	turnstile: () => 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit',
};

/* The global each script exposes once loaded. */
const GLOBAL = {
	recaptcha_v2: 'grecaptcha',
	recaptcha_v3: 'grecaptcha',
	hcaptcha: 'hcaptcha',
	turnstile: 'turnstile',
};

/**
 * (Re)load a provider script. The previous tag and global are dropped first
 * because a v3 site key is baked into the URL, so switching keys has to fetch
 * a fresh copy rather than reuse the loaded one.
 */
function loadScript( provider, siteKey ) {
	return new Promise( ( resolve, reject ) => {
		document
			.querySelectorAll( 'script[data-gs-captcha]' )
			.forEach( ( el ) => el.remove() );
		delete window[ GLOBAL[ provider ] ];

		const script = document.createElement( 'script' );
		script.src = SCRIPT[ provider ]( siteKey );
		script.async = true;
		script.defer = true;
		script.setAttribute( 'data-gs-captcha', provider );
		script.onload = () => resolve();
		script.onerror = () =>
			reject(
				new Error(
					__(
						'The provider’s script could not be loaded — check the network and any content blockers.',
						'gemsecurity'
					)
				)
			);
		document.head.appendChild( script );
	} );
}

/** Wait for the provider global to appear (scripts init asynchronously). */
function waitForGlobal( provider, tries = 60 ) {
	return new Promise( ( resolve, reject ) => {
		const tick = ( left ) => {
			const api_ = window[ GLOBAL[ provider ] ];
			if ( api_ && ( api_.render || api_.execute || api_.ready ) ) {
				resolve( api_ );
				return;
			}
			if ( left <= 0 ) {
				reject( new Error( __( 'The provider’s script did not initialise.', 'gemsecurity' ) ) );
				return;
			}
			setTimeout( () => tick( left - 1 ), 100 );
		};
		tick( tries );
	} );
}

export default function TestCaptcha( { provider, siteKey, secretKey } ) {
	const [ state, setState ] = useState( 'idle' ); // idle | loading | waiting | done
	const [ result, setResult ] = useState( null );
	const box = useRef( null );

	const verify = useCallback(
		async ( token ) => {
			try {
				const { data } = await api.post( 'credentials/test', {
					target: 'captcha',
					values: {
						provider,
						site_key: siteKey,
						secret_key: secretKey,
						token,
					},
				} );
				setResult( { ok: !! data.ok, message: data.message, detail: data.detail } );
			} catch ( e ) {
				setResult( {
					ok: false,
					message:
						e?.response?.data?.message ||
						__( 'The test could not be run.', 'gemsecurity' ),
				} );
			}
			setState( 'done' );
		},
		[ provider, siteKey, secretKey ]
	);

	const fail = ( message ) => {
		setResult( { ok: false, message } );
		setState( 'done' );
	};

	const run = async () => {
		setResult( null );

		if ( ! siteKey || ! secretKey ) {
			setResult( {
				ok: false,
				message: __( 'Enter both the site key and the secret key first.', 'gemsecurity' ),
			} );
			setState( 'done' );
			return;
		}

		setState( 'loading' );
		if ( box.current ) {
			box.current.innerHTML = '';
		}

		try {
			await loadScript( provider, siteKey );
			const widget = await waitForGlobal( provider );

			// v3 is scored, not solved: ask for a token directly.
			if ( 'recaptcha_v3' === provider ) {
				setState( 'waiting' );
				widget.ready( () => {
					widget
						.execute( siteKey, { action: 'gemsecurity_test' } )
						.then( verify )
						.catch( () =>
							fail(
								__(
									'The provider rejected this site key.',
									'gemsecurity'
								)
							)
						);
				} );
				return;
			}

			setState( 'waiting' );
			widget.render( box.current, {
				sitekey: siteKey,
				callback: verify,
				'error-callback': () =>
					fail(
						__(
							'The provider rejected this site key for this domain.',
							'gemsecurity'
						)
					),
				'expired-callback': () =>
					fail( __( 'The challenge expired — run the test again.', 'gemsecurity' ) ),
			} );
		} catch ( e ) {
			// render() throws synchronously on a malformed site key.
			fail( e.message || __( 'The provider rejected this site key.', 'gemsecurity' ) );
		}
	};

	return (
		<div className="gs-credtest">
			<Button
				variant="secondary"
				onClick={ run }
				loading={ state === 'loading' }
				disabled={ state === 'waiting' }
			>
				<Icon name="check" size={ 15 } />
				{ __( 'Test CAPTCHA keys', 'gemsecurity' ) }
			</Button>

			{ state === 'waiting' && (
				<p className="gs-credtest__hint">
					{ 'recaptcha_v3' === provider
						? __( 'Requesting a token from the provider…', 'gemsecurity' )
						: __( 'Solve the challenge to finish the test.', 'gemsecurity' ) }
				</p>
			) }

			{ /* The provider renders its widget here. */ }
			<div ref={ box } className="gs-credtest__widget" />

			{ result && (
				<div
					className={ `gs-credtest__result ${ result.ok ? 'is-ok' : 'is-fail' }` }
					role="status"
				>
					<Icon name={ result.ok ? 'check' : 'alert' } size={ 15 } />
					<div>
						<strong>{ result.message }</strong>
						{ result.detail && (
							<span className="gs-credtest__detail">{ result.detail }</span>
						) }
					</div>
				</div>
			) }
		</div>
	);
}
