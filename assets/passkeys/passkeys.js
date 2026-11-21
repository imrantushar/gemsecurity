/* GemSecurity passkeys — WebAuthn client for wp-login.php and the profile screen. */
( function () {
	'use strict';

	var cfg = window.gemsecPasskeys;
	if ( ! cfg ) {
		return;
	}
	var t = cfg.i18n;

	function b64uToBuf( s ) {
		s = s.replace( /-/g, '+' ).replace( /_/g, '/' );
		while ( s.length % 4 ) {
			s += '=';
		}
		var bin = atob( s );
		var out = new Uint8Array( bin.length );
		for ( var i = 0; i < bin.length; i++ ) {
			out[ i ] = bin.charCodeAt( i );
		}
		return out.buffer;
	}

	function bufToB64u( buf ) {
		var bytes = new Uint8Array( buf );
		var s = '';
		for ( var i = 0; i < bytes.length; i++ ) {
			s += String.fromCharCode( bytes[ i ] );
		}
		return btoa( s ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
	}

	function api( method, path, body ) {
		var opts = {
			method: method,
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/json', 'X-WP-Nonce': cfg.nonce }
		};
		if ( body ) {
			opts.body = JSON.stringify( body );
		}
		return fetch( cfg.root + path, opts ).then( function ( r ) {
			return r.json().then( function ( data ) {
				if ( ! r.ok ) {
					var e = new Error( ( data && data.message ) || t.failed );
					e.status = r.status;
					throw e;
				}
				return data;
			} );
		} );
	}

	function supported() {
		return !! ( window.PublicKeyCredential && navigator.credentials && navigator.credentials.get );
	}

	function isCancel( err ) {
		return err && ( 'NotAllowedError' === err.name || 'AbortError' === err.name );
	}

	/* ------------------------------ Login ------------------------------ */

	function initLogin() {
		var box = document.getElementById( 'gemsec-passkey-login' );
		if ( ! box || ! supported() ) {
			return;
		}
		box.hidden = false;
		var btn = box.querySelector( '[data-gemsec-passkey-login]' );
		var msg = box.querySelector( '.gemsec-passkey-msg' );
		var controller = null;

		function say( text ) {
			msg.textContent = text || '';
		}

		function run( conditional ) {
			if ( controller ) {
				controller.abort();
			}
			controller = new AbortController();
			var signal = controller.signal;
			var token;
			say( '' );

			return api( 'POST', '/login/options' ).then( function ( opts ) {
				token = opts.token;
				var pk = opts.publicKey;
				var request = {
					publicKey: {
						challenge: b64uToBuf( pk.challenge ),
						rpId: pk.rpId,
						timeout: pk.timeout,
						userVerification: pk.userVerification,
						allowCredentials: []
					},
					signal: signal
				};
				if ( conditional ) {
					request.mediation = 'conditional';
				}
				return navigator.credentials.get( request );
			} ).then( function ( cred ) {
				var r = cred.response;
				var form = document.getElementById( 'loginform' );
				var remember = form && form.querySelector( '#rememberme' ) ? form.querySelector( '#rememberme' ).checked : false;
				var redirect = form && form.querySelector( 'input[name="redirect_to"]' ) ? form.querySelector( 'input[name="redirect_to"]' ).value : '';
				return api( 'POST', '/login/verify', {
					token: token,
					id: cred.id,
					clientDataJSON: bufToB64u( r.clientDataJSON ),
					authenticatorData: bufToB64u( r.authenticatorData ),
					signature: bufToB64u( r.signature ),
					userHandle: r.userHandle ? bufToB64u( r.userHandle ) : '',
					remember: remember,
					redirect_to: redirect
				} );
			} ).then( function ( res ) {
				window.location.assign( res.redirect );
			} ).catch( function ( err ) {
				if ( isCancel( err ) ) {
					if ( ! conditional ) {
						say( t.cancelled );
					}
					return;
				}
				say( err.message || t.failed );
			} );
		}

		btn.addEventListener( 'click', function () {
			run( false );
		} );

		// Offer saved passkeys in the browser's autofill list as well.
		if ( window.PublicKeyCredential.isConditionalMediationAvailable ) {
			window.PublicKeyCredential.isConditionalMediationAvailable().then( function ( ok ) {
				if ( ! ok ) {
					return;
				}
				var user = document.getElementById( 'user_login' );
				if ( user ) {
					user.setAttribute( 'autocomplete', 'username webauthn' );
				}
				run( true );
			} );
		}
	}

	/* ----------------------------- Profile ----------------------------- */

	function initProfile() {
		var root = document.getElementById( 'gemsec-passkeys-profile' );
		if ( ! root ) {
			return;
		}
		var list = root.querySelector( 'ul' );
		var add = root.querySelector( '[data-gemsec-passkey-add]' );
		var msg = root.querySelector( '.msg' );

		if ( ! supported() ) {
			add.disabled = true;
			msg.textContent = t.unsupported;
		}

		function say( text, bad ) {
			msg.textContent = text || '';
			msg.style.color = bad ? '#b32d2e' : '';
		}

		function fmt( iso ) {
			return iso ? new Date( iso ).toLocaleString() : t.never;
		}

		function render( items ) {
			list.textContent = '';
			if ( ! items.length ) {
				var empty = document.createElement( 'li' );
				empty.textContent = t.none;
				list.appendChild( empty );
				return;
			}
			items.forEach( function ( p ) {
				var li = document.createElement( 'li' );
				var info = document.createElement( 'div' );
				var name = document.createElement( 'strong' );
				name.textContent = p.name;
				var meta = document.createElement( 'div' );
				meta.className = 'meta';
				meta.textContent = ( p.synced ? t.synced : t.device ) + ' · ' + t.created + ' ' + fmt( p.created_at ) + ' · ' + t.lastUsed + ' ' + fmt( p.last_used_at );
				info.appendChild( name );
				info.appendChild( meta );

				var actions = document.createElement( 'div' );
				var rn = document.createElement( 'button' );
				rn.type = 'button';
				rn.className = 'button button-small';
				rn.textContent = t.rename;
				rn.addEventListener( 'click', function () {
					var v = window.prompt( t.namePrompt, p.name );
					if ( v && v.trim() ) {
						api( 'POST', '/' + p.id, { name: v.trim() } ).then( function ( r ) {
							render( r.passkeys );
						} ).catch( function ( e ) {
							say( e.message, true );
						} );
					}
				} );
				var rm = document.createElement( 'button' );
				rm.type = 'button';
				rm.className = 'button button-small button-link-delete';
				rm.textContent = t.remove;
				rm.addEventListener( 'click', function () {
					if ( window.confirm( t.confirm ) ) {
						api( 'DELETE', '/' + p.id ).then( function ( r ) {
							render( r.passkeys );
						} ).catch( function ( e ) {
							say( e.message, true );
						} );
					}
				} );
				actions.appendChild( rn );
				actions.appendChild( document.createTextNode( ' ' ) );
				actions.appendChild( rm );

				li.appendChild( info );
				li.appendChild( actions );
				list.appendChild( li );
			} );
		}

		add.addEventListener( 'click', function () {
			say( '' );
			var token;
			add.disabled = true;
			api( 'POST', '/register/options' ).then( function ( opts ) {
				token = opts.token;
				var pk = opts.publicKey;
				pk.challenge = b64uToBuf( pk.challenge );
				pk.user.id = b64uToBuf( pk.user.id );
				pk.excludeCredentials = ( pk.excludeCredentials || [] ).map( function ( c ) {
					return { type: c.type, id: b64uToBuf( c.id ) };
				} );
				return navigator.credentials.create( { publicKey: pk } );
			} ).then( function ( cred ) {
				var r = cred.response;
				return api( 'POST', '/register/verify', {
					token: token,
					clientDataJSON: bufToB64u( r.clientDataJSON ),
					attestationObject: bufToB64u( r.attestationObject ),
					transports: r.getTransports ? r.getTransports() : []
				} );
			} ).then( function ( res ) {
				render( res.passkeys );
				say( t.added );
			} ).catch( function ( err ) {
				say( isCancel( err ) ? t.cancelled : ( err.message || t.failed ), true );
			} ).then( function () {
				add.disabled = ! supported();
			} );
		} );

		api( 'GET', '' ).then( function ( r ) {
			render( r.passkeys );
		} ).catch( function ( e ) {
			say( e.message, true );
		} );
	}

	if ( 'login' === cfg.mode ) {
		initLogin();
	} else if ( 'profile' === cfg.mode ) {
		initProfile();
	}
}() );
