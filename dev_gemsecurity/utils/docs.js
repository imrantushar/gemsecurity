import { useEffect, useState } from 'react';
import api from '@Utils/api';

/**
 * In-product documentation, fetched once and shared by every consumer.
 *
 * Two layers come back from the same request:
 *  - `docs`   — a per-module guide, keyed by page slug, for the help drawer.
 *  - `guides` — per-field setup instructions, keyed by guide id, rendered
 *               inline next to the fields they describe.
 *
 * Both come from PHP (Modules\Docs), so they are translatable and add-ons can
 * extend them. They are deliberately *not* localized into the page payload —
 * the text is long, only a fraction of it is ever read, and it never changes
 * mid-session, so one lazy request beats shipping it on every admin page load.
 */
let cache = null;
let inflight = null;

export function fetchDocs() {
	if ( cache ) {
		return Promise.resolve( cache );
	}
	if ( ! inflight ) {
		inflight = api
			.get( 'docs' )
			.then( ( r ) => {
				cache = {
					docs: r.data?.docs || {},
					guides: r.data?.guides || {},
				};
				return cache;
			} )
			.catch( () => {
				inflight = null; // Allow a retry the next time something asks.
				return { docs: {}, guides: {} };
			} );
	}
	return inflight;
}

/** Shared loader: resolves the whole payload once per session. */
function usePayload( enabled ) {
	const [ payload, setPayload ] = useState( cache );

	useEffect( () => {
		if ( ! enabled || payload ) {
			return;
		}
		let alive = true;
		fetchDocs().then( ( p ) => alive && setPayload( p ) );
		return () => {
			alive = false;
		};
	}, [ enabled, payload ] );

	return payload;
}

/**
 * Module guide for one page slug. Returns `{ doc, loading }`; `doc` is null
 * while loading and when the page has no guide.
 *
 * @param {string}  slug    Page slug, e.g. "gemsecurity-firewall".
 * @param {boolean} enabled Skip the request until the drawer is opened.
 */
export function useDoc( slug, enabled = true ) {
	const payload = usePayload( enabled );
	return {
		doc: payload ? payload.docs[ slug ] || null : null,
		loading: enabled && ! payload,
	};
}

/**
 * Field-level setup guide by id, e.g. "social.google". Null until loaded, and
 * null for an id with no guide — callers render nothing in both cases.
 *
 * @param {string} id Guide id.
 */
export function useGuide( id ) {
	const payload = usePayload( !! id );
	return payload && id ? payload.guides[ id ] || null : null;
}
