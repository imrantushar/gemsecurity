import React, { useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import Icon from '@Components/ui/Icon';
import { Button } from '@Components/ui/Controls';

/**
 * "Test these credentials" button with an inline result.
 *
 * Third-party keys are the one setting where a typo is not inert — a wrong
 * CAPTCHA secret rejects every login, a wrong webhook drops alerts silently —
 * and the failure surfaces somewhere far away from this screen. This checks
 * the values against the real provider *before* they are saved, so `values`
 * is read from the live form rather than from stored settings.
 *
 * @param {string}   target    Tester id: captcha | social | slack | telegram | webhook | siem.
 * @param {Function} getValues Returns the current form values for the test.
 * @param {string}   label     Optional button label.
 */
export default function TestCredentials( { target, getValues, label } ) {
	const [ busy, setBusy ] = useState( false );
	const [ result, setResult ] = useState( null );

	const run = async () => {
		setBusy( true );
		setResult( null );
		try {
			const { data } = await api.post( 'credentials/test', {
				target,
				values: getValues(),
			} );
			setResult( {
				ok: !! data.ok,
				message: data.message,
				detail: data.detail,
			} );
		} catch ( e ) {
			setResult( {
				ok: false,
				message:
					e?.response?.data?.message ||
					__( 'The test could not be run.', 'gemsecurity' ),
			} );
		}
		setBusy( false );
	};

	return (
		<div className="gs-credtest">
			<Button variant="secondary" onClick={ run } loading={ busy }>
				<Icon name="check" size={ 15 } />
				{ label || __( 'Test credentials', 'gemsecurity' ) }
			</Button>

			{ result && (
				<div
					className={ `gs-credtest__result ${
						result.ok ? 'is-ok' : 'is-fail'
					}` }
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
