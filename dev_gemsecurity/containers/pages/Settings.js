import React from 'react';
import { __ } from '@wordpress/i18n';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Field, NumberInput, Button } from '@Components/ui/Controls';

const KEYS = [ 'logs_retention_days' ];

export default function Settings() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );

	return (
		<div className="gs-page">
			<Card
				title={ __( 'General settings', 'gemsecurity' ) }
				description={ __( 'Plugin-wide preferences. Firewall, login and admin options live on their own pages.', 'gemsecurity' ) }
			>
				<Field
					label={ __( 'Log retention', 'gemsecurity' ) }
					suffix={ __( 'days', 'gemsecurity' ) }
					description={ __( 'Activity log entries older than this are pruned daily. Set to 0 to keep them forever.', 'gemsecurity' ) }
				>
					<NumberInput
						min="0"
						value={ form.logs_retention_days ?? 30 }
						onChange={ ( e ) => setField( 'logs_retention_days', Number( e.target.value ) ) }
					/>
				</Field>
			</Card>

			<div className="gs-savebar">
				<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>
					{ __( 'Save changes', 'gemsecurity' ) }
				</Button>
			</div>
		</div>
	);
}
