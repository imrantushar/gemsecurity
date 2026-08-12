import React from 'react';
import { __ } from '@wordpress/i18n';
import useSettingsForm from '@Utils/useSettingsForm';
import { Card, Toggle, Field, NumberInput, ListInput, Button } from '@Components/ui/Controls';
import { ProSection } from '@Components/ui/Pro';

const KEYS = [
	'antispam_enabled',
	'antispam_min_seconds',
	'antispam_heuristics',
	'antispam_max_links',
	'antispam_keywords',
];

export default function AntiSpam() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Silent bot protection', 'gemsecurity' ) }
				description={ __( 'A hidden honeypot plus a minimum time-on-page check stops automated comment and registration spam — with no puzzle for real visitors.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Enable silent anti-spam', 'gemsecurity' ) }
					description={ __( 'Applies to comment and registration forms.', 'gemsecurity' ) }
					checked={ form.antispam_enabled }
					onChange={ ( v ) => setField( 'antispam_enabled', v ) }
				/>
				{ form.antispam_enabled && (
					<Field label={ __( 'Minimum time before submit', 'gemsecurity' ) } suffix={ __( 'seconds', 'gemsecurity' ) } description={ __( 'Submissions faster than this are treated as bots.', 'gemsecurity' ) }>
						<NumberInput min="1" value={ form.antispam_min_seconds ?? 3 } onChange={ ( e ) => setField( 'antispam_min_seconds', Number( e.target.value ) ) } />
					</Field>
				) }
			</Card>

			<ProSection
				title={ __( 'Heuristic comment filtering', 'gemsecurity' ) }
				description={ __( 'Score comment content and auto-flag spam.', 'gemsecurity' ) }
			>
				<Card title={ __( 'Comment heuristics', 'gemsecurity' ) }>
					<Toggle
						label={ __( 'Auto-flag spammy comments', 'gemsecurity' ) }
						checked={ form.antispam_heuristics }
						onChange={ ( v ) => setField( 'antispam_heuristics', v ) }
					/>
					{ form.antispam_heuristics && (
						<>
							<Field label={ __( 'Max links before spam', 'gemsecurity' ) }>
								<NumberInput min="0" value={ form.antispam_max_links ?? 3 } onChange={ ( e ) => setField( 'antispam_max_links', Number( e.target.value ) ) } />
							</Field>
							<Field label={ __( 'Spam keywords', 'gemsecurity' ) } description={ __( 'One per line. A comment containing any of these is flagged. Your link blocklist is also checked.', 'gemsecurity' ) }>
								<ListInput value={ form.antispam_keywords || [] } onChange={ ( v ) => setField( 'antispam_keywords', v ) } placeholder={ 'viagra\ncasino\ncrypto giveaway' } />
							</Field>
						</>
					) }
				</Card>
			</ProSection>

			<div className="gs-savebar">
				<Button onClick={ () => save() } loading={ saving } disabled={ ! dirty }>
					{ __( 'Save changes', 'gemsecurity' ) }
				</Button>
			</div>
		</div>
	);
}
