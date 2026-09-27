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
	// Every comment control lives here now. `captcha_on_comments` was on the
	// CAPTCHA page and `comments_disabled` in the firewall's hardening list, so
	// deciding how comments are handled meant visiting three screens.
	'captcha_on_comments',
	'comments_disabled',
];

export default function AntiSpam() {
	const { form, setField, save, saving, dirty } = useSettingsForm( KEYS );

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Comments', 'gemsecurity' ) }
				description={ __( 'Comments are a common spam and malicious-content vector. If the site does not use them, closing them entirely removes the surface.', 'gemsecurity' ) }
			>
				<Toggle
					label={ __( 'Disable comments entirely', 'gemsecurity' ) }
					description={ __( 'Closes comments and pingbacks everywhere, hides existing ones and removes the comment UI. The rest of this page has no effect while this is on.', 'gemsecurity' ) }
					checked={ form.comments_disabled }
					onChange={ ( v ) => setField( 'comments_disabled', v ) }
				/>
			</Card>

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
				<Toggle
					label={ __( 'Also show a CAPTCHA on the comment form', 'gemsecurity' ) }
					description={ __( 'A visible challenge on top of the silent checks. Configure the provider on the CAPTCHA page; without one this does nothing.', 'gemsecurity' ) }
					checked={ form.captcha_on_comments }
					onChange={ ( v ) => setField( 'captcha_on_comments', v ) }
				/>
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
