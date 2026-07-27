import React, { useState } from 'react';
import { __ } from '@wordpress/i18n';
import api from '@Utils/api';
import { Card, Toggle, Button, Badge, EmptyState, TextInput } from '@Components/ui/Controls';
import Icon from '@Components/ui/Icon';
import { useToast } from '@Components/ui/Toast';

/**
 * Code & database search — "grep from the dashboard". Read-only: finds where a
 * string lives across wp-content files and the database, for incident response.
 */
export default function SearchPanel() {
	const toast = useToast();
	const [ term, setTerm ] = useState( '' );
	const [ regex, setRegex ] = useState( false );
	const [ files, setFiles ] = useState( true );
	const [ database, setDatabase ] = useState( true );
	const [ result, setResult ] = useState( null );
	const [ busy, setBusy ] = useState( false );

	const run = async () => {
		if ( term.trim().length < 2 ) {
			toast( __( 'Enter at least 2 characters to search.', 'gemsecurity' ), 'warning' );
			return;
		}
		const scope = [];
		if ( files ) {
			scope.push( 'files' );
		}
		if ( database ) {
			scope.push( 'database' );
		}
		if ( ! scope.length ) {
			toast( __( 'Pick at least one place to search.', 'gemsecurity' ), 'warning' );
			return;
		}
		setBusy( true );
		try {
			const r = await api.post( 'search', { term, regex, scope } );
			setResult( r.data.result );
		} catch ( e ) {
			const msg = e && e.response && e.response.data && e.response.data.message;
			toast( msg || __( 'Search failed.', 'gemsecurity' ), 'error' );
		}
		setBusy( false );
	};

	const onKeyDown = ( e ) => {
		if ( e.key === 'Enter' ) {
			run();
		}
	};

	const codeCell = { fontSize: 11, whiteSpace: 'pre-wrap', wordBreak: 'break-all' };

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Search files & database', 'gemsecurity' ) }
				description={ __( 'Grep your whole site from here — find where a string lives across all wp-content files and the database (options, posts, meta, comments). Handy for tracking down an injected domain, base64_decode, eval, and the like. Read-only; nothing is changed.', 'gemsecurity' ) }
			>
				<div className="gs-search-bar">
					<TextInput
						type="text"
						value={ term }
						placeholder={ __( 'e.g. chickenroad.de   or   base64_decode', 'gemsecurity' ) }
						onChange={ ( e ) => setTerm( e.target.value ) }
						onKeyDown={ onKeyDown }
					/>
					<Button onClick={ run } loading={ busy }>
						<Icon name="radar" size={ 16 } /> { __( 'Search', 'gemsecurity' ) }
					</Button>
				</div>
				<div className="gs-search-opts">
					<Toggle label={ __( 'Files (wp-content)', 'gemsecurity' ) } checked={ files } onChange={ setFiles } />
					<Toggle label={ __( 'Database', 'gemsecurity' ) } checked={ database } onChange={ setDatabase } />
					<Toggle label={ __( 'Regular expression', 'gemsecurity' ) } checked={ regex } onChange={ setRegex } />
				</div>
			</Card>

			{ result && (
				<>
					<Card>
						<div className="gs-scan-summary">
							<Badge tone={ ( result.file_count + result.db_count ) ? 'warning' : 'success' }>
								{ ( result.file_count + result.db_count )
									? `${ result.file_count + result.db_count } ${ __( 'match(es)', 'gemsecurity' ) }`
									: __( 'No matches', 'gemsecurity' ) }
							</Badge>
							<span className="gs-muted">
								{ `${ result.file_count } ${ __( 'in files', 'gemsecurity' ) } · ${ result.db_count } ${ __( 'in database', 'gemsecurity' ) } · ${ result.files_scanned } ${ __( 'files scanned', 'gemsecurity' ) }` }
							</span>
						</div>
						{ result.truncated && (
							<div className="gs-alert gs-alert--warning">
								<Icon name="alert" size={ 18 } />
								<span>{ __( 'Results were capped. Must-use plugins, the active theme and drop-ins are always searched first, so injected code is still surfaced — narrow the term for the rest.', 'gemsecurity' ) }</span>
							</div>
						) }
					</Card>

					{ result.file_matches.length > 0 && (
						<Card title={ __( 'File matches', 'gemsecurity' ) }>
							<table className="gs-table">
								<thead><tr>
									<th>{ __( 'File', 'gemsecurity' ) }</th>
									<th>{ __( 'Line', 'gemsecurity' ) }</th>
									<th>{ __( 'Match', 'gemsecurity' ) }</th>
								</tr></thead>
								<tbody>
									{ result.file_matches.map( ( m, i ) => (
										<tr key={ i }>
											<td><code>{ m.file }</code></td>
											<td className="gs-nowrap">{ m.line }</td>
											<td><code style={ codeCell }>{ m.snippet }</code></td>
										</tr>
									) ) }
								</tbody>
							</table>
						</Card>
					) }

					{ result.db_matches.length > 0 && (
						<Card title={ __( 'Database matches', 'gemsecurity' ) }>
							<table className="gs-table">
								<thead><tr>
									<th>{ __( 'Table', 'gemsecurity' ) }</th>
									<th>{ __( 'Row', 'gemsecurity' ) }</th>
									<th>{ __( 'Match', 'gemsecurity' ) }</th>
								</tr></thead>
								<tbody>
									{ result.db_matches.map( ( m, i ) => (
										<tr key={ i }>
											<td><code>{ m.source }</code></td>
											<td className="gs-nowrap">#{ m.id }{ m.ref ? ` · ${ m.ref }` : '' }</td>
											<td><code style={ codeCell }>{ m.snippet }</code></td>
										</tr>
									) ) }
								</tbody>
							</table>
						</Card>
					) }

					{ result.file_matches.length === 0 && result.db_matches.length === 0 && (
						<Card>
							<EmptyState
								title={ __( 'No matches', 'gemsecurity' ) }
								description={ __( 'Nothing in your files or database matched that term.', 'gemsecurity' ) }
							/>
						</Card>
					) }
				</>
			) }
		</div>
	);
}
