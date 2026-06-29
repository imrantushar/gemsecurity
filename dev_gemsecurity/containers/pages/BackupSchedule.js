import React, { useState, useEffect, useCallback } from 'react';
import { __ } from '@wordpress/i18n';
import backupApi from '@Utils/backupApi';
import { useToast } from '@Components/ui/Toast';
import { Card, Button, Field, Select, TextInput, Badge, EmptyState, Loading } from '@Components/ui/Controls';
import { isPro, ProBadge } from '@Components/ui/Pro';

export default function BackupSchedule() {
	const toast = useToast();
	const pro = isPro();

	const [ items, setItems ] = useState( null );
	const [ form, setForm ] = useState( { schedule_name: 'Daily backup', backup_type: 'full', frequency: 'daily', run_time: '02:00' } );
	const [ busy, setBusy ] = useState( '' );

	const load = useCallback( async () => {
		try {
			const { data } = await backupApi.get( 'schedules' );
			setItems( data.items || [] );
		} catch ( e ) {
			setItems( [] );
		}
	}, [] );

	useEffect( () => {
		load();
	}, [ load ] );

	const set = ( k, v ) => setForm( ( f ) => ( { ...f, [ k ]: v } ) );

	const create = async () => {
		setBusy( 'create' );
		try {
			await backupApi.post( 'schedules', { ...form, storage_drivers: [ 'local' ] } );
			toast( __( 'Schedule created.', 'gemsecurity' ), 'success' );
			load();
		} catch ( e ) {
			const msg = e?.response?.data?.message;
			toast( msg || __( 'Could not create the schedule.', 'gemsecurity' ), 'error' );
		}
		setBusy( '' );
	};

	const toggle = async ( id ) => {
		setBusy( `t${ id }` );
		try {
			await backupApi.post( `schedules/${ id }/toggle`, {} );
			load();
		} catch ( e ) { /* ignore */ }
		setBusy( '' );
	};

	const remove = async ( id ) => {
		setBusy( `d${ id }` );
		try {
			await backupApi.delete( `schedules/${ id }` );
			setItems( ( l ) => l.filter( ( s ) => s.id !== id ) );
		} catch ( e ) { /* ignore */ }
		setBusy( '' );
	};

	if ( items === null ) {
		return <div className="gs-page"><Loading /></div>;
	}

	const atFreeLimit = ! pro && items.length >= 1;

	const freqOptions = [
		{ value: 'daily', label: __( 'Daily', 'gemsecurity' ) },
		{ value: 'weekly', label: pro ? __( 'Weekly', 'gemsecurity' ) : __( 'Weekly (Pro)', 'gemsecurity' ) },
		{ value: 'monthly', label: pro ? __( 'Monthly', 'gemsecurity' ) : __( 'Monthly (Pro)', 'gemsecurity' ) },
	];

	return (
		<div className="gs-page">
			<Card title={ __( 'Scheduled backups', 'gemsecurity' ) }>
				{ items.length === 0 ? (
					<EmptyState title={ __( 'No schedules yet.', 'gemsecurity' ) } description={ __( 'Create an automatic backup schedule below.', 'gemsecurity' ) } />
				) : (
					<table className="gs-table">
						<thead>
							<tr><th>{ __( 'Name', 'gemsecurity' ) }</th><th>{ __( 'Type', 'gemsecurity' ) }</th><th>{ __( 'Frequency', 'gemsecurity' ) }</th><th>{ __( 'Next run', 'gemsecurity' ) }</th><th></th></tr>
						</thead>
						<tbody>
							{ items.map( ( s ) => (
								<tr key={ s.id }>
									<td>{ s.schedule_name }</td>
									<td style={ { textTransform: 'capitalize' } }>{ s.backup_type }</td>
									<td style={ { textTransform: 'capitalize' } }>{ s.frequency } @ { s.run_time }</td>
									<td>
										<Badge tone={ s.status === 'active' ? 'success' : 'info' }>{ s.status }</Badge>
										<div style={ { color: '#6b7385', fontSize: 11 } }>{ s.next_run }</div>
									</td>
									<td style={ { textAlign: 'right', whiteSpace: 'nowrap' } }>
										<Button variant="secondary" loading={ busy === `t${ s.id }` } onClick={ () => toggle( s.id ) }>{ s.status === 'active' ? __( 'Pause', 'gemsecurity' ) : __( 'Activate', 'gemsecurity' ) }</Button>
										{ ' ' }
										<Button variant="danger" loading={ busy === `d${ s.id }` } onClick={ () => remove( s.id ) }>{ __( 'Delete', 'gemsecurity' ) }</Button>
									</td>
								</tr>
							) ) }
						</tbody>
					</table>
				) }
			</Card>

			<Card
				title={ <span>{ __( 'New schedule', 'gemsecurity' ) } { ! pro && <ProBadge /> }</span> }
				description={ pro ? __( 'Multiple schedules, cloud destinations and weekly/monthly frequency.', 'gemsecurity' ) : __( 'Free includes a single daily local schedule. Upgrade for more frequencies, multiple schedules and cloud.', 'gemsecurity' ) }
				actions={
					<Button loading={ busy === 'create' } disabled={ atFreeLimit } onClick={ create }>
						{ __( 'Create schedule', 'gemsecurity' ) }
					</Button>
				}
			>
				{ atFreeLimit && (
					<p className="gs-card__desc">{ __( 'Free is limited to one schedule. Upgrade to Pro to add more.', 'gemsecurity' ) }</p>
				) }
				<Field label={ __( 'Name', 'gemsecurity' ) }>
					<TextInput value={ form.schedule_name } onChange={ ( e ) => set( 'schedule_name', e.target.value ) } />
				</Field>
				<Field label={ __( 'What to back up', 'gemsecurity' ) }>
					<Select
						options={ [ { value: 'full', label: __( 'Full site', 'gemsecurity' ) }, { value: 'database', label: __( 'Database', 'gemsecurity' ) }, { value: 'files', label: __( 'Files', 'gemsecurity' ) } ] }
						value={ form.backup_type } onChange={ ( e ) => set( 'backup_type', e.target.value ) }
					/>
				</Field>
				<Field label={ __( 'Frequency', 'gemsecurity' ) }>
					<Select options={ freqOptions } value={ form.frequency } onChange={ ( e ) => set( 'frequency', pro ? e.target.value : 'daily' ) } />
				</Field>
				<Field label={ __( 'Run at', 'gemsecurity' ) }>
					<TextInput value={ form.run_time } onChange={ ( e ) => set( 'run_time', e.target.value ) } placeholder="02:00" />
				</Field>
			</Card>
		</div>
	);
}
