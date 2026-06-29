import React, { useRef, useState } from 'react';
import { __ } from '@wordpress/i18n';
import { useDispatch } from 'react-redux';
import { Card, Field, Button } from '@Components/ui/Controls';
import { useToast } from '@Components/ui/Toast';
import { fetchSettings } from '@Redux/settingsSlice';
import api from '@Utils/api';

function formatBytes( bytes ) {
	if ( bytes < 1024 ) {
		return bytes + ' B';
	}
	return ( bytes / 1024 ).toFixed( 1 ) + ' KB';
}

export default function Transfer() {
	const dispatch = useDispatch();
	const toast = useToast();
	const fileRef = useRef( null );

	const [ exporting, setExporting ] = useState( false );
	const [ importing, setImporting ] = useState( false );
	const [ selectedFile, setSelectedFile ] = useState( null );
	const [ importError, setImportError ] = useState( null );

	const handleExport = async () => {
		setExporting( true );
		try {
			const { data } = await api.get( 'settings/export' );
			const blob = new Blob( [ JSON.stringify( data, null, 2 ) ], { type: 'application/json' } );
			const a = document.createElement( 'a' );
			a.href = URL.createObjectURL( blob );
			a.download = `gemsecurity-settings-${ new Date().toISOString().slice( 0, 10 ) }.json`;
			a.click();
			URL.revokeObjectURL( a.href );
			toast( __( 'Settings exported.', 'gemsecurity' ), 'success' );
		} catch ( err ) {
			toast( __( 'Export failed.', 'gemsecurity' ), 'error' );
		} finally {
			setExporting( false );
		}
	};

	const handleFileChange = ( e ) => {
		const file = e.target.files?.[ 0 ] || null;
		setSelectedFile( file );
		setImportError( null );
	};

	const handleImport = async () => {
		if ( ! selectedFile ) {
			return;
		}
		setImporting( true );
		setImportError( null );
		try {
			const text = await selectedFile.text();
			let parsed;
			try {
				parsed = JSON.parse( text );
			} catch {
				setImportError( __( 'The selected file is not valid JSON.', 'gemsecurity' ) );
				return;
			}
			await api.post( 'settings/import', parsed );
			dispatch( fetchSettings() );
			setSelectedFile( null );
			if ( fileRef.current ) {
				fileRef.current.value = '';
			}
			toast( __( 'Settings imported successfully.', 'gemsecurity' ), 'success' );
		} catch ( err ) {
			const msg =
				err?.response?.data?.message ||
				err?.response?.data?.code ||
				__( 'Import failed. Please check the file and try again.', 'gemsecurity' );
			setImportError( msg );
		} finally {
			setImporting( false );
		}
	};

	return (
		<div className="gs-page">
			<Card
				title={ __( 'Export settings', 'gemsecurity' ) }
				description={ __( 'Download all GemSecurity settings as a JSON file. Use it to quickly configure other sites.', 'gemsecurity' ) }
			>
				<div className="gs-notice gs-notice--warning" style={ { marginBottom: '1rem' } }>
					<strong>{ __( 'Security notice:', 'gemsecurity' ) }</strong>{ ' ' }
					{ __( 'The exported file may contain sensitive values such as OAuth client secrets, CAPTCHA keys, and alert webhook tokens. Store it securely and do not share it publicly.', 'gemsecurity' ) }
				</div>
				<Button onClick={ handleExport } loading={ exporting }>
					{ __( 'Download settings file', 'gemsecurity' ) }
				</Button>
			</Card>

			<Card
				title={ __( 'Import settings', 'gemsecurity' ) }
				description={ __( 'Upload a settings file exported from another GemSecurity installation. Imported values are merged with existing settings.', 'gemsecurity' ) }
			>
				<Field label={ __( 'Settings file (.json)', 'gemsecurity' ) }>
					<input
						ref={ fileRef }
						type="file"
						accept=".json,application/json"
						onChange={ handleFileChange }
						style={ { display: 'block', marginTop: '4px' } }
					/>
				</Field>

				{ selectedFile && (
					<p style={ { marginTop: '0.5rem', color: '#666', fontSize: '0.875rem' } }>
						{ __( 'Selected:', 'gemsecurity' ) }{ ' ' }
						<strong>{ selectedFile.name }</strong>{ ' ' }
						({ formatBytes( selectedFile.size ) })
					</p>
				) }

				{ importError && (
					<div className="gs-notice gs-notice--error" style={ { marginTop: '0.75rem' } }>
						{ importError }
					</div>
				) }

				<div style={ { marginTop: '1rem' } }>
					<Button
						onClick={ handleImport }
						loading={ importing }
						disabled={ ! selectedFile || importing }
					>
						{ __( 'Apply import', 'gemsecurity' ) }
					</Button>
				</div>
			</Card>
		</div>
	);
}
