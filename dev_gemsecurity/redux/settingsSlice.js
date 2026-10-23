import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '@Utils/api';
import { refreshScoreTips } from '@Components/ui/PageScoreTips';

export const fetchSettings = createAsyncThunk( 'settings/fetch', async () => {
	const { data } = await api.get( 'settings' );
	return data.settings;
} );

/**
 * @param {Object} partial Settings to change.
 * @param {string} [source] How: 'save' | 'instant' | 'quick_fix' | 'undo' — for the audit log.
 */
export const saveSettings = createAsyncThunk( 'settings/save', async ( { settings, source = 'save' } ) => {
	const { data } = await api.post( 'settings', { settings, source } );
	// Any toggle change could move the score — invalidate the in-page tips
	// cache so the next route change pulls a fresh assessment.
	refreshScoreTips();
	return data.settings;
} );

const settingsSlice = createSlice( {
	name: 'settings',
	initialState: {
		data: null,
		loading: false,
		saving: false,
		error: null,
	},
	reducers: {
		// Optimistic local edit before saving.
		setField: ( state, action ) => {
			if ( ! state.data ) {
				state.data = {};
			}
			state.data[ action.payload.key ] = action.payload.value;
		},
		setFields: ( state, action ) => {
			state.data = { ...( state.data || {} ), ...action.payload };
		},
	},
	extraReducers: ( builder ) => {
		builder
			.addCase( fetchSettings.pending, ( state ) => {
				state.loading = true;
				state.error = null;
			} )
			.addCase( fetchSettings.fulfilled, ( state, action ) => {
				state.loading = false;
				state.data = action.payload;
			} )
			.addCase( fetchSettings.rejected, ( state, action ) => {
				state.loading = false;
				state.error = action.error.message;
			} )
			.addCase( saveSettings.pending, ( state ) => {
				state.saving = true;
			} )
			.addCase( saveSettings.fulfilled, ( state, action ) => {
				state.saving = false;
				state.data = action.payload;
			} )
			.addCase( saveSettings.rejected, ( state, action ) => {
				state.saving = false;
				state.error = action.error.message;
			} );
	},
} );

export const { setField, setFields } = settingsSlice.actions;
export default settingsSlice.reducer;
