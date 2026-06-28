import { configureStore } from '@reduxjs/toolkit';
import settings from '@Redux/settingsSlice';

const store = configureStore( {
	reducer: {
		settings,
	},
} );

export default store;
