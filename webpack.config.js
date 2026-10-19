const defaultConfig = require('@wordpress/scripts/config/webpack.config');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');
const path = require('path');

const GEMSECURITY_VERSION = '1.1.0';

const config = {
	...defaultConfig,
	entry: {
		backend: path.resolve(__dirname, 'dev_gemsecurity/backend.js'),
		setup: path.resolve(__dirname, 'dev_gemsecurity/setup.js'),
	},
	output: {
		filename: `[name].${GEMSECURITY_VERSION}.js`,
		path: path.resolve(__dirname, 'assets/build'),
	},
	plugins: [...defaultConfig.plugins, new CleanWebpackPlugin()],
	resolve: {
		alias: {
			...defaultConfig.resolve.alias,
			'@Components': path.resolve(__dirname, 'dev_gemsecurity/components/'),
			'@Containers': path.resolve(__dirname, 'dev_gemsecurity/containers/'),
			'@Global':     path.resolve(__dirname, 'dev_gemsecurity/global/'),
			'@Redux':      path.resolve(__dirname, 'dev_gemsecurity/redux/'),
			'@Utils':      path.resolve(__dirname, 'dev_gemsecurity/utils/'),
		},
	},
};

module.exports = config;
