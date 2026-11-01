const defaultConfig = require('@wordpress/scripts/config/webpack.config');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');
const webpack = require('webpack');
const path = require('path');

const isProduction = process.env.NODE_ENV !== 'development';

const GEMSECURITY_VERSION = '1.1.0';

/**
 * The uncompiled source each generated file is built from. Every entry is
 * dev_gemsecurity/<name>.js, which imports the .scss files its CSS is built from, so the
 * generated files map back onto their sources by name.
 */
const sourceOf = (filename, chunkName) =>
	filename.endsWith('.css')
		? `the .scss files imported by dev_gemsecurity/${chunkName}.js`
		: `dev_gemsecurity/${chunkName}.js`;

/**
 * Header on every generated file saying where its readable source is and how
 * to rebuild it (WordPress.org guideline 4). Added after minification, which
 * would strip it, and never to .asset.php, where it would print to the page.
 */
const sourceHeader = new webpack.BannerPlugin({
	banner: ({ filename, chunk }) =>
		[
			'GemSecurity - generated file, do not edit.',
			'',
			`Built from ${sourceOf(filename, chunk.name)}.`,
			'The complete uncompiled source ships in this plugin\'s dev_gemsecurity/',
			'folder and is public at https://github.com/imrantushar/gemsecurity.',
			'',
			'To rebuild this file, run the following in the plugin folder:',
			'  npm install',
			'  npm run build',
			'',
			'License: GPL-3.0-or-later',
		].join('\n'),
	test: /\.(js|css)$/,
	entryOnly: true,
	stage: webpack.Compilation.PROCESS_ASSETS_STAGE_ANALYSE,
});

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
	plugins: [...defaultConfig.plugins, new CleanWebpackPlugin(), ...(isProduction ? [sourceHeader] : [])],
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
