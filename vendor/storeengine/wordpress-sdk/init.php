<?php
/**
 * StoreEngine License Management Client SDK.
 *
 * Copyright (c) 2025, KodeZen. (https://kodezen.com/contact-us/)
 * Portions copyright (c) 2019 Automattic, Inc. (https://automattic.com/contact/)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * @package StoreEngine\LicenseManagementClientSDK
 */

declare( strict_types=1 );

if ( ! function_exists( 'se_license_manager_register_1_dot_5_dot_2' ) && function_exists( 'add_action' ) ) { // WRCS: DEFINED_VERSION.

	if ( ! class_exists( 'SE_License_SDK_Version_Manager', false ) ) {
		require_once __DIR__ . '/classes/SE_License_SDK_Version_Manager.php';
		add_action( 'plugins_loaded', [ 'SE_License_SDK_Version_Manager', 'initialize_latest_version' ], 1, 0 );
	}

	add_action( 'plugins_loaded', 'se_license_manager_register_1_dot_5_dot_2', 0, 0 ); // WRCS: DEFINED_VERSION.

	// phpcs:disable Generic.Functions.OpeningFunctionBraceKernighanRitchie.ContentAfterBrace
	/**
	 * Registers this version of SE_License_SDK.
	 */
	function se_license_manager_register_1_dot_5_dot_2() { // WRCS: DEFINED_VERSION.
		$versions = SE_License_SDK_Version_Manager::instance();
		$versions->register( '1.5.2', 'se_license_manager_initialize_1_dot_5_dot_2' ); // WRCS: DEFINED_VERSION.
	}

	// phpcs:disable Generic.Functions.OpeningFunctionBraceKernighanRitchie.ContentAfterBrace
	/**
	 * Initializes this version of Action Scheduler.
	 */
	function se_license_manager_initialize_1_dot_5_dot_2() { // WRCS: DEFINED_VERSION.
		// A final safety check is required even here, because historic versions of Action Scheduler
		// followed a different pattern. (In some unusual cases, we could reach this point and the
		// SE_License_SDK class is already defined—so we need to guard against that.)
		if ( ! class_exists( 'SE_License_SDK', false ) ) {
			require_once __DIR__ . '/classes/abstracts/SE_License_SDK.php';
			SE_License_SDK::init( __FILE__, '1.5.2' );
		}
	}

	// Support usage in themes - load this version if no plugin has loaded a version yet.
	if ( did_action( 'plugins_loaded' ) && ! doing_action( 'plugins_loaded' ) && ! class_exists( 'SE_License_SDK', false ) ) {
		se_license_manager_initialize_1_dot_5_dot_2(); // WRCS: DEFINED_VERSION.
		do_action( 'action_scheduler_pre_theme_init' );
		SE_License_SDK_Version_Manager::initialize_latest_version();
	}
}

// End of file init.php.