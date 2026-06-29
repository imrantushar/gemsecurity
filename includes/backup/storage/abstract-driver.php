<?php
namespace GemBackup\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class AbstractDriver {

	/**
	 * Upload a local file to the storage destination.
	 *
	 * @param string $local_path  Absolute path to the local file.
	 * @param string $remote_name Desired filename/path at the destination.
	 * @return bool|\WP_Error True on success, WP_Error on failure.
	 */
	abstract public function upload( $local_path, $remote_name );

	/**
	 * Delete a file from the storage destination.
	 *
	 * @param string $remote_name
	 * @return bool|\WP_Error
	 */
	abstract public function delete( $remote_name );

	/**
	 * List files in the storage destination.
	 *
	 * @return array|\WP_Error Array of file info arrays on success.
	 */
	abstract public function list_files();

	/**
	 * Test the connection / credentials for this driver.
	 *
	 * @return bool|\WP_Error
	 */
	abstract public function test_connection();

	/**
	 * Download a remote file to a local path (default: not supported).
	 *
	 * @param string $remote_name
	 * @param string $local_path
	 * @return bool|\WP_Error
	 */
	public function download( $remote_name, $local_path ) {
		return new \WP_Error( 'gembackup_no_download', 'This driver does not support download yet.' );
	}

	/**
	 * Helper — read a setting value for this driver.
	 *
	 * @param string $key
	 * @param mixed  $default
	 * @return mixed
	 */
	protected function setting( $key, $default = null ) {
		return \GemBackup\Helper::get_setting( $key, $default );
	}
}
