<?php
namespace GemBackup\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Driver_Factory {

	public static function make( $key ) {
		$map = [
			'local'     => Local::class,
			'gdrive'    => Gdrive::class,
			'dropbox'   => Dropbox::class,
			'onedrive'  => Onedrive::class,
			's3'        => S3::class,
			'r2'        => R2::class,
			'backblaze' => Backblaze::class,
			'ftp'       => Ftp::class,
		];

		$map = apply_filters( 'gembackup/driver_map', $map );

		if ( ! isset( $map[ $key ] ) ) {
			return new \WP_Error( 'gembackup_unknown_driver', 'Unknown storage driver: ' . $key );
		}

		$class = $map[ $key ];
		if ( ! class_exists( $class ) ) {
			return new \WP_Error( 'gembackup_missing_driver', 'Driver class missing: ' . $class );
		}

		return new $class();
	}
}
