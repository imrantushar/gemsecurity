<?php
namespace GemBackup\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class S3 extends S3_Base {

	public function __construct() {
		$this->access_key = (string) $this->setting( 's3_access_key', '' );
		$this->secret_key = (string) $this->setting( 's3_secret_key', '' );
		$this->bucket     = (string) $this->setting( 's3_bucket', '' );
		$this->region     = (string) $this->setting( 's3_region', 'us-east-1' );
		$this->folder     = trim( (string) $this->setting( 's3_folder', 'gembackup' ), '/' );
	}

	protected function get_endpoint() {
		return "https://{$this->bucket}.s3.{$this->region}.amazonaws.com";
	}
}
