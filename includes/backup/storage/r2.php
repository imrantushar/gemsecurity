<?php
namespace GemBackup\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class R2 extends S3_Base {

	private $account_id;

	public function __construct() {
		$this->account_id = (string) $this->setting( 'r2_account_id', '' );
		$this->access_key = (string) $this->setting( 'r2_access_key', '' );
		$this->secret_key = (string) $this->setting( 'r2_secret_key', '' );
		$this->bucket     = (string) $this->setting( 'r2_bucket', '' );
		$this->region     = 'auto';
		$this->folder     = trim( (string) $this->setting( 'r2_folder', 'gembackup' ), '/' );
		$this->service    = 's3';
	}

	protected function get_endpoint() {
		return "https://{$this->account_id}.r2.cloudflarestorage.com/{$this->bucket}";
	}
}
