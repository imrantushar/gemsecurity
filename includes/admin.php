<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Admin {

	public static function init() {
		Admin\Menu::init();
		Admin\Setup::init();
	}
}
