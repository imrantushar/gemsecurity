<?php
namespace GemSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Autoload {

	private static $instance;

	private $autoload_directories = array(
		'GemSecurity' => GEMSECURITY_ROOT_DIR_PATH . 'includes/',
	);

	public static function get_instance() {
		if ( ! isset( self::$instance ) ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function add_namespace_directory( $namespace, $directory ) {
		$this->autoload_directories[ $namespace ] = $directory;
	}

	public function autoload( $class ) {
		foreach ( $this->autoload_directories as $namespace => $directory ) {
			if ( 0 === strpos( $class, $namespace ) ) {
				$class_to_load = $class;
				$filename = strtolower(
					preg_replace(
						[ '/^' . $namespace . '\\\\/', '/([a-z])([A-Z])/', '/_/', '/\\\\/' ],
						[ '', '$1-$2', '-', DIRECTORY_SEPARATOR ],
						$class_to_load
					)
				);
				$file = $directory . $filename . '.php';
				if ( is_readable( $file ) ) {
					require_once $file;
				}
			}
		}
	}

	public function __construct() {
		spl_autoload_register( [ $this, 'autoload' ] );
	}
}

Autoload::get_instance();
