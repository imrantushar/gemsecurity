<?php
namespace GemBackup\Helpers;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Serialized-data-aware search & replace.
 * Used for migration / clone-to-new-URL restores.
 */
class Search_Replace {

	public static function replace_in_string( $value, $from, $to ) {
		if ( $from === '' || $from === $to ) return $value;
		$data = self::maybe_unserialize_recursive( $value );

		if ( is_array( $data ) || is_object( $data ) ) {
			$data = self::deep_replace( $data, $from, $to );
			return serialize( $data );
		}
		if ( is_string( $value ) ) {
			return str_replace( $from, $to, $value );
		}
		return $value;
	}

	public static function deep_replace( $data, $from, $to ) {
		if ( is_string( $data ) ) {
			return str_replace( $from, $to, $data );
		}
		if ( is_array( $data ) ) {
			foreach ( $data as $k => $v ) {
				$data[ $k ] = self::deep_replace( $v, $from, $to );
			}
			return $data;
		}
		if ( is_object( $data ) ) {
			$vars = get_object_vars( $data );
			foreach ( $vars as $k => $v ) {
				$data->$k = self::deep_replace( $v, $from, $to );
			}
			return $data;
		}
		return $data;
	}

	private static function maybe_unserialize_recursive( $value ) {
		if ( is_string( $value ) && self::is_serialized( $value ) ) {
			return @unserialize( $value, [ 'allowed_classes' => false ] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,PHPCompatibility.FunctionUse.NewFunctionParameters
		}
		return $value;
	}

	private static function is_serialized( $data ) {
		if ( ! is_string( $data ) ) return false;
		$data = trim( $data );
		if ( 'N;' === $data ) return true;
		if ( strlen( $data ) < 4 ) return false;
		if ( ':' !== $data[1] ) return false;
		$last = $data[ strlen( $data ) - 1 ];
		if ( ';' !== $last && '}' !== $last ) return false;
		return (bool) preg_match( '/^[adObisN]:/', $data );
	}

	/**
	 * Walk every wp_options + post + postmeta + usermeta and replace.
	 */
	public static function replace_all_tables( $from, $to ) {
		global $wpdb;
		$replaced = 0;

		$tables = [
			[ $wpdb->options,  'option_value', 'option_id', 'option_name' ],
			[ $wpdb->postmeta, 'meta_value',   'meta_id',   'meta_key' ],
			[ $wpdb->usermeta, 'meta_value',   'umeta_id',  'meta_key' ],
			[ $wpdb->posts,    'post_content', 'ID',        'post_title' ],
			[ $wpdb->posts,    'guid',         'ID',        'post_title' ],
		];

		foreach ( $tables as $entry ) {
			list( $table, $col, $pk, $label ) = $entry;
			$rows = $wpdb->get_results( "SELECT {$pk}, {$col} FROM {$table} WHERE {$col} LIKE '%" . esc_sql( $from ) . "%' LIMIT 100000", ARRAY_A );
			foreach ( $rows as $row ) {
				$new_val = self::replace_in_string( $row[ $col ], $from, $to );
				if ( $new_val !== $row[ $col ] ) {
					$wpdb->update( $table, [ $col => $new_val ], [ $pk => $row[ $pk ] ] );
					$replaced++;
				}
			}
		}

		return $replaced;
	}
}
