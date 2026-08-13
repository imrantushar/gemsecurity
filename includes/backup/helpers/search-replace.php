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
			// maybe_unserialize_recursive() deliberately calls unserialize()
			// with allowed_classes => false (avoiding PHP object-injection
			// gadget chains from arbitrary stored data), so every object
			// reaching here is a __PHP_Incomplete_Class stand-in — PHP
			// fatals on any attempt to write a property on one. Leave
			// objects untouched rather than crash the whole run; only
			// array/string values get searched into. This is an inherent
			// tradeoff of not instantiating arbitrary classes, not
			// something a fix here can avoid.
			if ( $data instanceof \__PHP_Incomplete_Class ) {
				return $data;
			}
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
			// $table/$col/$pk are fixed identifiers from the hardcoded list
			// above, not user input, so they can't go through a %s
			// placeholder — only $from (the LIKE value) needs prepare().
			// esc_like() additionally escapes LIKE's own %/_ wildcards
			// within $from itself, so a literal % in the search string
			// doesn't unintentionally widen the match.
			$sql  = "SELECT {$pk}, {$col} FROM {$table} WHERE {$col} LIKE %s LIMIT 100000";
			$like = '%' . $wpdb->esc_like( $from ) . '%';
			$rows = $wpdb->get_results( $wpdb->prepare( $sql, $like ), ARRAY_A );
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
