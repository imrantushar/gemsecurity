<?php
namespace GemBackup\Engine;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Resumable SQL dumper.
 * State shape:
 * {
 *   tables: [ 'wp_options', 'wp_posts', ... ],
 *   index:  0,                  // current table index
 *   offset: 0,                  // row offset within current table
 *   schema_written: { wp_options: true, ... },
 *   completed: false,
 * }
 */
class Database_Dumper {

	const ROWS_PER_TICK = 2000;

	public static function get_tables( $include_smart_skip = true ) {
		global $wpdb;
		$tables = $wpdb->get_col( "SHOW TABLES" );
		if ( ! $include_smart_skip ) {
			return $tables;
		}

		$skip_patterns = [ '_transient', '_session_tokens', '_actionscheduler_logs' ];
		$extra = (string) ( get_option( GEMBACKUP_SETTINGS_NAME )['exclude_tables_extra'] ?? '' );
		foreach ( array_filter( array_map( 'trim', explode( "\n", $extra ) ) ) as $name ) {
			$skip_patterns[] = $name;
		}

		return array_values( array_filter( $tables, function( $t ) use ( $skip_patterns ) {
			foreach ( $skip_patterns as $pattern ) {
				if ( strpos( $t, $pattern ) !== false ) return false;
			}
			return true;
		} ) );
	}

	public static function init_state() {
		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		$tables = self::get_tables( ! empty( $settings['exclude_tables_smart'] ) );
		return [
			'tables'         => $tables,
			'index'          => 0,
			'offset'         => 0,
			'schema_written' => [],
			'completed'      => false,
		];
	}

	/**
	 * Process one tick — writes up to ROWS_PER_TICK rows then returns updated state.
	 *
	 * @param string $sql_path  Path to the .sql file (appended to).
	 * @param array  $state
	 * @return array updated state
	 */
	public static function tick( $sql_path, array $state ) {
		global $wpdb;
		if ( ! empty( $state['completed'] ) ) {
			return $state;
		}

		$fp = fopen( $sql_path, 'ab' );
		if ( ! $fp ) {
			return $state;
		}

		// Header (first tick only)
		if ( filesize( $sql_path ) === 0 ) {
			fwrite( $fp, "-- GemBackup SQL dump\n" );
			fwrite( $fp, "-- Generated: " . current_time( 'mysql' ) . "\n" );
			fwrite( $fp, "SET NAMES utf8mb4;\nSET foreign_key_checks = 0;\n\n" );
		}

		$rows_left = self::ROWS_PER_TICK;

		while ( $rows_left > 0 && $state['index'] < count( $state['tables'] ) ) {
			$table = $state['tables'][ $state['index'] ];

			if ( empty( $state['schema_written'][ $table ] ) ) {
				$create = $wpdb->get_row( "SHOW CREATE TABLE `{$table}`", ARRAY_N );
				if ( $create && isset( $create[1] ) ) {
					fwrite( $fp, "\n-- ----------------------------------\n-- Table `{$table}`\n-- ----------------------------------\n" );
					fwrite( $fp, "DROP TABLE IF EXISTS `{$table}`;\n" );
					fwrite( $fp, $create[1] . ";\n\n" );
				}
				$state['schema_written'][ $table ] = true;
			}

			$batch = min( $rows_left, self::ROWS_PER_TICK );
			$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$table}` LIMIT %d OFFSET %d", $batch, $state['offset'] ), ARRAY_A );

			if ( empty( $rows ) ) {
				$state['index']++;
				$state['offset'] = 0;
				continue;
			}

			foreach ( $rows as $row ) {
				$cols = array_map( function( $c ) { return "`{$c}`"; }, array_keys( $row ) );
				$vals = array_map( function( $v ) use ( $wpdb ) {
					if ( $v === null ) return 'NULL';
					if ( is_numeric( $v ) && ! preg_match( '/^0\d+/', $v ) ) return $v;
					return "'" . esc_sql( $v ) . "'";
				}, array_values( $row ) );
				fwrite( $fp, "INSERT INTO `{$table}` (" . implode( ',', $cols ) . ") VALUES (" . implode( ',', $vals ) . ");\n" );
			}

			$state['offset'] += count( $rows );
			$rows_left      -= count( $rows );

			if ( count( $rows ) < $batch ) {
				$state['index']++;
				$state['offset'] = 0;
			}
		}

		if ( $state['index'] >= count( $state['tables'] ) ) {
			fwrite( $fp, "\nSET foreign_key_checks = 1;\n" );
			$state['completed'] = true;
		}

		fclose( $fp );
		return $state;
	}

	public static function progress( $state ) {
		$total = max( 1, count( $state['tables'] ) );
		return min( 100, (int) ( ( $state['index'] / $total ) * 100 ) );
	}
}
