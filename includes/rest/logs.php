<?php
namespace GemSecurity\Rest;

use GemSecurity\Modules\AuditLog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Activity log controller.
 */
class Logs {

	/**
	 * GET /logs
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function get( $request ) {
		global $wpdb;
		$table = $wpdb->prefix . 'gemsecurity_logs';

		$per_page = min( 100, max( 1, (int) $request->get_param( 'per_page' ) ?: 20 ) );
		$page     = max( 1, (int) $request->get_param( 'page' ) ?: 1 );
		$offset   = ( $page - 1 ) * $per_page;

		$severity = sanitize_text_field( (string) $request->get_param( 'severity' ) );
		$type     = sanitize_text_field( (string) $request->get_param( 'event_type' ) );
		$category = sanitize_text_field( (string) $request->get_param( 'category' ) );
		$search   = sanitize_text_field( (string) $request->get_param( 'search' ) );

		$where  = [ '1=1' ];
		$params = [];

		if ( $severity ) {
			$where[]  = 'severity = %s';
			$params[] = $severity;
		}
		if ( $type ) {
			$where[]  = 'event_type = %s';
			$params[] = $type;
		}
		if ( $category ) {
			$map = AuditLog::category_map();
			if ( ! empty( $map[ $category ] ) ) {
				$placeholders = implode( ',', array_fill( 0, count( $map[ $category ] ), '%s' ) );
				$where[]      = "event_type IN ({$placeholders})";
				$params       = array_merge( $params, $map[ $category ] );
			}
		}
		if ( $search ) {
			$where[]  = '(message LIKE %s OR ip_address LIKE %s)';
			$like     = '%' . $wpdb->esc_like( $search ) . '%';
			$params[] = $like;
			$params[] = $like;
		}

		// "Who did what": everything one account did, or everything done to one post.
		$user_id = absint( $request->get_param( 'user_id' ) );
		if ( $user_id ) {
			$where[]  = 'user_id = %d';
			$params[] = $user_id;
		}
		$post_id = absint( $request->get_param( 'post_id' ) );
		if ( $post_id ) {
			$where[]  = '(context LIKE %s OR context LIKE %s)';
			$params[] = '%' . $wpdb->esc_like( '"post_id":' . $post_id . ',' ) . '%';
			$params[] = '%' . $wpdb->esc_like( '"post_id":' . $post_id . '}' ) . '%';
		}

		$where_sql = implode( ' AND ', $where );

		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
		$total     = (int) ( $params ? $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ) : $wpdb->get_var( $count_sql ) );

		$list_params = array_merge( $params, [ $per_page, $offset ] );
		$list_sql    = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY id DESC LIMIT %d OFFSET %d";
		$rows        = $wpdb->get_results( $wpdb->prepare( $list_sql, $list_params ), ARRAY_A );

		// Attach display names for users referenced in the logs. Iterate the
		// real array: by-reference over a `(array)` cast only edits a copy.
		$rows = is_array( $rows ) ? $rows : [];
		foreach ( $rows as &$row ) {
			$row['user_display'] = '';
			if ( ! empty( $row['user_id'] ) ) {
				$user = get_userdata( (int) $row['user_id'] );
				$row['user_display'] = $user ? $user->user_login : '#' . (int) $row['user_id'];
			}
			$row['revision_url'] = '';
			$ctx = ! empty( $row['context'] ) ? json_decode( $row['context'], true ) : null;
			if ( ! empty( $ctx['revision'] ) ) {
				$row['revision_url'] = admin_url( 'revision.php?revision=' . (int) $ctx['revision'] );
			}
		}
		unset( $row );

		return rest_ensure_response( [
			'success'     => true,
			'logs'        => $rows ? $rows : [],
			'total'       => $total,
			'total_pages' => (int) ceil( $total / $per_page ),
			'page'        => $page,
		] );
	}

	/**
	 * GET /logs/export — return the (optionally filtered) log as CSV text.
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function export( $request ) {
		global $wpdb;
		$table = $wpdb->prefix . 'gemsecurity_logs';

		$severity = sanitize_text_field( (string) $request->get_param( 'severity' ) );
		$category = sanitize_text_field( (string) $request->get_param( 'category' ) );
		$search   = sanitize_text_field( (string) $request->get_param( 'search' ) );

		$where  = [ '1=1' ];
		$params = [];
		if ( $severity ) {
			$where[]  = 'severity = %s';
			$params[] = $severity;
		}
		if ( $category ) {
			$map = AuditLog::category_map();
			if ( ! empty( $map[ $category ] ) ) {
				$ph       = implode( ',', array_fill( 0, count( $map[ $category ] ), '%s' ) );
				$where[]  = "event_type IN ({$ph})";
				$params   = array_merge( $params, $map[ $category ] );
			}
		}
		if ( $search ) {
			$like     = '%' . $wpdb->esc_like( $search ) . '%';
			$where[]  = '(message LIKE %s OR ip_address LIKE %s)';
			$params[] = $like;
			$params[] = $like;
		}
		$where_sql = implode( ' AND ', $where );
		$sql       = "SELECT id, created_at, severity, event_type, message, ip_address, user_id FROM {$table} WHERE {$where_sql} ORDER BY id DESC LIMIT 5000";
		$rows      = $params ? $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A ) : $wpdb->get_results( $sql, ARRAY_A );

		$out = "id,created_at,severity,event_type,message,ip_address,user_id\n";
		foreach ( (array) $rows as $r ) {
			$out .= implode( ',', array_map( [ __CLASS__, 'csv_cell' ], $r ) ) . "\n";
		}

		return rest_ensure_response( [ 'success' => true, 'csv' => $out, 'count' => count( (array) $rows ) ] );
	}

	private static function csv_cell( $value ) {
		$value = (string) $value;
		if ( preg_match( '/[",\r\n]/', $value ) ) {
			$value = '"' . str_replace( '"', '""', $value ) . '"';
		}
		return $value;
	}

	/**
	 * DELETE /logs — clears the activity log.
	 */
	public static function clear() {
		global $wpdb;
		$table = $wpdb->prefix . 'gemsecurity_logs';
		$wpdb->query( "TRUNCATE TABLE {$table}" );

		return rest_ensure_response( [ 'success' => true ] );
	}
}
