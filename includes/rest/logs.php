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

		$where_sql = implode( ' AND ', $where );

		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
		$total     = (int) ( $params ? $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ) : $wpdb->get_var( $count_sql ) );

		$list_params = array_merge( $params, [ $per_page, $offset ] );
		$list_sql    = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY id DESC LIMIT %d OFFSET %d";
		$rows        = $wpdb->get_results( $wpdb->prepare( $list_sql, $list_params ), ARRAY_A );

		// Attach display names for users referenced in the logs.
		foreach ( (array) $rows as &$row ) {
			$row['user_display'] = '';
			if ( ! empty( $row['user_id'] ) ) {
				$user = get_userdata( (int) $row['user_id'] );
				$row['user_display'] = $user ? $user->user_login : '#' . (int) $row['user_id'];
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
	 * DELETE /logs — clears the activity log.
	 */
	public static function clear() {
		global $wpdb;
		$table = $wpdb->prefix . 'gemsecurity_logs';
		$wpdb->query( "TRUNCATE TABLE {$table}" );

		return rest_ensure_response( [ 'success' => true ] );
	}
}
