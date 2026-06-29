<?php
namespace GemBackup\Api;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Logs_Controller extends Rest_Controller {

	protected $rest_base = 'logs';

	public function register_routes() {
		register_rest_route( $this->namespace, '/' . $this->rest_base, [
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'list_logs' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
			[
				'methods'             => 'DELETE',
				'callback'            => [ $this, 'clear_logs' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
		] );
	}

	public function list_logs( $request ) {
		global $wpdb;
		$level  = $request->get_param( 'level' );
		$search = $request->get_param( 'search' );
		$limit  = max( 1, min( 500, (int) ( $request->get_param( 'limit' ) ?: 100 ) ) );

		$where = [ '1=1' ];
		$args  = [];

		if ( $level && in_array( $level, [ 'info', 'success', 'warning', 'error' ], true ) ) {
			$where[] = 'level = %s';
			$args[]  = $level;
		}
		if ( $search ) {
			$where[] = 'message LIKE %s';
			$args[]  = '%' . $wpdb->esc_like( $search ) . '%';
		}

		$where_sql = implode( ' AND ', $where );
		$sql = "SELECT * FROM {$wpdb->gembackup_logs} WHERE {$where_sql} ORDER BY created_at DESC LIMIT %d";
		$args[] = $limit;
		$rows = $wpdb->get_results( $wpdb->prepare( $sql, $args ), ARRAY_A );

		return $this->ok( [
			'items' => array_map( function( $r ) {
				return [
					'id'         => (int) $r['id'],
					'backup_id'  => $r['backup_id'] ? (int) $r['backup_id'] : null,
					'level'      => $r['level'],
					'message'    => $r['message'],
					'context'    => $r['context'] ? json_decode( $r['context'], true ) : null,
					'created_at' => $r['created_at'],
				];
			}, $rows ),
		] );
	}

	public function clear_logs() {
		global $wpdb;
		$wpdb->query( "TRUNCATE TABLE {$wpdb->gembackup_logs}" );
		return $this->ok( [ 'cleared' => true ] );
	}
}
