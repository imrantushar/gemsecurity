<?php
namespace GemBackup\Api;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Schedules_Controller extends Rest_Controller {

	protected $rest_base = 'schedules';

	public function register_routes() {
		register_rest_route( $this->namespace, '/' . $this->rest_base, [
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'list_schedules' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'create_schedule' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
		] );

		register_rest_route( $this->namespace, '/' . $this->rest_base . '/(?P<id>\d+)', [
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'get_schedule' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
			[
				'methods'             => 'PUT',
				'callback'            => [ $this, 'update_schedule' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
			[
				'methods'             => 'DELETE',
				'callback'            => [ $this, 'delete_schedule' ],
				'permission_callback' => [ $this, 'permissions_check' ],
			],
		] );

		register_rest_route( $this->namespace, '/' . $this->rest_base . '/(?P<id>\d+)/toggle', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'toggle_schedule' ],
			'permission_callback' => [ $this, 'permissions_check' ],
		] );
	}

	public function list_schedules() {
		global $wpdb;
		$rows = $wpdb->get_results( "SELECT * FROM {$wpdb->gembackup_schedules} ORDER BY created_at DESC", ARRAY_A );
		return $this->ok( [ 'items' => array_map( [ $this, 'format' ], $rows ) ] );
	}

	public function get_schedule( $request ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->gembackup_schedules} WHERE id=%d", (int) $request['id'] ), ARRAY_A );
		if ( ! $row ) {
			return $this->fail( 'gembackup_not_found', __( 'Schedule not found.', 'gembackup' ), 404 );
		}
		return $this->ok( $this->format( $row ) );
	}

	public function create_schedule( $request ) {
		global $wpdb;
		$params = $request->get_json_params();
		$drivers = $params['storage_drivers'] ?? [ 'local' ];
		if ( ! is_array( $drivers ) ) {
			$drivers = [ $drivers ];
		}
		$drivers   = array_map( 'sanitize_key', $drivers );
		$is_pro    = \GemSecurity\Backup::is_pro();
		$frequency = in_array( ( $params['frequency'] ?? 'daily' ), [ 'daily', 'weekly', 'monthly' ], true ) ? $params['frequency'] : 'daily';

		// Free tier: a single daily schedule to local storage, no encryption.
		if ( ! $is_pro ) {
			if ( ! \GemSecurity\Backup::drivers_allowed( $drivers ) ) {
				return $this->fail( 'gembackup_pro_required', __( 'Cloud storage requires GemSecurity Pro.', 'gembackup' ), 403 );
			}
			if ( 'daily' !== $frequency ) {
				return $this->fail( 'gembackup_pro_required', __( 'Weekly and monthly schedules require GemSecurity Pro.', 'gembackup' ), 403 );
			}
			$existing = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->gembackup_schedules}" );
			if ( $existing >= 1 ) {
				return $this->fail( 'gembackup_pro_required', __( 'Multiple schedules require GemSecurity Pro.', 'gembackup' ), 403 );
			}
		}

		$data = [
			'schedule_name'   => sanitize_text_field( $params['schedule_name'] ?? 'Schedule' ),
			'backup_type'     => sanitize_key( $params['backup_type'] ?? 'full' ),
			'storage_drivers' => wp_json_encode( $drivers ),
			'frequency'       => $frequency,
			'run_time'        => preg_match( '/^\d{2}:\d{2}$/', $params['run_time'] ?? '02:00' ) ? $params['run_time'] : '02:00',
			'retention'       => max( 1, (int) ( $params['retention'] ?? 10 ) ),
			'label'           => isset( $params['label'] ) ? sanitize_text_field( $params['label'] ) : null,
			'encrypted'       => ( $is_pro && ! empty( $params['encrypted'] ) ) ? 1 : 0,
			'incremental'     => ! empty( $params['incremental'] ) ? 1 : 0,
			'status'          => ! empty( $params['active'] ) || ! isset( $params['active'] ) ? 'active' : 'paused',
			'next_run'        => current_time( 'mysql' ),
		];
		$wpdb->insert( $wpdb->gembackup_schedules, $data );
		$id = (int) $wpdb->insert_id;
		return $this->get_schedule( new \WP_REST_Request( 'GET', '', [ 'id' => $id ] ) );
	}

	public function update_schedule( $request ) {
		global $wpdb;
		$id = (int) $request['id'];
		$params = $request->get_json_params();
		$update = [];
		$allowed = [ 'schedule_name', 'backup_type', 'frequency', 'run_time', 'retention', 'label', 'encrypted', 'incremental', 'status' ];
		foreach ( $allowed as $key ) {
			if ( array_key_exists( $key, $params ) ) {
				$update[ $key ] = is_bool( $params[ $key ] ) ? (int) $params[ $key ] : $params[ $key ];
			}
		}
		if ( isset( $params['storage_drivers'] ) ) {
			$update['storage_drivers'] = wp_json_encode( array_map( 'sanitize_key', (array) $params['storage_drivers'] ) );
		}
		if ( ! empty( $update ) ) {
			$wpdb->update( $wpdb->gembackup_schedules, $update, [ 'id' => $id ] );
		}
		return $this->get_schedule( $request );
	}

	public function delete_schedule( $request ) {
		global $wpdb;
		$wpdb->delete( $wpdb->gembackup_schedules, [ 'id' => (int) $request['id'] ] );
		return $this->ok( [ 'deleted' => true ] );
	}

	public function toggle_schedule( $request ) {
		global $wpdb;
		$id = (int) $request['id'];
		$current = $wpdb->get_var( $wpdb->prepare( "SELECT status FROM {$wpdb->gembackup_schedules} WHERE id=%d", $id ) );
		$next = $current === 'active' ? 'paused' : 'active';
		$wpdb->update( $wpdb->gembackup_schedules, [ 'status' => $next ], [ 'id' => $id ] );
		return $this->get_schedule( $request );
	}

	private function format( $row ) {
		return [
			'id'              => (int) $row['id'],
			'schedule_name'   => $row['schedule_name'],
			'backup_type'     => $row['backup_type'],
			'storage_drivers' => json_decode( $row['storage_drivers'], true ),
			'frequency'       => $row['frequency'],
			'run_time'        => $row['run_time'],
			'next_run'        => $row['next_run'],
			'last_run'        => $row['last_run'],
			'retention'       => (int) $row['retention'],
			'label'           => $row['label'],
			'encrypted'       => (bool) $row['encrypted'],
			'incremental'     => (bool) $row['incremental'],
			'status'          => $row['status'],
			'created_at'      => $row['created_at'],
		];
	}
}
