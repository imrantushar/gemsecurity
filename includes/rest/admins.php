<?php
namespace GemSecurity\Rest;

use GemSecurity\Helper;
use GemSecurity\Modules\AdminGuard;
use GemSecurity\Modules\HiddenAdmin;
use GemSecurity\Security\AdminAudit;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Administrator listing (whitelist management + hidden / suspicious admin
 * detection and remediation).
 */
class Admins {

	/**
	 * GET /admins
	 *
	 * Lists administrators from the filter-proof AdminAudit source (so hidden
	 * accounts are always included) and returns the reconciled verdict for the
	 * UI banner. Uses HiddenAdmin::verdict() so a concealment that only fires
	 * inside wp-admin — invisible to this REST request — is still reflected.
	 */
	public static function get() {
		if ( HiddenAdmin::enabled() ) {
			$verdict = HiddenAdmin::verdict();
			$admins  = $verdict['admins'];
			$audit   = $verdict['result'];
		} else {
			$audit  = AdminAudit::audit();
			$admins = AdminAudit::admins();
		}

		return rest_ensure_response( [
			'success'   => true,
			'admins'    => $admins,
			'whitelist' => (array) Helper::get_setting( 'admin_whitelist', [] ),
			'audit'     => self::audit_payload( $audit ),
		] );
	}

	/**
	 * POST /admins/remove
	 *
	 * Remove (delete or demote) a specific administrator by ID — the remediation
	 * for a hidden / suspicious / unapproved admin. Protections for the current
	 * user, user ID 1, the site owner and super admins are enforced inside
	 * AdminAudit::remove_admin().
	 *
	 * @param \WP_REST_Request $request
	 */
	public static function remove( $request ) {
		$user_id = (int) $request->get_param( 'user_id' );
		$action  = 'demote' === $request->get_param( 'action' ) ? 'demote' : 'delete';

		$result = AdminAudit::remove_admin( $user_id, $action );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		if ( HiddenAdmin::enabled() ) {
			HiddenAdmin::forget( $user_id );
			$verdict = HiddenAdmin::verdict();
			$admins  = $verdict['admins'];
			$audit   = $verdict['result'];
		} else {
			$audit  = AdminAudit::audit();
			$admins = AdminAudit::admins();
		}

		return rest_ensure_response( [
			'success' => true,
			'admins'  => $admins,
			'audit'   => self::audit_payload( $audit ),
		] );
	}

	/**
	 * GET /admins/sweep — dry run.
	 *
	 * Shows exactly who the sweep would remove before anything happens, so a
	 * mistyped whitelist is caught while it is still reversible.
	 */
	public static function preview_sweep() {
		return rest_ensure_response( [
			'success' => true,
			'preview' => true,
		] + AdminGuard::sweep( 'manual', true ) );
	}

	/**
	 * POST /admins/sweep — remove every unapproved administrator now.
	 */
	public static function sweep() {
		$result = AdminGuard::sweep( 'manual' );

		if ( HiddenAdmin::enabled() ) {
			$verdict = HiddenAdmin::verdict();
			$admins  = $verdict['admins'];
			$audit   = $verdict['result'];
		} else {
			$audit  = AdminAudit::audit();
			$admins = AdminAudit::admins();
		}

		return rest_ensure_response( [
			'success' => true,
			'admins'  => $admins,
			'audit'   => self::audit_payload( $audit ),
		] + $result );
	}

	/**
	 * Compact the audit result to the fields the UI banner needs.
	 *
	 * @param array $audit
	 * @return array
	 */
	private static function audit_payload( $audit ) {
		return [
			'raw_count'      => $audit['raw_count'],
			'visible_count'  => $audit['visible_count'],
			'counted'        => $audit['counted'],
			'hidden_ids'     => $audit['hidden_ids'],
			'suspicious_ids' => isset( $audit['suspicious_ids'] ) ? $audit['suspicious_ids'] : [],
			'mismatch'       => $audit['mismatch'],
		];
	}
}
