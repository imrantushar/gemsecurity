<?php
namespace GemSecurity\Modules;

use GemSecurity\Helper;
use GemSecurity\Mailer;
use GemSecurity\Security\AdminAudit;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The morning letter: who can administer this site, what code runs on it, and
 * what changed since yesterday.
 *
 * Alerts fire when something crosses a threshold, which means a quiet inbox is
 * ambiguous — nothing happened, or nothing was noticed. A short daily statement
 * of the two things that decide who controls a WordPress site (its
 * administrators and its active plugins) makes an unexpected change obvious the
 * next morning, and turns "no email" into a signal rather than a silence.
 *
 * The comparison is against a snapshot stored at the previous send, so
 * "activated since yesterday" survives a plugin being switched on and off
 * between reports.
 */
class DailyReport {

	const CRON_HOOK = 'gemsecurity_daily_report';
	const SNAPSHOT  = 'gemsecurity_daily_report_snapshot';

	public static function init() {
		add_action( self::CRON_HOOK, [ __CLASS__, 'send' ] );
		add_action( 'init', [ __CLASS__, 'schedule' ] );
		add_action( 'update_option_' . GEMSECURITY_SETTINGS_NAME, [ __CLASS__, 'reschedule' ], 10, 2 );
	}

	/* ------------------------------------------------------------------ */
	/* Scheduling                                                          */
	/* ------------------------------------------------------------------ */

	/** Keep the daily event scheduled at the configured hour, or clear it. */
	public static function schedule() {
		$next = wp_next_scheduled( self::CRON_HOOK );

		if ( ! Helper::get_setting( 'daily_report_enabled', false ) ) {
			if ( $next ) {
				wp_unschedule_event( $next, self::CRON_HOOK );
			}
			return;
		}

		if ( ! $next ) {
			wp_schedule_event( self::next_run_timestamp(), 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Re-schedule when the switch or the hour changes.
	 *
	 * @param mixed $old
	 * @param mixed $new
	 */
	public static function reschedule( $old, $new ) {
		foreach ( [ 'daily_report_enabled', 'daily_report_hour' ] as $key ) {
			$before = is_array( $old ) && isset( $old[ $key ] ) ? $old[ $key ] : null;
			$after  = is_array( $new ) && isset( $new[ $key ] ) ? $new[ $key ] : null;
			if ( $before !== $after ) {
				$next = wp_next_scheduled( self::CRON_HOOK );
				if ( $next ) {
					wp_unschedule_event( $next, self::CRON_HOOK );
				}
				self::schedule();
				return;
			}
		}
	}

	/**
	 * The next occurrence of the configured hour in the site's own timezone —
	 * "morning" has to mean morning where the site owner is, not UTC.
	 *
	 * @return int
	 */
	private static function next_run_timestamp() {
		$hour = (int) Helper::get_setting( 'daily_report_hour', 7 );
		$hour = max( 0, min( 23, $hour ) );

		$tz  = wp_timezone();
		$now = new \DateTimeImmutable( 'now', $tz );
		$run = $now->setTime( $hour, 0, 0 );
		if ( $run <= $now ) {
			$run = $run->modify( '+1 day' );
		}
		return $run->getTimestamp();
	}

	/* ------------------------------------------------------------------ */
	/* Report                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Build and send the report.
	 *
	 * @param bool $force Send even when the schedule is switched off (the
	 *                    "send now" button), without disturbing the snapshot.
	 * @return bool
	 */
	public static function send( $force = false ) {
		if ( ! $force && ! Helper::get_setting( 'daily_report_enabled', false ) ) {
			return false;
		}

		$data = self::collect();

		$to = Mailer::recipient();

		// A change worth noticing gets a different emoji and title, so the
		// notification preview alone says whether to open it.
		$changed = $data['new_plugins'] || $data['gone_plugins'] || $data['new_admins'] || $data['gone_admins'];
		$emoji   = $changed ? '🔔' : '☀️';
		$title   = $changed
			? __( 'Morning report — changes since yesterday', 'gemsecurity' )
			: __( 'Morning report — no changes', 'gemsecurity' );

		$sent = Mailer::send( $to, $emoji, $title, self::blocks( $data ), [
			'intro' => sprintf(
				/* translators: %s: formatted date. */
				__( 'Administrators, active plugins and anything that changed on your site as of %s.', 'gemsecurity' ),
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) )
			),
		] );

		// Only a scheduled send moves the baseline; a manual preview must not
		// consume "what changed since yesterday".
		if ( ! $force ) {
			self::store_snapshot( $data );
		}

		return $sent;
	}

	/**
	 * Everything the report talks about, plus the diff against the last send.
	 *
	 * @return array
	 */
	public static function collect() {
		$snapshot = get_option( self::SNAPSHOT, [] );
		$snapshot = is_array( $snapshot ) ? $snapshot : [];

		$plugins = self::active_plugins();
		$admins  = self::administrators();

		$old_plugins = isset( $snapshot['plugins'] ) && is_array( $snapshot['plugins'] ) ? $snapshot['plugins'] : [];
		$old_admins  = isset( $snapshot['admins'] ) && is_array( $snapshot['admins'] ) ? $snapshot['admins'] : [];

		// A first run has no baseline: report the inventory, but do not claim
		// every plugin on the site was "activated since yesterday".
		$first_run = empty( $snapshot );

		return [
			'first_run'    => $first_run,
			'since'        => isset( $snapshot['time'] ) ? (int) $snapshot['time'] : 0,
			'plugins'      => $plugins,
			'admins'       => $admins,
			'new_plugins'  => $first_run ? [] : array_values( array_diff( array_keys( $plugins ), array_keys( $old_plugins ) ) ),
			'gone_plugins' => $first_run ? [] : array_values( array_diff( array_keys( $old_plugins ), array_keys( $plugins ) ) ),
			'new_admins'   => $first_run ? [] : array_values( array_diff( array_keys( $admins ), array_keys( $old_admins ) ) ),
			'gone_admins'  => $first_run ? [] : array_values( array_diff( array_keys( $old_admins ), array_keys( $admins ) ) ),
			'old_plugins'  => $old_plugins,
			'old_admins'   => $old_admins,
			'events'       => self::event_counts(),
		];
	}

	/**
	 * Active plugins as file => [ name, version ].
	 *
	 * @return array<string,array>
	 */
	private static function active_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$all    = get_plugins();
		$active = (array) get_option( 'active_plugins', [] );
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', [] ) ) );
		}

		$out = [];
		foreach ( $active as $file ) {
			$out[ $file ] = [
				'name'    => isset( $all[ $file ]['Name'] ) ? $all[ $file ]['Name'] : $file,
				'version' => isset( $all[ $file ]['Version'] ) ? $all[ $file ]['Version'] : '',
			];
		}
		ksort( $out );
		return $out;
	}

	/**
	 * Administrators as id => [ login, email, whitelisted ].
	 *
	 * Read through the audit source rather than a user query, so an account
	 * hidden from the Users screen still appears in the letter — a hidden
	 * administrator is exactly what this report exists to surface.
	 *
	 * @return array<int,array>
	 */
	private static function administrators() {
		$whitelist = array_map(
			static function ( $e ) {
				return strtolower( trim( (string) $e ) );
			},
			(array) Helper::get_setting( 'admin_whitelist', [] )
		);

		$out = [];
		foreach ( AdminAudit::raw_admin_ids() as $id ) {
			$user = get_userdata( (int) $id );
			if ( ! $user ) {
				continue;
			}
			$out[ (int) $id ] = [
				'login'       => $user->user_login,
				'email'       => $user->user_email,
				'whitelisted' => in_array( strtolower( trim( $user->user_email ) ), $whitelist, true ),
			];
		}
		return $out;
	}

	/**
	 * Event counts for the last 24 hours, by severity.
	 *
	 * @return array<string,int>
	 */
	private static function event_counts() {
		global $wpdb;
		$table = $wpdb->prefix . 'gemsecurity_logs';

		// Our own logs table — the name is $wpdb->prefix + fixed suffix.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT severity, COUNT(*) c FROM {$table} WHERE created_at >= %s GROUP BY severity",
				gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS )
			),
			ARRAY_A
		);

		$out = [ 'critical' => 0, 'warning' => 0, 'notice' => 0, 'info' => 0 ];
		foreach ( (array) $rows as $row ) {
			$out[ $row['severity'] ] = (int) $row['c'];
		}
		return $out;
	}

	/** Persist the baseline the next report compares against. */
	private static function store_snapshot( array $data ) {
		update_option(
			self::SNAPSHOT,
			[
				'time'    => time(),
				'plugins' => $data['plugins'],
				'admins'  => $data['admins'],
			],
			false
		);
	}

	/* ------------------------------------------------------------------ */
	/* Composition                                                         */
	/* ------------------------------------------------------------------ */

	/**
	 * Turn the collected data into mail blocks. Changes lead, because they are
	 * the only part that ever needs acting on; the full inventory follows as
	 * reference.
	 *
	 * @param array $data
	 * @return array
	 */
	public static function blocks( array $data ) {
		$blocks = [];

		$blocks[] = [
			'type'  => 'stats',
			'items' => [
				__( 'Admins', 'gemsecurity' )    => count( $data['admins'] ),
				__( 'Plugins', 'gemsecurity' )   => count( $data['plugins'] ),
				__( 'Critical', 'gemsecurity' )  => $data['events']['critical'],
				__( 'Warnings', 'gemsecurity' )  => $data['events']['warning'],
			],
		];

		if ( $data['first_run'] ) {
			$blocks[] = [
				'type' => 'notice',
				'tone' => 'info',
				'text' => __( 'This is the first report, so there is nothing to compare against yet. From tomorrow it will list what changed.', 'gemsecurity' ),
			];
		}

		// --- Changes -------------------------------------------------------
		if ( $data['new_plugins'] ) {
			$blocks[] = [
				'type' => 'notice',
				'tone' => 'warning',
				'text' => sprintf(
					/* translators: %s: plugin names. */
					__( '<strong>Newly activated:</strong> %s. If you did not do this, treat it as an intrusion.', 'gemsecurity' ),
					esc_html( implode( ', ', self::plugin_names( $data['new_plugins'], $data['plugins'] ) ) )
				),
			];
		}
		if ( $data['new_admins'] ) {
			$blocks[] = [
				'type' => 'notice',
				'tone' => 'critical',
				'text' => sprintf(
					/* translators: %s: usernames. */
					__( '<strong>New administrator account(s):</strong> %s.', 'gemsecurity' ),
					esc_html( implode( ', ', self::admin_names( $data['new_admins'], $data['admins'] ) ) )
				),
			];
		}
		if ( $data['gone_plugins'] || $data['gone_admins'] ) {
			$gone = [];
			if ( $data['gone_plugins'] ) {
				$gone[] = sprintf(
					/* translators: %s: plugin names. */
					__( 'Plugins deactivated: %s', 'gemsecurity' ),
					esc_html( implode( ', ', self::plugin_names( $data['gone_plugins'], $data['old_plugins'] ) ) )
				);
			}
			if ( $data['gone_admins'] ) {
				$gone[] = sprintf(
					/* translators: %s: usernames. */
					__( 'Administrators removed: %s', 'gemsecurity' ),
					esc_html( implode( ', ', self::admin_names( $data['gone_admins'], $data['old_admins'] ) ) )
				);
			}
			$blocks[] = [
				'type' => 'notice',
				'tone' => 'info',
				'text' => implode( '<br>', $gone ),
			];
		}

		// --- Administrators -------------------------------------------------
		$admin_rows = [];
		foreach ( $data['admins'] as $id => $admin ) {
			$flag = '';
			if ( in_array( $id, array_map( 'intval', $data['new_admins'] ), true ) ) {
				$flag = ' <span style="color:#a01919;font-weight:700;">' . esc_html__( '(new)', 'gemsecurity' ) . '</span>';
			} elseif ( ! $admin['whitelisted'] && Helper::get_setting( 'admin_whitelist_enabled', false ) ) {
				$flag = ' <span style="color:#8a5a00;font-weight:700;">' . esc_html__( '(not on whitelist)', 'gemsecurity' ) . '</span>';
			}
			$admin_rows[] = [ esc_html( $admin['login'] ) . $flag, esc_html( $admin['email'] ) ];
		}
		$blocks[] = [
			'type'    => 'table',
			'heading' => __( 'Administrators', 'gemsecurity' ),
			'columns' => [ __( 'User', 'gemsecurity' ), __( 'Email', 'gemsecurity' ) ],
			'rows'    => $admin_rows,
		];

		// --- Plugins --------------------------------------------------------
		$plugin_rows = [];
		foreach ( $data['plugins'] as $file => $plugin ) {
			$flag = in_array( $file, $data['new_plugins'], true )
				? ' <span style="color:#8a5a00;font-weight:700;">' . esc_html__( '(new)', 'gemsecurity' ) . '</span>'
				: '';
			$plugin_rows[] = [ esc_html( $plugin['name'] ) . $flag, esc_html( $plugin['version'] ) ];
		}
		$blocks[] = [
			'type'    => 'table',
			'heading' => __( 'Active plugins', 'gemsecurity' ),
			'columns' => [ __( 'Plugin', 'gemsecurity' ), __( 'Version', 'gemsecurity' ) ],
			'rows'    => $plugin_rows,
		];

		$blocks[] = [
			'type'  => 'button',
			'url'   => admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG ),
			'label' => __( 'Open the security dashboard', 'gemsecurity' ),
		];

		return $blocks;
	}

	/**
	 * @param array $files
	 * @param array $lookup
	 * @return string[]
	 */
	private static function plugin_names( array $files, array $lookup ) {
		$out = [];
		foreach ( $files as $file ) {
			$out[] = isset( $lookup[ $file ]['name'] ) ? $lookup[ $file ]['name'] : $file;
		}
		return $out;
	}

	/**
	 * @param array $ids
	 * @param array $lookup
	 * @return string[]
	 */
	private static function admin_names( array $ids, array $lookup ) {
		$out = [];
		foreach ( $ids as $id ) {
			$out[] = isset( $lookup[ $id ]['login'] ) ? $lookup[ $id ]['login'] : '#' . $id;
		}
		return $out;
	}
}
