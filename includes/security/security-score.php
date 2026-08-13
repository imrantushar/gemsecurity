<?php
namespace GemSecurity\Security;

use GemSecurity\Helper;
use GemSecurity\Modules\Scanner;
use GemSecurity\Modules\HiddenAdmin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Security health assessment.
 *
 * Produces a single 0-100 score plus an actionable breakdown. Unlike a pure
 * "how many switches are on" tally, this is threat-aware: an *active* finding
 * from the scanners (injected malware, a foreign core file, a hidden admin, a
 * known vulnerability) dominates the score, because a hardened-but-compromised
 * site is not secure. Two inputs feed it:
 *
 *   - Posture checks — the hardening switches the owner controls, each weighted.
 *   - Threats — concrete problems the last scan / vulnerability / hidden-admin
 *     passes already found. A critical threat caps the score into failing
 *     territory until it is resolved; warnings shave points.
 *
 * Every failing check and every threat carries a short, specific fix so the
 * dashboard can render a prioritised to-do list rather than a bare number.
 */
class SecurityScore {

	/**
	 * @return array {
	 *   score:int, grade:string, posture_percent:int,
	 *   checks: array, threats: array, summary: array
	 * }
	 */
	public static function assess() {
		$checks  = self::checks();
		$threats = self::threats();

		$earned = 0;
		$total  = 0;
		$passed = 0;
		$failed = 0;
		foreach ( $checks as $c ) {
			$total += $c['weight'];
			if ( 'pass' === $c['status'] ) {
				$earned += $c['weight'];
				$passed++;
			} else {
				$failed++;
			}
		}
		$posture = $total > 0 ? (int) round( $earned / $total * 100 ) : 0;

		// Active threats dominate. Any critical finding caps the score into
		// failing territory; warnings each shave a few points off the posture.
		$critical = 0;
		$deduct   = 0;
		foreach ( $threats as $t ) {
			if ( 'critical' === $t['severity'] ) {
				$critical += (int) $t['count'];
			} else {
				$deduct += min( 15, 5 * (int) $t['count'] );
			}
		}

		if ( $critical > 0 ) {
			$score = min( $posture, 30 );
		} else {
			$score = max( 0, $posture - $deduct );
		}

		return [
			'score'           => $score,
			'grade'           => self::grade( $score ),
			'posture_percent' => $posture,
			'checks'          => $checks,
			'threats'         => $threats,
			'summary'         => [
				'passed'  => $passed,
				'failed'  => $failed,
				'threats' => count( $threats ),
			],
		];
	}

	/**
	 * @param int $p
	 * @return string
	 */
	private static function grade( $p ) {
		if ( $p >= 90 ) {
			return 'A';
		}
		if ( $p >= 75 ) {
			return 'B';
		}
		if ( $p >= 60 ) {
			return 'C';
		}
		if ( $p >= 40 ) {
			return 'D';
		}
		return 'F';
	}

	/* --------------------------------------------------------------------- */
	/* Posture checks                                                         */
	/* --------------------------------------------------------------------- */

	/**
	 * @return array<int,array{key:string,label:string,weight:int,status:string,fix:string}>
	 */
	private static function checks() {
		$defs = [
			[ 'firewall_enabled', 12, __( 'Firewall', 'gemsecurity' ), __( 'Turn on the firewall to block common attack traffic.', 'gemsecurity' ) ],
			[ 'login_attempts_enabled', 12, __( 'Brute-force protection', 'gemsecurity' ), __( 'Limit login attempts to stop password-guessing.', 'gemsecurity' ) ],
			[ 'two_factor_enabled', 10, __( 'Two-factor authentication', 'gemsecurity' ), __( 'Require a second factor so a stolen password is not enough.', 'gemsecurity' ) ],
			[ 'scanner_auto_scan', 8, __( 'Daily malware scan', 'gemsecurity' ), __( 'Enable the daily scan so new infections are caught automatically.', 'gemsecurity' ) ],
			[ 'vuln_scan_enabled', 6, __( 'Vulnerability scanning', 'gemsecurity' ), __( 'Check installed plugins and themes against known vulnerabilities.', 'gemsecurity' ) ],
			[ 'file_watcher_enabled', 6, __( 'File change watcher', 'gemsecurity' ), __( 'Baseline your theme, mu-plugins and drop-ins to detect tampering.', 'gemsecurity' ) ],
			[ 'security_headers_enabled', 6, __( 'Security headers', 'gemsecurity' ), __( 'Send hardening headers (HSTS, X-Frame-Options, CSP, …).', 'gemsecurity' ) ],
			[ 'disable_file_editing', 6, __( 'Theme/plugin file editor disabled', 'gemsecurity' ), __( 'Disable the built-in file editor so a stolen login cannot inject code.', 'gemsecurity' ) ],
			[ 'password_policy_enabled', 5, __( 'Strong-password policy', 'gemsecurity' ), __( 'Enforce length, complexity and breached-password checks.', 'gemsecurity' ) ],
			[ 'admin_whitelist_enabled', 5, __( 'Admin whitelist guard', 'gemsecurity' ), __( 'Auto-revoke administrator accounts you did not authorise.', 'gemsecurity' ) ],
			[ 'link_scanner_enabled', 4, __( 'Malicious-link detection', 'gemsecurity' ), __( 'Flag spam/malware domains your content links to.', 'gemsecurity' ) ],
			[ 'block_author_enumeration', 4, __( 'Author enumeration blocked', 'gemsecurity' ), __( 'Stop attackers from harvesting usernames.', 'gemsecurity' ) ],
			[ 'disable_user_rest', 4, __( 'REST user enumeration blocked', 'gemsecurity' ), __( 'Hide the user list from the public REST API.', 'gemsecurity' ) ],
			[ 'admin_login_alert_enabled', 3, __( 'Admin login alerts', 'gemsecurity' ), __( 'Get notified whenever an administrator signs in.', 'gemsecurity' ) ],
			[ 'xmlrpc_disabled', 3, __( 'XML-RPC disabled', 'gemsecurity' ), __( 'Disable XML-RPC if you do not use it — it is a brute-force vector.', 'gemsecurity' ) ],
			[ 'hide_wp_version', 2, __( 'WordPress version hidden', 'gemsecurity' ), __( 'Stop advertising your exact WordPress version.', 'gemsecurity' ) ],
		];

		$checks = [];
		foreach ( $defs as $d ) {
			$checks[] = [
				'key'    => $d[0],
				'label'  => $d[2],
				'weight' => $d[1],
				'status' => Helper::get_setting( $d[0], false ) ? 'pass' : 'fail',
				'fix'    => $d[3],
			];
		}

		// Recent-backup hygiene (not a plain setting).
		$checks[] = [
			'key'    => 'recent_backup',
			'label'  => __( 'Recent backup', 'gemsecurity' ),
			'weight' => 6,
			'status' => self::has_recent_backup() ? 'pass' : 'fail',
			'fix'    => __( 'Take a backup — you cannot recover from a hack without one.', 'gemsecurity' ),
		];

		return $checks;
	}

	/**
	 * @return bool
	 */
	private static function has_recent_backup() {
		global $wpdb;
		if ( empty( $wpdb->gembackup_backups ) ) {
			return false;
		}
		$table = $wpdb->gembackup_backups;
		$count = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE status = 'completed' AND created_at >= %s",
				gmdate( 'Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS )
			)
		);
		return $count > 0;
	}

	/* --------------------------------------------------------------------- */
	/* Active threats                                                         */
	/* --------------------------------------------------------------------- */

	/**
	 * @return array<int,array{key:string,label:string,severity:string,count:int,fix:string}>
	 */
	private static function threats() {
		$threats = [];

		$scan = Scanner::get_last_result();
		if ( ! is_array( $scan ) ) {
			$threats[] = [
				'key'      => 'no_scan',
				'label'    => __( 'No malware scan has run yet', 'gemsecurity' ),
				'severity' => 'warning',
				'count'    => 1,
				'fix'      => __( 'Run a scan from the Scanner page.', 'gemsecurity' ),
			];
		} else {
			$core    = count( (array) ( $scan['core_issues'] ?? [] ) );
			$foreign = count( (array) ( $scan['foreign_files'] ?? [] ) );
			$susp    = count( (array) ( $scan['suspicious'] ?? [] ) );
			$inj     = (int) ( $scan['file_watcher']['injection_count'] ?? 0 );
			$mu      = (int) ( $scan['mu_plugins']['suspicious_count'] ?? 0 );
			$links   = (int) ( $scan['link_scan']['flagged_count'] ?? 0 );

			if ( $core ) {
				$threats[] = self::threat( 'core_modified', sprintf( _n( '%d modified or missing core file', '%d modified or missing core files', $core, 'gemsecurity' ), $core ), 'critical', $core, __( 'Reinstall WordPress core to restore the official files.', 'gemsecurity' ) );
			}
			if ( $foreign ) {
				$threats[] = self::threat( 'foreign_files', sprintf( _n( '%d unexpected / foreign file', '%d unexpected / foreign files', $foreign, 'gemsecurity' ), $foreign ), 'critical', $foreign, __( 'Review and remove them in Scanner → Integrity & files.', 'gemsecurity' ) );
			}
			if ( $inj ) {
				$threats[] = self::threat( 'injections', sprintf( _n( '%d code / spam-link injection', '%d code / spam-link injections', $inj, 'gemsecurity' ), $inj ), 'critical', $inj, __( 'Clean the injected files/records shown by the file-change watcher.', 'gemsecurity' ) );
			}
			if ( $mu ) {
				$threats[] = self::threat( 'mu_suspicious', sprintf( _n( '%d suspicious auto-loaded file', '%d suspicious auto-loaded files', $mu, 'gemsecurity' ), $mu ), 'critical', $mu, __( 'Inspect the flagged mu-plugins / drop-ins.', 'gemsecurity' ) );
			}
			if ( $susp ) {
				$threats[] = self::threat( 'suspicious', sprintf( _n( '%d suspicious file', '%d suspicious files', $susp, 'gemsecurity' ), $susp ), 'warning', $susp, __( 'Review the flagged files in the last scan.', 'gemsecurity' ) );
			}
			if ( $links ) {
				$threats[] = self::threat( 'flagged_links', sprintf( _n( '%d flagged outbound-link domain', '%d flagged outbound-link domains', $links, 'gemsecurity' ), $links ), 'warning', $links, __( 'Check the flagged domains in Scanner → Linked sites.', 'gemsecurity' ) );
			}
		}

		$vuln = Vulnerability::get_last_result();
		if ( is_array( $vuln ) && (int) ( $vuln['count'] ?? 0 ) > 0 ) {
			$n = (int) $vuln['count'];
			$threats[] = self::threat( 'vulnerabilities', sprintf( _n( '%d known vulnerability', '%d known vulnerabilities', $n, 'gemsecurity' ), $n ), 'warning', $n, __( 'Update the affected plugins/themes to a fixed version.', 'gemsecurity' ) );
		}

		$ha = HiddenAdmin::get_last_result();
		if ( is_array( $ha ) && ! empty( $ha['hidden_ids'] ) ) {
			$n = count( $ha['hidden_ids'] );
			$threats[] = self::threat( 'hidden_admins', sprintf( _n( '%d hidden administrator account', '%d hidden administrator accounts', $n, 'gemsecurity' ), $n ), 'critical', $n, __( 'A concealed admin is a back-door — investigate and remove it immediately.', 'gemsecurity' ) );
		}

		return $threats;
	}

	private static function threat( $key, $label, $severity, $count, $fix ) {
		return [
			'key'      => $key,
			'label'    => $label,
			'severity' => $severity,
			'count'    => (int) $count,
			'fix'      => $fix,
		];
	}
}
