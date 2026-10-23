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

	/** Most a site can lose to warnings alone, before any critical finding. */
	const MAX_WARNING_DEDUCTION = 30;

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
		$has_critical = false;
		$deduct       = 0;
		foreach ( $threats as $t ) {
			if ( 'critical' === $t['severity'] ) {
				$has_critical = true;
			} else {
				$deduct += min( 15, 5 * (int) $t['count'] );
			}
		}

		// Each warning was already bounded at 15, but the total was not, so a
		// site with three kinds of warning lost 45 points and a fully hardened
		// one could still be graded F on warnings alone. Warnings should be
		// able to pull a grade down, not erase the posture work behind it.
		$deduct = min( self::MAX_WARNING_DEDUCTION, $deduct );

		if ( $has_critical ) {
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
	 * Posture checks.
	 *
	 * The fourth column is the page that actually configures the setting, so a
	 * failing check can link straight to it. Keeping it next to the fix text
	 * means whoever edits the wording also sees where it points.
	 *
	 * @return array<int,array{key:string,label:string,weight:int,status:string,fix:string,action:?array}>
	 */
	private static function checks() {
		$slug = GEMSECURITY_PLUGIN_SLUG;

		// [ setting key, weight, label, fix, page slug, one-click fixable ]
		// One-click is off for switches that can lock people out or break the
		// front end (2FA, admin whitelist, CSP headers) or need setup first
		// (file watcher baseline), or break remote clients (XML-RPC) — those still
		// link to their page. Mirrors dev_gemsecurity/utils/instantSettings.js.
		$defs = [
			[ 'firewall_enabled', 12, __( 'Firewall', 'gemsecurity' ), __( 'Turn on the firewall to block common attack traffic.', 'gemsecurity' ), $slug . '-firewall', true ],
			[ 'login_attempts_enabled', 12, __( 'Brute-force protection', 'gemsecurity' ), __( 'Limit login attempts to stop password-guessing.', 'gemsecurity' ), $slug . '-login-security', true ],
			[ 'two_factor_enabled', 10, __( 'Two-factor authentication', 'gemsecurity' ), __( 'Require a second factor so a stolen password is not enough.', 'gemsecurity' ), $slug . '-two-factor', false ],
			[ 'scanner_auto_scan', 8, __( 'Daily malware scan', 'gemsecurity' ), __( 'Enable the daily scan so new infections are caught automatically.', 'gemsecurity' ), $slug . '-scanner', true ],
			[ 'vuln_scan_enabled', 6, __( 'Vulnerability scanning', 'gemsecurity' ), __( 'Check installed plugins and themes against known vulnerabilities.', 'gemsecurity' ), $slug . '-scanner', true ],
			[ 'file_watcher_enabled', 6, __( 'File change watcher', 'gemsecurity' ), __( 'Baseline your theme, mu-plugins and drop-ins to detect tampering.', 'gemsecurity' ), $slug . '-scanner', false ],
			[ 'security_headers_enabled', 6, __( 'Security headers', 'gemsecurity' ), __( 'Send hardening headers (HSTS, X-Frame-Options, CSP, …).', 'gemsecurity' ), $slug . '-firewall', false ],
			[ 'disable_file_editing', 6, __( 'Theme/plugin file editor disabled', 'gemsecurity' ), __( 'Disable the built-in file editor so a stolen login cannot inject code.', 'gemsecurity' ), $slug . '-firewall', true ],
			[ 'password_policy_enabled', 5, __( 'Strong-password policy', 'gemsecurity' ), __( 'Enforce length, complexity and breached-password checks.', 'gemsecurity' ), $slug . '-login-security', true ],
			[ 'admin_whitelist_enabled', 5, __( 'Admin whitelist guard', 'gemsecurity' ), __( 'Auto-revoke administrator accounts you did not authorise.', 'gemsecurity' ), $slug . '-admin-guard', false ],
			[ 'link_scanner_enabled', 4, __( 'Malicious-link detection', 'gemsecurity' ), __( 'Flag spam/malware domains your content links to.', 'gemsecurity' ), $slug . '-scanner', true ],
			[ 'block_author_enumeration', 4, __( 'Author enumeration blocked', 'gemsecurity' ), __( 'Stop attackers from harvesting usernames.', 'gemsecurity' ), $slug . '-firewall', true ],
			[ 'disable_user_rest', 4, __( 'REST user enumeration blocked', 'gemsecurity' ), __( 'Hide the user list from the public REST API.', 'gemsecurity' ), $slug . '-firewall', true ],
			[ 'admin_login_alert_enabled', 3, __( 'Admin login alerts', 'gemsecurity' ), __( 'Get notified whenever an administrator signs in.', 'gemsecurity' ), $slug . '-login-security', true ],
			[ 'xmlrpc_disabled', 3, __( 'XML-RPC disabled', 'gemsecurity' ), __( 'Disable XML-RPC if you do not use it — it is a brute-force vector.', 'gemsecurity' ), $slug . '-firewall', false ],
			[ 'hide_wp_version', 2, __( 'WordPress version hidden', 'gemsecurity' ), __( 'Stop advertising your exact WordPress version.', 'gemsecurity' ), $slug . '-firewall', true ],
			[ 'protect_core_files_enabled', 4, __( 'wp-config.php and error logs protected', 'gemsecurity' ), __( 'Block web access to wp-config.php, debug.log and wp-admin/includes (Apache / LiteSpeed).', 'gemsecurity' ), $slug . '-firewall', true ],
		];

		$checks = [];
		foreach ( $defs as $d ) {
			$checks[] = [
				'key'    => $d[0],
				'label'  => $d[2],
				'weight' => $d[1],
				'status' => Helper::get_setting( $d[0], false ) ? 'pass' : 'fail',
				'fix'    => $d[3],
				'action' => self::action( $d[4] ),
				'quick'  => ! empty( $d[5] ),
			];
		}

		$checks = array_merge( $checks, self::environment_checks() );

		// Recent-backup hygiene — only scored when GemBackup is installed.
		if ( \GemSecurity\Helper::gembackup_active() ) {
			$checks[] = [
				'key'    => 'recent_backup',
				'label'  => __( 'Recent backup', 'gemsecurity' ),
				'weight' => 6,
				'status' => self::has_recent_backup() ? 'pass' : 'fail',
				'fix'    => __( 'Take a backup in GemBackup — you cannot recover from a hack without one.', 'gemsecurity' ),
				'action' => [
					'url'   => admin_url( 'admin.php?page=gembackup' ),
					'label' => __( 'Open GemBackup', 'gemsecurity' ),
				],
			];
		}

		return $checks;
	}

	/**
	 * Checks from WordPress's hardening guide that are about the site, not a
	 * GemSecurity switch. `fix_key`, when set, names the setting whose
	 * one-click fix resolves the check.
	 *
	 * @return array<int,array>
	 */
	private static function environment_checks() {
		global $wpdb;
		$slug   = GEMSECURITY_PLUGIN_SLUG;
		$checks = [];
		$add    = static function ( $key, $weight, $pass, $label, $fix, $action, $fix_key = '' ) use ( &$checks ) {
			$checks[] = [
				'key'     => $key,
				'label'   => $label,
				'weight'  => $weight,
				'status'  => $pass ? 'pass' : 'fail',
				'fix'     => $fix,
				'action'  => $action,
				'quick'   => '' !== $fix_key,
				'fix_key' => $fix_key,
			];
		};

		// An administrator called "admin" is the first name every brute-force
		// list tries; with it, an attacker only has to guess the password.
		$guessable = get_users( [
			'role'      => 'administrator',
			'login__in' => [ 'admin', 'administrator', 'webmaster', 'root', 'wpadmin' ],
			'fields'    => [ 'user_login' ],
			'number'    => 5,
		] );
		$add(
			'no_guessable_admin_login',
			3,
			empty( $guessable ),
			__( 'No administrator named "admin"', 'gemsecurity' ),
			$guessable
				/* translators: %s: the guessable login name(s). */
				? sprintf( __( 'Create a new administrator with an uncommon username, move content to it, then delete "%s".', 'gemsecurity' ), implode( '", "', wp_list_pluck( $guessable, 'user_login' ) ) )
				: __( 'Administrator usernames are not the first ones attackers try.', 'gemsecurity' ),
			[ 'url' => admin_url( 'users.php?role=administrator' ), 'label' => __( 'Open Users', 'gemsecurity' ) ]
		);

		// Inactive code still sits on the server, can still be reached
		// directly, and is easy to forget to update.
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$inactive_plugins = count( array_filter( array_keys( get_plugins() ), static function ( $f ) {
			return ! is_plugin_active( $f ) && ! is_plugin_active_for_network( $f );
		} ) );
		$keep_themes     = array_unique( [ get_stylesheet(), get_template() ] );
		$inactive_themes = max( 0, count( wp_get_themes() ) - count( $keep_themes ) - 1 ); // One spare default theme is reasonable.
		$add(
			'no_unused_code',
			2,
			0 === $inactive_plugins && 0 === $inactive_themes,
			__( 'No unused plugins or themes installed', 'gemsecurity' ),
			$inactive_plugins || $inactive_themes
				/* translators: 1: inactive plugins, 2: extra inactive themes. */
				? sprintf( __( 'Delete what you do not use: %1$d inactive plugin(s), %2$d extra inactive theme(s).', 'gemsecurity' ), $inactive_plugins, $inactive_themes )
				: __( 'Only code you use is installed.', 'gemsecurity' ),
			[ 'url' => admin_url( 'plugins.php?plugin_status=inactive' ), 'label' => __( 'Open Plugins', 'gemsecurity' ) ]
		);

		// Plugins that run PHP stored in the database turn any admin-account
		// or SQL-injection compromise straight into code execution.
		$code_exec = (array) apply_filters( 'gemsecurity/code_execution_plugins', [
			'code-snippets/code-snippets.php',
			'insert-php/insert_php.php',
			'insert-php-code-snippet/insert-php-code-snippet.php',
			'php-everywhere/php-everywhere.php',
			'php-code-widget/execphp.php',
			'exec-php/exec-php.php',
			'woody-ad-snippets/insert-php.php',
			'advanced-scripts/advanced-scripts.php',
		] );
		$running   = array_values( array_filter( $code_exec, 'is_plugin_active' ) );
		$add(
			'no_code_execution_plugins',
			2,
			empty( $running ),
			__( 'No plugins that run PHP from the database', 'gemsecurity' ),
			$running
				/* translators: %s: plugin folder names. */
				? sprintf( __( 'Move these snippets into a child theme or a small custom plugin, then remove: %s.', 'gemsecurity' ), implode( ', ', array_map( 'dirname', $running ) ) )
				: __( 'No plugin stores PHP in the database.', 'gemsecurity' ),
			[ 'url' => admin_url( 'plugins.php' ), 'label' => __( 'Open Plugins', 'gemsecurity' ) ]
		);

		// Errors shown on the page leak file paths, queries and plugin names.
		$shows_errors = defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY );
		$add(
			'errors_not_displayed',
			3,
			! $shows_errors,
			__( 'PHP errors are not shown to visitors', 'gemsecurity' ),
			$shows_errors
				? __( "Add define( 'WP_DEBUG_DISPLAY', false ); to wp-config.php, or turn WP_DEBUG off on a live site.", 'gemsecurity' )
				: __( 'Errors are kept out of the page.', 'gemsecurity' ),
			null
		);

		// WP_DEBUG_LOG's default target is inside the web root.
		$log         = defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG
			? ( is_string( WP_DEBUG_LOG ) ? WP_DEBUG_LOG : WP_CONTENT_DIR . '/debug.log' )
			: '';
		$log_in_root = '' !== $log && file_exists( $log ) && 0 === strpos( wp_normalize_path( $log ), wp_normalize_path( ABSPATH ) );
		$protected   = Helper::get_setting( 'protect_core_files_enabled', false ) && \GemSecurity\Security\CoreFileRules::installed();
		$add(
			'debug_log_private',
			3,
			! $log_in_root || $protected,
			__( 'Error log is not publicly readable', 'gemsecurity' ),
			$log_in_root && ! $protected
				? __( 'debug.log is inside the web root. Protect it, or point WP_DEBUG_LOG at a path outside the site.', 'gemsecurity' )
				: __( 'The error log cannot be downloaded from the web.', 'gemsecurity' ),
			self::action( $slug . '-firewall' ),
			$log_in_root && ! $protected ? 'protect_core_files_enabled' : ''
		);

		// Information only: renaming tables on a live site is risky, so this
		// weighs little and has no fix button.
		$add(
			'custom_table_prefix',
			1,
			'wp_' !== $wpdb->base_prefix,
			__( 'Database table prefix is not the default', 'gemsecurity' ),
			'wp_' === $wpdb->base_prefix
				? __( 'Tables use the default wp_ prefix. Use a custom prefix on new installs; changing it on a live site needs a full backup first.', 'gemsecurity' )
				: __( 'Tables use a custom prefix.', 'gemsecurity' ),
			null
		);

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
	 * @return array<int,array{key:string,label:string,severity:string,count:int,fix:string,action:?array}>
	 */
	private static function threats() {
		$threats = [];
		$scanner = GEMSECURITY_PLUGIN_SLUG . '-scanner';

		$scan = Scanner::get_last_result();
		if ( ! is_array( $scan ) ) {
			$threats[] = [
				'key'      => 'no_scan',
				'label'    => __( 'No malware scan has run yet', 'gemsecurity' ),
				'severity' => 'warning',
				'count'    => 1,
				'fix'      => __( 'Run a scan from the Scanner page.', 'gemsecurity' ),
				'action'   => self::action( $scanner ),
			];
		} elseif ( isset( $scan['wp_version'] ) && $scan['wp_version'] !== get_bloginfo( 'version' ) ) {
			// The last scan ran against a different WordPress version. Its core
			// findings describe files that have since been legitimately
			// replaced by the update, so every one of them would be reported as
			// "modified or missing" — a wall of criticals caused by patching,
			// which is the opposite of the lesson to teach. Say the result is
			// out of date instead of repeating what it said.
			$threats[] = [
				'key'      => 'scan_outdated',
				'label'    => sprintf(
					/* translators: %s: WordPress version the last scan ran against. */
					__( 'Last scan predates a WordPress update (ran against %s)', 'gemsecurity' ),
					$scan['wp_version']
				),
				'severity' => 'warning',
				'count'    => 1,
				'fix'      => __( 'Re-run the scan so core files are checked against the version this site is actually running.', 'gemsecurity' ),
				'action'   => self::action( $scanner ),
			];
		} else {
			$core    = count( (array) ( $scan['core_issues'] ?? [] ) );
			$foreign = count( (array) ( $scan['foreign_files'] ?? [] ) );
			$susp    = count( (array) ( $scan['suspicious'] ?? [] ) );
			$inj     = (int) ( $scan['file_watcher']['injection_count'] ?? 0 );
			$mu      = (int) ( $scan['mu_plugins']['suspicious_count'] ?? 0 );
			$links   = (int) ( $scan['link_scan']['flagged_count'] ?? 0 );

			if ( $core ) {
				$threats[] = self::threat( 'core_modified', sprintf( _n( '%d modified or missing core file', '%d modified or missing core files', $core, 'gemsecurity' ), $core ), 'critical', $core, __( 'Reinstall WordPress core to restore the official files.', 'gemsecurity' ), $scanner );
			}
			if ( $foreign ) {
				$threats[] = self::threat( 'foreign_files', sprintf( _n( '%d unexpected / foreign file', '%d unexpected / foreign files', $foreign, 'gemsecurity' ), $foreign ), 'critical', $foreign, __( 'Review and remove them in Scanner → Integrity & files.', 'gemsecurity' ), $scanner );
			}
			if ( $inj ) {
				$threats[] = self::threat( 'injections', sprintf( _n( '%d code / spam-link injection', '%d code / spam-link injections', $inj, 'gemsecurity' ), $inj ), 'critical', $inj, __( 'Clean the injected files/records shown by the file-change watcher.', 'gemsecurity' ), $scanner );
			}
			if ( $mu ) {
				$threats[] = self::threat( 'mu_suspicious', sprintf( _n( '%d suspicious auto-loaded file', '%d suspicious auto-loaded files', $mu, 'gemsecurity' ), $mu ), 'critical', $mu, __( 'Inspect the flagged mu-plugins / drop-ins.', 'gemsecurity' ), $scanner );
			}
			$ht = (array) ( $scan['htaccess'] ?? [] );
			if ( $ht ) {
				$ht_critical = false;
				foreach ( $ht as $h ) {
					if ( 'critical' === ( $h['severity'] ?? '' ) ) { $ht_critical = true; break; }
				}
				$n = count( $ht );
				$threats[] = self::threat(
					'htaccess',
					sprintf(
						/* translators: %d: number of .htaccess files. */
						_n( '%d .htaccess file grants execution or redirects traffic', '%d .htaccess files grant execution or redirect traffic', $n, 'gemsecurity' ),
						$n
					),
					$ht_critical ? 'critical' : 'warning',
					$n,
					__( 'Review them in Scanner → .htaccess. A rule that loads a PHP file into every request, or re-enables PHP in uploads, is a back-door.', 'gemsecurity' ),
					$scanner
				);
			}
			if ( $susp ) {
				$threats[] = self::threat( 'suspicious', sprintf( _n( '%d suspicious file', '%d suspicious files', $susp, 'gemsecurity' ), $susp ), 'warning', $susp, __( 'Review the flagged files in the last scan.', 'gemsecurity' ), $scanner );
			}
			if ( $links ) {
				$threats[] = self::threat( 'flagged_links', sprintf( _n( '%d flagged outbound-link domain', '%d flagged outbound-link domains', $links, 'gemsecurity' ), $links ), 'warning', $links, __( 'Check the flagged domains in Scanner → Linked sites.', 'gemsecurity' ), $scanner );
			}
		}

		$vuln = Vulnerability::get_last_result();
		if ( is_array( $vuln ) && (int) ( $vuln['count'] ?? 0 ) > 0 ) {
			$n = (int) $vuln['count'];
			$threats[] = self::threat( 'vulnerabilities', sprintf( _n( '%d known vulnerability', '%d known vulnerabilities', $n, 'gemsecurity' ), $n ), 'warning', $n, __( 'Update the affected plugins/themes to a fixed version.', 'gemsecurity' ), $scanner );
		}

		$ha = HiddenAdmin::get_last_result();
		if ( is_array( $ha ) && ! empty( $ha['hidden_ids'] ) ) {
			$n = count( $ha['hidden_ids'] );
			$threats[] = self::threat( 'hidden_admins', sprintf( _n( '%d hidden administrator account', '%d hidden administrator accounts', $n, 'gemsecurity' ), $n ), 'critical', $n, __( 'A concealed admin is a back-door — investigate and remove it immediately.', 'gemsecurity' ), GEMSECURITY_PLUGIN_SLUG . '-admin-guard' );
		}

		return $threats;
	}

	/**
	 * @param string $key
	 * @param string $label
	 * @param string $severity
	 * @param int    $count
	 * @param string $fix
	 * @param string $page Page slug that investigates or resolves this.
	 * @return array
	 */
	private static function threat( $key, $label, $severity, $count, $fix, $page ) {
		return [
			'key'      => $key,
			'label'    => $label,
			'severity' => $severity,
			'count'    => (int) $count,
			'fix'      => $fix,
			'action'   => self::action( $page ),
		];
	}

	/**
	 * Where to send someone who wants to act on a finding.
	 *
	 * Resolved through the registry rather than hardcoded, so a page that is
	 * renamed or turned into a Pro upsell cannot leave a dead link behind. A
	 * deactivated module has no page at all, so the link points at the Modules
	 * manager instead — turning the module back on is the actual first step.
	 *
	 * @param string $page_slug
	 * @return array{url:string,label:string}|null
	 */
	private static function action( $page_slug ) {
		$module = null;
		foreach ( \GemSecurity\Modules\Registry::all() as $id => $m ) {
			if ( $m['page_slug'] === $page_slug ) {
				$module = $id;
				break;
			}
		}

		if ( null === $module ) {
			return null;
		}

		if ( ! \GemSecurity\Modules\Registry::is_visible( $module ) ) {
			return [
				'url'   => admin_url( 'admin.php?page=' . GEMSECURITY_PLUGIN_SLUG . '-modules' ),
				'label' => __( 'Turn the module on', 'gemsecurity' ),
			];
		}

		$labels = \GemSecurity\Modules\Registry::labels();

		return [
			'url'   => admin_url( 'admin.php?page=' . $page_slug ),
			'label' => isset( $labels[ $module ]['title'] ) ? $labels[ $module ]['title'] : $module,
		];
	}
}
