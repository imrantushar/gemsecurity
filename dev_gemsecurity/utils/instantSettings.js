/**
 * Master on/off switches that save the moment they are flipped.
 *
 * A switch belongs here when turning it on or off is safe by itself, with no
 * other field on the page needed to make it work. Mirrors the one-click
 * `quick` flag in includes/security/security-score.php — keep them in step.
 *
 * Deliberately left out, so they go through the save bar with their settings:
 *  - two_factor_enabled, admin_whitelist_enabled: can lock people out unless
 *    the methods / whitelist beside them are set first.
 *  - security_headers_enabled: a CSP can break the front end; review first.
 *  - file_watcher_enabled: needs its baseline paths.
 *  - xmlrpc_disabled: breaks the mobile app and remote publishing.
 */
const INSTANT = new Set( [
	'firewall_enabled',
	'login_attempts_enabled',
	'scanner_auto_scan',
	'vuln_scan_enabled',
	'disable_file_editing',
	'password_policy_enabled',
	'link_scanner_enabled',
	'block_author_enumeration',
	'disable_user_rest',
	'admin_login_alert_enabled',
	'hide_wp_version',
	'protect_core_files_enabled',
] );

export function isInstantSetting( key ) {
	return INSTANT.has( key );
}
