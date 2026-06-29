=== GemSecurity — Firewall, Login Security, 2FA & Malware Scanner ===
Contributors: gemsecurity
Tags: security, firewall, two factor authentication, malware scanner, backup
Requires at least: 6.4
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPL-3.0+
License URI: http://www.gnu.org/licenses/gpl-3.0.txt

All-in-one WordPress security & backup: firewall, brute-force protection, 2FA, social login, CAPTCHA, hardening, malware scanning, activity logs and backups.

== Description ==

GemSecurity is an all-in-one security dashboard for WordPress with a fast, single-page admin (no page reloads). It hardens your site, blocks attacks, and gives you full visibility through an activity log and a live security score.

= Firewall & hardening =
* IP blocklist with CIDR range support
* One-click hardening: disable XML-RPC, file editor, author/REST user enumeration, hide WP version, disable application passwords
* Security headers: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS, Content-Security-Policy
* Web Application Firewall: SQLi / XSS / LFI / RCE inspection, request rate limiting, 404-flood throttling, and bad-bot blocking

= Login security =
* Brute-force lockout with configurable thresholds
* Admin-login email alerts and an absolute admin session timeout
* Custom login URL (rename wp-login.php)
* Login CAPTCHA — reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile
* Two-Factor Authentication — authenticator-app TOTP and email OTP, with one-time backup codes
* Social / OAuth login — Google, Facebook, GitHub and Twitter

= Scanning & monitoring =
* WordPress core file integrity check against official checksums
* Uploads malware/PHP pattern scan
* Known-vulnerability scanner for core, plugins and themes
* Admin Guard — administrator whitelist with rogue-admin auto-remediation
* Full activity log with retention and CSV export
* Security dashboard — score, stats and trends

= Backup & restore =
* Manual database, files and full-site backups
* Restore and download backups
* A daily scheduled backup to local storage
* Retention, exclude paths/tables and a backup activity log
* Pre-update automatic backup (fires before plugin/theme/core updates)
* (Pro) cloud storage — Amazon S3, Backblaze B2, Cloudflare R2, Dropbox, Google Drive, OneDrive, FTP — plus encryption, migration (search-replace), multiple/weekly/monthly schedules and restore-from-cloud

= GemSecurity Pro =
The optional GemSecurity Pro add-on unlocks active threat protection and remediation: Threat Defense (escalating auto-bans, ban ledger, bot blocklist), Geolocation/country access control, a signature malware scanner with quarantine, database injection scan, plugin/theme integrity vs WordPress.org, a post-hack recovery toolkit, file-change baseline, a hardening pack, auto-update enforcement and settings import/export.

== Installation ==

1. Upload the `gemsecurity` folder to `/wp-content/plugins/`, or install through Plugins → Add New.
2. Activate the plugin through the Plugins menu in WordPress.
3. Open the GemSecurity menu and review the dashboard; enable the protections you want.

== Frequently Asked Questions ==

= Will the firewall lock me out? =
No. Logged-in administrators are never blocked by the IP blocklist or auto-bans, and aggressive options default to off so you can opt in deliberately.

= Does it work without GemSecurity Pro? =
Yes. Everything described above works in the free plugin. Pro adds active threat protection, malware remediation and scale features.

== Changelog ==

= 1.0.0 =
* Initial release: firewall, hardening, security headers, WAF, login security, custom login URL, CAPTCHA, 2FA, social login, Admin Guard, core/uploads/vulnerability scanning, activity log and dashboard.
* Backups: manual database/files/full backups, restore, download, daily local schedule and pre-update automatic backups (cloud storage, encryption and migration in Pro).
