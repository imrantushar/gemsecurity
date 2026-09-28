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

= Where do I start? =
Open GemSecurity → Modules and turn on the areas your site needs, then work through Firewall, Login Security and Scanner — they cover the most common attacks. Every page has a "?" button in the top bar that explains what that page does, how to set it up, and what to watch out for.

= There are a lot of settings. Is there documentation inside the plugin? =
Yes. The "?" button in the top bar opens a guide for the page you are on: a short summary, what the feature actually does once enabled, numbered setup steps, and the caveats worth knowing before you switch something on.

= What does turning a module off actually do? =
A module that is off loads none of its code, registers no REST routes and shows no menu entry — so features you do not use cost nothing. Its settings are kept, so switching it back on restores your configuration exactly as it was. Menu entries appear and disappear as you toggle, without reloading the page.

= Will the firewall lock me out? =
No. Logged-in administrators are never blocked by the IP blocklist or auto-bans, and aggressive options default to off so you can opt in deliberately.

= Which settings could break my site if I enable them carelessly? =
The ones the in-plugin guides call out: a custom login URL (save the new address first), an admin IP allowlist on a dynamic home connection, an enforced Content-Security-Policy, HSTS preload, and country blocking applied to the whole site rather than just the login. Each of those is explained in the help drawer on its own page.

= Does it work without GemSecurity Pro? =
Yes. Everything described above works in the free plugin. Pro adds active threat protection, malware remediation and scale features.

== Changelog ==

= 1.0.0 - 28/09/2026 =
* Added - CAPTCHA is its own module, with its own page, instead of a card under Login Security. Sites that already use CAPTCHA keep it after the update.
* Added - A Notifications page for alert recipients, Slack, Telegram and webhook delivery, and scheduled reports. These used to be on the Settings page.
* Added - A daily report email, off by default. It lists every administrator and active plugin, and calls out any that were added or removed since the last report.
* Added - An alert when GemSecurity is deactivated, by email and through Slack, Telegram or the webhook when alerts are on. With extended protection on, the mu-plugin also sends a warning when the plugin is switched off without being deactivated normally, for example by editing the database.
* Added - Admin Guard removes administrators who are not on the whitelist every hour, and again whenever the whitelist changes. The "Check for unapproved admins" button lists who would be removed before anything happens.
* Added - Forced password resets, by role. A reset ends every session for those users and emails each of them a WordPress reset link. It can run on demand, or on a schedule for passwords older than a set number of days.
* Added - Test buttons for third-party settings, run before you save: CAPTCHA keys (with the real widget), social login app keys, Slack, Telegram, webhook, SIEM, alert email addresses, and the outside services the scanner and geolocation rely on.
* Added - The Scanner checks .htaccess files for rules that allow PHP to run or redirect visitors. A malicious file can be quarantined in one click and restored from Incident Response. The site's root .htaccess is reported for hand-editing instead, because it holds the permalink rules.
* Added - A file you have reviewed can be marked safe in the Scanner. If the file changes later, it is reported again. Empty "Silence is golden" index.php files are no longer reported.
* Added - Every item under "What needs your attention" on the dashboard links to the page where it is fixed.
* Added - A guide for every module in a help drawer, and setup guides beside the fields that need keys from another service.
* Added - Social login buttons can ask for a role for new accounts, and the `gemsecurity/social_login/role_registered` action fires after such an account is created.
* Changed - Each setting now lives on one page. The WAF rules, rate limiting, 404 throttling and bad-bot switches moved to the Firewall page (they were on the Pro-only Threat Defense page), the audit log switches to the Logs page, and the backup settings to the Backup page. Features that existed twice, such as the comment honeypot, the application password switch, quarantine and force logout, are now one. Your settings are carried over on update.
* Changed - All emails use one HTML template, and each subject names the site and its domain.
* Changed - With a custom login URL, a logged-out visit to wp-admin goes to the home page. If you are locked out, adding `define( 'GEMSECURITY_DISABLE_CUSTOM_LOGIN', true );` to wp-config.php turns the custom login URL off.
* Changed - A wrong CAPTCHA secret key no longer locks everyone out of the login form. Verification is skipped and the problem is logged as critical until the key is fixed.
* Changed - The Virtual Patch list is titled "Shields currently active" and no longer shows red severity badges, so it does not read as a list of problems.
* Changed - The StoreEngine license SDK is updated to 1.5.6. It now ships only in GemSecurity, and GemSecurity Pro uses this copy.
* Fixed - With a custom login URL, visiting wp-admin while logged out redirected to the secret login address.
* Fixed - A custom login URL with spaces or capitals was previewed as one address and served at another. A URL that became empty after cleaning left the switch on while wp-login.php stayed open.
* Fixed - A custom login URL broke two-factor and social login sign-ins.
* Fixed - A correct two-factor code could send the user back to the login form, and a correct emailed code could be reported as invalid, on hosts whose object cache is not shared between requests. Emailed codes are now limited to five attempts.
* Fixed - A failed social login always said "Sign-in could not be verified". It now gives the real reason, including the provider's own error.
* Fixed - Twitter/X sign-in stopped working after X retired its twitter.com sign-in addresses, and the credential test reported correct Twitter/X keys as wrong.
* Fixed - The CAPTCHA key test could fail with reCAPTCHA because the widget was drawn before Google's script was ready.
* Fixed - Alerts were never emailed, only sent to Slack, Telegram and the webhook.
* Fixed - An administrator who was not on the Admin Guard whitelist could still sign in if the account was created outside WordPress's normal user screens.
* Fixed - The Scanner reported WordPress core files as malware. After a core update, it showed every core file as modified until the next scan, and it did not scan again after the update when the daily scan was off.
* Fixed - Warnings alone could drop the security score to F.
* Fixed - Opening the Scanner page froze the admin, so no other menu item could be opened.
* Fixed - On a new site, the backup settings showed switches that are on by default as off, and saving that screen would have turned off the snapshot taken before a restore.
* Fixed - Switching a module on or off needed a page reload before the menu changed.
* Fixed - Virtual Patch, Payment Integrity, Incident Response and Monitoring appeared unlocked without GemSecurity Pro.
* Fixed - WordPress 6.7 and later logged a notice on every request because translations were loaded too early.

= 1.0-beta1 - 13/08/2026 =
First public beta. GemSecurity is an all-in-one, registry-driven security suite with a single-page React dashboard, live security score and a toggleable module manager.

* Added - Firewall & WAF: SQLi/XSS/LFI/RCE request inspection, IP blocklist (CIDR), request rate limiting, 404-flood throttling, bad-bot and AI-crawler blocking, search-bot verification.
* Added - Hardening: disable XML-RPC / file editor / author & REST user enumeration, hide WP version, application-password governance, and security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS, CSP).
* Added - Login Security: brute-force lockouts, session limits & idle timeout, password policy, custom login URL, admin-login email alerts, magic-link and lockdown.
* Added - Two-Factor Authentication: app-based TOTP, email OTP and one-time backup codes with per-role enforcement; login CAPTCHA (reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile).
* Added - Social Login: OAuth sign-in with Google, Facebook, GitHub and Twitter/X.
* Added - Admin Guard: rogue-admin auto-remediation, administrator whitelist and hidden-admin detection.
* Added - API & Access hardening: REST API rate limiting, application-password max-age, username-enumeration and generic-login-error protection.
* Added - Anti-Spam: frictionless bot checks on comments and registration with heuristic filtering.
* Added - Scanner: WordPress core file-integrity checks against official checksums, uploads malware/PHP-pattern scan, file-change detection, link scanning, and known-vulnerability scanning for core/plugins/themes.
* Added - Activity Logs & real-time Alerts with retention and CSV export.
* Added - Backups: manual database / files / full-site backups, restore, download, daily local schedule, retention, exclude paths/tables and pre-update automatic backups.
* Added - Module manager with a live security score and one-page dashboard.

Active threat defense, virtual patching, geolocation access control, payment-integrity monitoring, incident response, uptime/TLS monitoring, signature malware remediation & quarantine, database-injection scan, file integrity vs WordPress.org, recovery toolkit, and cloud backup storage with encryption & migration are available in GemSecurity Pro.
