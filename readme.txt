=== GemSecurity ===
Contributors: kodezen, tusharimran
Tags: security, firewall, two factor authentication, malware scanner, backup
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPL-3.0+
License URI: http://www.gnu.org/licenses/gpl-3.0.txt

Firewall, 2FA, malware scanner, login security and backups — one dashboard, one plugin, zero bloat.

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

= The Kodezen Ecosystem — Everything Works Together, Natively =

GemSecurity is part of a connected family of WordPress plugins built to run your whole business from one platform:

* [GemCRM](https://gemcrm.net/) — CRM, email marketing, newsletters and marketing automation
* [StoreEngine](https://storeengine.pro/) — sell digital & physical products, subscriptions, and memberships
* [Academy LMS](https://academylms.net/) — the top-rated WordPress LMS to create, sell, and manage courses
* [aBlocks](https://ablocks.pro/) — design fast, high-performance pages with 100+ Gutenberg blocks, no code
* [ZenCommunity](https://zencommunity.pro/) — communities, discussions, support tickets, and live chat
* [QuizPress](https://quizpress.pro/) — advanced quizzes, polls, surveys, and exams, 20+ question types
* [GameEngine](https://gameengine.pro/) — gamify engagement with points, badges, levels, and rewards
* [ZenAppBuilder](https://academylms.net/zenappbuilder/) — turn your Academy LMS site into a native mobile app
* [GemBooking](https://gembooking.net/) — accept and automate bookings for appointments and services
* [GemBoards](https://gemboards.com/) — manage projects, tasks, and teams with modern Kanban boards
* [Easy Content Manager (ECM)](https://easycontentmanager.pro/) — build custom post types, fields, and taxonomies, no code
* [Zaplane](https://zaplane.app/) — automate WordPress workflows across your favorite apps, no code

== External services ==

GemSecurity connects to the services below only for the feature named, and only after you turn that feature on. Nothing is sent on a default install except the WordPress.org lookups used by the vulnerability and plugin checks.

= CAPTCHA (Login & Access → CAPTCHA) =
When CAPTCHA is enabled, the provider's script loads on the login, registration and lost-password forms, and the CAPTCHA response token plus the visitor's IP address are sent to the provider to verify each submission.

* Google reCAPTCHA — [Terms](https://policies.google.com/terms), [Privacy](https://policies.google.com/privacy)
* hCaptcha — [Terms](https://www.hcaptcha.com/terms), [Privacy](https://www.hcaptcha.com/privacy)
* Cloudflare Turnstile — [Terms](https://www.cloudflare.com/website-terms/), [Privacy](https://www.cloudflare.com/privacypolicy/)

= Social login (Login & Access → Social Login) =
When a visitor signs in with a provider, the OAuth authorization code is sent to that provider and the user's name, email and avatar are returned to your site.

* Google — [Terms](https://policies.google.com/terms), [Privacy](https://policies.google.com/privacy)
* Facebook (Meta) — [Terms](https://www.facebook.com/terms.php), [Privacy](https://www.facebook.com/privacy/policy/)
* GitHub — [Terms](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service), [Privacy](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)
* X (Twitter) — [Terms](https://x.com/en/tos), [Privacy](https://x.com/en/privacy)

= Vulnerability scanner =
The slug and version of each installed plugin and theme, and your WordPress version, are sent to WPVulnerability to look up known vulnerabilities. [Terms and privacy](https://www.wpvulnerability.com/privacy/)

= Plugin and file integrity checks =
Plugin/theme slugs and versions are sent to WordPress.org to fetch official checksums, package details and original files for comparison. [Terms](https://wordpress.org/about/domains/), [Privacy](https://wordpress.org/about/privacy/)

= Breached-password check (Password Policy) =
When enabled, the first 5 characters of the SHA-1 hash of a new password are sent to Have I Been Pwned. The password itself never leaves your site. [Terms and privacy](https://haveibeenpwned.com/Privacy)

= Geolocation (Firewall → Geolocation) =
When country blocking is enabled, the visitor's IP address is sent to ip-api.com, falling back to ipapi.co, to look up the visitor's country. [ip-api.com terms](https://ip-api.com/docs/legal), [ipapi.co terms](https://ipapi.co/terms/), [ipapi.co privacy](https://ipapi.co/privacy/)

= Alerts (Notifications) =
When you add a Slack webhook or Telegram bot, security alert text (event, user, IP address and time) is sent to that channel.

* Slack — [Terms](https://slack.com/terms-of-service), [Privacy](https://slack.com/trust/privacy/privacy-policy)
* Telegram — [Terms](https://telegram.org/tos), [Privacy](https://telegram.org/privacy)

= Usage insights (opt-in) =
Only if you accept the opt-in notice, GemSecurity sends usage data to Kodezen at store.kodezen.com. This includes your site URL and name, the admin's name and email, the server IP, WordPress, PHP, database and server versions, the site language, active theme, and active and inactive plugins. If you choose to give feedback when deactivating, that feedback is sent too. Nothing is sent if you decline. [Terms](https://kodezen.com/terms-and-conditions/), [Privacy](https://kodezen.com/privacy-policy/)

== Source code and libraries ==

The admin JavaScript in `assets/build/` is compiled. Its human-readable source is included in the `dev_gemsecurity/` folder. To rebuild it, run `npm install` and then `npm run build`.

GemSecurity bundles these open-source libraries:

* [Redux Toolkit](https://github.com/reduxjs/redux-toolkit), [Redux](https://github.com/reduxjs/redux) and [React Redux](https://github.com/reduxjs/react-redux) — MIT
* [React Router](https://github.com/remix-run/react-router) — MIT
* [React Select](https://github.com/JedWatson/react-select) and [Emotion](https://github.com/emotion-js/emotion) — MIT
* [Axios](https://github.com/axios/axios) — MIT
* [qrcode.react](https://github.com/zpao/qrcode.react) — ISC
* [StoreEngine WordPress SDK](https://store.kodezen.com/) — GPL-3.0-or-later

React and WordPress packages are loaded from WordPress core, not bundled.

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

= 1.1.0 - 19/10/2026 =
* Added - Plugin Guard verifies every plugin against WordPress.org checksums with a trust list for premium, custom, theme and must-use plugins. With enforcement on, untrusted plugins are stopped before they load and deactivated, activation and non-.org installs are refused, unknown mu-plugins are quarantined, and a danger alert is sent. Runs from an early mu-plugin loader.
* Added - Install Lock blocks zip uploads, all installs, or every file modification for every account, with a logged 15-minute timed unlock.
* Added - Upload Shield (on by default) refuses executable files on every upload path, PHP hidden in images and scripted SVG, and writes uploads/.htaccess deny rules with a live PHP-execution probe and an nginx snippet.
* Added - A first-run setup wizard (welcome, protection level, features, alerts, summary) opens once after a fresh activation and is reachable again from the topbar; pre-wizard installs are marked legacy.
* Added - The admin menu is grouped into Dashboard, Firewall, Login & Access, Scanning, Logs & Monitoring and Settings. The WordPress sidebar shows one entry per group; existing module URLs keep working.
* Added - The audit log records how every event arrived (admin, REST, REST via application password, XML-RPC, AJAX, WP-CLI, cron), the user agent, and a short login session id, via a new `gemsecurity/log_args` filter.
* Added - Edits to live posts log a field-level diff (title, slug, content snippet, excerpt, author, date, parent, password, comments) and link the revision to compare or restore. New outbound links are listed and raise the event to warning.
* Added - SEO meta (title and description, canonical, robots, redirect, focus keyword), page template and featured image changes are logged. User creation, role changes (admin promotions at warning) and email or password changes are logged.
* Added - The Logs page lets you click a user to see everything they did, see the full history of a post, and expand a details row.
* Added - A public page picker for the custom login URL. Logged-out login, lost-password and register links on public pages point at the chosen public page (default: homepage) and the logout link at the homepage, so the secret address is no longer printed to visitors and bots. New filter `gemsecurity/custom_login_public_url`.
* Added - Front-end login forms outside wp-login.php are redirected to the 2FA challenge instead of skipping it. REST endpoints that run their own challenge (such as Academy's `/academy/v1/login`) can opt out via `gemsecurity/2fa_challenge_routes` and `gemsecurity/2fa_external_challenge`.
* Changed - 2FA seeds are sealed with AES-256-GCM. The key lives in `GEMSECURITY_SECRET_KEY` or a wp-content key file, not the database and not the WordPress salts, so salt rotation can no longer lock users out. Existing seeds are migrated on admin load.
* Changed - Password logins that cannot show the 2FA challenge (XML-RPC, HTTP basic auth, REST, AJAX popups) are refused for 2FA users; application passwords still work.
* Changed - Security headers are now added to REST responses, served before `send_headers` ever fires; endpoint-set headers are kept.
* Changed - Upload Shield's no-exec `.htaccess` now also covers wp-includes (core's wp-tinymce.php and ms-files.php stay allowed), languages and upgrade; removing it leaves other tools' rules byte-for-byte intact.
* Changed - Backups move back to the standalone GemBackup plugin. The Backup module, page, REST routes and tables are gone from GemSecurity. When GemBackup is active, the pre-update backup option, Incident Response roll back and the security score's recent-backup check are kept and link to GemBackup. Uninstall no longer drops backup tables, archives or GemBackup's cron events.
* Changed - Backup notification settings are removed from the Notifications page; they live in GemBackup's own settings.
* Changed - Finder (database and site scan) now searches the whole install (web root, core directories, every theme and stray folders) and more database tables.
* Changed - Admin UI adopts the GemCRM color system in light and dark, with border-only surfaces, 8px card radius and 4px buttons and inputs. Hard-coded semantic tints (alerts, badges, breach rows, danger buttons, threat items) use `color-mix()` on tokens so they follow both themes; brand gradients are replaced with solid brand blue.
* Fixed - A self-posting front-end login form has no referer, so the 2FA challenge used to send users to the dashboard; it now returns them to the requested URL.
* Fixed - `/logs` never returned the user display name, so the log never showed who did anything (a by-reference loop over an `(array)` cast wrote to a copy).

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
