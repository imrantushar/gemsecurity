# GemSecurity — Implemented Features

All-in-one WordPress security plugin. Version **1.0-beta1**, DB schema **2.0**.
This list reflects what is **actually shipped in the code** — 20 modules, 20 admin pages,
REST API + React SPA — audited against `includes/modules/registry.php` and the page
components in `dev_gemsecurity/containers/pages/`.

User-facing documentation lives in the plugin itself: `includes/modules/docs.php` holds a
per-module guide (what it does / how to set it up / what to watch out for), served over
`GET /gemsecurity/v1/docs` and shown in the help drawer behind the topbar "?" button.
**When you add a module, add its docs entry too** — `Docs::for_js()` is what the drawer reads.

## Architecture
- Single-page React admin (Redux) with client-side routing — no page reloads.
- REST API backend (`includes/rest/`), namespace `gemsecurity/v1`. Route groups are
  registered per module, so a deactivated module has no endpoints at all.
- Module-based PHP core (`includes/modules/`), running on both front-end and admin requests.
- `Modules\Registry` is the single source of truth: one descriptor per module feeds the boot
  loop, the WordPress menu, REST registration and the React nav at once.
- Custom DB tables + installer/uninstaller with full cleanup.

## Modules (20)

Core modules are always on. Pro modules show as a locked upsell until the Pro add-on is
active; after that they toggle like any other module — and a module that is off registers
no page, no menu entry and no routes.

| Module | Page | Tier |
| --- | --- | --- |
| Dashboard | `gemsecurity` | Core |
| Modules | `gemsecurity-modules` | Core |
| Firewall | `gemsecurity-firewall` | Free |
| Anti-Spam | `gemsecurity-anti-spam` | Free |
| Threat Defense | `gemsecurity-threats` | Pro |
| Virtual Patch | `gemsecurity-virtual-patch` | Pro |
| Login Security | `gemsecurity-login-security` | Free |
| Two-Factor | `gemsecurity-two-factor` | Free |
| Social Login | `gemsecurity-social-login` | Free |
| Geolocation | `gemsecurity-geolocation` | Pro |
| Admin Guard | `gemsecurity-admin-guard` | Free |
| API & Access | `gemsecurity-api-hardening` | Free |
| Scanner | `gemsecurity-scanner` | Free (Pro malware tab) |
| Payment Integrity | `gemsecurity-payment-integrity` | Pro |
| Incident Response | `gemsecurity-incident-response` | Pro |
| Logs | `gemsecurity-logs` | Core |
| Backup | `gemsecurity-backup` | Free (Pro cloud storage) |
| Monitoring | `gemsecurity-monitoring` | Pro |
| Pro Tools | `gemsecurity-pro-tools` | Pro |
| Settings | `gemsecurity-settings` | Core |

---

## Done Features

### Firewall & Hardening
- IP blocklist with CIDR range support.
- Real visitor IP detection — forwarding headers are honoured only behind a proxy the site
  owner explicitly trusts (Cloudflare, or a custom trusted-proxy list).
- Hardening toggles: disable XML-RPC, disable file editor, block author/REST user
  enumeration, hide WP version, disable application passwords, disable comments.
- Security headers — X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy, HSTS (max-age / subdomains / preload), CSP (report-only by default)
  with a violation-report collector.
- Bot control — AI-crawler blocking and reverse-DNS verification of self-declared search bots.
- `security.txt` publishing (contact / expires / policy) and a read-only file-permission audit.

### Anti-Spam
- Silent honeypot + minimum time-to-submit on comments and registration.
- Heuristic comment scoring on link count and keyword matches.

### WAF & Threat Defense (Pro)
- Request inspection for SQLi / XSS / LFI / RCE patterns, optionally including the request body.
- Rate limiting + 404-flood throttle.
- Bad-bot blocking, empty user-agent blocking and custom bot patterns.
- Escalating auto-bans: strikes → temporary → permanent, in a ban-ledger table with a manual
  ban manager UI.
- Extended-protection mu-plugin — early firewall that blocks banned/malicious requests before
  other plugins load; auto-installed/removed; fail-open.
- Anomaly scoring, credential-stuffing detection and a Live Traffic view.

### Virtual Patching (Pro)
- Mitigation rules matched against the installed plugin/theme and version, so only relevant
  rules are applied.
- Active-mitigation list with severity; extensible through the `gemsecurity/vpatch_rules` filter.

### Login Security
- Brute-force lockout with configurable attempt limit and lockout duration.
- Admin-login email alert; absolute admin session timeout; idle session timeout.
- Login CAPTCHA — reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile (login / registration /
  lost-password / comments) with a v3 score threshold.
- Password policy — minimum length, complexity, expiry, and a breached-password check via
  Have I Been Pwned (k-anonymity).
- Custom login URL (rename `wp-login.php`, 404 the default) and a login honeypot.
- Session management — list/end your own sessions, force-logout users.
- Pro: trusted devices (with alerts) and magic-link recovery.

### Two-Factor Authentication
- App TOTP (RFC 6238, no external libs) + email OTP fallback.
- Login-challenge interstitial and one-time backup codes.
- Enforce-by-role, with email-OTP fallback to avoid lockout.

### Social / OAuth Login
- Google, Facebook, GitHub, Twitter/X (OAuth 2.0 + PKCE for Twitter).
- Single fixed redirect URI, link-by-email, auto-provisioning with a configurable default role.
- Fires `wp_login`, so 2FA / alerts still apply.

### Geolocation Access Control (Pro)
- Self-contained IP→country resolver (CDN headers → free API, 24h cache, fail-open).
- Country whitelist as a login gate and/or whole-site 403, with an option for unknown locations.
- Per-user location lock with email-verify on a new country.
- Defaults off; admins exempt; `GEMSEC_GEO_DISABLE` kill-switch.

### Admin Guard
- Administrator whitelist with rogue-admin auto-delete / demote.
- Hidden-administrator detection.
- Email notification for both.

### API & Access Hardening
- REST API rate limiting (max requests per window, per IP).
- Application-password governance — inventory, disable outright, alert on creation, maximum age.
- Generic login errors, so an invalid username cannot be distinguished from a wrong password.

### Scanner
- WP core file integrity check against official WordPress.org checksums.
- Unexpected/foreign file and suspicious-pattern detection.
- File-change watcher between scans; outbound link scanning.
- Known-vulnerability scanner for core/plugins/themes (cached, fail-soft) + daily cron.
- mu-plugins and drop-ins inspection (code that runs without appearing on the Plugins screen).
- Supply chain — installed plugins checked against what WordPress.org actually ships, plus
  persistence checks.
- Pro: signature malware scan, database-injection findings, quarantine and a recovery toolkit.

### Payment Integrity (Pro)
- Client-side script inventory for nominated checkout/payment pages.
- Baseline authorisation and unauthorised-script reporting (PCI DSS 4.0 §6.4.3 / §11.6.1).

### Incident Response (Pro)
- Forensic timeline built from the audit log.
- File quarantine to a protected uploads folder (move, not delete).
- Log-everyone-out recovery action, invalidating stolen session cookies.

### Activity Log / Audit
- Audit log covering content edits, plugin/theme changes, user changes and settings changes.
- Severity/category filters, retention and CSV export.
- Pro: hash-chained entries (tamper-evidence) with a verify endpoint, SIEM/syslog forwarding
  and a compliance report.

### Alerts
- Channels: email, Slack, Telegram, generic webhook.
- Minimum-severity filter and an email digest.

### Backup
- Manual database / files / full-site backups; restore and download.
- Scheduled backups with retention, exclude paths/tables and a backup activity log.
- Pre-update automatic backup (fires before plugin/theme/core updates).
- Pro: cloud storage — Amazon S3, Backblaze B2, Cloudflare R2, Dropbox, Google Drive,
  OneDrive, FTP — plus encryption, migration (search-replace), multiple schedules and
  restore-from-cloud.

### Monitoring (Pro)
- Uptime, TLS-certificate expiry, DNS-change and SPF/DMARC checks on a daily cron.
- Alert address for warnings.

### Pro Tools (Pro)
- Admin IP allowlist; block sensitive files; block PHP execution in uploads; force HTTPS.
- File-change baseline over configurable scopes.
- Auto-update enforcement — vulnerable plugins only, or all plugins/themes.
- Settings import / export.

### Lockdown / Maintenance
- Lockdown/maintenance mode — 503 for non-admins, with a custom message.

### Dashboard
- Security score, stats, 7-day activity trend, recent events and last-scan result.

### Module manager
- Per-module activation stored in `gemsecurity_active_modules`, with menu, REST routes and
  boot all derived from it.
- Toggling a module updates the plugin nav and the WordPress admin menu immediately, with no
  page reload.

### In-product documentation
- Per-module guide (summary / what it does / setup steps / caveats) in
  `includes/modules/docs.php`, filterable via `gemsecurity/docs`.
- `GET /gemsecurity/v1/docs` returns the guides for visible modules, keyed by page slug.
- Help drawer on every page (topbar "?"), fetched lazily and cached for the session.

### Lifecycle
- Full uninstall cleanup (`uninstall.php`).

### Integrations
GemSecurity has no plugin-specific code for its consumers. It exposes a small public API
surface any companion plugin can call:
- `GemSecurity\Modules\LoginSecurity::is_locked_out( $ip )` — the shared brute-force ban
  ledger. Static.
- `( new GemSecurity\Modules\Captcha() )->verify_token( $token )` — verifies an explicit token
  against the configured provider. **Instance method**, not static.
- `( new GemSecurity\Modules\Waf() )->scan_string( $value )` — runs the SQLi/XSS/LFI/RCE
  pattern check against an arbitrary string. **Instance method**, not static.
- Public filter `gemsecurity/module_active`
  (`bool apply_filters( 'gemsecurity/module_active', false, string $module_id )`) — lets a
  companion plugin query whether a module is active. Registered unconditionally whenever
  GemSecurity is active — no gating module required.
- Extension filters: `gemsecurity/modules` (register a module), `gemsecurity/docs` (its help
  guide), `gemsecurity/admin_menu_list`, `gemsecurity/vpatch_rules`, `gemsecurity/upgrade_url`.

Academy LMS's own `Academy\Integration\GemSecurity` class (in the `academy` plugin, not this
one) is the first consumer: brute-force lockout on Academy's login (Free), plus WAF content
scanning on Q&A/lesson comments, geo-blocking on Academy's public REST routes,
enrollment-fraud alerting and AJAX rate limiting (Pro, checked at runtime via
`is_pro_active()`). It no-ops entirely when GemSecurity isn't active. CAPTCHA for Academy is
intentionally not part of this surface — Academy Pro already has its own reCAPTCHA
implementation.

---

## Not Yet Done (open / lower priority)
- Multisite support (network-level settings; per-site only today).
- Granular capabilities — every REST route and page is gated on `manage_options`.
- Front-end 2FA enrollment page for non-admin roles (enrollment lives in the admin today).
- Repair of modified core files (they are detected and can be quarantined, not restored
  file-by-file).
- Backup: one-click restore into staging, and white-label PDF reports.

## Recently closed (previously listed as open)
- File-change baseline/diff — shipped in Pro Tools.
- Quarantine of modified/malicious files — shipped in the Pro malware scanner and Incident
  Response.
- Plugin/theme integrity vs the WordPress.org repo — shipped in Scanner → Supply chain.
- SIEM streaming — shipped in Settings → Compliance & SIEM.
- i18n pass — `languages/gemsecurity.pot` is generated and strings are wrapped.
