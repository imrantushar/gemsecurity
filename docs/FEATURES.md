# GemSecurity — Implemented Features

All-in-one WordPress security plugin. Version **1.0.0**, DB schema **1.6**.
This list reflects what is **actually shipped in the code** (15 modules, 11 admin pages, REST API + React SPA), cross-checked against `docs/SECURITY-ROADMAP.md`.

## Architecture
- Single-page React admin (Redux) with StoreEngine-style client-side routing — no page reloads.
- REST API backend (`includes/rest/`) — dashboard, settings, logs, bans, sessions, admins, scanner, geolocation, social, two-factor.
- Module-based PHP core (`includes/modules/`), runs on both front-end and admin requests.
- Custom DB tables + installer/uninstaller with full cleanup.

## Admin Pages (11)
Dashboard · Firewall · Threat Defense · Login Security · Two-Factor · Social Login · Geolocation · Admin Guard · Scanner · Logs · Settings

---

## Done Features

### Firewall & Hardening
- IP blocklist with CIDR range support.
- Hardening toggles: disable XML-RPC, disable file editor, block author/REST user enumeration, hide WP version, disable application passwords.
- **Security headers** — X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS, CSP (report-only by default).

### WAF (Web Application Firewall)
- Request inspection for SQLi / XSS / LFI / RCE patterns.
- Rate limiting + 404-flood throttle.
- Bad-bot blocking.

### Threat Defense (auto-bans)
- Escalating auto-bans: strikes → temporary → permanent bans (custom ban-ledger table).
- Manual ban manager UI.
- **Extended protection mu-plugin** — early firewall that blocks banned/malicious requests before other plugins load; auto-installed/removed; fail-open.

### Login Security
- Brute-force lockout.
- Admin-login email alert.
- 24h admin session timeout.
- **Login CAPTCHA** — reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile (login / registration / lost-password).
- **Custom login URL** — rename `wp-login.php`, 404 the default.

### Two-Factor Authentication
- App TOTP (RFC 6238, no external libs) + email OTP fallback.
- Login-challenge interstitial.
- One-time backup codes.
- Enforce-by-role (email-OTP fallback to avoid lockout).

### Social / OAuth Login
- Google, Facebook, GitHub, Twitter (OAuth 2.0 + PKCE for Twitter).
- Single fixed redirect URI, link-by-email, auto-provisioning.
- Fires `wp_login` so 2FA / alerts still apply.

### Geolocation Access Control
- Self-contained IP→country resolver (CDN headers → free API, 24h cache, fail-open).
- Country whitelist as a login gate and/or whole-site 403.
- Per-user location lock (admin-assigned countries) with email-verify on a new country.
- Defaults off; admins exempt; `GEMSEC_GEO_DISABLE` kill-switch.

### Admin Guard
- Administrator whitelist.
- Rogue-admin auto-delete / demote.

### Scanner
- WP core file integrity check (checksums).
- Uploads malware / PHP-pattern scan.
- **Known-vulnerability scanner** — core/plugins/themes vs the free wpvulnerability.net feed (cached, fail-soft) + daily cron.

### Password Policy
- Length / complexity / expiry rules.
- Breached-password check via Have I Been Pwned (k-anonymity).

### Session Management
- List / end your own sessions.
- Force-logout users.
- Idle-timeout (distinct from the 24h absolute timeout).

### Activity Log / Audit
- Expanded audit log: content edits, plugin/theme changes, user changes, option/settings changes.
- Category filter on the Logs page.
- Log retention + **CSV export**.

### Alerts
- Alert channels: Slack / Telegram / generic webhook.
- Weekly email security digest.

### Lockdown / Maintenance
- Lockdown/maintenance mode — 503 for non-admins.
- Pre-update backup trigger (GemBackup integration).

### Dashboard
- Security score, stats, activity trend.

### Lifecycle
- Full uninstall cleanup (`uninstall.php`).

### Integrations
GemSecurity itself has no Academy-specific code — no module, no hooks into Academy's actions. Instead it exposes a small public API surface any companion plugin can call:
- `GemSecurity\Modules\LoginSecurity::is_locked_out( $ip )` — the shared brute-force ban ledger, callable directly.
- `GemSecurity\Modules\Captcha::verify_token( $token )` — verifies an explicit token against the configured CAPTCHA provider.
- `GemSecurity\Modules\Waf::scan_string( $value )` — runs the SQLi/XSS/LFI/RCE pattern check against an arbitrary string.
- Public filter `gemsecurity/module_active` (`bool apply_filters( 'gemsecurity/module_active', false, string $module_id )`) — lets a companion plugin query whether a given GemSecurity module is active. Registered unconditionally whenever GemSecurity is active — no gating module required.

Academy LMS's own `Academy\Integration\GemSecurity` class (in the `academy` plugin, not this one) is the first consumer: brute-force lockout on Academy's login (Free), plus WAF content scanning on Q&A/lesson comments, geo-blocking on Academy's public REST routes, enrollment-fraud alerting, and AJAX rate limiting (Pro, checked at runtime via `is_pro_active()`). It no-ops entirely when GemSecurity isn't active. CAPTCHA for Academy is intentionally not part of this surface — Academy Pro already has its own complete reCAPTCHA implementation.

---

## Not Yet Done (open / lower priority)
- File-change baseline/diff + quarantine/repair of modified core files.
- Plugin/theme file integrity vs the WP.org repo (only core is checked today).
- 2FA for non-admin roles via a front-end enrollment page.
- Multisite support.
- Full i18n pass.
- Granular capabilities (everything currently gated on `manage_options`).
- SIEM streaming.
