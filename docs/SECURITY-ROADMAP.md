# GemSecurity — Security Feature Roadmap

Status legend: ✅ shipped · 🔜 next sprint · ⭐ value (1–3) · ⚙️ effort (S/M/L)

## Already shipped (v1.0)
- ✅ Firewall: IP blocklist (+CIDR), hardening toggles (XML-RPC, file editor, author/REST enumeration, hide version, app passwords)
- ✅ Login Security: brute-force lockout, admin-login email alert, 24h admin session timeout
- ✅ Admin Guard: administrator whitelist + rogue-admin auto-delete/demote
- ✅ Scanner: WP core file integrity (checksums) + uploads malware/PHP pattern scan
- ✅ Activity log + retention, Dashboard (security score, stats, trend)
- ✅ StoreEngine-style client-side routing (no page reloads)

## Shipped in v1.1 (Tier-0 sprint + social login)
- ✅ **Two-Factor Authentication** — app TOTP (RFC 6238, no libs) + email OTP, login-challenge interstitial, one-time backup codes, enforce-by-role (email-OTP fallback so no lockout). Pages: *Two-Factor*.
- ✅ **Security headers** — X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS, CSP (report-only default). On the *Firewall* page.
- ✅ **Login CAPTCHA** — reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile on login/registration/lost-password. On the *Login Security* page.
- ✅ **Expanded audit log** — content, plugin/theme, user, and option changes; category filter on the *Logs* page.
- ✅ **Social/OAuth login** — Google, Facebook, GitHub, Twitter (OAuth 2.0 + PKCE for Twitter); single fixed redirect URI, link-by-email, auto-provisioning, fires `wp_login` so 2FA/alerts apply. Page: *Social Login*.
- ✅ **Geolocation access control** — self-contained IP→country resolver (CDN headers → free API, 24h cache, fail-open). Country whitelist as a login gate and/or whole-site 403; per-user location lock (admin-assigned countries) with email-verify on a new country. Defaults off; unknown/local IPs allowed; admins exempt; `GEMSEC_GEO_DISABLE` kill-switch. Page: *Geolocation*. (Supersedes the Tier-1 "Country/GeoIP blocking" item.)

---

## Tier 0 — Highest impact, fills the biggest credibility gaps

| Feature | Extends | ⭐ | ⚙️ | Notes |
|---|---|---|---|---|
| 🔜 **Two-Factor Authentication (2FA)** | Login Security | 3 | L | TOTP (Authenticator apps) + email OTP fallback; per-user enrolment, enforce-by-role, backup codes. The #1 missing feature vs competitors. |
| 🔜 **Known-vulnerability scanner** | Scanner | 3 | M | Cross-reference installed core/plugin/theme versions against a CVE feed (WPScan/Patchstack API, BYO key). "You have 2 vulnerable plugins." |
| 🔜 **Security headers** | Firewall | 3 | S | CSP (report-only→enforce), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS, Permissions-Policy — toggles + presets. |
| 🔜 **CAPTCHA on login/registration** | Login Security | 3 | M | reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile on login, registration, lost-password, comments. |
| 🔜 **Expanded audit log** | Logger | 3 | M | Track post/page edits, plugin/theme activate-deactivate-update, role/user changes, option & settings changes, file edits, exports. Currently only security events are logged. |

## Tier 1 — Strong value, natural extensions

| Feature | Extends | ⭐ | ⚙️ | Notes |
|---|---|---|---|---|
| **Escalating auto-bans** | Firewall + Logger | 3 | M | Auto-blocklist IPs that trigger N security events; temporary → permanent bans; ban list UI with manual add/remove + expiry. |
| **404 / rate-limit throttling** | Firewall | 2 | M | Lock out IPs hammering 404s (vuln scanners) and global per-IP request rate limiting beyond login. |
| **Country / GeoIP blocking** | Firewall | 2 | M | Block or allow-list by country; needs a GeoIP DB or IP-geolocation API. |
| **Plugin & theme file integrity** | Scanner | 2 | M | Diff installed plugins/themes against the WP.org repo (not just core); flag modified/injected files; quarantine + restore. |
| **Custom login URL** | Login Security | 2 | S | Rename `wp-login.php`; 404 the default; closes automated login attacks. |
| **Session management** | Login Security | 2 | M | Per-user active-session list, force-logout (single/all), "log out everywhere" on password change. |
| **Idle session timeout** | Login Security | 2 | S | Inactivity-based logout (distinct from the 24h absolute timeout already shipped). |
| **Password policy** | Login Security | 2 | M | Min length/complexity, expiry, reuse ban, breached-password check via HaveIBeenPwned k-anonymity. |
| **Real-time alert channels** | Logger | 2 | S | Send critical events to Slack / Telegram / generic webhook, not just email. |
| **Block sensitive file access** | Firewall | 2 | S | Deny `readme.html`, `*.sql`, `debug.log`, `wp-config` backups, and PHP execution in `/uploads`. |

## Tier 2 — Nice-to-have / polish

| Feature | Extends | ⭐ | ⚙️ | Notes |
|---|---|---|---|---|
| **One-click hardening** | Settings | 2 | S | "Apply recommended settings" button + per-item revert; raises the dashboard score in one click. |
| **Weekly security digest** | Logger | 2 | S | Scheduled email summary (scans, blocks, lockouts, pending updates). |
| **Outdated software alerts** | Scanner | 2 | S | Flag core/plugins/themes needing updates; optional auto-update enforcement. |
| **Restrict wp-admin by IP** | Firewall | 2 | S | Allow-list admin-area access to specific IPs (with self-lockout guard like Admin Guard). |
| **Database / content scan** | Scanner | 2 | M | Detect injected spam links or malicious JS in posts/options. |
| **Settings import/export** | Settings | 1 | S | Back up & migrate GemSecurity config as JSON. |
| **Disable XML-RPC selectively / pingbacks** | Firewall | 1 | S | Granular control instead of all-or-nothing. |
| **Force HTTPS + mixed-content fixer** | Firewall | 1 | S | Redirect to HTTPS, rewrite insecure asset URLs. |
| **Comment spam / honeypot** | Firewall | 1 | S | Block bot comments, registration honeypots. |
| **Recovery / lockdown mode** | Admin Guard | 2 | M | Emergency maintenance lockout that disables front-end + non-whitelisted logins. |

---

## Recommended next sprint (Tier 0 subset)
A coherent, high-value bundle that's mostly self-contained:
1. **2FA (TOTP + email OTP)** — biggest competitive gap.
2. **Security headers** — small effort, big hardening win, new Firewall section.
3. **Expanded audit log** — multiplies the value of the Logs page you already have.
4. **Login CAPTCHA** — pairs naturally with the existing Login Security page.

Integrations available in this install worth wiring: **`gembackup`** (pre-update/scheduled backups), and the vulnerability feed (Patchstack/WPScan) for the known-vuln scanner.
