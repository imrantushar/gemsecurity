# GemSecurity — Free vs Pro Plan

## Packaging philosophy
- **Free** = solid, self-contained protection that makes the plugin worth installing and ranks on WP.org: hardening, basic firewall/WAF, login protection, basic 2FA, manual scanning, logs. Generous enough to compete with Wordfence Free.
- **Pro** = everything that is *automated, real-time, remediating, enforced, or scaled*: malware removal, signature/scheduled scanning, real-time threat intel, country blocking, social login, advanced 2FA enforcement, alert channels, multisite, premium support.
- **Delivery:** a `gemsecurity-pro` addon that registers pro modules and flips `feature_flags`, mirroring `gembooking-pro` / `gemcrm-pro`. Free pages show locked Pro sections as upsells.

Legend: ✅ already built in the codebase · 🔨 needs building (from the gap analysis)

---

## FREE plan

### Core
- Security Dashboard — security score, stats, activity trend ✅
- Settings + full uninstall cleanup ✅

### Firewall & Hardening
- IP blocklist with CIDR ✅
- Hardening toggles — disable XML-RPC, file editor, user/REST enumeration, hide version, app passwords ✅
- Security headers — X-Frame, X-Content-Type, Referrer-Policy, Permissions-Policy, HSTS, CSP ✅

### WAF (basic)
- Static rule inspection — SQLi / XSS / LFI / RCE ✅
- Rate limiting + 404-flood throttle + bad-bot blocking ✅

### Login Security
- Brute-force lockout ✅
- Admin-login email alert ✅
- 24h admin session timeout ✅
- Custom login URL (rename wp-login.php) ✅
- Login CAPTCHA — reCAPTCHA / hCaptcha / Turnstile ✅

### Two-Factor (basic)
- App TOTP + email OTP, self-enrollment, backup codes ✅

### Social / OAuth Login
- Google, Facebook, GitHub, Twitter login ✅

### Admin Guard
- Administrator whitelist + rogue-admin auto-delete/demote ✅

### Scanner (manual)
- On-demand WP core integrity (checksums) ✅
- On-demand uploads malware/PHP pattern scan ✅
- Known-vulnerability scanner (community wpvulnerability.net feed) ✅

### Password & Sessions
- Password policy — length / complexity ✅
- View & end your own sessions ✅

### Logs & Alerts
- Activity log — security events, recent retention (e.g. 30 days) ✅
- Manual / basic ban list ✅
- Email alerts (basic) ✅

---

## PRO plan

### Malware & Scanner Pro
- **One-click malware removal / quarantine / repair & restore of modified core files** 🔨 *(top gap)*
- **Signature-based malware scan** — full filesystem vs known-malware/backdoor/web-shell DB 🔨
- **Database injection scan** — posts/options for spam links & malicious JS 🔨
- **File-change detection** — stored baseline + scheduled diff + alerts 🔨
- **Plugin/theme file integrity** vs the WP.org repo 🔨
- **Scheduled / automatic scans** + cron ✅ (cron exists; surface as Pro automation)
- **Post-hack recovery toolkit** — reset salts/secret keys, force password reset 🔨
- **Blocklist/reputation monitoring** — Google Safe Browsing & spam-list checks 🔨

### Firewall / WAF Pro
- **Real-time threat-intelligence rule feed** + auto-updating rules 🔨
- **Community/crowd-sourced malicious-IP reputation feed** 🔨
- **Escalating auto-bans + ban ledger** (strikes → temp → permanent) ✅
- **Extended protection mu-plugin** (early pre-load firewall) ✅
- Block sensitive-file access (`readme.html`, `.sql`, `debug.log`, PHP in `/uploads`) 🔨
- Force HTTPS + mixed-content fixer 🔨

### Access Control Pro
- **Geolocation / country access control** — login gate, site 403, per-user location lock ✅
- Restrict wp-admin by IP allow-list 🔨

### Two-Factor Pro
- **Enforce 2FA by role** ✅
- Front-end 2FA enrollment for non-admin roles 🔨
- WebAuthn / hardware security keys + SMS OTP 🔨
- Trusted devices / passwordless magic-link login 🔨

### Identity & Sessions Pro
- **Breached-password check** — Have I Been Pwned (k-anonymity) ✅
- Password expiry / reuse ban ✅
- **Force-logout other users** + idle-session timeout + "log out everywhere" ✅

### Monitoring & Ops Pro
- **Alert channels** — Slack / Telegram / webhook ✅
- **Weekly security digest** ✅
- Full audit log (all categories) + extended retention + **CSV export** + scheduled reports ✅
- **Lockdown / maintenance mode + pre-update GemBackup** ✅
- Settings import/export 🔨
- Auto-update enforcement for vulnerable plugins/themes 🔨

### Scale & Support (Pro only)
- **WP Multisite support** 🔨
- **Centralized multi-site management dashboard** 🔨
- Uptime / downtime monitoring 🔨
- Cloud-based scanning (zero server load) 🔨
- Granular capabilities (beyond `manage_options`) 🔨
- Priority support + license updates

---

## At-a-glance

| Area | Free | Pro |
|---|---|---|
| Firewall / hardening / headers | ✅ | + real-time rules, IP reputation, auto-bans |
| WAF | static rules | real-time feed + escalating bans + mu-plugin |
| Login security + custom URL + CAPTCHA | ✅ | + IP allow-list for wp-admin |
| Social / OAuth login | ✅ | — |
| Two-Factor | TOTP + email | + enforce-by-role, WebAuthn, passwordless |
| Scanner | manual core + uploads + vuln feed | signature DB, DB scan, file-change baseline, **remediation** |
| Country blocking | — | ✅ |
| Password breach / expiry | — | ✅ |
| Sessions | own only | manage all + idle timeout |
| Alerts | email | Slack / Telegram / webhook + weekly digest |
| Logs | recent, security | full, all categories, CSV export, reports |
| Lockdown + backup | — | ✅ |
| Multisite / central dashboard / uptime | — | 🔨 |

## Suggested pricing (annual, 1 site → unlimited)
- **Free** — WP.org.
- **Pro Personal** — 1 site (~$49)
- **Pro Business** — 5 sites (~$99)
- **Pro Agency** — 25+/unlimited sites + central dashboard (~$199+)

> Note: a large share of "Pro" features (geolocation, auto-bans, 2FA enforcement, alert channels, breach check, lockdown, sessions, CSV export) are **already built** — moving them behind the Pro flag turns existing work into immediate upsell value. Only the 🔨 items need new development. Social login and CAPTCHA stay in Free as adoption drivers.
