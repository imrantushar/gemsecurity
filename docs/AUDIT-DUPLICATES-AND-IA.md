# Feature duplication & settings/menu consolidation

Audit of `gemsecurity` + `gemsecurity-pro`, and the changes that resolved it.
Everything below is **done**; this file is the record of what moved where and
why, for anyone wondering what happened to a setting.

Settings migrate automatically on upgrade — see `Installer::migrate_settings()`,
gated on `GEMSECURITY_DB_VERSION` (now `2.1`).

---

## A. Duplicate features — collapsed to one implementation each

| # | Was | Now |
|---|-----|-----|
| A1 | **Two comment honeypots**, both on by default: `Captcha::render_honeypot()` (`comment_honeypot_enabled`) and `AntiSpam::fields()`. Both hooked `comment_form` + `preprocess_comment` @ prio 1, so every comment form carried two decoy fields and two validators. | `Captcha`'s removed. `AntiSpam` keeps it — it signs the timestamp with HMAC, has a configurable minimum, and covers registration too. Migration turns `antispam_enabled` on if the site relied on the honeypot. |
| A2 | **Two "disable application passwords" switches** on two pages in two modules — `disable_application_passwords` (Firewall) and `app_pw_disabled` (API & Access) — both filtering `wp_is_application_passwords_available`. | `app_pw_disabled` only; it also governs expiry and creation alerts. The Firewall version's priority-20 comment moved with it. Migration folds the old value in. |
| A3 | **Two quarantine stores** writing into the *same* directory with *separate* indexes, so a file quarantined by the malware scanner could not be seen or restored from Incident Response. | One `GemSecurity\Security\Quarantine`. Both callers delegate to it. `Quarantine::migrate_legacy()` merges both old indexes; nothing moves on disk. |
| A4 | **Two force-logout implementations** — Incident Response looped `get_users()` **capped at 1000**, Pro used one `DELETE`. | One `GemSecurity\Security\Recovery::logout_all_users()` (uncapped). Pro's delegates to it. The cap is gone — an incident is exactly when the user list may be large. |
| A5 | **Two file-change baselines** — free `FileWatcher` (theme/mu-plugins/drop-ins) and Pro `FileBaseline` (core/plugins/themes), overlapping on themes, with two options, two crons, two diff UIs. | One baseline. Pro now only *widens* it via `gemsecurity/file_watcher/roots` + `…/max_files`. Pro's REST routes, option and cron are gone; the orphaned snapshot option is deleted on upgrade. |
| A6 | **Two copies of `is_protected()`** (byte-identical) and two admin-deletion paths in `AdminGuard` and `AdminAudit`. | `AdminAudit::is_protected()` (now takes `$allow_self`) and `AdminAudit::delete_user()` are the single definitions; `AdminGuard` delegates. Each keeps its own log events. |
| A7 | **Two malware passes over the same files** — the free heuristic patterns and Pro's signature set — producing two overlapping lists on one page. | When Pro is active the free heuristic pass stands down and its card is hidden. The uploads-PHP check stays either way: it is not a heuristic, and the signature scanner skips asset directories. |

## B. Notifications — one recipient, one set of channels

Was: **4 recipient settings** (`alert_to_email`, `admin_login_alert_email`,
`monitor_alert_email`, backup `notify_email`), **4 hardcoded `admin_email`
fallbacks**, **2 webhook URLs**, and backup sending raw plain-text `wp_mail()`
while everything else used the branded `Mailer`.

Now: `Mailer::recipient()` is the single resolver (`alert_to_email`, falling back
to the admin address, filterable via `gemsecurity/notification_recipient`).
Everything routes through it and through `Mailer::send()`. The retired
per-feature addresses migrate into `alert_to_email` if it was empty; backup's
webhook migrates into `alert_webhook_url`.

**Behaviour bug fixed:** the Settings screen offered an alert address and a
"send a test email" button under the alerts master switch, but
`Alerts::on_event()` only ever posted to Slack/Telegram/webhook — real-time
alerts never emailed. They do now.

`security.txt` still publishes the *WordPress* admin address deliberately: that
is where researchers write, not where our notifications go.

## C. Settings that had no UI at all

- **Audit log controls** (`audit_log_enabled`, `audit_content`,
  `audit_plugins_themes`, `audit_users`, `audit_settings`) — live in PHP and in
  the REST schema, rendered by nothing. Now a "What gets logged" card at the top
  of the **Logs** page.
- **12 backup settings** — retention, encryption + passphrase, exclusions,
  failure notice, pre-restore snapshot, health threshold. The REST controller
  behind them had no consumer at all. Now `BackupSettings.js` on the **Backup**
  page, with the controller sanitising every key it accepts.
- **5 dead keys** (`schedule_enabled`, `schedule_frequency`,
  `schedule_backup_type`, `schedule_storage_driver`, `schedule_time`) — written
  on install, read by nothing; schedules live in the `schedules` table. Removed.
- **Key collision** — `logs_retention_days` existed in *both* option stores, so
  the Settings field looked like it covered backup log retention and never did.
  Backup's is now `backup_logs_retention_days`.

## D. Settings that were on the wrong page or in the wrong module

| Was | Now |
|-----|-----|
| CAPTCHA UI on Login Security, `Captcha` booting under **two-factor** — turn Two-Factor off and the card saved but did nothing | `Captcha` boots with **login-security** |
| Lockdown + pre-update backup UI on Settings, `Lockdown` booting under **login-security** — same silent failure | `Lockdown` boots with **settings** (core, always on) |
| `Alerts`, `DailyReport`, `Compliance` booting under **logs** while configured on Settings | boot with **settings** |
| **Free WAF settings locked behind a Pro page** — `waf_*`, `rate_limit_*`, `throttle_404_*`, `block_bad_bots`, `block_empty_ua` are enforced by the free `Waf` class, but their only UI was the Pro-gated Threat Defense page, rendered `inert` for free users | all on the **Firewall** page. Threat Defense keeps what is genuinely Pro: live traffic, the ban ledger, escalating auto-bans, the mu-plugin loader, custom bot patterns, behavioural detection |
| Bot settings split across two pages despite living in one class | one **Bot control** card on Firewall |
| Username enumeration split — author/REST switches on Firewall, `login_errors_generic` on API & Access | one **Username enumeration** card on Firewall; `generic_login_error()` moved to the `Firewall` class to match |
| Comment controls across three pages | all on **Anti-Spam** (`comments_disabled`, `captcha_on_comments`, the silent checks, heuristics). `Comments` boots with the anti-spam module |
| Backup schedule + storage rendered on **Settings**, unconditionally — including when the Backup module was off and their endpoints are not registered | on the **Backup** page |
| Recovery actions on two pages, with two different logout implementations | all on **Incident Response**; the Scanner's malware tab keeps scanning and quarantine |
| **Pro Tools** — a menu entry holding a hardening pack, a file baseline, auto-update rules and settings import/export | dissolved. Hardening pack → Firewall; baseline scopes + auto-updates → Scanner; import/export → Settings |
| `admin_ip_allowlist` vs `admin_whitelist` reading as the same thing | descriptions now say plainly that one is a network allowlist for wp-admin and the other is a list of approved administrator accounts |

## E. Menu & registry consistency

- **Pro pages rendered unlocked for free installs.** `get_pro_features()` was
  hand-maintained and had drifted: virtual patching, payment integrity, incident
  response and monitoring were flagged `is_pro` in the registry but missing from
  it, so `ProGate` never locked them. It is now derived from the registry, so a
  module flagged `is_pro` is gated automatically.
- The Modules page's **`logging` category** matched no module (`logs` was
  `core`), so that bucket never rendered. `logs` is now `logging`.
- The registry's **`rest` field** was read by nothing — `Api::register_routes()`
  gates routes on `is_active()` separately. Removed rather than left to drift.
- "Triggers GemBackup (if active)" — stale copy; backup is built in.

### Verified

`php -l` across both plugins; every registry class, label and page slug resolves
at runtime; 163 defaults ↔ 163 REST schema keys with no gaps either way; every
key the UI writes is sanitised; no setting left without a UI; every visible
module has a help drawer; Pro's classes load against the shared API; webpack
builds clean; and both migrations were exercised end-to-end on real option data,
including the idempotency of the quarantine merge.
