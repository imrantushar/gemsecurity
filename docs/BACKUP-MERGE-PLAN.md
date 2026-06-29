# GemSecurity × GemBackup — Merge Plan

Fold GemBackup's backup engine into the GemSecurity suite as a **Backup** area,
split free/pro, exploiting security×backup synergies (pre-update backups,
pre-recovery snapshots, one-click rollback after a compromise).

## What GemBackup brings
- **Engine:** DB dumper, file archiver, restore runner, manifest, encryption, search-replace (migration), async job queue, scheduler, health monitor, secure download, WP-CLI.
- **Storage drivers (8):** local, ftp, s3, backblaze (B2), r2, dropbox, gdrive, onedrive — registered through the `gembackup/driver_map` filter.
- **UI (6 pages):** Dashboard, Backups, Schedule, Storage, Logs, Settings (React + **Tailwind**).
- **Tables (4):** `gembackup_backups`, `gembackup_jobs`, `gembackup_schedules`, `gembackup_logs`.
- **Hooks already present:** `gembackup/run_backup`, `gembackup/driver_map`; GemSecurity already calls the former in Lockdown.

## Architecture decisions

1. **Code placement (gated by tier):**
   - **Free → `gemsecurity/includes/backup/`** — engine (dump/archive/restore/manifest/logger), `local` driver, job queue, REST for manual backup/restore/logs.
   - **Pro → `gemsecurity-pro/includes/backup/`** — cloud drivers, scheduler, encryption, search-replace migration, health/notifications, registered via `gembackup/driver_map` + `gemsecurity_pro/modules_loaded`.
2. **Namespace:** keep the `GemBackup\` namespace; register its `includes/backup/` path in both autoloaders (the free autoloader already supports `add_namespace_directory`). Minimal churn vs a rename to `GemSecurity\Backup\`.
3. **Settings:** a **separate, non-autoloaded** `gemsecurity_backup_settings` option (backup config is large and not needed on front-end requests — don't bloat the 4 KB autoloaded `gemsecurity_settings`). Pro keys merged via a `gemsecurity/backup_settings_schema` filter.
4. **Tables:** rename `gembackup_*` → `gemsecurity_backups` / `_backup_jobs` / `_backup_schedules` / `_backup_logs` for a single-brand schema (one-time, since pre-release no migration). Free installer creates all four; the engine uses them regardless of tier.
5. **Menu:** new **Backup** group in the GemSecurity sidebar — *Backups*, *Schedule* (Pro), *Storage* (Pro), with backup *Logs* folding into the existing Logs page. Pro pages get the existing PRO badge + lock.
6. **Pro gating:** reuse `Helper::is_pro_active()`, `Api::pro_permission()`, and the `driver_map` filter — same mechanism already used for the other Pro modules.

## Free / Pro split

| Feature | Free | Pro |
|---|---|---|
| Manual **database** backup | ✅ | |
| Manual **files / full-site** backup | ✅ | |
| **Local** storage + secure download | ✅ | |
| **Restore** from a local backup | ✅ | |
| Retention policy + exclude paths/tables | ✅ | advanced |
| Backup logs | ✅ | |
| **Scheduled** backups | ✅ daily only | ✅ any frequency, multiple schedules |
| **Cloud storage** (S3, B2, R2, Dropbox, GDrive, OneDrive, FTP) | | ✅ |
| **Encryption** (AES) | | ✅ |
| **Search-replace / migration** | | ✅ |
| **Restore from cloud** | | ✅ |
| **Failure notifications + health monitor** | | ✅ |
| **Pre-update auto-backup** (security integration) | | ✅ |
| **Pre-recovery snapshot** + one-click rollback | | ✅ |
| WP-CLI backup commands | ✅ | |

## Security × Backup synergies (the reason to merge)
- **Pre-update backup** — already wired (`gembackup/run_backup` from Lockdown); now in-product.
- **Pre-recovery snapshot** — Recovery Toolkit / quarantine takes an automatic backup before destructive action.
- **One-click rollback after a compromise** — the Malware page offers "restore last clean backup".
- **Backup posture in the security score** — "no recent backup" lowers the dashboard score.

## Phased delivery
- **Phase 0 — Scaffolding:** relocate engine into free, register autoload paths, rename tables, create the non-autoloaded settings option, secure-download route.
- **Phase 1 — Free backup:** manual DB/files/full backup → local, restore, logs, retention, daily schedule, WP-CLI. Working end-to-end, no cloud.
- **Phase 2 — Pro backup:** cloud drivers via `driver_map`, multi-schedule, encryption, migration, restore-from-cloud, notifications/health — all `pro_permission`-gated.
- **Phase 3 — UI:** see decision below.
- **Phase 4 — Synergies:** pre-recovery snapshot, rollback, score integration.
- **Phase 5 — Release:** versions, readme, uninstall (drop tables + dir + options), .distignore, rebuild, full audit.

## Locked decisions
1. **UI strategy: Port to GemSecurity UI.** Rebuild the 6 backup pages with GemSecurity's components + SCSS, reusing GemBackup's PHP engine + REST. One consistent look, one bundle. (GemBackup's Tailwind/dev source is reference-only and not shipped.)
2. **Free/Pro line: as proposed** (the table above stands — daily schedule is free; local-only is the free storage tier).
3. **GemBackup standalone: retired.** Backup ships only inside the GemSecurity suite. Add a guard so an active standalone `gembackup` plugin is detected (admin notice to deactivate) to avoid table/hook collisions.

## Risks
- Two UI toolchains / build pipelines (Phase 3 decision).
- Backup engine is heavy (long-running jobs) — ensure the async job queue + WP-Cron/Action-Scheduler path is preserved; not on the front-end request path.
- Large backup files + cloud SDKs increase plugin size (cloud SDKs live in Pro only).
- Table rename + settings option migration (mitigated: pre-release, no installed base).
