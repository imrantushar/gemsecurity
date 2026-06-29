# GemSecurity — Optimization Plan

Status: ✅ done · ⏳ proposed. Impact = runtime benefit, Risk = chance of regression.

## ✅ Tier 1 — front-end request path (every visitor) — DONE
- ✅ **Per-request settings cache** — `Helper` resolved the settings option on each of ~105 `get_setting()` calls; now cached once per request, invalidated on save. Impact: high · Risk: low.
- ✅ **Drop unused `wp_enqueue_media()`** — was loading the full media-library JS on every admin page; no screen uses it. Impact: medium (admin) · Risk: low.
- ✅ **Storage consolidation** — Pro malware scan + quarantine merged into one non-autoloaded option (earlier).

## ⏳ Tier 2 — admin asset weight
- ⏳ **Code-split the admin bundle** — one 283 KB JS file loads every page up-front. Lazy-load page components (`React.lazy` + dynamic `import()`) so the initial load is a small shell + per-page chunks. Impact: high (admin TTI) · Effort: medium · Risk: low–med (build/webpack change, needs re-test of every page).
- ⏳ **Split vendor chunk** — extract React/Redux/axios into a cached vendor chunk so app-code edits don't re-download the framework. Impact: medium · Effort: low.

## ⏳ Tier 3 — database & cron
- ✅ **Cache `BanList::is_banned()` across requests** — per-IP verdict cached in the object cache (5-min TTL, busted on ban/unban). Avoids the bans query per request on object-cache sites; collapses to the in-request static cache otherwise. Impact: medium (high-traffic) · Risk: low.
- ⏳ **Object-cache-aware throttles** — rate-limit / 404 / strike counters use transients; without a persistent object cache these are `wp_options` writes per request. Gate behind a "persistent cache detected" check or document the recommendation. (All off by default.) Impact: situational · Risk: low.
- ⏳ **File-baseline storage** — a baseline with plugins+themes scopes can grow the single option to multiple MB. Move to a dedicated table (path, hash) or gzip the serialized map before storing. Impact: medium (only when baseline enabled at scale) · Effort: medium.
- ⏳ **Logs table** — confirm pruning uses the `created_at` index; consider a composite `(event_type, created_at)` index if the Logs filter view gets slow at volume. Impact: low–med · Risk: low.

## ⏳ Tier 4 — micro / code
- ✅ **`Installer::default_settings()` memoized per request** — was rebuilt (and re-filtered) on every settings read/save. Impact: low · Risk: low.
- ⏳ **Early-bail in `Firewall`/`LoginSecurity` init** — they register `init` hooks unconditionally then check settings in the callback. Minor; most other modules already self-gate. Impact: low · Risk: low.
- ⏳ **Gzip large stored arrays** (vuln/scan results, baseline) before `update_option`. Impact: low · Risk: low.

## Deliberately NOT doing
- Don't merge `gemsecurity_last_scan` + `gemsecurity_vuln_scan` (different writer modules → write race for ~1 row saved).
- Don't merge the 200 KB baseline into the malware option (would load 200 KB on every quarantine action).
- Don't fold `gemsecurity_db_version` into settings (the version check is conventionally separate and runs before settings flow).
