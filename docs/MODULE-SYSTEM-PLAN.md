# GemSecurity — Module / Addon System Plan

> Goal: turn every feature area into an independently **activatable module**. If a
> user only wants Social Login, they activate that one module and only its
> menu item, REST routes, hooks, and React page load. Everything else costs
> nothing.

## Decisions (locked)

1. **Granularity** — module = **menu/page level** (~13 modules). Each module
   bundles its backing PHP class(es) + REST controller(s) + React page.
2. **Layer model** — **two layers**. Module activation is the coarse gate that
   controls whether a menu/REST/hooks load at all. The existing per-feature
   `*_enabled` settings survive as **granular sub-toggles inside an active
   module** (nothing about their behavior changes).
3. **Defaults** — **upgrade preserves current behavior** (activate modules whose
   settings are currently enabled); **fresh installs** boot the core modules
   plus a safe recommended set.

---

## 1. Core concept & data model

### 1.1 New option: active-module registry state
- New option `gemsecurity_active_modules` = `[ 'firewall' => true, 'social-login' => false, ... ]`.
- Read through a cached accessor (mirror `Helper::get_settings()` / `flush_settings_cache()` pattern).
- Bump `GEMSECURITY_DB_VERSION` and seed this option in the installer + an upgrade routine.

### 1.2 Module descriptor (the registry)
A single source of truth — `GemSecurity\Modules\Registry` — returns an ordered
map of module descriptors, filterable via `gemsecurity/modules`:

```php
'social-login' => [
    'id'         => 'social-login',
    'title'      => __( 'Social Login', 'gemsecurity' ),
    'desc'       => __( 'Let users sign in with Google, Facebook, GitHub, X.', 'gemsecurity' ),
    'icon'       => 'users',                       // shared with React nav
    'category'   => 'access',                      // grouping in the manager UI
    'core'       => false,                         // core modules can't be turned off
    'is_pro'     => false,
    'page_slug'  => 'gemsecurity-social-login',    // WP ?page= + React route key
    'classes'    => [ Modules\SocialLogin::class ],// booted only when active
    'rest'       => [ 'social' ],                  // route groups registered only when active
    'recommended'=> false,                         // seeded on fresh installs
],
```

This descriptor is the ONE place that ties together: menu entry, React nav item,
React page, PHP class boot, and REST registration. Everything else derives from it.

---

## 2. Module map (the 13 modules)

| Module id | Page | Backing PHP class(es) | REST groups | Kind |
|---|---|---|---|---|
| `dashboard` | Dashboard | — (aggregates) | `dashboard`, `search` | **core** (always on) |
| `firewall` | Firewall | `Waf`, `Firewall`, `Comments`, `SecurityHeaders` | `bots` | recommended |
| `threats` | Threat Defense | (Pro classes) | `bans` | **pro** |
| `login-security` | Login Security | `LoginSecurity`, `Sessions`, `PasswordPolicy`, `CustomLogin`, `Lockdown` | `sessions` | recommended |
| `two-factor` | Two-Factor | `TwoFactor`, `Captcha` | `2fa` | optional |
| `social-login` | Social Login | `SocialLogin` | `social` | optional |
| `geolocation` | Geolocation | `Geolocation` | `geo` | **pro** |
| `admin-guard` | Admin Guard | `AdminGuard`, `HiddenAdmin` | `admins` | recommended |
| `scanner` | Scanner | `Scanner`, `Finder`, `FileWatcher`, `LinkScanner` | `scan`, `mu-plugins` | recommended |
| `logs` | Logs | `AuditLog`, `Alerts` | `logs` | **core** (always on) |
| `backup` | Backup | `Backup` subsystem | `backup*` | optional |
| `pro-tools` | Pro Tools | (Pro classes) | — | **pro** |
| `settings` | Settings + **Modules manager** | — | `settings` | **core** (always on) |

Notes on backing-class folding (classes with no menu page of their own become
sub-features of a page-module, gated by their existing `*_enabled` setting):
- `SecurityHeaders`, `Comments` → **firewall** module.
- `Sessions`, `PasswordPolicy`, `CustomLogin`, `Lockdown` → **login-security**.
- `Captcha` → **two-factor** (login CAPTCHA lives with login/2FA).
- `HiddenAdmin` → **admin-guard**.

`dashboard`, `logs`, `settings` are **core** — the manager renders them as
always-on (no toggle), because the dashboard aggregates data, logs are the audit
backbone, and settings hosts the manager itself.

---

## 3. What each layer keys off the registry

### 3.1 PHP boot — `dispatch_hooks()` (`gemsecurity.php`)
Replace the hard-coded list of `Module::init()` calls with a loop:

```php
foreach ( Registry::active_modules() as $module ) {
    foreach ( $module['classes'] as $class ) {
        $class::init();   // class still runs its own *_enabled granular checks
    }
}
```
- Core module classes always boot.
- Pro modules additionally require `Helper::is_pro_active()` (keep the existing
  Pro guard inside those classes as defense-in-depth).
- Inactive module → its classes never load → **zero hook cost** (the real win
  over today, where every class boots and early-returns).

### 3.2 Admin menu — `Helper::get_admin_menu_list()`
Derive the menu from `Registry::active_modules()` instead of the static array.
Inactive modules produce no submenu. Keep the `is_pro` pill logic. Settings
stays last.

### 3.3 REST — `api.php`
Group route registration by module and register a group only if its module is
active:

```php
if ( Registry::is_active( 'social-login' ) ) {
    // register /social routes
}
```
Refactor `register_routes()` into per-group private methods so this stays
readable. Core groups (`settings`, `dashboard`, `logs`, `search`) always register.
Pro route groups keep `pro_permission`.

### 3.4 Assets localization — `Assets::get_scripts_data()`
Add `'modules' => Registry::for_js()` — the descriptor list (id, title, desc,
icon, category, core, is_pro, page_slug, active). React nav + manager + router
all read this instead of the hard-coded `NAV_ITEMS`.

### 3.5 React
- `utils/nav.js`: build `NAV_ITEMS` from `GS.modules` filtered to `active`
  (keep icon/label). Inactive modules disappear from the sidebar.
- `containers/App.js`: `PAGES` map stays (component registry), but the router
  only mounts a page whose module is active; unknown/inactive → redirect to
  Dashboard. Pro-locked pages keep the existing `ProGate` overlay.
- New page/tab **Modules manager** (see §5).

---

## 4. Migration & defaults (installer + upgrade)

### 4.1 Fresh install
Seed `gemsecurity_active_modules`:
- core → always `true`.
- `recommended: true` modules → `true` (firewall, login-security, admin-guard,
  scanner).
- everything else → `false`.

### 4.2 Upgrade (existing installs — no behavior change)
On DB-version bump, derive activation from current settings so nothing silently
turns off:
- A module is activated if **any** of its backing `*_enabled` settings is truthy
  (e.g. `social_login_enabled` → activate `social-login`;
  `two_factor_enabled` OR `captcha_enabled` → `two-factor`).
- Map documented per-module in the installer's upgrade routine.
- Pro modules follow their existing Pro-active + `*_enabled` state.

### 4.3 Deactivation semantics
Deactivating a module **does not delete** its settings or data — it just stops
loading. Re-activating restores prior granular config. (Data purge stays in
`uninstall.php` only.)

---

## 5. Modules manager UI

A **Modules** tab in Settings (or its own top-level page — recommend a tab to
avoid menu clutter). Renders `GS.modules` as a card grid grouped by `category`:
- Each card: icon, title, description, an on/off `Switch`, PRO pill for pro
  modules (locked switch + upsell when Pro inactive), "Core" badge (switch
  disabled) for core modules.
- Toggling posts to a new REST route `POST gemsecurity/v1/modules`
  `{ id, active }` → updates `gemsecurity_active_modules`, flushes cache.
- After a successful toggle: refresh nav (the menu/REST for the newly-activated
  module require a **page reload** because WP registers the admin menu +
  REST server-side; show a "reload to apply" prompt, or trigger
  `window.location.reload()`).

New REST: `GET/POST gemsecurity/v1/modules` (core group, `manage_options`).

---

## 6. File-by-file change list

**New**
- `includes/modules/registry.php` — `Registry` class (descriptors, `active_modules()`, `is_active()`, `for_js()`, seed/upgrade helpers).
- `includes/rest/modules.php` — `Rest\Modules` controller (get/save activation).
- `dev_gemsecurity/containers/pages/Modules.js` — manager UI.
- `dev_gemsecurity/redux/modulesSlice.js` (or fold into settingsSlice).

**Changed**
- `gemsecurity.php` — `dispatch_hooks()` loops the registry.
- `includes/helper.php` — `get_admin_menu_list()` derives from registry; add module-state cache accessor + flush hook.
- `includes/api.php` — group route registration by active module.
- `includes/assets.php` — localize `modules`.
- `includes/installer.php` — seed on install + upgrade migration; DB-version bump.
- `dev_gemsecurity/utils/nav.js` — build nav from `GS.modules`.
- `dev_gemsecurity/containers/App.js` — active-aware routing + Modules route.
- `dev_gemsecurity/containers/pages/Settings.js` — add Modules tab (if tabbed).
- `uninstall.php` — delete `gemsecurity_active_modules`.

**Pro plugin** (`gemsecurity-pro`) — register its Pro module descriptors via the
`gemsecurity/modules` filter so Threat Defense / Pro Tools become real modules
in the manager (locked/unlockable), consistent with free modules.

---

## 7. Phases — IMPLEMENTED (2026-08-09)

- **Phase 1 — Registry + PHP boot.** ✅ `includes/modules/registry.php` (14
  modules), `gemsecurity_active_modules` option, installer seed +
  `seed_if_missing()` derive-from-settings migration, DB version 1.7 → 1.8,
  `dispatch_hooks()` now loops `Registry::active_modules()`.
- **Phase 2 — Menu + REST gating.** ✅ `Helper::get_admin_menu_list()` derives
  from visible modules; `api.php` gates module-owned route groups by activation
  (core groups — settings, modules, dashboard, logs, search — always on).
- **Phase 3 — React.** ✅ `nav.js` builds from `GS.modules`; `App.js`
  activation-aware routing + inactive-module notice; `containers/pages/Modules.js`
  card-grid manager + toggle REST + reload prompt; `Icon` gained `layers`; SCSS
  for `.gs-modules`/`.gs-module-card`/`.gs-notice`.
- **Phase 4 — Pro integration.** ✅ Pro `Plugin::init()` gates Hardening /
  FileBaseline / AutoUpdate on `pro-tools` and MalwareScanner on `scanner`;
  pro modules already live in the free registry as `is_pro` (shown locked).
- **Phase 5 — Polish.** Category grouping + empty states done. Remaining
  nice-to-haves: cross-module dependency hints, gating the auto-scan cron on the
  scanner module, deriving `get_pro_features()` from the registry.

### Behavior note (existing installs)
The upgrade migration hides a module's menu page when none of its backing
`*_enabled` settings were on. In practice Two-Factor and Social Login start
hidden on sites that never enabled them — this is the intended "activate only
what you need" model. Re-activate from the **Modules** page (a page reload
applies the restored menu + REST).

---

## 8. Open considerations / risks

- **Menu/REST are server-registered** → activating a module needs a page reload
  to surface its menu + routes. Manager UI must make that explicit.
- **Backing-class folding**: a few classes (SecurityHeaders, Sessions, etc.)
  have no page; confirm the chosen home page for each (see §2 notes) so their
  granular settings render on the right page.
- **Dashboard/Logs data** from inactive modules: dashboard aggregation should
  tolerate missing sources gracefully (guard reads on inactive modules).
- **Pro dependency**: a pro module can't be active without Pro; manager shows it
  locked rather than allowing activation that no-ops.
