# Passkeys — Competitor Research & Build Plan

_Date: 2026-11-05. Status: proposal. Supersedes the "WebAuthn / passkeys 🔨" line items in FREE-VS-PRO.md and COMPETITOR-FLOW-ANALYSIS.md (§16 item 11, "Long-term parity")._

> Evidence note: findings come from web-search snippets and plugin directory listings. The Wordfence help/blog pages could not be fetched (empty responses), so Wordfence details are from search summaries only. Verify before using in marketing copy.

## 1. Why now (changes the earlier roadmap)

Earlier docs assumed passkeys were a Solid Security **Pro** feature and we could leave them as a Pro, "long-term" item. That is out of date:

- **Wordfence now ships passkeys on every plan, including Free** (Wordfence 9.0; the standalone Login Security plugin was closed 17 Aug 2026). The free tier lets admins pick which roles may use passkeys and require them per role, sharing the 2FA grace period. Works on wp-login and (opt-in) WooCommerce forms.
- Solid Security Pro has had passkeys longer; it's the paid reference.
- Small free plugins (Secure Passkeys, WP-WebAuthn, Multidots, Keyless Login, ASD Passkey) are the long tail.

**Implication:** basic passkey login is table stakes and must be **Free**. Pro revenue has to come from the extras in §4.

## 2. Competitor feature matrix

| Capability | Wordfence (Free) | Solid Security Pro | WP-WebAuthn | Secure Passkeys | Others (Keyless, ASD, Multidots) |
|---|---|---|---|---|---|
| Passkey login on wp-login | ✅ | ✅ | ✅ | ✅ | ✅ |
| Usernameless / discoverable login | ? | ? | ✅ | ? | varies |
| Per-role enablement | ✅ | ✅ (user groups) | ❌ | ❌ | ❌ |
| Require passkeys per role + grace period | ✅ | partial (setup prompt on next login) | ❌ | ❌ | ❌ |
| User profile management (list, add date, last used) | basic | ✅ | ✅ | ✅ | ✅ |
| Soft-delete / 7-day recovery of removed passkey | ❌ | ✅ | ❌ | ❌ | ❌ |
| WooCommerce forms | ✅ opt-in | ? | shortcodes | shortcode on account page | ASD Pro |
| Shortcodes / blocks for front-end | ❌ | ❌ | ✅ 4 + 4 blocks | ✅ + theme filters | varies |
| Setup reminder notice | ? | ✅ prompt | ❌ | ✅ toggle | ❌ |
| Disable password login entirely | ❌ | ❌ | ✅ | ❌ | varies |
| Restrict authenticator type | ❌ | ❌ | ✅ | ❌ | ❌ |
| Multisite | ? | ❌ | ? | ? | ? |
| Lockout-safe recovery story | warns only | partial | ❌ | ❌ | ❌ |
| Maintenance | active | active | stale (~450 days; needs gmp+mbstring) | ~1k installs | small |

Known pain points: lockout when the only passkey is lost (Wordfence docs say so explicitly); Windows Hello passkeys are device-bound (Solid docs); GMP/mbstring dependency (WP-WebAuthn); abandoned maintenance.

## 3. Where we start (GemSecurity today)

- `includes/modules/two-factor.php` — hooks `authenticate` at priority 99 (`maybe_challenge`), parks a pending challenge (transient + signed cookie), methods `totp | email`, backup codes, lockout counters, role enforcement. The challenge/pending-token machinery is reusable for a passkey step.
- `includes/modules/login-security.php`, `custom-login.php`, `magic-login.php`, `social-login.php`, `sessions.php`, `audit-log.php`, `security/recovery.php`, `security/secret-box.php` (sealed storage), `rest/credentials.php`, `rest/two-factor.php`.
- Pro: `login-devices.php` (trusted devices / new-device alerts, magic-link recovery).
- `composer.json` requires PHP ^7.4. Most WebAuthn libs need 8.1+ and GMP, so **don't take a heavy dependency**: write a small verifier (CBOR/COSE, ES256 + RS256 + EdDSA via `openssl_verify`/sodium, attestation `none` and `packed` self; `fmt: none` is the norm for passkeys). Fall back to "passkeys unavailable" with a clear admin notice if OpenSSL lacks a needed curve.

## 4. Product plan

### Free — match & beat Wordfence on basics
1. **Passkey login** on wp-login: "Sign in with a passkey" button, conditional UI (autofill) + usernameless discoverable credentials. Honors custom login URL and the hidden-admin module.
2. **Profile management**: add / rename / delete, created + last used + device type (synced vs device-bound via backup-eligible flags), AAGUID → provider name (iCloud Keychain, Google PM, 1Password, Windows Hello, YubiKey).
3. **Passkey as 2FA replacement**: a successful user-verified passkey satisfies the second-factor requirement (don't make users do passkey + TOTP). Passkey also becomes a selectable factor in the existing challenge screen.
4. **Roles & enforcement**: enable per role; require per role with a grace period (shared with 2FA enforcement); setup prompt after login.
5. **Lockout safety** (our main wedge, see §5): block removing the last passkey when it's the only login method unless a fallback exists; recovery via backup codes / email OTP / admin reset.
6. **Audit log + alerts**: registered / removed / used / failed events into existing audit-log and alerts modules.
7. **Rate-limit** assertion endpoints with the existing firewall/ban-list; strict origin, RP ID, counter and user-verification checks.
8. **WooCommerce & front-end**: login on My Account form, shortcode/block `[gemsec_passkey_login]` and `[gemsec_passkey_manage]`.

### Pro — the "extra" competitors lack
| # | Extra | Why it beats competitors | Builds on |
|---|---|---|---|
| P1 | **Passkey-only mode for privileged roles** (disable password + magic link + social for admins, keep break-glass) | Only WP-WebAuthn offers "disable password"; none do it per role safely | login-security, custom-login |
| P2 | **Attestation & authenticator policy** — allow-list by AAGUID (e.g. only hardware keys for admins, block software passkeys), require user verification, require device-bound | Enterprise/compliance ask; no WP competitor does AAGUID policy | new |
| P3 | **Step-up auth for sensitive actions** — re-prompt a passkey before plugin install, user-role change, export, password change, temp-access grant | Turns passkeys into a transaction guard, not just a login | admin-guard, plugin-guard, temp-access |
| P4 | **Safe recovery workflow** — time-delayed (e.g. 24h) email-confirmed recovery with admin notification, plus admin "issue enrollment link" for staff | Solves the #1 documented complaint (lockout) | magic-link recovery, recovery.php |
| P5 | **Passkey health dashboard** — adoption % by role, users with no passkey, only-one-passkey (single point of failure), stale passkeys, synced vs device-bound; one-click "nudge" email | Visibility competitors don't give; fits our security-score | security-score, dashboard |
| P6 | **Trusted-device + passkey risk engine** — new device / new country / Tor still needs passkey with UV; known device skips extra prompts | Unifies our existing Pro login-devices + geolocation | login-devices, geolocation |
| P7 | **Passkey for temp-access / client links** — contractor gets a time-boxed account that must enroll a passkey on first use | Unique to our temp-access module | temp-access |
| P8 | **Multisite & network policy** (Solid doesn't support multisite) | Gap for agencies | roadmap multisite |
| P9 | **Passkey-gated REST/Application passwords & WP-CLI-safe bypass rules** | API clients stay working; admin API keys need step-up to create | rest/app-passwords |
| P10 | **Compliance export** — CSV/PDF of passkey adoption + policy for audits (SOC2/ISO), via compliance module | Sells to agencies | compliance, daily-report |

Out of scope for v1: SMS, cross-site/related-origin passkeys, SCIM.

## 5. Differentiators to lead marketing with
1. **"Can't lock yourself out"** — enforced fallback checks, soft-delete restore window (match Solid's 7 days), delayed recovery.
2. **No server requirements** — no GMP, works on PHP 7.4 (WP-WebAuthn needs gmp+mbstring).
3. **Passkey ⇒ replaces 2FA** in one step, with enforcement and grace period, on the free plan.
4. **Fits the suite** — one audit log, one alert system, one score.

## 6. Technical design sketch

- Storage: new table `gemsec_passkeys` (id, user_id, credential_id [unique, base64url], public_key sealed via `secret-box`, sign_count, transports, aaguid, backup_eligible, backup_state, uv, name, created, last_used, deleted_at). Not user meta, because lookups by credential id are needed for usernameless login.
- Endpoints (REST, nonce-less but challenge-bound, rate limited): `register/options`, `register/verify`, `login/options`, `login/verify`, `manage/*` (cap `read`, own user only).
- Challenges: 32 random bytes, stored in a short-TTL transient keyed by session cookie, single use.
- Verify: origin match (respect custom login/front-end hosts and multi-domain via filter), RP ID, flags UP/UV, signature, sign-count regression → alert (clone detection) but warn only for synced passkeys (counter is always 0).
- Login: on success call `wp_set_auth_cookie`; skip `maybe_challenge` when UV passkey used (set a request flag read by `Two_Factor::user_needs_2fa`).
- Assets: small vanilla JS (no framework) loaded only on login/profile pages, wporg-compliant enqueue (follow the recent `wp_enqueue` convention).
- Settings keys: `passkeys_enabled`, `passkeys_roles`, `passkeys_required_roles`, `passkeys_grace_days`, `passkeys_usernameless`; Pro: `passkeys_password_off_roles`, `passkeys_aaguid_allow`, `passkeys_stepup_actions`.
- HTTPS required; show admin notice and disable on non-secure origins (localhost allowed).

## 7. Phasing

| Phase | Scope | Size |
|---|---|---|
| 0 | Spike: CBOR/COSE parser + ES256/RS256 verify against test vectors; pick scope of attestation formats | S |
| 1 (Free MVP) | Table, register/login endpoints, wp-login button + conditional UI, profile management, audit log, rate limit | L |
| 2 (Free) | 2FA replacement, role enable/require + grace, lockout safeguards, soft-delete restore, WooCommerce/shortcodes | M |
| 3 (Pro) | P1, P2, P4, P5 | L |
| 4 (Pro) | P3, P6, P7, P9, P10 | M |
| 5 | Multisite (P8) | M |

## 8. Risks / open questions
- Can we reliably verify without GMP on all supported hosts (ES256 via OpenSSL is fine; EdDSA needs sodium, so make it optional)?
- Interaction with custom login URL / hidden-admin and caching plugins on login pages.
- Free vs Pro line: P1 (passkey-only for admins) could arguably be Free. Recommend keep Pro; basic enforcement stays Free.
- Test matrix: Safari/iCloud Keychain, Chrome/Google PM, Windows Hello, 1Password, YubiKey, Firefox; add a manual QA doc under `docs/qa`.

## Sources
- Wordfence passkeys: https://www.wordfence.com/help/login-security/passkeys/ · https://www.wordfence.com/blog/2026/09/wordfence-passkeys/
- Solid Security passkeys docs: https://docs.nexcess.com/software/kadence/solid/solid-security/passkeys/
- WP-WebAuthn: https://wordpress.org/plugins/wp-webauthn · https://github.com/yrccondor/wp-webauthn
- Secure Passkeys: https://wordpress.org/plugins/secure-passkeys/
- Tag listing: https://wordpress.org/plugins/tags/passkey/
