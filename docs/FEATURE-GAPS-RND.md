# GemSecurity — Feature-Gap R&D (beyond the current roadmap)

Date: 2026-08-12. Method: cross-referenced the shipped feature set (`FEATURES.md`)
and the existing `SECURITY-ROADMAP.md` / `FREE-VS-PRO.md` against the 2024–2025
competitor landscape (Wordfence, Solid Security, MalCare, Patchstack, All-In-One
Security, Shield, WP Cerber, Jetpack, Sucuri, Cloudflare) and the current threat/
compliance picture (Patchstack & Wordfence annual reports, PCI-DSS 4.0, mailbox-
provider auth mandates, AI-scraper/credential-stuffing trends).

Everything below is **net-new or a sharpened enhancement** — items already covered
by the roadmap (malware removal, file-change baseline, WebAuthn/passkeys, real-time
rule feed, crowd IP reputation, restrict-wp-admin-by-IP, multisite, auto-update
enforcement, blocklist monitoring, uptime, cloud scanning, block-sensitive-files,
force-HTTPS) are **not** repeated.

Legend: **NEW** = not in shipped set or roadmap · **ENH** = sharpens a roadmap item.
Effort S/M/L · tier = suggested Free / Pro.

---

## ★ Top strategic gap — Virtual Patching (CVE-targeted mitigation)

**NEW · L · Pro.** The scanner today *reports* a vulnerable plugin; a generic WAF
feed blocks *generic* patterns. Neither neutralizes a specific, known, unpatched
CVE in place. The category leader (Patchstack) is built on this: once a vuln is
validated, a targeted firewall rule matched to that exact exploit/version is pushed
and removed once patched — mitigating ~48h before public disclosure.

Why it matters (2024 data): ~8,000 new WP vulns/yr (+34%), **96% in plugins**,
**43% exploitable unauthenticated**, **>50% not patched before disclosure**, **~35%
never patched**. Auto-update enforcement can't help when no fix exists (abandoned
plugins) or the vendor never ships one — vPatch is the only thing that can.

Pragmatic path: fuse three roadmap items into one flagship — ship **only the
vPatch rules matching each site's detected plugin/version inventory** (from the
existing vuln scanner). Keeps false-positives + overhead low; reframes GemSecurity
from "scanner + generic WAF" to "proactive mitigation platform."

---

## Tier A — high-value net-new (build next)

| Gap | Kind | Tier | Effort | Why |
|---|---|---|---|---|
| **Supply-chain / backdoor detection** — verify installed plugin/theme files vs .org canonical checksums (catch tampered files even when the version string is unchanged) + **ownership-change / new-maintainer + .org-removal alerts** | ENH (extends roadmapped "integrity vs wp.org") | Pro | M | 2024–25 wave: legit-channel backdoors (Social Warfare, EssentialPlugin's 30+ plugins, Gravity Forms, Smart Slider). Scanning + auto-update can't catch a backdoor pushed *as a normal update*. |
| **Client-side / payment-page script monitoring** — inventory scripts on checkout pages, authorize each, SRI/hash integrity, alert on tampering/new scripts (PCI-DSS 4.0 **6.4.3 + 11.6.1**, mandatory since Mar 2025) | NEW | Pro | M–L | Magecart/JS-skimmer defense **and** a hard compliance requirement for any card-taking store — and this install runs StoreEngine/WooCommerce. Distinct from server-side file baseline. |
| **REST API + Application-Password governance + enumeration suppression** — app-password inventory (last-used/scope/expiry/bulk-revoke, alert on new key), REST rate-limit + route permission audit, normalize login errors, oEmbed/author-slug masking | Mostly NEW (enumeration toggles partly exist) | Free + Pro | S–M | App passwords bypass 2FA (which we ship) and are long-lived/brute-forceable. Enumeration is the recon phase of nearly every automated attack. Low effort, high coverage. |
| **Real-time Live Traffic monitor** — every HTTP hit with IP + rDNS/WHOIS/country + firewall action, distinct from the WP audit log | NEW | Free (lite) + Pro | M | Marquee free-tier Wordfence/Cerber feature; the tool people actually use for triage. |
| **Compliance-grade audit log** — tamper-evident/hash-chained entries, retention policy, **SIEM/syslog forwarding**, framework-tagged PDF/CSV report export (GDPR/HIPAA/SOC2/PCI) | ENH (SIEM was a "someday" note) | Pro | M | Turns an existing feature into the thing regulated buyers actually purchase on. |

## Tier B — strong differentiators

| Gap | Kind | Tier | Effort | Why |
|---|---|---|---|---|
| **AI-crawler control** — GPTBot/CCBot/ClaudeBot/etc. allow-deny + robots + hard block; **verified-bot allowlisting via rDNS** (real Googlebot vs spoofed) | NEW | Free + Pro | S–M | AI scrapers are the fastest-growing traffic class (120M+ reqs/quarter); verified-bot handling also cuts false blocks. |
| **Credential-stuffing / behavioral bot detection** — breach-corpus check at login, distributed low-and-slow detection, risk-based/adaptive challenge | NEW (beyond volumetric auto-bans) | Pro | M–L | "~94% of login attempts are bots"; rotating-proxy credential reuse slips past volumetric brute-force bans. |
| **Behavioral / ML anomaly firewall** — score requests by behavior to catch zero-days signatures miss | NEW | Pro | L | Wordfence (2025 ML) and MalCare (Atomic) market hard against rule-only firewalls. Hard without a data network — pair with crowd feed. |
| **Incident-response forensic timeline** — correlate audit log + file-change + login anomalies into one chronology; **quarantine (not hard-delete)** + guided recovery playbook | ENH (over roadmapped malware primitives) | Pro | M–L | The investigator UX competitors win deals with; makes the roadmapped cleanup primitives usable. |
| **Trusted Devices + session-hijack detection** — device fingerprint, re-auth from new devices, deauth on mid-session IP/device change | NEW (beyond session mgmt) | Pro | M | Solid Pro's headline; targets session hijack + account takeover. |
| **Spam defense beyond login** — CAPTCHA on all forms (comments/registration/lost-pw/WooCommerce/CF7/Gravity), **silent/invisible CAPTCHA** (behavioral scoring), heuristic antispam engine | ENH (login CAPTCHA + comment honeypot exist) | Free + Pro | M | Visible reCAPTCHA reads as dated; silent scoring is the modern expectation (Shield/Turnstile). |
| **Role/capability governance** — capability-change auditing, unexpected-capability/least-privilege alerts (extends rogue-admin) | ENH | Free + Pro | M | Broken access control is a top-3 vector; contributor→admin escalation is the most common exploit prerequisite (34%). |

## Tier C — quick wins (cheap, high signal)

| Gap | Kind | Tier | Effort |
|---|---|---|---|
| **security.txt generator** (RFC 9116, `/.well-known/security.txt`) | NEW | Free | S |
| **Login honeypots / deception** — fake login trap that auto-bans any interactor; feeds the ban ledger | NEW | Free | S |
| **CSP: enforcing mode + violation-report endpoint + dashboard** (upgrade the current report-only CSP; also underpins payment-page monitoring) | ENH | Free + Pro | S–M |
| **File-permission scanner + fix recommendations** | NEW | Free | S |
| **SPF/DKIM/DMARC checker + alerts** for the site domain (full DMARC RUA ingestion is a larger Pro follow-up) | NEW | Free (checker) + Pro | S–M |
| **Persistence/backdoor checks** — flag malicious mu-plugins, backdoored cron events, hidden admins, obfuscated eval/base64 | ENH | Pro | S–M |

## Tier D — agency / ops (segment expansion)

| Gap | Kind | Tier | Effort |
|---|---|---|---|
| **White-label + branded client security reports (PDF)** | NEW | Pro | M |
| **1-click restore UX + staging/cloning** (backup engine + schedules already exist; restore-to-known-good + safe-update staging do not) | ENH | Pro | M–L |
| **SSL/TLS cert-expiry + DNS-change monitoring** (early defacement/hijack signal) | NEW | Pro | S–M |
| **Temporary / passwordless support login links** — time-boxed, role-scoped, auto-expiring, fully audited (implement carefully — the "Temporary Login" plugin shipped an auth-bypass CVE) | NEW | Pro | M |

Low value / note-only: DB table-prefix change; content protection (disable
right-click/copy, hotlink) — sell to non-technical owners, minimal real security.

**Architecturally out of reach for a plugin** (integrate/configure, don't rebuild):
edge cloud WAF + CDN + true DDoS mitigation (Sucuri/Cloudflare).

---

## UX / approach patterns worth copying (not features themselves)

- **Firewall "Learning mode"** — run the WAF in allowlist-building mode for ~1 week
  before enforcing, to kill false positives. Cheap, high-trust; directly answers the
  top objection to aggressive WAFs.
- **`auto_prepend_file` "extended protection" tier** — optional wizard to run the
  firewall before WP loads at all (earlier than the current mu-plugin), with server
  detection + one-click revert.
- **Crowd-sourced integrity hashes + free CrowdSec-style IP reputation** — Shield
  proves both can live in the *free* tier and cut false positives.
- **Per-action geo/role granularity** (Cerber) — "allow browsing but block this
  country/role from commenting/registering/REST/login" beats a blunt country block.
- **Zero-config framing** (MalCare) — "connect and forget," off-site scan/clean so
  site performance is untouched.

---

## Recommended bundles

**Free (wp.org growth / credibility):** REST + app-password governance + enumeration
suppression · verified-bot + AI-crawler control · security.txt · login honeypots ·
file-permission scanner · SPF/DKIM/DMARC checker · silent CAPTCHA on all forms ·
Live Traffic (lite). → All small/medium, and each is a "why isn't this everywhere"
credibility win.

**Pro flagship (the sell):** ① Virtual patching (★) · ② Supply-chain/backdoor
detection · ③ Client-side payment-page monitoring (PCI) · ④ Compliance-grade audit
log + SIEM + reports · ⑤ IR forensic timeline + quarantine. → Reframes the product
as a proactive, compliance-ready platform, not a scanner.

**Agency add-on:** white-label PDF reports · 1-click restore + staging · SSL/DNS
monitoring · temporary support logins.
