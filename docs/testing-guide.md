# GemSecurity — Security Testing Guide

Complete manual test procedures for every security measure implemented in the plugin.

---

## Table of Contents

1. [Brute-Force / Login Lockout](#1-brute-force--login-lockout)
2. [Admin Login Alert Email](#2-admin-login-alert-email)
3. [Admin Session Timeout (Absolute)](#3-admin-session-timeout-absolute)
4. [Idle Session Timeout](#4-idle-session-timeout)
5. [WAF — SQLi / XSS / LFI / RCE Detection](#5-waf--sqli--xss--lfi--rce-detection)
6. [WAF — Bad Bot Blocking](#6-waf--bad-bot-blocking)
7. [WAF — Rate Limiting](#7-waf--rate-limiting)
8. [WAF — 404 Throttling](#8-waf--404-throttling)
9. [Firewall — IP Blocklist](#9-firewall--ip-blocklist)
10. [Firewall — Author Enumeration Block](#10-firewall--author-enumeration-block)
11. [Firewall — WordPress Version Hiding](#11-firewall--wordpress-version-hiding)
12. [Firewall — User REST Endpoint Disabled](#12-firewall--user-rest-endpoint-disabled)
13. [Firewall — XML-RPC Disabled](#13-firewall--xml-rpc-disabled)
14. [Password Policy](#14-password-policy)
15. [Two-Factor Auth — TOTP](#15-two-factor-auth--totp)
16. [Two-Factor Auth — Email OTP](#16-two-factor-auth--email-otp)
17. [Two-Factor Auth — Backup Codes](#17-two-factor-auth--backup-codes)
18. [Custom Login URL](#18-custom-login-url)
19. [Security Headers](#19-security-headers)
20. [CAPTCHA](#20-captcha)
21. [Admin Guard (Rogue Admin Detection)](#21-admin-guard-rogue-admin-detection)
22. [Geolocation — Country Whitelist](#22-geolocation--country-whitelist)
23. [Geolocation — Per-User Location Lock](#23-geolocation--per-user-location-lock)
24. [Lockdown Mode (Maintenance)](#24-lockdown-mode-maintenance)
25. [File Scanner](#25-file-scanner)
26. [Alerts (Slack / Telegram / Webhook)](#26-alerts-slack--telegram--webhook)

---

## 1. Brute-Force / Login Lockout

**Module:** `includes/modules/login-security.php`  
**Settings:** `login_attempts_enabled`, `login_attempts_limit` (default: 5), `login_lockout_duration` (default: 30 min)

### Steps

1. Open `/wp-login.php` in a browser.
2. Submit wrong credentials repeatedly until you hit the configured limit.
3. On the next attempt the form should be blocked with:
   > *"Access temporarily blocked. Too many failed login attempts. Please try again in 30 minutes."*
4. Check **Audit Log** — expect `login_failed` entries followed by a `login_lockout` entry.
5. Log in with correct credentials from the same IP to confirm the counter resets (attempts transient is deleted on success).

### Expected log events

| Event | Severity |
|---|---|
| `login_failed` | notice |
| `login_lockout` | warning |

---

## 2. Admin Login Alert Email

**Module:** `includes/modules/login-security.php`  
**Settings:** `admin_login_alert_enabled` (default: off), `admin_login_alert_email`

### Steps

1. Enable the setting and enter a target email address.
2. Log in as any user with the `administrator` role.
3. Check the inbox — expect an email containing:
   - Username and email
   - Login timestamp
   - Visitor IP address
   - Browser user-agent

### Expected log events

| Event | Severity |
|---|---|
| `admin_login` | notice |

---

## 3. Admin Session Timeout (Absolute)

**Module:** `includes/modules/login-security.php`  
**Settings:** `admin_session_timeout_enabled` (default: off), `admin_session_timeout_hours` (default: 24)

### Steps
wp user meta update <USER_ID> _gemsecurity_login_time <TIMESTAMP_OVER_1H_AGO>
1. Enable the setting and set timeout to `1` hour for testing.
2. Log in as an administrator.
3. Backdate the login timestamp via WP-CLI to simulate expiry:
   ```bash
   wp user meta update <USER_ID> _gemsecurity_login_time <TIMESTAMP_OVER_1H_AGO>
   ```
4. Refresh any admin page — expect an automatic logout and redirect to `wp-login.php`.

### Expected log events

| Event | Severity |
|---|---|
| `admin_session_expired` | info |

---

## 4. Idle Session Timeout

**Module:** `includes/modules/sessions.php`  
**Settings:** `idle_timeout_enabled` (default: off), `idle_timeout_minutes` (default: 30)

### Steps

1. Enable the setting and set minutes to `1` for testing.
2. Log in as any user.
3. Backdate the last-activity meta via WP-CLI:
   ```bash
   wp user meta update <USER_ID> _gemsec_last_activity <TIMESTAMP_OVER_1MIN_AGO>
   ```
4. Refresh a page — expect automatic logout and redirect to `wp-login.php`.

### Expected log events

| Event | Severity |
|---|---|
| `idle_logout` | info |

---

## 5. WAF — SQLi / XSS / LFI / RCE Detection

**Module:** `includes/modules/waf.php`  
**Settings:** `waf_enabled`, `waf_block_sqli`, `waf_block_xss`, `waf_block_lfi`, `waf_block_rce`

> **Note:** Run these tests on a local dev site only.

### Test URLs (paste into your browser or use curl)

| Attack Type | Test URL |
|---|---|
| SQL Injection | `/?s=1 UNION SELECT 1,2,3 FROM wp_users` |
| SQL Injection | `/?id=1 OR 1=1` |
| XSS | `/?q=<script>alert(1)</script>` |
| XSS | `/?msg=<img src=x onerror=alert(1)>` |
| LFI | `/?file=../../etc/passwd` |
| LFI | `/?path=php://filter/convert.base64-encode/resource=index.php` |
| RCE | `/?cmd=system(whoami)` |
| RCE | `/?x=passthru(id)` |

### Expected result

HTTP `403` with message: *"Your request was blocked for security reasons."*

### Expected log events

| Event | Severity |
|---|---|
| `waf_block` | critical |

---

## 6. WAF — Bad Bot Blocking

**Module:** `includes/modules/waf.php`  
**Settings:** `block_bad_bots` (default: off)

### Steps

Run from terminal. Each should return HTTP `403`:

```bash
curl -A "sqlmap/1.7.8#stable" https://dev.test/
curl -A "Nikto/2.1.6" https://dev.test/
curl -A "WPScan v3.8.25" https://dev.test/
curl -A "python-requests/2.31.0" https://dev.test/
curl -A "Hydra" https://dev.test/
curl -A "" https://dev.test/           # empty UA — also blocked
```

### Blocked user-agent keywords

`sqlmap`, `nikto`, `nmap`, `masscan`, `zgrab`, `nuclei`, `acunetix`, `netsparker`, `fimap`, `dirbuster`, `gobuster`, `wpscan`, `hydra`, `libwww-perl`, `python-requests`, `curl/`, `wget/`

### Expected log events

| Event | Severity |
|---|---|
| `waf_bad_bot` | warning |

---

## 7. WAF — Rate Limiting

**Module:** `includes/modules/waf.php`  
**Settings:** `rate_limit_enabled` (default: off), `rate_limit_max` (default: 240/min), `rate_limit_window` (default: 1 min)

### Steps

Lower the limit to something testable (e.g., 10 requests/minute) in settings, then:

```bash
for i in $(seq 1 20); do
  echo -n "Request $i: "
  curl -s -o /dev/null -w "%{http_code}\n" https://dev.test/
done
```

Requests beyond the limit should return `429` with: *"Too many requests. Please slow down."*

### Expected log events

| Event | Severity |
|---|---|
| `waf_rate_limited` | warning |

---

## 8. WAF — 404 Throttling

**Module:** `includes/modules/waf.php`  
**Settings:** `throttle_404_enabled` (default: off), `throttle_404_max` (default: 20), `throttle_404_window` (default: 5 min)

### Steps

```bash
for i in $(seq 1 25); do
  curl -s -o /dev/null -w "%{http_code}\n" https://dev.test/fake-page-$i/
done
```

After hitting the threshold, check the audit log for `waf_404_flood`. The IP accumulates a strike toward the auto-ban threshold.

### Expected log events

| Event | Severity |
|---|---|
| `waf_404_flood` | warning |

---

## 9. Firewall — IP Blocklist

**Module:** `includes/modules/firewall.php`  
**Settings:** `firewall_enabled` (default: on), `ip_blocklist`

### Steps

1. Find your current IP:
   ```bash
   curl https://api.ipify.org
   ```
2. Add that IP (or `127.0.0.1`) to the IP blocklist in settings.
3. Visit the site — expect HTTP `403`: *"Your access to this site has been blocked."*
4. Remove your IP from the blocklist to restore access.

**CIDR range test:** Add `192.168.0.0/24` and make a request from within that subnet.

### Expected log events

| Event | Severity |
|---|---|
| `firewall_block` | warning |

---

## 10. Firewall — Author Enumeration Block

**Module:** `includes/modules/firewall.php`  
**Settings:** `block_author_enumeration` (default: on)

### Steps

```bash
curl -v "https://dev.test/?author=1" 2>&1 | grep -E "Location|HTTP/"
```

**Pass:** `301` redirect to homepage — no username revealed.  
**Fail:** `301` redirect to `/author/admin/` or similar (leaks the username).

### Expected log events

| Event | Severity |
|---|---|
| `author_enumeration_blocked` | notice |

---

## 11. Firewall — WordPress Version Hiding

**Module:** `includes/modules/firewall.php`  
**Settings:** `hide_wp_version` (default: on)

### Steps

```bash
curl -s https://dev.test/ | grep -i "generator"
```

**Pass:** No `<meta name="generator" content="WordPress ...">` in the output.  
**Fail:** WordPress version string is visible.

Also check that enqueued asset URLs have no `?ver=X.Y.Z` query string exposing the WP version.

---

## 12. Firewall — User REST Endpoint Disabled

**Module:** `includes/modules/firewall.php`  
**Settings:** `disable_user_rest` (default: on)

### Steps

```bash
curl -s https://dev.test/wp-json/wp/v2/users | head -c 200
```

**Pass:** Returns a 404 or `{"code":"rest_no_route",...}` error — no user data.  
**Fail:** Returns a JSON array of user objects (usernames, emails exposed).

---

## 13. Firewall — XML-RPC Disabled

**Module:** `includes/modules/firewall.php`  
**Settings:** `xmlrpc_disabled` (default: off)

### Steps

```bash
curl -X POST https://dev.test/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'
```

**Pass:** Empty response body or XML-RPC disabled message.  
**Fail:** Returns a list of available methods.

---

## 14. Password Policy

**Module:** `includes/modules/password-policy.php`  
**Settings:** `password_policy_enabled`, `password_min_length` (default: 10), `password_require_complexity`, `password_check_breached`, `password_expiry_days`

### Test cases

Go to **Users → Your Profile** and try setting each password:

| Password | Expected Result |
|---|---|
| `abc` | Blocked — too short |
| `alllowercase1!` | Blocked — missing uppercase |
| `ALLUPPERCASE1!` | Blocked — missing lowercase |
| `NoNumbers!!` | Blocked — missing number |
| `NoSymbols1` | Blocked — missing symbol |
| `Password1!` | Blocked — known breach (HIBP) |
| `Xj#9mKpQ2$vL` | Accepted |

### Password expiry test

1. Set `password_expiry_days` to `1`.
2. Set `_gemsec_pw_set` user meta to a timestamp >1 day old:
   ```bash
   wp user meta update <USER_ID> _gemsec_pw_set <OLD_TIMESTAMP>
   ```
3. Visit the admin dashboard — expect a yellow notice banner: *"Your password has expired..."*

---

## 15. Two-Factor Auth — TOTP

**Module:** `includes/modules/two-factor.php`  
**Settings:** `two_factor_enabled`, `two_factor_enforced_roles`

### Steps

1. Enable 2FA for your account, set method to **Authenticator App (TOTP)**.
2. Scan the QR code with Google Authenticator, Authy, or 1Password.
3. Log out, then log in with valid credentials.
4. You should land on the **2FA interstitial** form (not the dashboard).
5. Enter the current 6-digit code from your app → proceed to dashboard.
6. Log out, log in again, enter a **wrong code** → *"Invalid code. Please try again."*

### Expected log events

| Event | Severity |
|---|---|
| `2fa_challenge` | info |
| `2fa_failed` | warning |
| `2fa_success` | info |

---

## 16. Two-Factor Auth — Email OTP

**Module:** `includes/modules/two-factor.php`

### Steps

1. Set 2FA method to **Email** for a test user.
2. Log in with valid credentials.
3. Check the email inbox — expect a 6-digit code email (valid for 10 minutes).
4. Enter the code → proceed to dashboard.
5. Click **Resend code** → a new email should arrive (old code still works until replaced).
6. Wait >10 minutes or delete the transient, then submit the code → expect rejection.

---

## 17. Two-Factor Auth — Backup Codes

**Module:** `includes/modules/two-factor.php`

### Steps

1. Generate backup codes from the 2FA settings panel (10 codes, format: `xxxx-xxxx`).
2. Log out, then log in with valid credentials.
3. At the 2FA form, enter a backup code instead of a TOTP code.
4. Should succeed and proceed to the dashboard.
5. Try the **same code again** — it must be rejected (single-use).
6. Check that the code count decremented by 1 in the settings.

### Expected log events

| Event | Severity |
|---|---|
| `2fa_success` | notice (backup code used) |

---

## 18. Custom Login URL

**Module:** `includes/modules/custom-login.php`  
**Settings:** `custom_login_enabled`, `custom_login_slug`

### Steps

1. Enable the feature, set slug to `my-secret-login`.
2. Visit `https://dev.test/wp-login.php` while logged out → expect `404`.
3. Visit `https://dev.test/my-secret-login/` → expect the normal WordPress login form.
4. Log in via the custom URL → confirm redirect works correctly.
5. Confirm the "Lost your password?" and logout links all point to the custom slug.
6. Visit `https://dev.test/wp-login.php?action=logout` → should still work (logout must not break).

---

## 19. Security Headers

**Module:** `includes/modules/security-headers.php`  
**Settings:** `security_headers_enabled`, individual header settings

### Steps

```bash
curl -I https://dev.test/
```

**Expected headers:**

| Header | Expected Value |
|---|---|
| `X-Frame-Options` | `SAMEORIGIN` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=()` |
| `Strict-Transport-Security` | `max-age=15552000` (HTTPS only) |
| `Content-Security-Policy` | your configured value |

Also verify headers appear on:
- The homepage (front-end)
- `/wp-admin/` (admin)
- `/wp-login.php` (login page)

**Online tool:** [securityheaders.com](https://securityheaders.com) — enter your site URL for a graded report.

---

## 20. CAPTCHA

**Module:** `includes/modules/captcha.php`  
**Settings:** `captcha_enabled`, `captcha_provider`, `captcha_site_key`, `captcha_secret_key`

### Google reCAPTCHA v2 test keys (safe for local dev)

```
Site key:   6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI
Secret key: 6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe
```

### Steps

1. Configure the test keys and enable CAPTCHA on the login form.
2. Visit the login page — the CAPTCHA widget should render.
3. Submit the form **without** solving the CAPTCHA → expect: *"Please complete the CAPTCHA challenge."*
4. Solve the CAPTCHA and submit with valid credentials → proceed normally.
5. Repeat for register and lost-password forms if those are enabled.

### Expected log events

| Event | Severity |
|---|---|
| `captcha_failed` | notice |

---

## 21. Admin Guard (Rogue Admin Detection)

**Module:** `includes/modules/admin-guard.php`  
**Settings:** `admin_whitelist_enabled`, `admin_whitelist`, `rogue_admin_action` (`demote` or `delete`), `notify_on_rogue_admin`

### Steps — new account

1. Enable the guard. Ensure your real admin email is in the whitelist.
2. Go to **Users → Add New**, create a user with role `Administrator` and a **non-whitelisted** email.
3. Save.
   - If `rogue_admin_action = delete`: the account should be deleted immediately.
   - If `rogue_admin_action = demote`: the role should be changed to `subscriber`.
4. Check **Audit Log** for `rogue_admin_deleted` or `rogue_admin_demoted`.
5. Check the site admin inbox for the notification email.

### Steps — role promotion

1. Create a regular subscriber with a non-whitelisted email.
2. Go to **Users**, edit them, change their role to `Administrator`, save.
3. The role should revert to subscriber (or the account deleted).

### Protected accounts (should NOT be blocked)

| Account | Reason |
|---|---|
| User ID 1 | Founding user |
| User with `admin_email` address | Site owner |
| Currently logged-in admin | Self-protection |
| Multisite super admins | Elevated privilege |

### Expected log events

| Event | Severity |
|---|---|
| `rogue_admin_deleted` | critical |
| `rogue_admin_demoted` | critical |

---

## 22. Geolocation — Country Whitelist

**Module:** `includes/modules/geolocation.php`  
**Settings:** `geo_enabled`, `geo_block_site_enabled`, `geo_whitelist_login_enabled`, `geo_allowed_countries`

### Steps

1. Enable geo blocking. Add only `US` to the allowed countries list.
2. To test from a blocked country, use a VPN endpoint in an unlisted country.
3. Visit the site → expect HTTP `403`: *"Access from your location is not permitted."*
4. Login attempt from a blocked country → expect: *"Login blocked. Sign-in from your location is not permitted."*

### Expected log events

| Event | Severity |
|---|---|
| `geo_site_blocked` | warning |
| `geo_login_blocked` | warning |

---

## 23. Geolocation — Per-User Location Lock

**Module:** `includes/modules/geolocation.php`  
**Settings:** `geo_user_lock_enabled`, `geo_user_lock_action` (`verify` or `block`)

### Steps

1. Enable per-user locking. Assign `US` as the allowed country for a test user.
2. Log in from a VPN endpoint in a different country (e.g., `DE`).
3. After correct password entry:
   - **`verify` mode:** Session is torn down, you are shown an email OTP form. Enter the emailed code → new country is added to the user's allowed list.
   - **`block` mode:** Immediately shown a 403 — *"This account cannot be accessed from your current location."*
4. Log in again from the same new country → no challenge this time (country was saved).

### Expected log events

| Event | Severity |
|---|---|
| `geo_new_location` | notice |
| `geo_verified` | notice |
| `geo_verify_failed` | warning |
| `geo_login_blocked` | warning |

---

## 24. Lockdown Mode (Maintenance)

**Module:** `includes/modules/lockdown.php`  
**Settings:** `lockdown_enabled`, `lockdown_message`

### Steps

1. Enable lockdown mode. Set a custom message if desired.
2. Open the site in an **incognito window** (not logged in) → expect HTTP `503` with the maintenance message.
3. In your regular browser (logged in as admin) → site should load normally.
4. Disable lockdown → site returns to normal for everyone.

---

## 25. File Scanner

**Module:** `includes/modules/scanner.php`

### Steps — core integrity

1. Run a scan from the GemSecurity dashboard.
2. Note the "clean" baseline result.
3. Add a harmless comment to a WordPress core file:
   ```bash
   echo "// test" >> /path/to/wp-includes/functions.php
   ```
4. Run the scan again → that file should be flagged as **modified**.
5. Restore the file: `git checkout /path/to/wp-includes/functions.php`

### Steps — suspicious upload detection

1. Place a PHP file in the uploads directory:
   ```bash
   echo "<?php phpinfo(); ?>" > /path/to/wp-content/uploads/shell-test.php
   ```
2. Run the scan → expect a **critical** finding: *"Executable PHP file inside the uploads directory."*
3. Remove the test file after verifying.

### Steps — malware pattern detection

The scanner flags PHP files with **2+ suspicious patterns**. To test without real malware:

```bash
cat > /path/to/wp-content/mu-plugins/test-suspicious.php << 'EOF'
<?php
// test file - delete after scan
eval(base64_decode('dGVzdA=='));
shell_exec('id');
EOF
```

Run the scan → expect a **warning** finding listing the matched patterns.  
Delete the test file after verifying.

---

## 26. Alerts (Slack / Telegram / Webhook)

**Module:** `includes/modules/alerts.php`  
**Settings:** `alerts_enabled`, `alert_min_severity`, `alert_slack_webhook`, `alert_telegram_token`, `alert_telegram_chat`, `alert_webhook_url`

### Steps — webhook test (easiest)

1. Go to [webhook.site](https://webhook.site) and copy your unique URL.
2. Paste it into `alert_webhook_url` in settings.
3. Trigger a high-severity event (e.g., trigger a WAF block or a brute-force lockout).
4. Check webhook.site — the alert payload should arrive within seconds.

### Steps — weekly digest

Trigger the digest manually via WP-CLI:

```bash
wp cron event run gemsecurity_weekly_digest
```

Expect an email to the configured address with a summary of the last 7 days.

### Debounce behavior

Alerts are rate-limited to one per event type per 5 minutes. To test the same event type twice, either wait 5 minutes or delete the debounce transient:

```bash
wp transient delete gemsec_alert_<MD5_OF_EVENT_TYPE>
```

---

## Useful WP-CLI Reference

```bash
# View all GemSecurity settings
wp option get gemsecurity_settings --format=json

# Backdate admin login time (test session timeout)
wp user meta update <USER_ID> _gemsecurity_login_time $(date -v-2H +%s)

# Backdate last activity (test idle timeout)
wp user meta update <USER_ID> _gemsec_last_activity $(date -v-2M +%s)

# Backdate password set time (test password expiry)
wp user meta update <USER_ID> _gemsec_pw_set $(date -v-2d +%s)

# Clear a brute-force lockout for an IP
wp transient delete gemsec_lock_$(echo -n "127.0.0.1" | md5)

# View recent audit log entries
wp db query "SELECT event_type, severity, message, created_at FROM $(wp db prefix)gemsecurity_logs ORDER BY id DESC LIMIT 20;" --allow-root

# Trigger the weekly digest
wp cron event run gemsecurity_weekly_digest

# List active cron events registered by the plugin
wp cron event list | grep gemsec
```

---

## Test Checklist

Use this to track which features have been verified:

- [ ] Brute-force lockout triggers after N failed attempts
- [ ] Lockout message is shown correctly
- [ ] Admin login alert email is received
- [ ] Admin session timeout logs out after configured hours
- [ ] Idle timeout logs out after configured minutes
- [ ] WAF blocks SQLi patterns (403)
- [ ] WAF blocks XSS patterns (403)
- [ ] WAF blocks LFI patterns (403)
- [ ] WAF blocks RCE patterns (403)
- [ ] Bad bot user-agents are blocked (403)
- [ ] Rate limit triggers 429 after threshold
- [ ] 404 flood is logged as `waf_404_flood`
- [ ] IP blocklist returns 403
- [ ] Author enumeration `?author=1` redirects to home
- [ ] WordPress version not visible in page source
- [ ] `/wp-json/wp/v2/users` returns no data when logged out
- [ ] XML-RPC endpoint returns empty/disabled response
- [ ] Weak password is rejected at profile update
- [ ] Breached password is rejected (HIBP check)
- [ ] Password expiry notice appears in admin
- [ ] TOTP 2FA interstitial appears after login
- [ ] Wrong TOTP code is rejected
- [ ] Email OTP is received and accepted
- [ ] Backup code works once then is consumed
- [ ] `/wp-login.php` returns 404 when custom login is active
- [ ] Custom login slug serves the login form correctly
- [ ] Security headers present in HTTP response
- [ ] CAPTCHA widget renders on login form
- [ ] Form rejected without CAPTCHA token
- [ ] Non-whitelisted admin account is demoted/deleted by Admin Guard
- [ ] Admin Guard notification email is received
- [ ] Site returns 503 in lockdown mode for guests
- [ ] Admins can access site during lockdown
- [ ] Scanner detects modified core files
- [ ] Scanner detects PHP files in uploads directory
- [ ] Alert webhook receives payload on high-severity event
- [ ] Weekly digest is sent via email and alert channels
- [ ] Geolocation blocks site access from non-whitelisted country
- [ ] Geolocation blocks login from non-whitelisted country
- [ ] Per-user location lock triggers email OTP on new country
