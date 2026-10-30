# GemSecurity — Page / Section / Item list (QA assignment)

Format: **Page → Section → Items**. Only the item names are listed (exactly as they appear on screen). Fill the **Assigned to** column with one person per item.

`[Pro]` = shown only when the GemSecurity Pro add-on is active.

---

## 1. Setup Wizard (`page=gemsecurity-setup`)

### Step 1 — Welcome
| Item | Assigned to |
|---|---|
| Site domain chip | |
| Block attacks card | |
| Find problems card | |
| Stay informed card | |
| Let's get started button | |
| Skip setup | |

### Step 2 — A few questions
| Item | Assigned to |
|---|---|
| What kind of site is this? (Blog or portfolio / Business site / Online store / Membership, courses or community / Agency or multi-client site) | |
| Who else logs in? (Only me / A small team / Members and customers can register) | |
| Has anything suspicious happened lately? (All quiet / Spam, brute-force or odd traffic / Been hacked before, or files look changed) | |
| Where does your traffic come from? (Global audience / A few specific countries / Mostly bots and scrapers lately) | |
| If a real visitor got blocked once, how bad is that? (Terrible — be gentle / Balanced is fine / Fine — lock it down) | |
| Recommended-for-you box (Essential / Recommended / Maximum) | |

### Step 3 — Review features
| Item | Assigned to |
|---|---|
| Feature list by category (tick / untick each module) | |
| Pro modules shown disabled when Pro is not active | |

### Step 4 — Alerts
| Item | Assigned to |
|---|---|
| Email me security alerts | |
| Send alerts to | |
| Alert me about | |
| Weekly security summary | |
| Finish setup | |

### Step 5 — All set
| Item | Assigned to |
|---|---|
| Protection level (Change) | |
| Features switched on (View) | |
| Alerts sent to (Edit) | |
| What happens next | |
| Run first scan | |
| Go to dashboard | |

---

## 2. Top bar and navigation (all pages)

| Section | Item | Assigned to |
|---|---|---|
| Top bar | Logo link to Dashboard | |
| Top bar | Breadcrumb / page name | |
| Top bar | Group tabs and dropdowns (Dashboard, Firewall, Login & Access, Scanning, Logs & Monitoring, Settings) | |
| Top bar | Security score pill | |
| Top bar | Score popover (Active issues, To fix, Fix, Fix all, Undo) | |
| Top bar | Theme toggle | |
| Left sub-nav | Sub-nav items for each group | |
| Page header card | Icon, name, status pill, description | |
| Score tips banner | Boost your score list, Fix, Fix all, dismiss | |
| Help drawer | "?" guide for the current page | |
| Save bar | Unsaved changes, Discard, Save changes | |
| Leave dialog | Stay / Leave without saving | |

---

## 3. Dashboard (`page=gemsecurity`)

| Section | Item | Assigned to |
|---|---|---|
| Security score | Score ring | |
| Security score | Grade pill | |
| Security score | Protections active bar | |
| Security score | Fix N issues | |
| What needs your attention | Issue rows (title, severity, description) | |
| What needs your attention | Enable / Run scan / Review button | || What needs your attention | Plugin lock row (opens Firewall) | |

| What needs your attention | View all / Show less | |
| Access | Logins | |
| Access | Failed logins | |
| Access | Lockouts | |
| Threats | Rogue admins | |
| Threats | Vulnerabilities | |
| Threats | Critical events | |
| Firewall | Blocked requests | |
| Firewall | Bots blocked | |
| Firewall | Banned IPs | |
| Activity | Last 7 days chart | |
| Recent events | Event list | |

---

## 4. Modules (`page=gemsecurity-modules`)

| Section | Item | Assigned to |
|---|---|---|
| Header | Active N of M progress | |
| Header | Search modules | |
| Core | Dashboard, Modules, Notifications, Settings, Logs (Always on, Configure) | |
| Firewall & threats | Firewall | |
| Firewall & threats | Anti-Spam | |
| Firewall & threats | Threat Defense [Pro] | |
| Firewall & threats | Virtual Patch [Pro] | |
| Login & access | Login Security | |
| Login & access | CAPTCHA | |
| Login & access | Two-Factor | |
| Login & access | Social Login | |
| Login & access | Geolocation [Pro] | |
| Login & access | Admin Guard | |
| Login & access | API & Access | |
| Scanning | Scanner | |
| Scanning | Plugin Guard | |
| Scanning | Payment Integrity [Pro] | |
| Scanning | Incident Response [Pro] | |
| Maintenance | Monitoring [Pro] | |

---

## 5. Firewall (`page=gemsecurity-firewall`)

| Section | Item | Assigned to |
|---|---|---|
| Firewall | Enable firewall | |
| Firewall | IP blocklist | || Firewall | IP safelist | |
| Firewall | Your current IP, Add to safelist | |
| Firewall | Own IP refused in blocklist (warning message) | |

| Real visitor IP detection | This site is behind Cloudflare | |
| Real visitor IP detection | Other trusted proxies | || Site protection | Lock GemSecurity: unlock password, Turn lock on | |
| Site protection | Lock: Send me a code (step 1 of 2, password) | |
| Site protection | Lock: 6-digit emailed code, Unlock for 10 minutes (step 2 of 2) | |
| Site protection | Lock: Start over | |
| Site protection | Lock: Lock again now | |
| Site protection | Lock: Remove the lock | |
| Site protection | Lock: no Deactivate / Delete link on the Plugins page | |
| Site protection | Lock: protected settings and module off-switch refused while locked | |
| Site protection | Lock: plugin / theme install, upload and file editors refused while locked | |
| Site protection | Turn off all file uploads | |
| Site protection | Admin bar menu: GemSecurity > File uploads ON / OFF | |

| Hardening | Disable theme & plugin file editor | |
| Hardening | Disable XML-RPC | |
| Hardening | Hide WordPress version | |
| Hardening | Protect wp-config.php, error logs and wp-admin/includes | |
| Username enumeration | Block author enumeration | |
| Username enumeration | Block REST user enumeration | |
| Username enumeration | Generic login error messages | |
| Web Application Firewall | Enable request inspection (WAF) | |
| Web Application Firewall | Block SQL injection | |
| Web Application Firewall | Block cross-site scripting (XSS) | |
| Web Application Firewall | Block path traversal / file inclusion | |
| Web Application Firewall | Block remote code execution patterns | |
| Web Application Firewall | Also inspect POST request bodies | |
| Rate limiting & throttling | Limit request rate per IP | |
| Rate limiting & throttling | Max requests | |
| Rate limiting & throttling | Per window | |
| Rate limiting & throttling | Throttle 404 floods | |
| Rate limiting & throttling | Max 404s | |
| Security headers | Enable security headers | |
| Security headers | X-Frame-Options | |
| Security headers | Referrer-Policy | |
| Security headers | X-Content-Type-Options: nosniff | |
| Security headers | Permissions-Policy | |
| Security headers | HSTS (Strict-Transport-Security) | |
| Security headers | HSTS Max-age | |
| Security headers | Include subdomains | |
| Security headers | Preload | |
| Security headers | Content-Security-Policy | |
| Security headers | CSP directives | |
| Security headers | Report-only (do not enforce) | |
| Security headers | Collect violation reports | |
| Recent CSP violations | Violations table | |
| Bot control | Block malicious bots & scanners | |
| Bot control | Also block empty / missing user agents | |
| Bot control | Block AI crawlers & scrapers | |
| Bot control | Verify search-engine bots | |
| Hardening pack [Pro] | Restrict wp-admin by IP | |
| Hardening pack [Pro] | Allowed IPs | |
| Hardening pack [Pro] | Block sensitive files | |
| Hardening pack [Pro] | Block PHP execution in /uploads | |
| Hardening pack [Pro] | Force HTTPS | |
| security.txt | Serve security.txt | |
| security.txt | Contact | |
| security.txt | Expires | |
| security.txt | Policy URL | |
| File permissions | Permissions table (Path, Current, Recommended, Status) | |

---

## 6. Anti-Spam (`page=gemsecurity-anti-spam`)

| Section | Item | Assigned to |
|---|---|---|
| Comments | Disable comments entirely | |
| Silent bot protection | Enable silent anti-spam | |
| Silent bot protection | Minimum time before submit | |
| Silent bot protection | Also show a CAPTCHA on the comment form | |
| Heuristic comment filtering | Auto-flag spammy comments | |
| Heuristic comment filtering | Max links before spam | |
| Heuristic comment filtering | Spam keywords | |

---

## 7. Threat Defense [Pro] (`page=gemsecurity-threats`)

| Section | Item | Assigned to |
|---|---|---|
| Live traffic | Traffic table (Time, IP, Method, URI) | |
| Banned IP addresses | IP, Reason, Minutes fields | |
| Banned IP addresses | Ban IP | |
| Banned IP addresses | Ban list, Unban | |
| Bot activity | Blocked (24h) | |
| Bot activity | Blocked (7d) | |
| Bot activity | Top triggered patterns | |
| Custom bot patterns | Add pattern | |
| Custom bot patterns | Remove | |
| Escalating auto-ban | Enable auto-ban | |
| Escalating auto-ban | Strikes before ban | |
| Escalating auto-ban | Strike window | |
| Escalating auto-ban | Ban duration | |
| Escalating auto-ban | Extended protection (run firewall before other plugins) | |
| Advanced detection | Behavioral anomaly detection | |
| Advanced detection | Anomaly score threshold | |
| Advanced detection | Credential-stuffing detection | |
| Advanced detection | Distinct usernames before ban | |
| Advanced detection | Live traffic monitor | |

---

## 8. Virtual Patch [Pro] (`page=gemsecurity-virtual-patch`)

| Section | Item | Assigned to |
|---|---|---|
| Virtual patching | Enable virtual patching | |
| Virtual patching | Protections active count | |
| Shields currently active | Rule table (CVE / Rule, Blocks, Applies to, Attack severity, Status) | |

---

## 9. Login Security (`page=gemsecurity-login-security`)

| Section | Item | Assigned to |
|---|---|---|
| Brute-force protection | Limit login attempts | |
| Brute-force protection | Max attempts | |
| Brute-force protection | Lockout duration | |
| Administrator login alerts | Email me when an administrator logs in | |
| Administrator session timeout | Auto-logout administrators | |
| Administrator session timeout | Log out after | |
| Password policy | Enforce password policy | |
| Password policy | Minimum length | |
| Password policy | Expire passwords after | |
| Password policy | Require mixed case, number & symbol | |
| Password policy | Reject passwords found in data breaches | |
| Password policy | Test connection | |
| Custom login URL | Enable custom login URL | |
| Custom login URL | Login slug | |
| Custom login URL | Public login links go to | |
| Idle session timeout | Enable idle timeout | |
| Idle session timeout | Minutes idle | |
| Login honeypot | Enable login honeypot | |
| Trusted devices [Pro] | Track devices & detect new ones | |
| Trusted devices [Pro] | Email the user on a new-device sign-in | |
| Magic-link recovery [Pro] | Enable magic-link recovery | |
| Magic-link recovery [Pro] | Send login link | |
| Password rotation | Apply to roles | |
| Password rotation | Email each user a reset link | |
| Password rotation | Include my own account | |
| Password rotation | Check who this affects | |
| Password rotation | Force a reset for N users | |
| Password rotation | Cancel for N waiting users | |
| Password rotation | Rotate passwords automatically | |
| Password rotation | Maximum password age | |
| Your active sessions | Sessions table | |
| Your active sessions | Log out other sessions | |

---

## 10. CAPTCHA (`page=gemsecurity-captcha`)

| Section | Item | Assigned to |
|---|---|---|
| Header | Enabled / Disabled toggle | |
| Header | Status pill | |
| Choose a provider | Google reCAPTCHA v2 | |
| Choose a provider | hCaptcha | |
| Choose a provider | Cloudflare Turnstile | |
| Choose a provider | Use reCAPTCHA v3 instead | |
| Add your keys | Provider console link | |
| Add your keys | Step-by-step guide | |
| Add your keys | Site key | |
| Add your keys | Secret key (show / hide) | |
| Add your keys | v3 score threshold | |
| Add your keys | Verify keys | |
| Where to show it | Login form | |
| Where to show it | Registration form | |
| Where to show it | Lost-password form | |
| Where to show it | Comment form (link to Anti-Spam) | |
| Live preview | Login / Register / Reset tabs | |
| Ready to protect? | Provider chosen | |
| Ready to protect? | Shown on a form | |
| Ready to protect? | Keys look valid | |
| Ready to protect? | Keys verified | |

---

## 11. Two-Factor (`page=gemsecurity-two-factor`)

| Section | Item | Assigned to |
|---|---|---|
| My two-factor | Set up authenticator app | |
| My two-factor | QR code / manual key | |
| My two-factor | Enter the 6-digit code, Verify & enable | |
| My two-factor | Backup codes (save, Download) | |
| My two-factor | Use email codes instead | |
| My two-factor | Backup codes left | |
| My two-factor | Regenerate backup codes | |
| My two-factor | Disable | |
| Two-factor system | Enable two-factor authentication | |
| Two-factor system | Require two-factor by role | |
| Two-factor system | Required for (roles) | || Two-factor system | All roles option | |


---

## 12. Social Login (`page=gemsecurity-social-login`)

| Section | Item | Assigned to |
|---|---|---|
| Social login | Enable social login | |
| Social login | Authorized redirect URI, Copy | |
| Account behavior | Allow new account registration | |
| Account behavior | Link to existing accounts by email | |
| Account behavior | Default role for new accounts | |
| Google | Enabled | |
| Google | Client ID | |
| Google | Client secret | |
| Facebook | Enabled, Client ID, Client secret | |
| GitHub | Enabled, Client ID, Client secret | |
| X (Twitter) | Enabled, Client ID, Client secret | |

---

## 13. Geolocation [Pro] (`page=gemsecurity-geolocation`)

| Section | Item | Assigned to |
|---|---|---|
| Geolocation access control | Enable geolocation | |
| Geolocation access control | Test country lookup | |
| Visitor countries | Mode (Include / Exclude) | |
| Visitor countries | Allowed / Blocked countries | |
| Visitor countries | Block sign-in from other countries | |
| Visitor countries | Block entire site from other countries | |
| Visitor countries | Block when the country is unknown | |
| Visitor countries | Also apply the login block to administrators | || Administrator sign-in location | Restrict administrator sign-in to selected countries | |
| Administrator sign-in location | Countries administrators can sign in from, Add (my country) | |
| Administrator sign-in location | Also applies to application passwords and social login | |

| Per-user location lock | Enable per-user location lock | |
| Per-user location lock | User search | |
| Per-user location lock | Allowed countries per user, Save | |
| Per-user location lock | When a user signs in from a new country (Email a verification code / Block the login) | |

---

## 14. Admin Guard (`page=gemsecurity-admin-guard`)

| Section | Item | Assigned to |
|---|---|---|
| Whitelist guard | Enforce the administrator whitelist | |
| Whitelist guard | Action for promoted users (Demote / Delete) | |
| Whitelist guard | Email the site owner when a rogue admin is blocked | |
| Existing administrators | Check for unapproved admins | |
| Existing administrators | Delete them now | |
| Existing administrators | Demote them now | |
| Hidden administrator detection | Detect hidden administrators | |
| Hidden administrator detection | Email the site owner when a hidden admin is detected | |
| Approved administrators | Approved / Not approved list | |
| Approved administrators | Pre-approve an email address, Add | |

---

## 15. API & Access (`page=gemsecurity-api-hardening`)

| Section | Item | Assigned to |
|---|---|---|
| REST API | Rate-limit the REST API | |
| REST API | Max requests | |
| REST API | Per window | |
| Application passwords | Disable application passwords site-wide | |
| Application passwords | Email an alert when a new one is created | |
| Application passwords | Auto-expire after | |
| Existing application passwords | Passwords table | |
| Existing application passwords | Revoke | |
| Existing application passwords | Revoke all | |

---

## 16. Scanner (`page=gemsecurity-scanner`)

### Header
| Item | Assigned to |
|---|---|
| Scan summary (issues, WordPress version, last scan) | |
| Daily scan on / off badge | |
| Run scan now | |

### Tab: Integrity & files — Scan settings
| Item | Assigned to |
|---|---|
| Run a scan automatically every day | |
| Check core, plugins & themes for known vulnerabilities | |
| Test vulnerability feed | |
| Test WordPress.org connection | |
| Watch theme, must-use plugins & drop-ins for file changes | |
| Also baseline (WordPress core / All plugins / All themes) [Pro] | |
| Detect links to malicious or spam sites | |
| Link blocklist | |
| Link allowlist | |
| Auto-update vulnerable plugins & themes [Pro] | |
| Auto-update all plugins [Pro] | |
| Auto-update all themes [Pro] | |

### Tab: Integrity & files — Results
| Section | Item | Assigned to |
|---|---|---|
| Core file integrity | Core file list | |
| Core file integrity | Check core files / Repair files [Pro] | || Core file integrity | View & fix button | |
| Core file integrity | Popup: diff against the official file | |
| Core file integrity | Popup: Restore original | |
| Core file integrity | Popup: Edit file, Save file, Cancel | |
| Core file integrity | Popup: close (x, Esc, outside click) | |

| Unexpected / foreign files | File list, Mark as safe, Quarantine | |
| Suspicious files | File list, Mark as safe, Quarantine | |
| .htaccess rules | Rules list | |
| File change watcher | Set current files as clean baseline | |
| File change watcher | Changed files, Injected code lists | |
| Linked sites | Domain list, Block | |
| Known vulnerabilities | Vulnerability list | |
| Auto-executed code | mu-plugins and drop-ins list | |
| Supply chain | Plugin status list, Re-check | |
| Persistence checks | Findings list | |
| Files marked as safe | List, Remove | |

### Tab: Malware & recovery [Pro]
| Section | Item | Assigned to |
|---|---|---|
| Malware scanner | Run scan | |
| Malware scanner | Daily automatic scan | |
| Infected files | File list, Quarantine, Quarantine all | |
| Database findings | Findings list, Remove | |
| Quarantined files | List, Restore | |
| Plugin integrity (WordPress.org) | Verify, Verify all, filter | |

### Tab: Search
| Section | Item | Assigned to |
|---|---|---|
| Search files & database | Search term | |
| Search files & database | Files (wp-content) | |
| Search files & database | Database | |
| Search files & database | Regular expression | |
| Search files & database | Search | |
| Search files & database | File matches, Database matches | |

---

## 17. Plugin Guard (`page=gemsecurity-plugin-guard`)

| Section | Item | Assigned to |
|---|---|---|
| Plugin Guard (status) | Enforcing / Report only badge | |
| Plugin Guard (status) | Counts (Verified, Trusted, Modified, Blocked) | |
| Plugin Guard (status) | Re-check against WordPress.org | |
| Plugin Guard (status) | Turn on enforcement | |
| Plugin Guard (status) | Trust selected & turn on | |
| Plugin Guard (status) | Turn enforcement off | |
| Installed plugins | Plugin table, Trust, Remove trust | |
| Installed themes | Theme table | |
| Install Lock | Off / Locked / Temporarily unlocked | |
| Install Lock | Lock now | |
| Install Lock | Unlock for 15 minutes | |
| Upload Shield | Block executable uploads | |
| Upload Shield | Also block SVG, HTML and JavaScript files | |
| Upload Shield | Block the uploader's IP address | |
| Upload Shield | Ban length | |
| Upload Shield | Can PHP run where it should not? (Run test) | |
| Must-use plugins | Must-use list | |
| Must-use plugins | Quarantined by Plugin Guard, Restore & trust | |
| Pre-approve an upload | Folder name, Pre-approve | |
| Activity | Blocked activity table | |

---

## 18. Payment Integrity [Pro] (`page=gemsecurity-payment-integrity`)

| Section | Item | Assigned to |
|---|---|---|
| Payment-page integrity | Monitor payment-page scripts | |
| Payment-page integrity | Extra payment page IDs | |
| Unauthorised scripts detected | Script list | |
| Authorised script inventory | Inventory table | |
| Authorised script inventory | Authorise current | |

---

## 19. Incident Response [Pro] (`page=gemsecurity-incident-response`)

| Section | Item | Assigned to |
|---|---|---|
| Recovery actions | Log out everyone | |
| Recovery actions | Regenerate keys & salts | |
| Recovery actions | Roll back to last clean backup (Restore latest backup) | |
| Forensic timeline | Timeline table | |
| Forensic timeline | Refresh | |
| Quarantine | File path (quarantine a file) | |
| Quarantine | Quarantined items, Restore | |

---

## 20. Logs (`page=gemsecurity-logs`)

| Section | Item | Assigned to |
|---|---|---|
| What gets logged | Record activity in the audit log | |
| What gets logged | User accounts | |
| What gets logged | Plugins & themes | |
| What gets logged | Settings changes | |
| What gets logged | Content | |
| Activity log | Category filter | |
| Activity log | Severity filter | |
| Activity log | Search message or IP | |
| Activity log | Log table (Severity, Event, Message, User / UA, IP, When) | |
| Activity log | Details / Hide details | |
| Activity log | Previous / Next | |
| Activity log | Export CSV | |
| Activity log | Clear logs | |

---

## 21. Monitoring [Pro] (`page=gemsecurity-monitoring`)

| Section | Item | Assigned to |
|---|---|---|
| Monitoring | Enable daily monitoring & alerts | |
| Monitoring | Run checks now | |
| Status | Site reachable | |
| Status | TLS certificate | |
| Status | DNS A record | |
| Status | SPF record | |
| Status | DMARC record | |

---

## 22. Notifications (`page=gemsecurity-notifications`)

| Section | Item | Assigned to |
|---|---|---|
| Where alerts go | Security email | |
| Where alerts go | Send a test email | |
| Where alerts go | Alert email: Request origin table (IP address, Location [Pro]) | |
| Where alerts go | Enable real-time alerts | |
| Where alerts go | Alert on severity | |
| Where alerts go | Slack incoming webhook URL, Send a test message | |
| Where alerts go | Telegram bot token, chat ID, Test bot & chat | |
| Where alerts go | Generic webhook URL, Send a test event | |
| What you get told about | An administrator signs in | |
| What you get told about | Someone signs in from an unrecognised device [Pro] | |
| What you get told about | A rogue administrator is blocked | |
| What you get told about | An administrator hidden from the users list is found | |
| What you get told about | An application password is created | |
| Sent on a schedule | Email a daily report | |
| Sent on a schedule | Send at | |
| Sent on a schedule | Send a report now | |
| Sent on a schedule | Send a weekly security digest | |
| Daily security scan | Run a scan automatically every day | |
| Daily security scan | Check core, plugins & themes for known vulnerabilities | |

---

## 23. Settings (`page=gemsecurity-settings`)

| Section | Item | Assigned to |
|---|---|---|
| General settings | Log retention | |
| Compliance & SIEM | Tamper-evident audit log | |
| Compliance & SIEM | Verify integrity | |
| Compliance & SIEM | Download report | |
| Compliance & SIEM | Forward events to SIEM | |
| Compliance & SIEM | HTTP collector endpoint | |
| Compliance & SIEM | Send a test event | |
| Compliance & SIEM | Minimum severity | |
| Compliance & SIEM | Also write to system syslog | |
| Notifications & reports | Open Notifications link | |
| Maintenance & recovery | Lockdown mode | |
| Maintenance & recovery | Maintenance message | |
| Maintenance & recovery | Back up before plugin/theme/core updates | |
| Settings import / export [Pro] | Include API keys and secrets | |
| Settings import / export [Pro] | Export settings | |
| Settings import / export [Pro] | Import settings | |

---

## 24. Non-page features (run in the background or on other screens)

| Feature | Item | Assigned to |
|---|---|---|
| Login screen | Login lockout message | |
| Login screen | CAPTCHA widget | |
| Login screen | Social login buttons | |
| Login screen | Two-factor challenge | |
| Login screen | Custom login URL | |
| Comment / registration forms | Honeypot and time check | |
| Scheduled jobs | Daily scan, prune logs, weekly digest, daily report, password rotation, Admin Guard sweep, Plugin Guard verify | |
| Install / uninstall | Activation defaults | |
| Install / uninstall | Upgrade from previous version | |
| Install / uninstall | Deactivate and delete clean-up | |
| Free vs Pro | Free plugin alone (no Pro) | |
| Free vs Pro | Free + Pro active | |
| REST API | Permissions per endpoint | |
