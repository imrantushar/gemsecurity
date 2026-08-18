<?php
namespace GemSecurity\Modules;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * In-product documentation for every module.
 *
 * GemSecurity ships a lot of switches, and a switch label alone rarely says
 * what it protects against, what to fill in, or what it may break. This
 * registry holds a short guide per module — what it does, how to set it up,
 * and what to watch out for — which the admin surfaces in the help drawer
 * (the "?" button in the topbar) alongside the page it documents.
 *
 * Keyed by module id, matching Registry::all(). An entry is:
 *  - summary string    One or two sentences: what this module is for.
 *  - does    string[]  What it actually does once active.
 *  - setup   string[]  Ordered steps to get it working.
 *  - notes   string[]  Caveats, gotchas and recommendations.
 */
class Docs {

	/** In-request cache of the resolved doc map. */
	private static $cache = null;

	/**
	 * Every module's guide, keyed by module id.
	 *
	 * @return array<string,array>
	 */
	public static function all() {
		if ( null !== self::$cache ) {
			return self::$cache;
		}

		$docs = [

			/* ---------------------------------------------------------- */
			/* Core                                                        */
			/* ---------------------------------------------------------- */

			'dashboard' => [
				'summary' => __( 'Your security overview: the current protection status, activity from the last 7 days, recent events and the result of the most recent scan.', 'gemsecurity' ),
				'does'    => [
					__( 'Summarises which protections are on and which are still off.', 'gemsecurity' ),
					__( 'Charts blocked requests, failed logins and bans over the last 7 days.', 'gemsecurity' ),
					__( 'Lists the newest activity-log events so problems surface early.', 'gemsecurity' ),
					__( 'Shows when the site was last scanned and what the scan found.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Open Modules and turn on the feature areas this site needs — everything else stays dormant.', 'gemsecurity' ),
					__( 'Work through Firewall, Login Security and Scanner first; they cover the most common attacks.', 'gemsecurity' ),
					__( 'Set an alert address in Settings → Alerts & notifications so you hear about incidents without logging in.', 'gemsecurity' ),
					__( 'Run a first scan from the Scanner page to get a clean baseline to compare against later.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Counters only cover events recorded while the relevant module was active.', 'gemsecurity' ),
					__( 'A quiet dashboard is not proof of safety — check the Scanner and Logs pages periodically.', 'gemsecurity' ),
				],
			],

			'modules' => [
				'summary' => __( 'Turn feature areas on or off. A module that is off loads no code, registers no REST routes and shows no menu entry, so unused features cost nothing.', 'gemsecurity' ),
				'does'    => [
					__( 'Activation is the coarse gate; the individual settings inside a module stay as fine-grained switches.', 'gemsecurity' ),
					__( 'Turning a module off immediately removes its page from both the plugin nav and the WordPress menu.', 'gemsecurity' ),
					__( 'Core modules (Dashboard, Modules, Logs, Settings) are always on and cannot be turned off.', 'gemsecurity' ),
					__( 'Pro modules show as locked until the Pro add-on is active; then they toggle like any other module.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Switch on a module to reveal its page, then open that page and configure it.', 'gemsecurity' ),
					__( 'Leave modules you do not use switched off — it keeps the menu short and skips their code entirely.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Turning a module off does not erase its settings; switching it back on restores them exactly as they were.', 'gemsecurity' ),
					__( 'On upgrade, activation was derived from your existing settings, so a module whose features were all off may start hidden.', 'gemsecurity' ),
				],
			],

			'logs' => [
				'summary' => __( 'A tamper-evident audit trail of everything that matters: logins, user and role changes, plugin and theme activity, settings changes, blocks and bans.', 'gemsecurity' ),
				'does'    => [
					__( 'Records security-relevant events with actor, IP, severity and timestamp.', 'gemsecurity' ),
					__( 'Filters by severity, event type, user or IP, and exports the result as CSV.', 'gemsecurity' ),
					__( 'Sends real-time alerts for events above the severity you choose.', 'gemsecurity' ),
					__( 'Pro: hash-chains each entry so deleted or edited rows can be detected, and can forward events to a SIEM or syslog collector.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Set how long entries are kept in Settings → General (log retention, in days).', 'gemsecurity' ),
					__( 'Choose an alert channel and minimum severity in Settings → Alerts & notifications.', 'gemsecurity' ),
					__( 'Pro: enable the hash chain in Settings → Compliance & SIEM, then use Verify to prove the log is intact.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Retention trims old rows on a schedule — set it long enough to cover an investigation, short enough to keep the table small.', 'gemsecurity' ),
					__( 'Log verification only proves the chain from the point you enabled it, not events recorded before.', 'gemsecurity' ),
				],
			],

			'settings' => [
				'summary' => __( 'Plugin-wide preferences: log retention, compliance and SIEM forwarding, alert channels, maintenance lockdown and licensing.', 'gemsecurity' ),
				'does'    => [
					__( 'Alerts: email, Slack, Telegram or a generic webhook, with a minimum-severity filter and an optional digest.', 'gemsecurity' ),
					__( 'Compliance: log hash-chaining, SIEM/syslog forwarding and a severity floor for what gets shipped.', 'gemsecurity' ),
					__( 'Maintenance: site lockdown with a custom message, and taking a backup before plugin or theme updates.', 'gemsecurity' ),
					__( 'Daily report: a morning email listing every administrator and active plugin, and anything that changed since yesterday.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Add the address or webhook that should receive alerts, then set the minimum severity so routine noise stays out of your inbox.', 'gemsecurity' ),
					__( 'Turn on the daily report to get a morning inventory of administrators and active plugins, with new ones called out — then use "Send one now" to see what it looks like.', 'gemsecurity' ),
					__( 'Use lockdown while you investigate an incident: visitors see your message, administrators keep full access.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Alerts are only as reliable as your site mail. If WordPress email is unreliable here, use Slack, Telegram or a webhook instead.', 'gemsecurity' ),
					__( 'Lockdown blocks the front end for visitors — remember to switch it back off.', 'gemsecurity' ),
					__( 'Deactivating GemSecurity emails the alert address with a critical warning naming who did it, and pushes the same message to Slack, Telegram or your webhook — switching security off is the first move in most intrusions.', 'gemsecurity' ),
					__( 'Every email names the site and its domain in the subject, after an emoji for the event type — so alerts from several installs stay apart in one inbox.', 'gemsecurity' ),
					__( 'The first daily report has no baseline, so it lists the inventory without claiming everything is new. Comparisons start the next morning.', 'gemsecurity' ),
				],
			],

			/* ---------------------------------------------------------- */
			/* Firewall & threats                                          */
			/* ---------------------------------------------------------- */

			'firewall' => [
				'summary' => __( 'The front door: an IP blocklist, the classic WordPress hardening switches, browser security headers, bot control and a security.txt file.', 'gemsecurity' ),
				'does'    => [
					__( 'Blocks individual IPs and CIDR ranges before WordPress does any real work.', 'gemsecurity' ),
					__( 'Hardening: disable XML-RPC, disable the theme/plugin file editor, block author and REST user enumeration, hide the WordPress version, disable application passwords, disable comments.', 'gemsecurity' ),
					__( 'Sends security headers — X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, HSTS and CSP — and collects CSP violation reports.', 'gemsecurity' ),
					__( 'Bot control: block AI crawlers and verify self-declared search engines by reverse DNS, so fake Googlebots are turned away.', 'gemsecurity' ),
					__( 'Publishes /.well-known/security.txt and audits file permissions for world-writable paths.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Turn the firewall on, then enable the hardening switches one at a time and check the site still works after each.', 'gemsecurity' ),
					__( 'If the site sits behind Cloudflare or another proxy, enable the matching option under Real visitor IP detection — otherwise every visitor looks like the proxy and blocks or rate limits hit everyone at once.', 'gemsecurity' ),
					__( 'Enable security headers, leave CSP in report-only mode, then read Recent CSP violations for a few days before enforcing it.', 'gemsecurity' ),
					__( 'Fill in a contact address under security.txt so researchers know where to report problems.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Disabling XML-RPC breaks the classic WordPress mobile app, Jetpack-style remote publishing and some pingback workflows.', 'gemsecurity' ),
					__( 'HSTS tells browsers to refuse plain HTTP for the max-age you set — only enable it once HTTPS works on every subdomain you include, and treat preload as permanent.', 'gemsecurity' ),
					__( 'A CSP that is enforced too early will silently break embeds, analytics and page builders. Report-only first.', 'gemsecurity' ),
					__( 'Never trust proxy headers unless the site really is behind that proxy — spoofed headers would let an attacker rotate their apparent IP at will.', 'gemsecurity' ),
				],
			],

			'anti-spam' => [
				'summary' => __( 'Stops comment and registration spam without CAPTCHAs: invisible bot checks plus a heuristic score for anything that gets through.', 'gemsecurity' ),
				'does'    => [
					__( 'Adds a hidden honeypot field and a minimum time-to-submit, both invisible to real visitors.', 'gemsecurity' ),
					__( 'Scores comments on link count and keyword matches, holding or rejecting the worst.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Turn on silent bot protection — no keys or accounts needed.', 'gemsecurity' ),
					__( 'Leave the minimum submit time at a few seconds; raise it only if spam still gets through.', 'gemsecurity' ),
					__( 'Enable heuristic filtering, set the maximum number of links you consider normal, and add keywords you keep seeing in spam.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Aggressive keyword lists cause false positives — check the held queue for a while after adding new terms.', 'gemsecurity' ),
					__( 'Heavily cached sites can serve a stale form timestamp; if legitimate comments are refused, lower the minimum submit time.', 'gemsecurity' ),
				],
			],

			'threats' => [
				'summary' => __( 'Active defence: a request firewall that inspects traffic for attack patterns, rate limits and 404 throttling, escalating auto-bans, and live traffic visibility.', 'gemsecurity' ),
				'does'    => [
					__( 'Inspects requests for SQL injection, XSS, local file inclusion and remote code execution patterns, optionally including the request body.', 'gemsecurity' ),
					__( 'Rate limits requests and throttles 404 floods — the usual signature of a vulnerability scanner.', 'gemsecurity' ),
					__( 'Blocks known-bad bots, empty user agents and your own custom patterns.', 'gemsecurity' ),
					__( 'Escalates repeat offenders from strikes to a temporary ban and then a permanent one, all in a ban ledger you can edit.', 'gemsecurity' ),
					__( 'Detects request anomalies and credential-stuffing bursts, and shows requests as they arrive in Live traffic.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Enable the firewall and leave all four attack classes on unless a legitimate integration trips one.', 'gemsecurity' ),
					__( 'Enable the early-load loader so banned requests are rejected before other plugins run.', 'gemsecurity' ),
					__( 'Set the auto-ban threshold, window and duration to match your traffic — start lenient and tighten later.', 'gemsecurity' ),
					__( 'Turn on Live traffic while tuning, then turn it off again; it records every request and adds write load.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Body inspection reads POST payloads, which costs a little performance on write-heavy sites.', 'gemsecurity' ),
					__( 'Rate limits apply per IP — verify the proxy settings on the Firewall page first, or all traffic will share one bucket.', 'gemsecurity' ),
					__( 'The early loader fails open: if it cannot run, requests are allowed rather than the site going down.', 'gemsecurity' ),
					__( 'The early loader doubles as a watchdog: it is removed on a normal deactivation, so finding it still installed while GemSecurity is inactive means the plugin was disabled outside WordPress — the database edited, or the folder renamed — and it emails a warning about exactly that.', 'gemsecurity' ),
					__( 'Whitelist your own address before tightening thresholds so a testing burst cannot lock you out.', 'gemsecurity' ),
				],
			],

			'virtual-patch' => [
				'summary' => __( 'Blocks exploitation of known plugin and theme vulnerabilities at the request level, so you are covered in the gap between a disclosure and the vendor’s fix.', 'gemsecurity' ),
				'does'    => [
					__( 'Matches mitigation rules against the plugins and versions actually installed here.', 'gemsecurity' ),
					__( 'Applies only the relevant rules, so an unrelated vulnerability costs nothing.', 'gemsecurity' ),
					__( 'Lists every mitigation that is switched on and blocking attacks right now.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Turn virtual patching on; matching rules apply immediately, with no configuration per vulnerability.', 'gemsecurity' ),
					__( 'Review Active mitigations after each plugin update — a mitigation disappearing usually means you updated past the vulnerable version.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'A virtual patch buys time; it is not a substitute for updating the vulnerable plugin.', 'gemsecurity' ),
					__( 'The list is what is protecting you, not what is wrong. Two generic rules — SQL injection and path traversal — apply to every request on every site and are always present; a severity of "critical" describes the attack they block, not a problem found here.', 'gemsecurity' ),
					__( 'Developers can add site-specific rules through the gemsecurity/vpatch_rules filter.', 'gemsecurity' ),
				],
			],

			/* ---------------------------------------------------------- */
			/* Login & access                                              */
			/* ---------------------------------------------------------- */

			'login-security' => [
				'summary' => __( 'Everything around the login form: brute-force lockouts, CAPTCHA, password rules, session limits, a renamed login URL and admin login alerts.', 'gemsecurity' ),
				'does'    => [
					__( 'Locks out an IP after a number of failed attempts, for a duration you set.', 'gemsecurity' ),
					__( 'Emails you when an administrator signs in, and ends administrator sessions after a set number of hours.', 'gemsecurity' ),
					__( 'Adds a CAPTCHA (reCAPTCHA v2/v3, hCaptcha or Turnstile) to login, registration, lost-password and comment forms.', 'gemsecurity' ),
					__( 'Enforces a password policy: minimum length, complexity, a breached-password check and optional expiry.', 'gemsecurity' ),
					__( 'Moves wp-login.php to a URL of your choosing and 404s the old one, and logs idle users out.', 'gemsecurity' ),
					__( 'Pro: remembers trusted devices and offers magic-link recovery.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Start with brute-force protection — a limit of 5 attempts and a 15–30 minute lockout suits most sites.', 'gemsecurity' ),
					__( 'For CAPTCHA, create a site key and secret key with your chosen provider, paste both in, then pick which forms it guards.', 'gemsecurity' ),
					__( 'If you enable a custom login URL, save the new address somewhere safe before logging out.', 'gemsecurity' ),
					__( 'Set the password policy before onboarding new users; existing passwords are only checked at the next change.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'A custom login URL is obscurity, not authentication — keep brute-force protection and two-factor on as well.', 'gemsecurity' ),
					__( 'reCAPTCHA v3 scores rather than challenges: lower the threshold if real users get rejected.', 'gemsecurity' ),
					__( 'Short idle timeouts on a site with long editing sessions will cost people their unsaved work.', 'gemsecurity' ),
					__( 'Lockouts are per IP, so several users behind one office connection share a bucket.', 'gemsecurity' ),
				],
			],

			'two-factor' => [
				'summary' => __( 'A second factor at login: app-based one-time codes with an email fallback, one-time backup codes, and enforcement per role.', 'gemsecurity' ),
				'does'    => [
					__( 'Supports authenticator apps (TOTP) and email one-time codes.', 'gemsecurity' ),
					__( 'Issues single-use backup codes for when the phone is not to hand.', 'gemsecurity' ),
					__( 'Requires two-factor for the roles you select, falling back to email codes so nobody is locked out.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Enable the two-factor system, then set up your own account first under My two-factor.', 'gemsecurity' ),
					__( 'Scan the QR code with an authenticator app and confirm one generated code to finish enrolment.', 'gemsecurity' ),
					__( 'Download the backup codes and store them outside the site.', 'gemsecurity' ),
					__( 'Only once your own login works, require two-factor for administrators and any other roles.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'TOTP depends on a correct server clock; a badly drifted clock rejects every valid code.', 'gemsecurity' ),
					__( 'Emailed codes last 10 minutes and allow five guesses; after that the code is discarded and a new one must be requested. The message says which of those happened rather than always reporting an invalid code.', 'gemsecurity' ),
					__( 'Email fallback is only as secure as the mailbox — use the app method for administrators.', 'gemsecurity' ),
					__( 'The login CAPTCHA belongs to this module but is configured on the Login Security page.', 'gemsecurity' ),
				],
			],

			'social-login' => [
				'summary' => __( 'Lets people sign in with Google, Facebook, GitHub or X instead of a password, with optional account creation.', 'gemsecurity' ),
				'does'    => [
					__( 'Adds provider buttons to the login form using OAuth 2.0.', 'gemsecurity' ),
					__( 'Links a social account to an existing user by email address, or creates one with a default role.', 'gemsecurity' ),
					__( 'Fires the normal WordPress login hooks, so two-factor and login alerts still apply.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Create an OAuth app with the provider and copy its client ID and secret.', 'gemsecurity' ),
					__( 'Paste the redirect URI shown on this page into the provider’s allowed-callback list exactly as displayed.', 'gemsecurity' ),
					__( 'Enable the provider, then decide whether new visitors may register and which role they receive.', 'gemsecurity' ),
					__( 'Test in a private window before announcing it.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Linking by email trusts the provider’s email — only enable it for providers that verify addresses.', 'gemsecurity' ),
					__( 'If sign-in fails, the message now names the cause: "the provider refused" with its own error (redirect_uri_mismatch means the URI above is not registered exactly, invalid_client means the secret is wrong), while "expired or already used" means the attempt took too long or the browser dropped the cookie. Every failure is also written to the activity log.', 'gemsecurity' ),
					__( 'Never grant a role above Subscriber by default to self-registered accounts.', 'gemsecurity' ),
				],
			],

			'geolocation' => [
				'summary' => __( 'Country-level access control: allow logins only from countries you expect, optionally block the whole site, and pin individual users to their own countries.', 'gemsecurity' ),
				'does'    => [
					__( 'Resolves visitor country from CDN headers, falling back to a lookup API with a 24-hour cache.', 'gemsecurity' ),
					__( 'Applies your country list as a login gate, a whole-site block, or both.', 'gemsecurity' ),
					__( 'Locks chosen users to specific countries and can email-verify a login from a new one.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Add the countries your team and customers actually log in from — include your own, and any you travel to.', 'gemsecurity' ),
					__( 'Start with the login gate only. Blocking the whole site also blocks customers and search engines.', 'gemsecurity' ),
					__( 'Decide what happens to unknown locations; blocking them is safe for a login gate, risky site-wide.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Lookups fail open: if the country cannot be resolved, the visitor is allowed rather than locked out.', 'gemsecurity' ),
					__( 'VPNs and mobile networks routinely resolve to another country — expect occasional surprises.', 'gemsecurity' ),
					__( 'The GEMSEC_GEO_DISABLE constant is the emergency exit if you lock yourself out.', 'gemsecurity' ),
				],
			],

			'admin-guard' => [
				'summary' => __( 'Watches the administrator role itself: only approved accounts stay administrators, and hidden administrators are surfaced.', 'gemsecurity' ),
				'does'    => [
					__( 'Keeps an approved-administrator list and demotes or deletes any account that appears outside it.', 'gemsecurity' ),
					__( 'Refuses the sign-in of an administrator who is not on the list, and ends an existing session belonging to one — so an account added straight to the database, or created while this module was off, still cannot get in.', 'gemsecurity' ),
					__( 'Sweeps the administrators that already exist — hourly and whenever you change the whitelist — so an unapproved account is removed even if it never signs in.', 'gemsecurity' ),
					__( 'Detects administrators hidden from the users list — a classic backdoor left behind after a breach.', 'gemsecurity' ),
					__( 'Emails you when either fires.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Review the approved list and confirm every account on it is one you recognise.', 'gemsecurity' ),
					__( 'Choose what happens to a rogue administrator: demote is the safe default, delete is irreversible.', 'gemsecurity' ),
					__( 'Use "Check for unapproved admins" before relying on it: the preview lists exactly who would be removed, which is worth seeing while the action is set to delete.', 'gemsecurity' ),
					__( 'Enable both notifications so you hear about it even if you are not logged in.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Add legitimate new administrators to the list before creating them, or they will be demoted straight away.', 'gemsecurity' ),
					__( 'Some membership and staffing plugins create elevated accounts on purpose — check before switching to delete.', 'gemsecurity' ),
					__( 'Login enforcement needs a non-empty list: while the list is empty every administrator would count as unapproved, so the check stays off rather than locking you out.', 'gemsecurity' ),
					__( 'User ID 1, the site-owner address and multisite super admins are never blocked, whatever the list says.', 'gemsecurity' ),
				],
			],

			'api-hardening' => [
				'summary' => __( 'Closes the paths that bypass the login form: REST API rate limiting, application-password governance and generic login errors.', 'gemsecurity' ),
				'does'    => [
					__( 'Rate limits REST requests per IP within a window you choose.', 'gemsecurity' ),
					__( 'Lists every existing application password, can disable them entirely, alerts when a new one is created, and flags ones older than your maximum age.', 'gemsecurity' ),
					__( 'Replaces WordPress login errors with a generic message so invalid usernames cannot be distinguished from wrong passwords.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Review the existing application passwords and revoke any you do not recognise.', 'gemsecurity' ),
					__( 'If nothing here uses application passwords, disable them outright.', 'gemsecurity' ),
					__( 'Turn on REST rate limiting, then confirm your site builder, mobile app or headless front end still works.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Application passwords are how most external integrations authenticate — check before disabling them.', 'gemsecurity' ),
					__( 'REST limits apply to logged-in editors too, so keep the ceiling above what your own admin work generates.', 'gemsecurity' ),
				],
			],

			/* ---------------------------------------------------------- */
			/* Scanning                                                    */
			/* ---------------------------------------------------------- */

			'scanner' => [
				'summary' => __( 'Finds what should not be there: modified core files, foreign or suspicious files, changed files, risky outbound links, known vulnerabilities and auto-executed code.', 'gemsecurity' ),
				'does'    => [
					__( 'Verifies core files against the official WordPress.org checksums and lists unexpected or modified ones.', 'gemsecurity' ),
					__( 'Watches for file changes between scans and flags newly added or edited files.', 'gemsecurity' ),
					__( 'Scans content for outbound links to known-bad destinations.', 'gemsecurity' ),
					__( 'Checks installed plugins and themes against known vulnerabilities and against what WordPress.org actually ships.', 'gemsecurity' ),
					__( 'Inspects mu-plugins and drop-ins — code that runs on every request without appearing on the Plugins screen.', 'gemsecurity' ),
					__( 'Pro: full malware scanning with quarantine and a recovery toolkit.', 'gemsecurity' ),
					__( 'The malware scan covers the whole install — the web root, wp-includes, wp-admin and wp-content — and reads PHP, JavaScript and .htaccess, not PHP alone.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Run a full scan now to establish a clean baseline.', 'gemsecurity' ),
					__( 'Enable automatic scanning so it repeats on a schedule instead of when you remember.', 'gemsecurity' ),
					__( 'Turn on the file-change watcher and the vulnerability check.', 'gemsecurity' ),
					__( 'Work through the findings, then rescan so the list reflects the fixed state.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Scans read every file and are I/O heavy — schedule them for a quiet hour on large sites.', 'gemsecurity' ),
					__( 'Premium plugins are not on WordPress.org, so integrity checks cannot confirm them; that is expected, not a finding.', 'gemsecurity' ),
					__( 'Caching and backup plugins legitimately write files constantly; expect noise from them in the change watcher.', 'gemsecurity' ),
					__( 'Take a backup before deleting or quarantining anything a scan flags.', 'gemsecurity' ),
				],
			],

			'payment-integrity' => [
				'summary' => __( 'Watches the scripts on your checkout pages so a skimmer injected into payment forms is caught, as PCI DSS 4.0 requires.', 'gemsecurity' ),
				'does'    => [
					__( 'Builds an inventory of every script loaded on the pages you nominate.', 'gemsecurity' ),
					__( 'Compares each page load against that authorised baseline and reports anything new.', 'gemsecurity' ),
					__( 'Flags unauthorised scripts so you can review them before customers are affected.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Enable the monitor and select your checkout and payment pages.', 'gemsecurity' ),
					__( 'Visit those pages so the inventory populates, including any scripts that only load at checkout.', 'gemsecurity' ),
					__( 'Review the inventory and authorise each script you recognise; anything left over is worth investigating.', 'gemsecurity' ),
					__( 'Re-check after adding an analytics, chat or A/B testing tool — they add scripts by design.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Tag managers load scripts dynamically, so expect entries you did not add by hand.', 'gemsecurity' ),
					__( 'This detects and reports; it does not block. Treat an unexpected script as an incident.', 'gemsecurity' ),
				],
			],

			'incident-response' => [
				'summary' => __( 'The page for the worst day: a forensic timeline of what happened, file quarantine, and the recovery actions that stop an attack in progress.', 'gemsecurity' ),
				'does'    => [
					__( 'Builds a timeline from the audit log so you can see the sequence of an intrusion.', 'gemsecurity' ),
					__( 'Quarantines suspicious files out of the web root instead of deleting them, so they can be restored or examined.', 'gemsecurity' ),
					__( 'Logs every user out at once, which invalidates stolen session cookies.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Nothing to configure in advance — but do make sure logging and alerts are on, because the timeline is built from them.', 'gemsecurity' ),
					__( 'During an incident: log everyone out, quarantine what the scanner flagged, then read the timeline from the earliest suspicious event.', 'gemsecurity' ),
					__( 'Reset passwords and revoke application passwords once you know how they got in.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Logging everyone out includes you; keep your credentials to hand.', 'gemsecurity' ),
					__( 'Quarantined files stay on disk in a protected folder — keep them until the investigation is finished.', 'gemsecurity' ),
					__( 'The timeline can only show what was recorded, which is why retention matters before an incident, not after.', 'gemsecurity' ),
				],
			],

			/* ---------------------------------------------------------- */
			/* Maintenance                                                 */
			/* ---------------------------------------------------------- */

			'backup' => [
				'summary' => __( 'Scheduled backups of files and database, kept locally or — with Pro — pushed to remote storage.', 'gemsecurity' ),
				'does'    => [
					__( 'Creates on-demand or scheduled backups of the database, the files, or both.', 'gemsecurity' ),
					__( 'Keeps a list of completed backups with their size and status for download.', 'gemsecurity' ),
					__( 'Can run automatically before plugin and theme updates.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Take one backup by hand first to confirm the site has enough disk space and execution time.', 'gemsecurity' ),
					__( 'Add a schedule — daily for the database, weekly for files suits most sites.', 'gemsecurity' ),
					__( 'Configure a storage destination so copies live somewhere other than the server being backed up.', 'gemsecurity' ),
					__( 'Download one archive and confirm it opens. An untested backup is not a backup.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Local-only backups die with the server. Keep at least one copy off-site.', 'gemsecurity' ),
					__( 'Large sites can exceed PHP time or memory limits mid-backup; check the result rather than assuming success.', 'gemsecurity' ),
					__( 'Schedules run on WP-Cron, which needs traffic — on a quiet site, wire up a real system cron.', 'gemsecurity' ),
				],
			],

			'monitoring' => [
				'summary' => __( 'Watches the things that break quietly: uptime, TLS certificate expiry, DNS changes and SPF/DMARC email authentication.', 'gemsecurity' ),
				'does'    => [
					__( 'Checks the site is reachable and reports when it is not.', 'gemsecurity' ),
					__( 'Warns before the TLS certificate expires rather than after.', 'gemsecurity' ),
					__( 'Notices DNS record changes, which often precede or follow a domain hijack.', 'gemsecurity' ),
					__( 'Verifies SPF and DMARC records so your mail keeps arriving and is harder to spoof.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Enable monitoring and set the address that should receive warnings.', 'gemsecurity' ),
					__( 'Review the Status panel after the first daily run and fix anything already flagged.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'Checks run on a daily schedule, so this is early warning rather than second-by-second uptime monitoring.', 'gemsecurity' ),
					__( 'Use an address on a different domain, so a mail problem here does not swallow its own alert.', 'gemsecurity' ),
				],
			],

			'pro-tools' => [
				'summary' => __( 'The hardening pack: an admin IP allowlist, blocking sensitive files and PHP execution in uploads, forced HTTPS, a file-change baseline, auto-update enforcement and settings import/export.', 'gemsecurity' ),
				'does'    => [
					__( 'Restricts wp-admin to an IP allowlist.', 'gemsecurity' ),
					__( 'Blocks direct access to sensitive files and stops PHP running from the uploads directory — the usual landing spot for an uploaded shell.', 'gemsecurity' ),
					__( 'Forces HTTPS site-wide.', 'gemsecurity' ),
					__( 'Records a file-change baseline over the scopes you pick, so later changes stand out.', 'gemsecurity' ),
					__( 'Auto-updates plugins and themes — either only the vulnerable ones, or everything.', 'gemsecurity' ),
					__( 'Exports settings as a file you can import into another site.', 'gemsecurity' ),
				],
				'setup'   => [
					__( 'Only enable the admin IP allowlist if your address is static, and add it before saving.', 'gemsecurity' ),
					__( 'Turn on the uploads PHP block and sensitive-file block — they rarely affect anything legitimate.', 'gemsecurity' ),
					__( 'Take a file baseline once the site is in a known-good state, and re-take it after intentional updates.', 'gemsecurity' ),
					__( 'Start auto-updates with vulnerable plugins only; updating everything can break a site unattended.', 'gemsecurity' ),
				],
				'notes'   => [
					__( 'A dynamic home IP plus an admin allowlist means locking yourself out the next time your router reconnects.', 'gemsecurity' ),
					__( 'Exported settings describe your defences — store the file somewhere private.', 'gemsecurity' ),
					__( 'Re-baseline after every legitimate update, or the change list fills with noise you learn to ignore.', 'gemsecurity' ),
				],
			],
		];

		/**
		 * Filter the in-product documentation. Add-ons that register their own
		 * modules through `gemsecurity/modules` should add a matching entry
		 * here so their page gets a help drawer too.
		 *
		 * @param array<string,array> $docs Keyed by module id.
		 */
		self::$cache = apply_filters( 'gemsecurity/docs', $docs );

		return self::$cache;
	}

	/**
	 * Setup guides for the individual fields that need something fetched from
	 * somewhere else — an OAuth client, a CAPTCHA key pair, a Slack webhook.
	 *
	 * A page can say *what* a field is; only a guide can say where the value
	 * comes from. These render inline, next to the fields they describe, as a
	 * collapsed "How to get these credentials" panel.
	 *
	 * Keyed by guide id. An entry is:
	 *  - title string    Panel heading.
	 *  - steps string[]  Ordered instructions, written against the provider's
	 *                    own UI wording.
	 *  - link  array     Optional { url, label } to the provider's console.
	 *  - notes string[]  Optional caveats shown under the steps.
	 *
	 * @return array<string,array>
	 */
	public static function guides() {
		$guides = [

			/* ---- Social login providers ------------------------------- */

			'social.google' => [
				'title' => __( 'How to get a Google client ID and secret', 'gemsecurity' ),
				'link'  => [ 'url' => 'https://console.cloud.google.com/apis/credentials', 'label' => __( 'Google Cloud console → Credentials', 'gemsecurity' ) ],
				'steps' => [
					__( 'Open the Google Cloud console and select an existing project, or create one for this site.', 'gemsecurity' ),
					__( 'Go to APIs & Services → OAuth consent screen, choose External, and fill in the app name, support email and developer contact.', 'gemsecurity' ),
					__( 'Go to APIs & Services → Credentials → Create credentials → OAuth client ID, and choose Web application.', 'gemsecurity' ),
					__( 'Under Authorised redirect URIs, add the redirect URI shown at the top of this page — exactly, including https and any trailing path.', 'gemsecurity' ),
					__( 'Create the client, then copy the Client ID and Client secret into the fields here and save.', 'gemsecurity' ),
					__( 'Use Test credentials below to confirm the pair before saving — a wrong secret only shows up when a real person tries to sign in.', 'gemsecurity' ),
				],
				'notes' => [
					__( 'While the consent screen is in Testing, only the test users you list can sign in. Publish it before going live.', 'gemsecurity' ),
				],
			],

			'social.facebook' => [
				'title' => __( 'How to get a Facebook app ID and secret', 'gemsecurity' ),
				'link'  => [ 'url' => 'https://developers.facebook.com/apps/', 'label' => __( 'Meta for Developers → My Apps', 'gemsecurity' ) ],
				'steps' => [
					__( 'Open Meta for Developers → My Apps → Create App, and pick the Consumer (or Other → Consumer) type.', 'gemsecurity' ),
					__( 'Add the Facebook Login product to the app and choose the Web platform, entering your site URL.', 'gemsecurity' ),
					__( 'In Facebook Login → Settings, paste the redirect URI from the top of this page into Valid OAuth Redirect URIs.', 'gemsecurity' ),
					__( 'Open App settings → Basic and copy the App ID into Client ID, and the App secret into Client secret.', 'gemsecurity' ),
					__( 'Use Test credentials below to confirm the pair before saving — a wrong secret only shows up when a real person tries to sign in.', 'gemsecurity' ),
				],
				'notes' => [
					__( 'Facebook only returns an email address if the user granted the email permission — accounts without one cannot be linked by email.', 'gemsecurity' ),
					__( 'The app must be switched from Development to Live before anyone outside your app roles can sign in.', 'gemsecurity' ),
				],
			],

			'social.github' => [
				'title' => __( 'How to get a GitHub client ID and secret', 'gemsecurity' ),
				'link'  => [ 'url' => 'https://github.com/settings/developers', 'label' => __( 'GitHub → Developer settings → OAuth Apps', 'gemsecurity' ) ],
				'steps' => [
					__( 'Open GitHub → Settings → Developer settings → OAuth Apps → New OAuth App.', 'gemsecurity' ),
					__( 'Set Homepage URL to your site, and Authorization callback URL to the redirect URI shown at the top of this page.', 'gemsecurity' ),
					__( 'Register the application, then copy the Client ID.', 'gemsecurity' ),
					__( 'Choose Generate a new client secret and copy it immediately — GitHub shows it only once.', 'gemsecurity' ),
					__( 'Use Test credentials below to confirm the pair before saving — a wrong secret only shows up when a real person tries to sign in.', 'gemsecurity' ),
				],
				'notes' => [
					__( 'A GitHub account can hide its email address; those users are created with the account they signed in as rather than linked by email.', 'gemsecurity' ),
				],
			],

			'social.twitter' => [
				'title' => __( 'How to get X (Twitter) OAuth 2.0 credentials', 'gemsecurity' ),
				'link'  => [ 'url' => 'https://developer.x.com/en/portal/dashboard', 'label' => __( 'X Developer Portal', 'gemsecurity' ) ],
				'steps' => [
					__( 'Open the X Developer Portal and create a project and an app inside it.', 'gemsecurity' ),
					__( 'In the app’s User authentication settings, enable OAuth 2.0 and set App type to Web App.', 'gemsecurity' ),
					__( 'Set the Callback URI to the redirect URI shown at the top of this page, and fill in a website URL.', 'gemsecurity' ),
					__( 'Save, then copy the OAuth 2.0 Client ID and Client Secret into the fields here.', 'gemsecurity' ),
					__( 'Use Test credentials below to confirm the pair before saving — a wrong secret only shows up when a real person tries to sign in.', 'gemsecurity' ),
				],
				'notes' => [
					__( 'Use the OAuth 2.0 client credentials, not the older API key and API secret — they are different values on the same screen.', 'gemsecurity' ),
					__( 'X rarely returns an email address, so new accounts get a placeholder you can change later.', 'gemsecurity' ),
				],
			],

			/* ---- CAPTCHA providers ------------------------------------ */

			'captcha.recaptcha_v2' => [
				'title' => __( 'How to get reCAPTCHA v2 keys', 'gemsecurity' ),
				'link'  => [ 'url' => 'https://www.google.com/recaptcha/admin/create', 'label' => __( 'Google reCAPTCHA admin console', 'gemsecurity' ) ],
				'steps' => [
					__( 'Open the reCAPTCHA admin console and register a new site.', 'gemsecurity' ),
					__( 'Choose reCAPTCHA v2 → "I\'m not a robot" Checkbox.', 'gemsecurity' ),
					__( 'Add your domain — without https:// and without a trailing slash. Add localhost too if you test locally.', 'gemsecurity' ),
					__( 'Submit, then copy the Site key and Secret key into the fields here.', 'gemsecurity' ),
					__( 'Then use Test CAPTCHA keys below: it renders the real widget and verifies the token, which is the only way to prove both keys before they reach the login form.', 'gemsecurity' ),
				],
				'notes' => [
					__( 'The two keys are not interchangeable: the site key is public and rendered in the page, the secret key is never sent to the browser.', 'gemsecurity' ),
				],
			],

			'captcha.recaptcha_v3' => [
				'title' => __( 'How to get reCAPTCHA v3 keys', 'gemsecurity' ),
				'link'  => [ 'url' => 'https://www.google.com/recaptcha/admin/create', 'label' => __( 'Google reCAPTCHA admin console', 'gemsecurity' ) ],
				'steps' => [
					__( 'Open the reCAPTCHA admin console and register a new site.', 'gemsecurity' ),
					__( 'Choose reCAPTCHA v3 — v2 keys will not work here, and vice versa.', 'gemsecurity' ),
					__( 'Add your domain, submit, and copy the Site key and Secret key into the fields here.', 'gemsecurity' ),
					__( 'Leave the score threshold at the default, then watch the admin console’s score distribution before changing it.', 'gemsecurity' ),
					__( 'Then use Test CAPTCHA keys below: it renders the real widget and verifies the token, which is the only way to prove both keys before they reach the login form.', 'gemsecurity' ),
				],
				'notes' => [
					__( 'v3 never shows a challenge: it scores each request from 0.0 (bot) to 1.0 (human). A threshold that is too high rejects real people silently.', 'gemsecurity' ),
				],
			],

			'captcha.hcaptcha' => [
				'title' => __( 'How to get hCaptcha keys', 'gemsecurity' ),
				'link'  => [ 'url' => 'https://dashboard.hcaptcha.com/sites', 'label' => __( 'hCaptcha dashboard → Sites', 'gemsecurity' ) ],
				'steps' => [
					__( 'Create an hCaptcha account and open the dashboard.', 'gemsecurity' ),
					__( 'Add a new site and enter your domain as the hostname.', 'gemsecurity' ),
					__( 'Copy the Sitekey into Site key here.', 'gemsecurity' ),
					__( 'Open Settings and copy your account Secret key into Secret key here — it is account-wide, not per site.', 'gemsecurity' ),
					__( 'Then use Test CAPTCHA keys below: it renders the real widget and verifies the token, which is the only way to prove both keys before they reach the login form.', 'gemsecurity' ),
				],
			],

			'captcha.turnstile' => [
				'title' => __( 'How to get Cloudflare Turnstile keys', 'gemsecurity' ),
				'link'  => [ 'url' => 'https://dash.cloudflare.com/?to=/:account/turnstile', 'label' => __( 'Cloudflare dashboard → Turnstile', 'gemsecurity' ) ],
				'steps' => [
					__( 'Open the Cloudflare dashboard → Turnstile → Add site.', 'gemsecurity' ),
					__( 'Enter your domain and choose the Managed widget unless you have a reason not to.', 'gemsecurity' ),
					__( 'Copy the Site Key and Secret Key into the fields here.', 'gemsecurity' ),
					__( 'Then use Test CAPTCHA keys below: it renders the real widget and verifies the token, which is the only way to prove both keys before they reach the login form.', 'gemsecurity' ),
				],
				'notes' => [
					__( 'Your domain does not have to use Cloudflare’s DNS or proxy for Turnstile to work.', 'gemsecurity' ),
				],
			],

			/* ---- Alert channels --------------------------------------- */

			'alerts.slack' => [
				'title' => __( 'How to get a Slack incoming webhook URL', 'gemsecurity' ),
				'link'  => [ 'url' => 'https://api.slack.com/apps', 'label' => __( 'Slack API → Your Apps', 'gemsecurity' ) ],
				'steps' => [
					__( 'Open Slack API → Your Apps → Create New App → From scratch, and pick the workspace to post into.', 'gemsecurity' ),
					__( 'Open Incoming Webhooks and turn the feature on.', 'gemsecurity' ),
					__( 'Choose Add New Webhook to Workspace and select the channel that should receive alerts.', 'gemsecurity' ),
					__( 'Copy the generated URL (it starts with https://hooks.slack.com/services/) into the field here.', 'gemsecurity' ),
				],
				'notes' => [
					__( 'The webhook URL is a credential — anyone holding it can post to that channel. Do not commit it anywhere public.', 'gemsecurity' ),
				],
			],

			'alerts.telegram' => [
				'title' => __( 'How to get a Telegram bot token and chat ID', 'gemsecurity' ),
				'link'  => [ 'url' => 'https://t.me/BotFather', 'label' => __( 'Telegram → BotFather', 'gemsecurity' ) ],
				'steps' => [
					__( 'Message @BotFather on Telegram and send /newbot, then follow the prompts to name the bot.', 'gemsecurity' ),
					__( 'Copy the token BotFather returns into Bot token here.', 'gemsecurity' ),
					__( 'Send your new bot a message (or add it to the group that should receive alerts, and post there).', 'gemsecurity' ),
					__( 'Open https://api.telegram.org/bot<TOKEN>/getUpdates in a browser and copy the chat id from the response into Chat ID.', 'gemsecurity' ),
				],
				'notes' => [
					__( 'A bot cannot start a conversation. If nobody has messaged it, getUpdates comes back empty and alerts will not deliver.', 'gemsecurity' ),
					__( 'Group chat IDs are negative numbers — include the minus sign.', 'gemsecurity' ),
				],
			],

			'alerts.webhook' => [
				'title' => __( 'How the generic webhook works', 'gemsecurity' ),
				'steps' => [
					__( 'Point this at any URL that accepts an HTTP POST — an automation platform, a chat bridge, or your own endpoint.', 'gemsecurity' ),
					__( 'GemSecurity posts a JSON body describing the event: type, severity, message, IP, user and timestamp.', 'gemsecurity' ),
					__( 'Set the minimum severity above so routine events do not flood the receiver.', 'gemsecurity' ),
				],
				'notes' => [
					__( 'Delivery is fire-and-forget: a receiver that is down loses those alerts rather than queueing them.', 'gemsecurity' ),
				],
			],

			'siem.endpoint' => [
				'title' => __( 'How to forward logs to a SIEM', 'gemsecurity' ),
				'steps' => [
					__( 'Create an HTTP collector (HEC or equivalent) in your SIEM and copy its ingest URL here.', 'gemsecurity' ),
					__( 'Alternatively enable syslog output to ship to a local collector instead of over HTTP.', 'gemsecurity' ),
					__( 'Set the minimum severity to control the volume — everything at or above it is forwarded.', 'gemsecurity' ),
					__( 'Trigger a test event (a failed login will do) and confirm it arrives before relying on it.', 'gemsecurity' ),
				],
				'notes' => [
					__( 'Forwarding is in addition to the local log, not instead of it; retention here still applies.', 'gemsecurity' ),
				],
			],
		];

		/**
		 * Filter the inline field-level setup guides.
		 *
		 * @param array<string,array> $guides Keyed by guide id.
		 */
		return apply_filters( 'gemsecurity/docs_guides', $guides );
	}

	/**
	 * A single module's guide, normalised so consumers can rely on every key.
	 *
	 * @param string $id Module id.
	 * @return array|null Null when the module has no documentation.
	 */
	public static function get( $id ) {
		$all = self::all();
		if ( empty( $all[ $id ] ) ) {
			return null;
		}
		return array_merge(
			[ 'summary' => '', 'does' => [], 'setup' => [], 'notes' => [] ],
			$all[ $id ]
		);
	}

	/**
	 * Documentation for the React app, keyed by page slug (what the admin
	 * knows a page by) and carrying the module title for the drawer header.
	 * Only visible modules are included — a module you cannot open needs no
	 * help page.
	 *
	 * @return array<string,array>
	 */
	public static function for_js() {
		$out    = [];
		$labels = Registry::labels();
		foreach ( Registry::all() as $id => $module ) {
			if ( ! Registry::is_visible( $id ) ) {
				continue;
			}
			$doc = self::get( $id );
			if ( ! $doc ) {
				continue;
			}
			$out[ $module['page_slug'] ] = [
				'id'     => $id,
				'title'  => isset( $labels[ $id ]['title'] ) ? $labels[ $id ]['title'] : $id,
				'is_pro' => $module['is_pro'],
			] + $doc;
		}
		return $out;
	}
}
