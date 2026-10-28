# New Features: Test Guide

Test on a local or staging site only. Do functional checks only.

**Before you start**
- Log in as an administrator.
- Create a second administrator and call it **Admin B** (Users > Add New).
- Items marked **[Pro]** need GemSecurity Pro active.

---

# 1. Own IP cannot be blocked

Page: Firewall

## 1.1 Own IP is refused in the blocklist
1. Open **Firewall**.
2. Look under **IP safelist**. Note "Your current IP".
3. Type that IP in **IP blocklist**.
4. Click **Save**.

**Expected:** A warning says it is your own IP. The IP is not in the blocklist.

## 1.2 Add own IP to the safelist
1. Open **Firewall**.
2. Click **Add to safelist** (next to "Your current IP").
3. Click **Save**.

**Expected:** Your IP is in the safelist. The button is gone.

## 1.3 Other IP can be blocked
1. Open **Firewall**.
2. Type `10.9.9.9` in **IP blocklist**.
3. Click **Save**.

**Expected:** Saved with no warning.

## 1.4 Safelisted IP is never blocked
1. Add your IP to the safelist and save.
2. Log out.
3. Open `/wp-login.php`.

**Expected:** The login page opens.

---

# 2. Plugin lock (unlock password)

Page: Firewall > Site protection > Lock GemSecurity

How it works: the lock has its own password. It is not linked to any user. Opening it takes two steps: the password, then a 6-digit code sent by email. Without both nobody can deactivate or delete GemSecurity, or turn the lock off. This includes the admin who set it.

## 2.1 Turn the lock on
1. Open **Firewall**.
2. Under **Lock GemSecurity**, type a password (8+ characters).
3. Click **Turn lock on**.

**Expected:** Message "Lock is on". The panel shows **Unlocked for 10 minutes** (you just set it).

## 2.2 Short password is refused
1. With the lock off, type `abc`.

**Expected:** **Turn lock on** stays disabled.

## 2.3 Lock again
1. Click **Lock again now**.

**Expected:** The panel shows **Locked**.

## 2.4 No Deactivate link while locked
1. Open **Plugins**.

**Expected:** GemSecurity (and GemSecurity Pro) has no Deactivate or Delete link. This is true for every admin, including the one who set the lock.

## 2.5 Bulk deactivate is blocked
1. On **Plugins**, tick GemSecurity.
2. Choose **Bulk actions > Deactivate** and click **Apply**.

**Expected:** GemSecurity stays active.

## 2.6 Wrong password
1. Open **Firewall**.
2. Type a wrong password. Click **Send me a code**.

**Expected:** Error "Wrong password". No email is sent. Still locked.

## 2.7 Too many wrong passwords
1. Enter a wrong password 6 times in a row.

**Expected:** Error "Too many wrong passwords. Try again in 15 minutes."

## 2.8 Right password sends a code (step 1)
1. Type the right password. Click **Send me a code**.
2. Open **Plugins**.

**Expected:** The panel moves to step 2 and shows your email partly hidden (like `d****@example.com`). An email "Your GemSecurity unlock code" arrives with a 6-digit code. The Deactivate link is **still not there**: the password alone does not unlock.

## 2.8b Wrong code
1. In step 2, type `000000`. Click **Unlock for 10 minutes**.

**Expected:** Error "Wrong code". Still locked.

## 2.8c Too many wrong codes
1. Enter a wrong code 6 times.

**Expected:** Error asking you to enter the password again for a new code.

## 2.8d Right code unlocks (step 2)
1. Type the code from the email. Click **Unlock for 10 minutes**.
2. Open **Plugins**.

**Expected:** Message "Unlocked for 10 minutes". Deactivate link is visible. Deactivating works.

## 2.8e A code works only once
1. Lock again. Do steps 1 and 2 to unlock with a code.
2. Lock again. Try to use the same code again.

**Expected:** Error "No code is waiting, or it expired."

## 2.8f Code expires
1. Do step 1 and wait 10 minutes.
2. Enter the code.

**Expected:** Error "No code is waiting, or it expired."

## 2.8g Start over
1. Do step 1. In step 2 click **Start over**.

**Expected:** Back to the password box.

## 2.8h Code goes to the email from when the lock was set
1. Turn the lock on as Admin A (email a@example.com).
2. Change the alert email in **Settings > Notifications** to another address.
3. Do step 1.

**Expected:** The code goes to a@example.com, not the changed address.

## 2.8i Too many code requests
1. Do step 1 four times in a row.

**Expected:** The 4th time gives "Too many codes requested. Try again in 15 minutes."

## 2.9 Unlock ends
1. Unlock. Click **Lock again now** (or wait 10 minutes).
2. Open **Plugins**.

**Expected:** Deactivate link is gone again.

## 2.10 Another admin cannot get around it
1. Log in as **Admin B**.
2. Open **Plugins**.
3. Open **Firewall** and look at the lock panel.

**Expected:** No Deactivate link. Lock shows **Locked**. Unlocking in Admin A's session does not unlock Admin B.

## 2.11 Deleting a user does not remove the lock
1. With the lock on, delete any other administrator.

**Expected:** The lock is still on.

## 2.12 Remove the lock
1. Unlock with the password.
2. Click **Remove the lock**.

**Expected:** Message "Lock removed". The password box is shown again.

## 2.13 The password is never shown
1. Open `/wp-json/gemsecurity/v1/settings` in the logged-in browser.

**Expected:** No password or hash in the response.

## 2.13b The password is not visible in wp-admin
1. With the lock on, open `/wp-admin/options.php`.
2. Find `gemsecurity_lock_hash`.

**Expected:** The field shows "SERIALIZED DATA" and is greyed out. The password hash is not visible and cannot be edited or emptied.

## 2.14 Recovery (lost password)
1. Add `define( 'GEMSEC_PLUGIN_LOCK_DISABLE', true );` to `wp-config.php`.
2. Open **Plugins**.

**Expected:** Deactivate link is back. Remove the line after the test.

---

# 3. File upload on/off

Page: WordPress top admin bar

## 3.1 Turn uploads off
1. Hover **GemSecurity** in the top admin bar.
2. Click **File uploads: ON - click to turn off**.

**Expected:** The menu now says "File uploads: OFF". On Firewall, **Turn off all file uploads** is on.

## 3.2 Media upload is blocked
1. With uploads off, open **Media > Add New**.
2. Upload a JPG.

**Expected:** The upload fails.

## 3.3 Plugin zip upload is blocked
1. Open **Plugins > Add New > Upload Plugin**.
2. Choose any zip and install.

**Expected:** It fails.

## 3.4 Editor upload is blocked
1. Edit a post. Add an **Image** block.
2. Click **Upload** and choose a file.

**Expected:** It fails.

## 3.5 Turn uploads on again
1. Click the same admin bar item.
2. Upload a JPG in **Media > Add New**.

**Expected:** The menu says "File uploads: ON". The upload works.

## 3.6 Other users do not see the menu
1. Log in as an Author or Subscriber.
2. Look at the top admin bar.

**Expected:** No GemSecurity menu.

---

# 4. Scanner: core file popup

Page: Scanning > Scanner

**Prepare:** Open `readme.html` in the site root. Add `<!-- tampered -->` at the end and save.

## 4.1 Scan finds the changed file
1. Open **Scanner**.
2. Click **Run scan now**. Wait about 15 seconds.
3. Open **Core file integrity**.

**Expected:** `readme.html` is listed as Modified.

## 4.2 See the difference
1. Click **View & fix** on `readme.html`.

**Expected:** A popup opens. Your added line is red with a "+".

## 4.3 Close the popup
1. Click the **x**. Reopen it.
2. Press **Esc**. Reopen it.
3. Click outside the popup.

**Expected:** The popup closes each time.

## 4.4 Restore the original
1. Open **View & fix** again.
2. Click **Restore original**.
3. Click OK on the confirmation.

**Expected:** Message "Original file restored". The issue leaves the list. `readme.html` is back to normal.

## 4.5 A backup is kept
1. Open the folder `wp-content/uploads/gemsecurity-core-backup/`.

**Expected:** A `.bak` file of the changed version is there.

## 4.6 Edit is off by default
1. Tamper `readme.html` again and scan.
2. Open **View & fix**.

**Expected:** No **Edit file** button. A message says editing is off.

## 4.7 Edit when allowed
1. Open **Firewall > Hardening**.
2. Turn off **Disable theme & plugin file editor** and save.
3. Open **Scanner > View & fix** on the file.
4. Click **Edit file**, change some text, click **Save file**.

**Expected:** Message "File saved".

## 4.8 Cancel an edit
1. Click **Edit file**.
2. Change some text.
3. Click **Cancel**.

**Expected:** The diff view comes back. Nothing is saved.

**After testing:** Restore `readme.html` and turn the file editor setting back on.

---

# 5. Two-Factor: "All roles"

Page: Login & Access > Two-Factor

## 5.1 All roles option exists
1. Turn on two-factor.
2. Click the **Required for** dropdown.

**Expected:** The first option is **All roles**.

## 5.2 All roles forces everyone
1. Select **All roles** and click **Save**.
2. Log in as a Subscriber.

**Expected:** A second step (code) is asked.

## 5.3 Other roles also asked
1. Log in as an Editor.
2. Log in as an Administrator.

**Expected:** A second step is asked for both.

## 5.4 All roles stands alone
1. Select **All roles**. Then also pick **Editor**.

**Expected:** "All roles" is removed. Only Editor stays.

## 5.5 Selecting All clears others
1. Select **Editor** and **Author**.
2. Select **All roles**.

**Expected:** Only "All roles" is left.

---

# 6. Visitor countries **[Pro]**

Page: Login & Access > Geolocation

**Prepare:** Turn on **Enable geolocation**. Click **Test country lookup** and confirm it works. Note your country.

## 6.1 Mode option exists
1. Open **Geolocation**.
2. Find **Visitor countries**.

**Expected:** A **Mode** dropdown has Include and Exclude.

## 6.2 Exclude blocks a country
1. Set Mode to **Exclude**.
2. Select your own country.
3. Turn on **Block entire site from other countries**.
4. Click **Save**.
5. Open the site in a private window (logged out).

**Expected:** A 403 "Access denied" page.

## 6.3 Admin is not blocked
1. With the same setting, stay logged in as admin and open the site.

**Expected:** The site opens.

## 6.4 Exclude another country
1. Exclude a country that is not yours. Save.
2. Open the site logged out.

**Expected:** The site opens.

## 6.5 Include only another country
1. Set Mode to **Include**.
2. Select a country that is not yours. Save.
3. Open the site logged out.

**Expected:** A 403 page.

## 6.6 Include your country
1. Set Mode to **Include**. Select your country. Save.
2. Open the site logged out.

**Expected:** The site opens.

## 6.7 Each mode keeps its own list
1. Select a country in Include mode.
2. Switch to Exclude mode.

**Expected:** The list is empty or different. Switch back and the first list is still there.

**Recovery if locked out:** add `define( 'GEMSEC_GEO_DISABLE', true );` to `wp-config.php`. Remove it after.

---

# 7. Admin sign-in location **[Pro]**

Page: Login & Access > Geolocation > Administrator sign-in location

## 7.1 Turn it on
1. Turn on **Restrict administrator sign-in to selected countries**.

**Expected:** A country box appears. If your country is missing, an **Add (country)** button shows.

## 7.2 Wrong country blocks admin login
1. Select only a country that is not yours. Save.
2. Log out.
3. Log in as an administrator.

**Expected:** Login is refused. Message: "Administrators cannot sign in from your location".

## 7.3 Other roles can still log in
1. Log in as an Editor.

**Expected:** Login works.

## 7.4 Right country allows admin login
1. Use the recovery line (above) to get in. Remove it after.
2. Add your own country and save.
3. Log out and log in as admin.

**Expected:** Login works.

---

# 8. Location in alert emails

**Prepare:** Use a mail catcher (Local's Mailhog).

## 8.1 IP in the email
1. Trigger a GemSecurity email. For example, send a test email from Notifications.
2. Open the email.

**Expected:** A **Request origin** table with **IP address**.

## 8.2 Country in the email **[Pro]**
1. With Pro and geolocation working, trigger an email again.

**Expected:** The table also shows **Location** (city, country).

## 8.3 No table for scheduled reports
1. Trigger a scheduled report (cron).

**Expected:** No **Request origin** table.

---

# 9. Attacker with an admin login (bypass checks)

Idea: someone logs in as an administrator. They must not be able to switch off the protection from the features above.

**Prepare:** Turn the plugin lock on (section 2). Make sure it shows **Locked**. Log in as an administrator.

## 9.1 Security settings cannot be changed while locked
1. Open **Firewall**. Add an IP to **IP safelist**. Click **Save**.

**Expected:** A message says GemSecurity is locked. The safelist is unchanged after reload.

## 9.2 Same for other protected settings
1. Try each of these and Save: turn off **Enable firewall**, turn on **Turn off all file uploads**, change **Two-Factor** required roles, turn off two-factor, change anything on **Geolocation** **[Pro]**.

**Expected:** Each one is refused with the same message and keeps its old value.

## 9.3 Normal settings still save
1. Change something unrelated (for example the alert email in **Notifications**). Save.

**Expected:** It saves.

## 9.4 Cannot turn a module off
1. Open **Settings > Modules**.
2. Turn off a module (for example **Firewall**).

**Expected:** Refused: "GemSecurity is locked...". The module stays on.

## 9.5 Admin bar upload switch is blocked
1. Click **GemSecurity > File uploads** in the admin bar.

**Expected:** An error page says GemSecurity is locked. The upload state does not change.

## 9.6 Cannot install or edit code
1. Open **Plugins > Add New**.
2. Try **Upload Plugin**.
3. Open **Appearance > Theme File Editor** (if enabled).

**Expected:** Install and editor are not allowed (the page says you cannot do this). 

## 9.7 Core file edit is blocked
1. Open **Scanner** and **View & fix** on a flagged core file.

**Expected:** No **Edit file** button. **Restore original** still works.

## 9.8 Unlock restores normal use
1. Unlock (password, then emailed code).
2. Repeat 9.1.

**Expected:** The setting saves. After the 10 minutes, or **Lock again now**, changes are refused again.

## 9.9 A fake country header is ignored **[Pro]**
1. On a site that is **not** behind Cloudflare, send a request with the header `CF-IPCountry: US` (browser console or curl).
2. Open **Geolocation** and use the country test (or see Logs).

**Expected:** The country is NOT US because of the header. A country header is believed only when the request comes through a proxy you trust (**Firewall > Real visitor IP detection**).

## 9.10 Admin login location also covers other logins **[Pro]**
**Tip for local testing:** add `127.0.0.1` and `::1` to **Firewall > Other trusted proxies**. Then send `X-Forwarded-For: 8.8.8.8` with your request to look like a public IP. Remove them afterwards.

Needs a real (non-local) IP. Set admin countries to one that is not yours.
1. Log in as administrator with the normal login form.
2. Try a REST call with an application password for an administrator.
3. Log in as administrator with **Social Login** (if set up).

**Expected:** All three are refused. Editors and other roles are not affected.

## 9.11 Unknown country blocks administrators **[Pro]**
Needs a real (non-local) IP. Turn off internet from the server (so the country lookup fails), or block `ip-api.com`.
1. Try to log in as administrator with the admin location rule on.

**Expected:** Refused (it does not let admins in when the country is unknown). Local/private IPs, like your dev site, are still allowed.

---

# Final checks
1. Firewall page saves other settings normally.
2. Admin login works with all new settings at default.
3. No errors in `wp-content/debug.log`.
4. No red errors in the browser console on Firewall, Geolocation, Scanner and Two-Factor pages.
