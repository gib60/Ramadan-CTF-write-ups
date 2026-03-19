# The Compromised Charity — Forensics Challenge Walkthrough

## Description
The Ramadan Charity Fund has reported suspicious activity on their donation website. Donations are not reaching the intended recipients and the organization has no idea why. You have been brought in as a forensic investigator. A snapshot of the website's files has been provided to you. Find out what happened.

---

## Overview
This challenge provides a 
- `charity-wp.zip` - a zip file containing the WordPress file system
- A netcat server that guides the investigation through 13 questions

The goal is to trace the attacker's footprints across three stages: initial access, persistence, and data exfiltration.

---

## Part 1 — The Backdoor Plugin

Navigate to `wp-content/plugins/` and list the directories. You will notice a plugin called `charity-manager` that does not exist in the official WordPress GitHub repository — this is immediately suspicious.

Navigate into the plugin directory:
```
wp-content/plugins/charity-manager/
├── charity-manager.php   ← looks clean, just a plugin header
└── core.php              ← contains the malicious code
```

`charity-manager.php` looks completely legitimate. However `core.php` contains:
```php
eval(base64_decode("..."));
```

Decode the base64 string — you get a PHP reverse shell. Reading through the decoded code reveals:
```php
$ip = '10.10.10.55';  // C2 server
```

**Q1: What is the name of the suspicious plugin?**
→ `charity-manager`

**Q2: Which file contains the malicious code?**
→ `core.php`

**Q3: What encoding method was used to hide the payload?**
→ `base64`

**Q4: What type of attack tool is hidden inside the payload?**
→ `reverse shell` / `php reverse shell`

**Q5: What is the attacker's C2 IP address?**
→ `10.10.10.55`

✅ Part 1 complete — server reveals password to unlock the next file.  

Logs Password : xK9mP2q

---

## Part 2 — The Access Logs

Back in the WordPress root directory you notice a `wp-logs/` directory — this does not exist in a standard WordPress installation. Inside you find a password protected `wp-logs.zip`. Use the password revealed by the server to unlock it and extract `access.log`.

The log contains hundreds of normal HTTP requests from various IPs. Filter by the attacker's IP `10.10.10.55`:

```
10.10.10.55 - - [02/Mar/2026 03:00:01] "POST /wp-cron.php?doing_wp_cron HTTP/1.1" 200 0
10.10.10.55 - - [03/Mar/2026 03:00:02] "POST /wp-cron.php?doing_wp_cron HTTP/1.1" 200 0
10.10.10.55 - - [04/Mar/2026 03:00:01] "POST /wp-cron.php?doing_wp_cron HTTP/1.1" 200 0
...
```

The same external IP hitting `wp-cron.php` every night at exactly 3AM — the attacker is remotely triggering the cron to maintain persistence on the server.

**Q6: What is the name of the suspicious directory in the WordPress root?**
→ `wp-logs`

**Q7: What WordPress endpoint is being repeatedly targeted by the attacker?**
→ `wp-cron.php`

**Q8: At what time does the attacker trigger the cron every night?**
→ `03:00`

**Q9: What persistence technique is the attacker using?**
→ `cron abuse` / `cron persistence` / `wp-cron abuse`

✅ Part 2 complete — server reveals password to unlock the next file.

Payment-config.php Password : bL7nR4w

---

## Part 3 — The Stolen Funds

Navigate to `wp-content/` — you notice an `uploads/` directory that does not exist in the official WordPress GitHub repository. Inside you find a password protected `uploads.zip`. Use the password revealed by the server to unlock it and find `payment-config.php`.

A PHP file inside `uploads/` is immediately suspicious — this directory should never contain executable PHP files. Opening it reveals a tampered payment gateway configuration:

```php
'redirect_account'  => 'cashout@protonmail.com',
'modified_by'       => 'ghost',
'modified_date'     => '2026-03-05 03:00:00',
```

The attacker redirected all charity donations to their own account. The `modified_date` is `2026-03-05 03:00:00` — the same 3AM timestamp as the cron activity from Part 2, confirming this was done during one of their nightly sessions.

**Q10: What is the name of the suspicious directory inside wp-content?**
→ `uploads`

**Q11: What is the name of the suspicious file found inside?**
→ `payment-config.php`

**Q12: What email account is set to receive the stolen donations?**
→ `cashout@protonmail.com`

**Q13: What is the exact date and time the configuration was tampered with?**
→ `2026-03-05 03:00:00`

✅ Part 3 complete — server reveals the full flag.

---

## Full Flag
```
Spark{wp_plug1n5_4re_4_h4cker5_p4r4d1se}
```

---

## Attack Timeline
1. **Attacker planted a fake plugin** (`charity-manager`) with a PHP reverse shell to gain initial access
2. **Attacker abused wp-cron** — triggered it every night at 3AM from `10.10.10.55` to maintain persistence
3. **Attacker tampered with the payment gateway** — redirected all donations to `cashout@protonmail.com` starting March 5th
