# Wordfence Bug Bounty Program — Official Rules Reference

> Source: https://www.wordfence.com/threat-intel/bug-bounty-program/
> Source: https://www.wordfence.com/threat-intel/bug-bounty-program/terms-and-conditions/
> Last verified: 2026-03-12

---

## 1. Program Scope

### 1.1 In-Scope Assets

All WordPress plugins and themes (free and premium), excluding out-of-scope assets listed in §1.2.

#### High Threat Vulnerabilities (>= 25 Active Installations)

Available to **all researcher tiers**. Must be exploitable by unauthenticated or low-level authenticated (Subscriber, Customer) attackers:

- Arbitrary PHP File Upload or Read
- Arbitrary PHP File Deletion
- Arbitrary Options Update
- Remote Code Execution
- Authentication Bypass to Admin
- Privilege Escalation to Admin

> **Note:** High Threat vulns in plugins/themes with 25–999 active installations must be listed in the WordPress.org Plugin Repository to be in-scope.

#### Common and Dangerous Vulnerabilities (>= 500 Active Installations)

Available to **all researcher tiers**. Must be exploitable by unauthenticated or low-level authenticated (Subscriber, Customer) attackers:

- Stored Cross-Site Scripting
- SQL Injection

> **Note:** Common and Dangerous vulns in plugins/themes with 500–999 active installations must be listed in the WordPress.org Plugin Repository. Premium plugins/themes are excluded below 1,000 active installations.

#### All Other In-Scope Vulnerabilities (tier-dependent thresholds)

| Researcher Tier       | Min Active Installations |
|-----------------------|--------------------------|
| Standard Researcher   | >= 50,000                |
| Resourceful Researcher| >= 10,000                |
| 1337 Researcher       | >= 500                   |

### 1.2 Out-of-Scope Assets

- **WordPress Core** (has own HackerOne program)
- **All Automattic Products** (HackerOne: hackerone.com/automattic)
- **All Facebook Products** (facebook.com/whitehat)
- **All Google Products** (bughunters.google.com)
- **All Siteground Products** (siteground.com responsible disclosure)
- **All Yoast Products** (yoast.com/security-program)
- Plugins/Themes closed to downloads or sales at time of submission
- Web services associated with a plugin/theme that are not run locally (e.g., vendor APIs)
- WordPress plugins/themes not downloadable from WordPress.org with fewer than 1,000 estimated active installations or sales
- Any software whose developer maintains their own public bug bounty or responsible disclosure program

> Contact wfi-support@wordfence.com to confirm scope before submission if unsure.

> **Important — CVE Assignment vs Bounty Eligibility:** Wordfence will still assign CVE IDs to valid vulnerabilities discovered in out-of-scope assets and out-of-scope vulnerability types. Being out of scope only means the finding is **not eligible for a bounty reward** — it does not prevent you from getting a CVE. This applies to WordPress Core vulns, out-of-scope vendor products, PR:H vulns, and anything on the explicitly out-of-scope vulnerability list.

### 1.3 Explicitly In-Scope Vulnerability Types

All issues with considerable impact to CIA of a WordPress site, as long as they do **not** require high-level permissions (PR:H) to exploit:

1. Stored Cross-Site Scripting
2. Reflected Cross-Site Scripting
3. Cross-Site Request Forgery (considerable security impact required)
4. Missing Authorization (considerable security impact required)
5. Arbitrary Content Deletion
6. SQL Injection
7. Insecure Direct Object Reference
8. Arbitrary File Upload
9. Arbitrary File Download/Read
10. Arbitrary File Deletion
11. Local File Include / Remote File Include
12. Directory Traversal
13. Privilege Escalation to Admin
14. Privilege Escalation to Non-Admin
15. Authentication Bypass to Admin
16. Authentication Bypass to Non-Admin
17. Remote Code Execution / Code Injection
18. Information Disclosure
19. Server-Side Request Forgery
20. PHP Object Injection
21. Intentional Backdoors Added by Developers that are Accessible by Threat Actors

### 1.4 Explicitly Out-of-Scope Vulnerability Types

1. CSV Injection
2. IP Spoofing (where only impact is integrity)
3. Secrets stored in plaintext in DB (not exploitable via another vuln in the plugin)
4. WAF Rule Bypasses
5. CSS Injection (no considerable demonstrable security impact)
6. HTML Injection (no considerable demonstrable security impact)
7. DoS Vulnerabilities (no considerable demonstrable security impact)
8. CAPTCHA Bypasses
9. CORS Issues
10. Vulnerable packages/dependencies not verifiably exploitable in that plugin/theme
11. **Any vulnerability requiring PR:H** — Administrator, Editor, Shop Manager, and any role with `unfiltered_html` capability
12. Open Redirect
13. TabNabbing
14. Race condition vulns not easily replicable in common configuration
15. Cache Poisoning (no considerable demonstrable security impact)
16. TOCTOU (no considerable demonstrable security impact)
17. Self Cross-Site Scripting
18. Username Enumeration
19. Theoretical Vulnerabilities
20. Lack of HTTP Headers
21. Clickjacking
22. Server-Side Request Forgery via DNS Rebinding
23. API Key Updates/Overwrites/Reads
24. Full Path Disclosure
25. CSRF on unauthenticated forms or forms with no sensitive actions
26. Vulns only affecting outdated/unpatched browsers (2+ stable versions behind latest)
27. Any vulnerability with CVSS 3.1 < 4.0 that can't be leveraged to achieve a higher score
28. Vulns only exploitable on EOL software (PHP, MySQL, Apache, nginx, OpenSSL)
29. SQL Injection requiring `wp_magic_quotes` to be disabled
30. Vulns requiring local server access
31. Vulns only exploitable when admin explicitly grants access to lower-privileged user (unlikely scenario)
32. Vulns requiring excessive brute force (case-by-case exceptions for high-likelihood)
33. File Uploads with Embedded Client-Side Scripts or Macros (e.g., PDF XSS)
34. Double Extension File Upload Attacks (e.g., `.php.png`)
35. Uploaded files in publicly accessible directories where exposed info can't lead to full site compromise
36. Private/Hidden/Draft/Pending/Password Protected Post Access
37. Vulns requiring enabling/disabling PHP functions (e.g., `allow_url_fopen`)

> **Note:** Out-of-scope vulnerabilities may still receive a CVE ID — they are only ineligible for bounty payment.

---

## 2. Authentication Levels (Scope Mapping)

| Auth Level      | PR:H? | In Scope | Notes |
|-----------------|-------|----------|-------|
| Unauthenticated | No    | YES      | Highest bounty tier |
| Subscriber      | No    | YES      | Default WP role |
| Customer        | No    | YES      | WooCommerce role |
| Student         | No    | YES      | LMS role |
| Contributor     | No    | YES      | Mid-level auth, lower bounties |
| Author          | No    | YES      | Mid-level auth, lower bounties |
| Editor          | Yes   | **NO**   | Has `unfiltered_html` |
| Shop Manager    | Yes   | **NO**   | Has `unfiltered_html` |
| Administrator   | Yes   | **NO**   | Has `unfiltered_html` |
| Super Admin     | Yes   | **NO**   | Multisite admin |

> **Key rule:** Any role that has the `unfiltered_html` capability is classified as PR:H and is out of scope.

---

## 3. Researcher Tiers

### 3.1 Standard Researcher

- **Entry:** Default tier for all registered researchers
- **Pending submissions:** up to 10
- **Scope:**
  - High Threat vulns: >= 25 installs
  - Common & Dangerous vulns (SQLi, Stored XSS): >= 500 installs
  - All other vulns: >= 50,000 installs

### 3.2 Resourceful Researcher

- **Pending submissions:** up to 25
- **Scope:**
  - High Threat vulns: >= 25 installs
  - Common & Dangerous vulns: >= 500 installs
  - All other vulns: >= 10,000 installs
- **Unlock requirements (at least one):**
  - 1 critical severity, high impact (50k+ installs) in-scope vuln
  - OR 3 high severity, high impact in-scope vulns
  - OR 10 high/critical severity, medium impact in-scope vulns
- **AND:** Must not have submitted more than 5 False Positive or Low Quality reports
- **Benefits:** Exclusive achievement badge

### 3.3 1337 Researcher

- **Pending submissions:** up to 50
- **Scope:**
  - High Threat vulns: >= 25 installs
  - Common & Dangerous vulns: >= 500 installs
  - All other vulns: >= 500 installs
- **Unlock requirements (at least one):**
  - 5 critical severity in-scope vulns (50k+ installs)
  - OR 10 high severity in-scope vulns (50k+ installs)
- **AND (at least one):**
  - Proof of certification: OSCP, OSWA, OSWE, OSEP, OSED, eWPTx, eWPT, CISSP, CISM, CISA, GWAPT
  - OR 15 high quality valid vulnerability reports
- **AND:** Must not have submitted more than 10 False Positive or Low Quality reports (in 90-day window)
- **Maintenance (yearly):** At least one of: 5 critical, 10 high, or 20 medium severity vulns. Max 10 FP/low-quality in 90-day window.
- **Benefits:**
  - 5% automatic bonus on all eligible submissions
  - Exclusive achievement badge
  - Lower install threshold (500+)

### Severity Definitions for Tier Qualification

These are NOT based on CVSS alone — they combine CVSS + threat factor (likelihood of mass exploitation). Plugin/theme must have >= 50,000 active installations.

**Critical Severity Examples:**
- Unauthenticated Arbitrary File Deletion/Read/Upload to RCE
- Unauthenticated Remote Code Execution
- Unauthenticated Privilege Escalation
- Unauthenticated SQL Injection
- Unauthenticated Stored XSS
- Missing Authorization to Unauthenticated Data Alteration/Read in a Critical Way
- Authentication Bypass to Admin

**High Severity Examples:**
- Authenticated (Subscriber/Customer) RCE, File Upload to RCE, File Deletion, File Read
- Authenticated (Subscriber/Customer) Privilege Escalation to Admin
- Authenticated (Subscriber/Customer) SQL Injection
- Authenticated (Subscriber/Customer) Stored XSS
- Missing Authorization to Authenticated (Subscriber/Customer) Data Alteration/Read in a Critical Way

**Medium Impact (for Resourceful tier):**
Any of the above in software with 1,000–50,000 active installations.

---

## 4. Bounty Rewards

### 4.1 General Principles

- Max bounty: **$31,200** (Standard) / **$32,760** (1337 with 5% bonus)
- Minimum bounty: **$5**
- Bounties are based on: active installations, vulnerability type, authentication requirements, impact, and prerequisites
- Bounty estimator available at: https://www.wordfence.com/threat-intel/bug-bounty-program/#rewards

### 4.2 Bounty Estimator Vulnerability Types

The estimator supports these vulnerability categories:
- Stored Cross-Site Scripting
- Reflected Cross-Site Scripting
- Cross-Site Request Forgery
- Missing Authorization
- SQL Injection
- Insecure Direct Object Reference
- Arbitrary File Upload
- Arbitrary File Download/Read
- Arbitrary File Deletion
- Local File Include / Remote File Include
- Directory Traversal
- Privilege Escalation to Admin
- Privilege Escalation to Non-Admin
- Arbitrary Options Update
- Authentication Bypass to Admin
- Authentication Bypass to Non-Admin
- Remote Code Execution / Code Injection
- Arbitrary Shortcode Execution
- Sensitive Information Disclosure
- Basic Information Disclosure
- Server-Side Request Forgery
- PHP Object Injection w/o Gadget
- Intentional Backdoors Accessible by Threat Actor
- IP Spoofing

### 4.3 Privileges Required Categories

- No Authentication
- Low-Level Authentication (Subscribers, Customers, Students)
- Mid-Level Authentication (Contributors, Authors)
- High-Level Authentication (Shop Manager, Administrator, Super Admin, Editor) — **OUT OF SCOPE**

### 4.4 Install Count Tiers

| Range | Notes |
|-------|-------|
| < 25 | Out of scope for all |
| 25 – 499 | High Threat only, WP.org repo required |
| 500 – 999 | + Common & Dangerous (1337 tier: all vulns), WP.org repo required |
| 1,000 – 4,999 | Premium plugins eligible |
| 5,000 – 9,999 | |
| 10,000 – 14,999 | Resourceful tier: all vulns eligible |
| 15,000 – 29,999 | |
| 30,000 – 49,999 | |
| 50,000 – 99,999 | Standard tier: all vulns eligible |
| 100,000 – 499,999 | |
| 500,000 – 999,999 | |
| 1,000,000 – 4,999,999 | |
| 5,000,000+ | Highest bounties |

### 4.5 Factors That Reduce Bounties

- Prerequisites to exploit (settings, server config)
- Difficult/unreplicable exploitation
- Active user interaction required or unlikely passive interaction
- Limited CIA impact
- Dependency on another vulnerability not in same software (typically bounty halved)

### 4.6 PHP Object Injection Special Rules

- Awarded at highest impact level only if a **newly documented** usable gadget is present and exploitation is demonstrated
- "Newly documented" = POP chain not previously used to earn a bounty in the program
- Otherwise awarded at lower rate (PHP Object Injection w/o Gadget)
- After a gadget is reported, subsequent PHP OI vulns using same gadget within 30 versions are awarded at w/o Gadget rate

### 4.7 Premium Plugin Install Count Rules

- For premium plugins without public install counts: sales count used as 1:1 proxy
- If no sales info available, Wordfence uses internal metrics to estimate
- Premium version of a free plugin may be considered in-scope based on free plugin's install count, but reward is based on premium version's install count
- Bundled plugin install counts are determined at Wordfence's discretion

---

## 5. Bounty Bonuses

### 5.1 Multiplier Bonuses

| Bonus | Multiplier | Condition |
|-------|-----------|-----------|
| Proof of Active 0-day Exploitation | +15% | Evidence of active exploitation, no patch, corroborated by Wordfence |
| Chaining Master | +15% | Multiple vulns chained in single software for higher impact (e.g., privesc to admin) |
| Creative Vulnerability Finder | +10% | New technique or vulnerability type with little prior coverage |
| Meaningful Researcher | +10% | Ample documentation + easy-to-use PoC |
| 1337 Researcher Bonus | +5% | Automatic for all 1337 tier submissions |
| Affects Multiple Assets | +10% per 10 pieces of software | Same code in multiple plugins/themes (max ~100). Must document all affected software |
| Affects Multiple Functions | Varies | +20% for each of first 5 functions, +10% per 5 from 6–20, +5% per 5 from 21–50. Max 50 functions. Must document all |

### 5.2 Monthly Bug Detector Streak Bonus

Non-cumulative — you receive the highest bonus tier you qualify for.

#### Apprentice Bug Detector (first 10 submissions/month)
Includes out-of-scope vulns except those on the explicitly out-of-scope list (e.g., admin-level vulns).

| Submissions | Bonus |
|-------------|-------|
| 5+          | $35   |
| 10+         | $75   |

#### Trainee Bug Detector (submissions 11–30)
Only in-scope vulnerabilities count beyond 10.

| Total Submissions | In-Scope Required | Bonus |
|-------------------|-------------------|-------|
| 20+               | 10+               | $200  |
| 30+               | 20+               | $300  |

#### Professional Bug Detector (submissions 31+)
Only High Threat vulnerabilities count beyond 30.

| Total Submissions | In-Scope Required | High Threat Required | Bonus  |
|-------------------|-------------------|----------------------|--------|
| 40+               | 20+               | 10+                  | $600   |
| 50+               | 20+               | 20+                  | $1,000 |
| 60+               | 20+               | 30+                  | $1,200 |

> Streak bonus paid on the 1st and 15th of each month after review.

---

## 6. Submission Rules

### 6.1 Exclusivity & Confidentiality

- Wordfence must be the **only** organization you submit the vulnerability to
- Vulnerability must not be previously disclosed elsewhere
- Details are confidential until (a) Wordfence completes responsible disclosure and (b) CVE is made public
- First offense for sharing details during disclosure: warning. Subsequent offenses: potential ban

### 6.2 Duplicate & Multi-CVE Rules

- First researcher to submit with valid PoC gets the bounty (duplicates get nothing)
- Vulns requiring multiple CVEs may only earn a single bounty for the higher-paying CVE type
  - Example: Missing Auth + CSRF = only Missing Auth bounty (may get 2 CVEs)
- Vulns with same codebase as previously disclosed vuln that received a bounty: no additional bounty
- Only one critical impact bounty per vuln type + impact level per plugin per first submitter
- Patch bypasses within 10 version releases: reduced bounty (case-by-case), not full bounty

### 6.3 Pending Submission Limits

| Tier | Max Pending |
|------|-------------|
| Standard | 10 |
| Resourceful | 25 |
| 1337 | 50 |

### 6.4 Payout Schedule

- Processed twice monthly: **1st** and **15th** of each month
- All bounties accrued in the period before the next payout date are paid in bulk

### 6.5 Prohibited Acts

- No automated tools for bulk vulnerability discovery (may result in restricted rewards)
- Developers cannot report vulns in their own software for bounties (can still get CVE IDs)
- 5+ FP/low-quality/out-of-scope submissions in 7 days = 7-day restriction
- 10+ FP/low-quality in 1 year = warning of potential permanent ban
- No gaming the program (e.g., withholding info to submit bypass later, team coordination to split bounties across components)
- No creating multiple accounts or soliciting others to submit on your behalf

---

## 7. Current Promotions

### Triple Threat Bug Bounty Challenge (through April 6, 2026)

High Threat vulnerabilities earn triple stacked bonuses:

1. **2x all High Threat vulnerability bounties** (excluding 5,000,000+ installs)
2. **+30% bonus** for High Threat vulns in software with 30,000+ active installs (excluding 5,000,000+)
3. **$300 extra** for every 3 High Threat vulns submitted (minimum 1,000 installs)

> The Bounty Estimator automatically factors in promotional bonuses.

---

## 8. Discrepancies Found in Our Specs (002 & 007)

### spec 002 — Scope Auto-Validation

| Issue | Our Spec | Official Rules |
|-------|----------|----------------|
| Editor scope | Listed as out of scope | Correct, but reason is `unfiltered_html` capability, not just role name |
| Shop Manager | Not mentioned | Out of scope (has `unfiltered_html`) |
| `unfiltered_html` rule | Not mentioned | Any role with this capability is PR:H = out of scope |
| Student role | Not mentioned | In scope as low-level auth |
| Scope categories | Single matrix | Three distinct categories: High Threat (25+), Common & Dangerous (500+), All Other (tier-dependent) |
| `reflected_xss` threshold | 50,000 (standard), 500 (elite) | Tier-dependent under "All Other": 50k/10k/500 |
| `csrf` threshold | 50,000 (standard) | Same — tier-dependent under "All Other" |
| `sql_injection` threshold | 500 | 500 — correct (Common & Dangerous category) |
| `stored_xss` threshold | 500 | 500 — correct (Common & Dangerous category) |
| WP.org repo requirement | Not mentioned | Required for 25–999 (High Threat) and 500–999 (Common & Dangerous) |
| Premium plugin exclusion | Not mentioned | Premium excluded below 1,000 installs for Common & Dangerous |
| Pending submission limits | 5 / 15 / 30 | **10 / 25 / 50** |
| Resourceful tier threshold | Not in matrix | >= 10,000 for "all other" vulns |

### spec 007 — Reporting Enhancements

| Issue | Our Spec | Official Rules |
|-------|----------|----------------|
| Bounty bonuses | Not documented | 7 distinct bonus types (0-day 15%, chaining 15%, creative 10%, meaningful 10%, 1337 5%, multi-asset, multi-function) |
| Monthly streak bonus | Not documented | 6-tier monthly bonus system ($35–$1,200) |
| Bounty estimator vuln types | Not listed | 24 distinct categories including Arbitrary Shortcode Execution, Basic vs Sensitive Info Disclosure |
| PHP Object Injection rules | Not documented | Complex gadget-based pricing with 30-version window |
| Patch bypass rules | Not documented | Reduced bounty within 10 version releases |
| Duplicate rules | Not documented | Same codebase = no additional bounty; one critical impact per vuln type per plugin |
| Premium install count rules | Not documented | Sales as 1:1 proxy; bundled plugins at Wordfence discretion |

---

## 9. Recommended SCOPE_MATRIX Update

```python
# Three-tier scope system matching official rules

HIGH_THREAT_VULNS = {
    "arbitrary_php_file_upload",
    "arbitrary_php_file_read",
    "arbitrary_php_file_deletion",
    "arbitrary_options_update",
    "remote_code_execution",
    "authentication_bypass_to_admin",
    "privilege_escalation_to_admin",
}

COMMON_DANGEROUS_VULNS = {
    "stored_xss",
    "sql_injection",
}

# Minimum install thresholds
HIGH_THREAT_MIN_INSTALLS = 25  # All tiers
COMMON_DANGEROUS_MIN_INSTALLS = 500  # All tiers

ALL_OTHER_MIN_INSTALLS = {
    "standard": 50_000,
    "resourceful": 10_000,
    "1337": 500,
}

# WordPress.org repo required below these thresholds
WPORG_REQUIRED_THRESHOLD = {
    "high_threat": 1000,  # 25-999 must be on WP.org
    "common_dangerous": 1000,  # 500-999 must be on WP.org
}

# Premium plugins excluded below this threshold for Common & Dangerous
PREMIUM_EXCLUSION_THRESHOLD = 1000

# Out-of-scope auth levels (PR:H)
OUT_OF_SCOPE_ROLES = {"editor", "administrator", "super_admin", "shop_manager"}
# More precisely: any role with unfiltered_html capability

# Pending submission limits
PENDING_LIMITS = {
    "standard": 10,
    "resourceful": 25,
    "1337": 50,
}
```
