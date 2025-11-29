# Wordfence Bug Bounty Program Scope

## In Scope Assets

### 🚨 High Threat Vulnerabilities 🚨

All WordPress plugins and themes, free and premium (excluding those listed in Out of Scope Assets) with **≥ 25 Active Installations** for selected High Threat Vulnerabilities exploitable by unauthenticated or low-level authenticated (i.e. Subscriber, Customer) attackers:

- Arbitrary PHP File Upload or Read
- Arbitrary PHP File Deletion
- Arbitrary Options Update
- Remote Code Execution
- Authentication Bypass to Admin
- Privilege Escalation to Admin

> **Note:** High Threat Vulnerabilities in plugins and themes with between 25 and 999 Active Installations must be listed in the WordPress.org Plugin Repository to be in-scope.

### ⚠ Common and Dangerous Vulnerabilities ⚠

All WordPress plugins and themes, free and premium (excluding those listed in Out of Scope Assets) with **≥ 500 Active Installations** for selected Common and Dangerous Vulnerabilities exploitable by unauthenticated or low-level authenticated (i.e. Subscriber, Customer) attackers:

- Stored Cross-Site Scripting
- SQL Injection

> **Note:** Common and Dangerous Vulnerabilities in plugins and themes with between 500 and 999 Active Installations must be listed in the WordPress.org Plugin Repository to be in-scope. Premium plugins and themes are excluded from the scope below 1,000 active installations.

### All Other Vulnerabilities

For other vulnerabilities, all WordPress plugins and themes, free and premium (excluding those listed in Out of Scope Assets) are in scope with active installation thresholds that vary with your Researcher tier:

| Researcher Tier | Minimum Active Installations |
|-----------------|------------------------------|
| Standard Researchers | ≥ 50,000 |
| Resourceful Researchers | ≥ 10,000 |
| 1337 Researchers | ≥ 500 |

If in doubt on what's in scope for your tier, use the bounty estimator to check if your discovery is in scope, or out of scope.

---

## Out of Scope Assets

There are some assets explicitly out of scope of the bug bounty program. Please note this list is non-exhaustive. If you would like to confirm whether a specific product is in-scope prior to submission, please contact wfi-support@wordfence.com. CVE IDs will still be assigned to vulnerabilities in the products below.

- **WordPress Core** – Has its own Bug Bounty Program
- **All Automattic Products** – Has its own Bug Bounty Program
- **All Facebook Products** – Has its own Bug Bounty Program
- **All Google Products** – Has its own Bug Bounty Program
- **All Siteground Products** – Has its own Bug Bounty Program
- **All Yoast Products** – Has its own Bug Bounty Program

Additionally, the following are considered out of scope:
- Plugins or Themes Closed to Downloads or Sales at the time of submission
- Any web service associated with a WordPress plugin or theme that is not run locally (such as an API running on a plugin vendor's website)

> CVEs may still be assigned to vulnerabilities discovered in the products outlined above, however, they will not be eligible for a bounty.

---

## Explicitly In-Scope Vulnerabilities

All issues in WordPress Plugins and Themes with a considerable impact to the confidentiality, integrity, and availability of a WordPress site are considered in scope as long as they do not require high level permissions (such as administrator or editor, i.e. CVSSv3.1 PR:H) to exploit.

- Stored Cross-Site Scripting
- Reflected Cross-Site Scripting
- Cross-Site Request Forgery (with considerable security impact)
- Missing Authorization (leading to considerable security impact)
- Arbitrary Content Deletion
- SQL Injection
- Insecure Direct Object Reference
- Arbitrary File Upload
- Arbitrary File Download/Read
- Arbitrary File Deletion
- Local File Include/Remote File Include
- Directory Traversal
- Privilege Escalation to Admin
- Privilege Escalation to Non-Admin
- Authentication Bypass to Admin
- Authentication Bypass to Non-Admin
- Remote Code Execution/Code Injection
- Information Disclosure
- Server-Side Request Forgery
- PHP Object Injection
- Intentional Backdoors Added by Developers that are Accessible by Threat Actors

---

## Explicitly Out of Scope Vulnerabilities

Vulnerabilities that have a minimal impact on the security of WordPress sites, or are unlikely to be successfully exploited in the wild will likely be considered out of scope.

- CSV Injection
- IP Spoofing (where the only impact is integrity)
- Secrets (such as 2FA secrets) stored in plaintext in a database that can't be exploited through another vulnerability in the plugin
- Web Application Firewall (WAF) Rule Bypasses
- CSS Injection (without considerable and demonstrable security impact)
- HTML Injection (without considerable and demonstrable security impact)
- DoS Vulnerabilities (without considerable and demonstrable security impact)
- CAPTCHA Bypasses
- CORS Issues
- Software containing vulnerable packages or dependencies that are not verifiably exploitable in that plugin or theme
- Any Vulnerability requiring PR:H to Exploit (Administrator, Editor, Shop Manager roles, and any role with 'unfiltered_html' capability)
- Open Redirect
- TabNabbing
- Vulnerabilities dependent on successfully exploiting a race condition that is not easily replicable in a common configuration
- Cache Poisoning (without considerable and demonstrable security impact)
- TOCTOU (without considerable and demonstrable security impact)
- Self Cross-Site Scripting
- Issues that lead to Username Enumeration
- Theoretical Vulnerabilities
- Lack of HTTP Headers
- Clickjacking
- Server-Side Request Forgery via DNS Rebinding
- API Key Updates/Overwrites/Reads
- Full Path Disclosure
- Cross-Site Request Forgery on unauthenticated forms or on forms with no sensitive actions
- Vulnerabilities that only affect users of outdated or unpatched browsers (2+ stable versions behind latest)
- Any Vulnerability with a CVSS 3.1 score lower than 4.0 that can't be leveraged to achieve a higher score
- Vulnerabilities only exploitable on configurations running EOL versions of software (PHP, MySQL, Apache, Nginx, OpenSSL)
- Any SQL Injection that requires wp_magic_quotes to be disabled to exploit
- Security issues that require local access to the server to exploit
- Vulnerabilities that can only be exploited by an administrator explicitly granting access to a lower-privileged user (where likelihood of granting is minimal or access is to functionality that can be abused)
- Vulnerabilities that require excessive brute force to exploit (case-by-case basis for high likelihood of success)
- File Uploads with Embedded Client-Side Scripts or Macros (i.e. PDF files injected with XSS payloads)
- Double Extension File Upload Attacks (i.e. .php.png)
- Uploaded files in publicly accessible directories where information exposed cannot lead to full site compromise
- Private/Hidden/Draft/Pending/Password Protected Post Access

> CVEs may still be assigned to vulnerabilities discovered in the out of scope list above, however, they will not be eligible for a bounty.