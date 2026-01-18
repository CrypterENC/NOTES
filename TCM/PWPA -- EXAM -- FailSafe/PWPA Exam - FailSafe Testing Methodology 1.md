# PWPA Exam - FailSafe Testing Methodology & Checklist

**Target:** FailSafe Password Manager (10.0.0.10)  
**Duration:** 48 hours testing + 48 hours reporting  
**Goal:** Find 75+ points worth of vulnerabilities

---

## Testing Phases Overview

### Phase 1: Reconnaissance & Mapping (2-3 hours)
- [ ] Map all endpoints and features
- [ ] Identify technology stack
- [ ] Enumerate API endpoints
- [ ] Understand user roles and workflows
- [ ] Identify input fields and parameters

### Phase 2: Authentication Testing (3-4 hours)
- [ ] Test registration functionality
- [ ] Test login functionality
- [ ] Test password reset
- [ ] Test session management
- [ ] Test MFA (if present)
- [ ] Look for auth bypass

### Phase 3: Authorization Testing (3-4 hours)
- [ ] Test IDOR vulnerabilities
- [ ] Test horizontal privilege escalation
- [ ] Test vertical privilege escalation
- [ ] Test broken access control

### Phase 4: Injection Testing (15-20 hours)
- [ ] SQL Injection (all input fields)
- [ ] Cross-Site Scripting (XSS)
- [ ] Command Injection
- [ ] Template Injection
- [ ] XXE Injection
- [ ] File Inclusion (LFI/RFI)

### Phase 5: Business Logic Testing (5-8 hours)
- [ ] CSRF vulnerabilities
- [ ] SSRF vulnerabilities
- [ ] Open Redirects
- [ ] Race Conditions
- [ ] Logic flaws

### Phase 6: Configuration & Deployment (2-3 hours)
- [ ] Security headers
- [ ] TLS/SSL configuration
- [ ] CORS configuration
- [ ] Information disclosure
- [ ] Default credentials

### Phase 7: Documentation & Reporting (4-6 hours)
- [ ] Organize findings
- [ ] Create screenshots
- [ ] Write remediation
- [ ] Calculate CVSS scores
- [ ] Generate PDF report

---

## Detailed Testing Checklist

### PHASE 1: RECONNAISSANCE & MAPPING

#### 1.1 Application Structure
- [ ] Identify all pages/endpoints
- [ ] Identify all forms
- [ ] Identify all API endpoints
- [ ] Map user workflows
- [ ] Identify user roles

**Commands:**
```bash
# Check basic connectivity
curl -I http://10.0.0.10

# Get full HTML
curl http://10.0.0.10

# Check for API
curl http://10.0.0.10/api

# Check for common endpoints
curl http://10.0.0.10/admin
curl http://10.0.0.10/api/users
curl http://10.0.0.10/api/passwords
```

#### 1.2 Technology Stack
- [ ] Identify web server (Express.js confirmed)
- [ ] Identify framework/libraries
- [ ] Identify database (if possible)
- [ ] Check for version information

**Commands:**
```bash
# Check headers
curl -I http://10.0.0.10 | grep -i "server\|x-powered-by"

# Check for version info
curl http://10.0.0.10 | grep -i "version\|v[0-9]"
```

#### 1.3 Burp Suite Setup
- [ ] Start Burp Suite
- [ ] Configure proxy (127.0.0.1:8080)
- [ ] Configure browser to use proxy
- [ ] Enable passive scanning
- [ ] Set scope to 10.0.0.10

#### 1.4 Application Crawling
- [ ] Browse entire application
- [ ] Click all links
- [ ] Submit all forms (without payloads)
- [ ] Review Burp Site Map
- [ ] Export all discovered URLs

---

### PHASE 2: AUTHENTICATION TESTING

#### Specific Vulnerabilities to Test (25-point targets in bold)

**High Priority (25 points):**
- [ ] **Broken Authentication** - Brute force protection (already tested - weak rate limiting found)
- [ ] **SQL Injection** - Registration username field
- [ ] **SQL Injection** - Login username field
- [ ] **Stored XSS** - Registration fields
- [ ] **Broken Authentication** - Account enumeration
- [ ] **Broken Authentication** - Weak password policies
- [ ] **Broken Authentication** - Default credentials

**Medium Priority (reportable):**
- [ ] Lack of Rate Limiting (already tested - 50 requests allowed)
- [ ] Session management issues (predictable tokens, long timeout)
- [ ] Password reset vulnerabilities
- [ ] Account lockout bypass
- [ ] Concurrent session issues
- [ ] Logout functionality issues
- [ ] Cookie security (Secure, SameSite flags)

#### 2.1 Registration Functionality
- [ ] Test registration form
- [ ] Capture registration request in Burp
- [ ] Test SQL injection in registration fields
- [ ] Test XSS in registration fields
- [ ] Test weak password validation
- [ ] Test email verification bypass
- [ ] Test duplicate account creation

**Fields to test:**
- [ ] Username
- [ ] Email
- [ ] Password
- [ ] Confirm password
- [ ] Any other fields

#### 2.2 Login Functionality
- [ ] Test login form
- [ ] Capture login request in Burp
- [ ] Test SQL injection in login
- [ ] Test brute force (rate limiting?)
- [ ] Test account enumeration
- [ ] Test weak password policies
- [ ] Test default credentials

**Test accounts:**
- [ ] admin / admin
- [ ] admin / password
- [ ] test / test
- [ ] etc.

#### 2.3 Session Management
- [ ] Analyze session tokens
- [ ] Check token predictability
- [ ] Test session timeout
- [ ] Test concurrent sessions
- [ ] Test logout functionality
- [ ] Check cookie attributes (HttpOnly, Secure, SameSite)

#### 2.4 Password Reset
- [ ] Test password reset flow
- [ ] Test token reuse
- [ ] Test token expiration
- [ ] Test account takeover via reset
- [ ] Test email verification bypass

#### 2.5 MFA (if present)
- [ ] Test MFA bypass
- [ ] Test response manipulation
- [ ] Test status code manipulation
- [ ] Test backup codes

---

### PHASE 3: AUTHORIZATION TESTING

#### 3.1 IDOR Testing
- [ ] Identify user-specific resources
- [ ] Test direct object references
- [ ] Test parameter manipulation
- [ ] Test predictable IDs (sequential, UUID patterns)
- [ ] Test access to other users' data

**Common parameters to test:**
- [ ] user_id
- [ ] account_id
- [ ] document_id
- [ ] password_id
- [ ] Any numeric or UUID parameter

**Example:**
```
/api/user/1 → try /api/user/2, /api/user/3, etc.
/api/passwords/abc123 → try /api/passwords/abc124, etc.
```

#### 3.2 Horizontal Privilege Escalation
- [ ] Access other users' profiles
- [ ] Access other users' passwords
- [ ] Access other users' shared items
- [ ] Modify other users' data

#### 3.3 Vertical Privilege Escalation
- [ ] Test admin functionality with regular user
- [ ] Test role parameter manipulation
- [ ] Test permission bypass
- [ ] Test function-level access control

#### 3.4 Broken Access Control
- [ ] Test missing authorization checks
- [ ] Test permission-based access control
- [ ] Test data exposure in responses

---

### PHASE 4: INJECTION TESTING

#### 4.1 SQL Injection

**Test all input fields:**
- [ ] Registration fields
- [ ] Login fields
- [ ] Search fields
- [ ] Filter fields
- [ ] API parameters
- [ ] Headers (User-Agent, Cookie, etc.)

**Basic payloads:**
```sql
' OR '1'='1
' OR 1=1 --
' OR 1=1 /*
admin' --
' UNION SELECT NULL,NULL,NULL --
```

**SQLMap:**
```bash
sqlmap -u "http://10.0.0.10/api/endpoint?param=value" --dbs
sqlmap -u "http://10.0.0.10/api/endpoint?param=value" -D database_name --tables
```

#### 4.2 Cross-Site Scripting (XSS)

**Test all input fields:**
- [ ] Registration fields
- [ ] Profile fields
- [ ] Comment fields
- [ ] Search fields
- [ ] Any user input

**Reflected XSS payloads:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

**Stored XSS payloads:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

**DOM-based XSS:**
- [ ] Analyze JavaScript code
- [ ] Test source-to-sink flows
- [ ] Test unsafe DOM operations

#### 4.3 Command Injection

**Test fields that might execute commands:**
- [ ] Ping functionality
- [ ] DNS lookup
- [ ] File operations
- [ ] Network operations

**Payloads:**
```bash
; id
| whoami
|| whoami
& whoami
&& whoami
`whoami`
$(whoami)
```

#### 4.4 Template Injection (SSTI)

**Test fields that might use templates:**
- [ ] Email templates
- [ ] Report generation
- [ ] Any dynamic content

**Payloads:**
```
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}
```

#### 4.5 XXE Injection

**Test XML parsing functionality:**
- [ ] File uploads (XML, SVG)
- [ ] API endpoints accepting XML
- [ ] Configuration uploads

**Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

#### 4.6 File Inclusion (LFI/RFI)

**Test file inclusion parameters:**
- [ ] ?page=
- [ ] ?file=
- [ ] ?include=
- [ ] ?lang=
- [ ] ?template=

**Payloads:**
```
../../../etc/passwd
../../etc/passwd
/etc/passwd
php://filter/convert.base64-encode/resource=index.php
```

#### 4.7 Insecure File Upload

- [ ] Test client-side validation bypass
- [ ] Test file type restrictions
- [ ] Test magic byte manipulation
- [ ] Test extension bypass (.php.jpg, .phtml)
- [ ] Test Content-Type manipulation
- [ ] Test uploaded file execution

---

### PHASE 5: BUSINESS LOGIC TESTING

#### 5.1 CSRF (Cross-Site Request Forgery)
- [ ] Identify state-changing operations
- [ ] Check for CSRF tokens
- [ ] Test token validation
- [ ] Test CSRF on sensitive operations

#### 5.2 SSRF (Server-Side Request Forgery)
- [ ] Identify URL fetching functionality
- [ ] Test access to internal resources
- [ ] Test cloud metadata access
- [ ] Test port scanning

**Payloads:**
```
http://localhost/admin
http://127.0.0.1:8080
http://169.254.169.254/latest/meta-data/
```

#### 5.3 Open Redirects
- [ ] Identify redirect parameters
- [ ] Test redirect bypass
- [ ] Test chaining with other vulnerabilities

#### 5.4 Race Conditions
- [ ] Identify operations with timing issues
- [ ] Test concurrent requests
- [ ] Use Burp Turbo Intruder

#### 5.5 Business Logic Flaws
- [ ] Test price manipulation
- [ ] Test quantity bypass
- [ ] Test coupon abuse
- [ ] Test workflow bypass
- [ ] Test permission logic

---

### PHASE 6: CONFIGURATION & DEPLOYMENT

#### 6.1 Security Headers
```bash
curl -I http://10.0.0.10 | grep -i "content-security-policy\|x-frame-options\|hsts\|x-content-type-options"
```

- [ ] Content-Security-Policy (CSP)
- [ ] X-Frame-Options
- [ ] X-Content-Type-Options
- [ ] Strict-Transport-Security (HSTS)
- [ ] X-XSS-Protection
- [ ] Referrer-Policy

#### 6.2 TLS/SSL Configuration
- [ ] Check certificate validity
- [ ] Test for weak ciphers
- [ ] Test SSL/TLS downgrade

#### 6.3 CORS Configuration
- [ ] Check CORS headers
- [ ] Test CORS bypass

#### 6.4 Cookie Security
- [ ] Check HttpOnly flag
- [ ] Check Secure flag
- [ ] Check SameSite flag

#### 6.5 Information Disclosure
- [ ] API keys in JavaScript
- [ ] Internal IPs in errors
- [ ] Database connection strings
- [ ] Source code disclosure
- [ ] Backup file exposure
- [ ] Version information

#### 6.6 Default Credentials
- [ ] Test for default admin credentials
- [ ] Check for debug mode
- [ ] Check for verbose error messages

---

### PHASE 7: DOCUMENTATION & REPORTING

#### 7.1 Organize Findings
- [ ] Group vulnerabilities by type
- [ ] Calculate CVSS scores for each
- [ ] Prioritize by severity

#### 7.2 Create Screenshots
- [ ] Screenshot for every vulnerability
- [ ] Show request/response
- [ ] Show impact/proof

#### 7.3 Write Remediation
- [ ] Specific fix for each vulnerability
- [ ] Code examples if applicable
- [ ] Best practices

#### 7.4 Generate Report
- [ ] Use PWPA Report Template
- [ ] Include all required sections
- [ ] Proofread
- [ ] Convert to PDF
- [ ] Submit to exam portal

---

## Quick Priority Matrix

### FIND THESE FIRST (25 points each)
1. **SQL Injection** - Test all input fields
2. **Broken Authentication** - Test login/session
3. **Broken Access Control** - Test IDOR/authorization
4. **Stored XSS** - Test all stored data
5. **Command Injection** - Test system commands
6. **SSRF** - Test URL fetching
7. **XXE** - Test XML parsing
8. **Template Injection** - Test templates
9. **Open Redirect** - Test redirects

### THEN TEST THESE
- CSRF
- Insecure File Upload
- Race Conditions
- Business Logic Flaws
- Security Headers
- Information Disclosure

---

## Time Allocation (48 hours)

| Phase | Hours | Tasks |
|-------|-------|-------|
| Reconnaissance | 2-3 | Map app, identify endpoints |
| Authentication | 3-4 | Test login, registration, session |
| Authorization | 3-4 | Test IDOR, privilege escalation |
| Injection | 15-20 | SQLi, XSS, Command, SSTI, XXE, LFI |
| Business Logic | 5-8 | CSRF, SSRF, Open Redirect, Logic |
| Configuration | 2-3 | Headers, TLS, CORS, Cookies |
| Documentation | 4-6 | Screenshots, remediation, report |
| **TOTAL** | **48** | **Complete testing** |

---

## Key Reminders

✅ **DO THIS:**
- Test systematically (don't jump around)
- Document as you go (don't wait until end)
- Take screenshots immediately
- Test all user roles
- Test all input vectors
- Validate all findings

❌ **DON'T DO THIS:**
- Go out of scope (only 10.0.0.10)
- Perform DoS attacks
- Violate academic honesty
- Report consequences instead of vulnerabilities
- Submit in wrong format (PDF only)
- Forget screenshots or remediation

---

## Vulnerability Scoring Reference

| Vulnerability | Points | Status |
|---|---|---|
| SQL Injection | 25 | Find this! |
| Stored XSS | 25 | Find this! |
| Command Injection | 25 | Find this! |
| Template Injection | 25 | Find this! |
| XXE | 25 | Find this! |
| IDOR | 25 | Find this! |
| BOLA | 25 | Find this! |
| BFLA | 25 | Find this! |
| SSRF | 25 | Find this! |
| Broken Access Control | 25 | Find this! |
| Broken Authentication | 25 | Find this! |
| Open Redirect | 25 | Find this! |

**Need 75+ points to pass = Find 3-4 of these**

---

**Ready to start testing? Let's go! 🚀**

**Last Updated:** January 2026
