# PWPA Exam Guide & Scoring Breakdown

**Practical Web Pentest Associate (PWPA) - FailSafe Application**

**Exam Duration:** 48 hours testing + 48 hours reporting  
**Target:** FailSafe Web Application (10.0.0.10)  
**Passing Score:** 75+ points

---

## Table of Contents

1. [Exam Overview](#exam-overview)
2. [Scoring Breakdown](#scoring-breakdown)
3. [Critical Exam Requirements](#critical-exam-requirements)
4. [Testing Strategy](#testing-strategy)
5. [Report Requirements](#report-requirements)
6. [Common Mistakes to Avoid](#common-mistakes-to-avoid)
7. [Exam Tips & Tricks](#exam-tips--tricks)

---

## Exam Overview

### Scenario
FailSafe is a **web-based password manager** designed to help users manage and share passwords securely. You are performing a penetration test to identify impactful vulnerabilities.

### Key Objectives
1. Identify impactful vulnerabilities (not just any vulnerability)
2. Apply both automated AND manual testing techniques
3. Create a thorough, professional report with screenshots and remediation for ALL findings

### Exam Environment
- **Target IP:** 10.0.0.10
- **Access:** VPN connection required
- **Tools:** Any tools at your disposal
- **Environment Resets:** Unlimited (resets revert to baseline, don't change exam)

---

## Scoring Breakdown

### 25-Point Vulnerabilities (Multiple instances = 1 point only)

**CRITICAL: Multiple instances of the SAME vulnerability type only count ONCE for maximum points**

These are the high-value targets. Finding ANY of these = 25 points:

1. **SQL Injection** (25 pts)
   - Any SQL injection vulnerability
   - Multiple instances in different locations = still 25 pts total
   - Blind SQLi counts as SQLi

2. **Stored Cross-Site Scripting (XSS)** (25 pts)
   - Stored XSS in comments, profiles, posts, etc.
   - Multiple stored XSS locations = still 25 pts total
   - Reflected XSS does NOT count for this category

3. **Command Injection** (25 pts)
   - OS command execution
   - Blind command injection counts

4. **Template Injection** (25 pts)
   - Server-Side Template Injection (SSTI)
   - Any template engine (Jinja2, Freemarker, etc.)

5. **XML External Entity Injection (XXE)** (25 pts)
   - XXE in XML parsers
   - File disclosure via XXE
   - SSRF via XXE

6. **Insecure Direct Object Reference (IDOR)** (25 pts)
   - Access to other users' data by modifying object references
   - Example: /user/profile/123 → /user/profile/124

7. **Broken Object Level Authorization (BOLA)** (25 pts)
   - Similar to IDOR but broader
   - Unauthorized access to objects/resources

8. **Broken Function Level Authorization (BFLA)** (25 pts)
   - Access to admin functions with regular user account
   - Vertical privilege escalation

9. **Server-Side Request Forgery (SSRF)** (25 pts)
   - Application makes requests to internal resources
   - Access to cloud metadata
   - Port scanning via SSRF

10. **Broken Access Control** (25 pts)
    - General authorization bypass
    - Missing access controls

11. **Broken Authentication** (25 pts)
    - Authentication bypass
    - Weak password policies
    - Session management flaws
    - MFA bypass

12. **Open Redirect** (25 pts)
    - Redirect to external domains
    - Can be chained with other vulnerabilities

### Other Reportable Vulnerabilities (Variable Points)

These should be reported but may have lower point values or be counted as "weaknesses":

- **Lack of Rate Limiting** - DoS potential
- **Lack of Security Controls / Best Practices** - General weaknesses
- **Weak Passwords** - Policy issues
- **Cleartext Submission of Passwords** - Transmission security
- **HTTP(S) Vulnerabilities** - Protocol issues
- **Information Disclosure Without Impact** - Low severity
- **Weak Security Headers** - Missing CSP, HSTS, etc.
- **Verbose Error Messages** - Information leakage
- **Insecure File Upload** - File handling issues
- **CSRF** - Cross-site request forgery
- **Race Conditions** - Timing-based issues
- **Business Logic Flaws** - Application logic issues

---

## Critical Exam Requirements

### ✅ MUST DO to Pass

1. **Earn 75+ Points**
   - Find impactful vulnerabilities
   - Focus on the 25-point categories
   - Quality over quantity

2. **Submit Professional Report**
   - **Format:** PDF ONLY (not .docx, .zip, or other formats)
   - **Content:** ALL findings documented
   - **Screenshots:** REQUIRED for every vulnerability
   - **Remediation:** REQUIRED for every vulnerability
   - **Proof of Concept:** Clear steps to reproduce

3. **Document ALL Findings**
   - Not just critical vulnerabilities
   - Include weaknesses and best practice violations
   - Report even if you don't think it's worth points

### ❌ DO NOT DO (Immediate Disqualification)

- **Go Out of Scope**
  - Only test 10.0.0.10
  - Do NOT test underlying infrastructure
  - Do NOT test OS or container hosting
  - **Consequence:** Immediate exam termination and disqualification

- **Perform DoS/DDoS Attacks**
  - Explicitly out of scope
  - Will result in disqualification

- **Violate Academic Honesty Policy**
  - Do not disclose exam environment details
  - Do not solicit assistance from others
  - Do not share course materials
  - **Consequence:** Exam termination and loss of attempt

---

## Testing Strategy

### Phase 1: Reconnaissance (4-6 hours)

**Objective:** Map the application thoroughly

- [ ] Enumerate all endpoints and features
- [ ] Identify technology stack
- [ ] Map user roles and functionality
- [ ] Identify input fields and parameters
- [ ] Use Burp Suite to crawl application
- [ ] Analyze JavaScript for endpoints

**Focus Areas for FailSafe (Password Manager):**
- [ ] User registration/login
- [ ] Password storage/retrieval
- [ ] Password sharing functionality
- [ ] User profile management
- [ ] API endpoints
- [ ] Admin functionality (if any)

### Phase 2: Vulnerability Testing (36-40 hours)

**Priority Order (by point value):**

1. **High-Value Vulnerabilities First (25 pts each)**
   - [ ] SQL Injection (test all input fields)
   - [ ] Broken Authentication (login, session, MFA)
   - [ ] Broken Access Control (IDOR, BOLA, BFLA)
   - [ ] XSS (Stored, Reflected, DOM-based)
   - [ ] Command Injection
   - [ ] SSRF
   - [ ] XXE
   - [ ] Template Injection
   - [ ] Open Redirect

2. **Medium-Value Vulnerabilities**
   - [ ] CSRF
   - [ ] Insecure File Upload
   - [ ] Race Conditions
   - [ ] Business Logic Flaws

3. **Low-Value but Reportable**
   - [ ] Weak Security Headers
   - [ ] Rate Limiting Issues
   - [ ] Information Disclosure
   - [ ] Weak Password Policies

**Testing Methodology:**
- Use both automated tools (Burp Scanner, SQLMap) and manual testing
- Test all user roles (anonymous, authenticated, admin if applicable)
- Test all input vectors (GET, POST, headers, cookies, JSON)
- Test edge cases and boundary conditions

### Phase 3: Validation & Documentation (2-4 hours)

- [ ] Verify all findings are reproducible
- [ ] Capture screenshots for every vulnerability
- [ ] Document exact steps to reproduce
- [ ] Prepare proof of concept for each finding
- [ ] Calculate CVSS scores
- [ ] Prepare remediation recommendations

---

## Report Requirements

### Report Format & Delivery

- **Format:** PDF ONLY
- **Delivery:** Upload to exam portal
- **Deadline:** 48 hours after testing ends
- **Content:** Must include ALL findings (not just critical)

### Report Structure (Use Your Template)

**Recommended sections:**
1. Executive Summary
2. Engagement Overview
3. Methodology
4. Scope & Rules of Engagement
5. Summary of Findings (table format)
6. Overall Risk Rating
7. Detailed Findings (for each vulnerability):
   - Title
   - Severity (CVSS score)
   - Description
   - Affected URLs/Parameters
   - Steps to Reproduce
   - Proof of Concept (screenshots)
   - Impact
   - Remediation
   - References (OWASP, CWE, CVE)
8. Testing Coverage
9. Tools Used
10. Appendices

### Critical Report Elements

**For EVERY vulnerability, include:**

✅ **Screenshots** - Visual proof of vulnerability
✅ **Reproduction Steps** - Clear, numbered steps
✅ **Remediation** - How to fix it
✅ **Impact** - What can an attacker do?
✅ **CVSS Score** - Severity rating

**Failure to include these = Exam Failure**

---

## Important Scoring Notes

### ⚠️ CRITICAL SCORING RULES

**1. Vulnerability vs. Consequence**
- **Correct:** Report "SQL Injection in login parameter allows database access"
- **Incorrect:** Report "SQL Injection allows attacker to hijack accounts" (this is the consequence)
- **Scoring:** Vulnerability + consequence = 1 point (not 2)

**2. Multiple Instances of Same Vulnerability**
- **Correct:** Report "Stored XSS found in comments, profiles, and posts" = 25 pts
- **Incorrect:** Report each location separately = still 25 pts total (not 75 pts)
- **Scoring:** Same vulnerability type = maximum points once only

**3. Impactful vs. Non-Impactful**
- **Impactful:** Information disclosure of hard-coded secret used to sign tokens = COUNTS
- **Non-Impactful:** Information disclosure of application version = may not count
- **Key:** Must have clear, exploitable impact

**4. Information Disclosure Scoring**
- **With Impact:** Leaking API key, database credentials, secrets = COUNTS
- **Without Impact:** Leaking version numbers, framework names = LOW/NO points
- **Rule:** Must be exploitable or lead to further compromise

---

## Common Mistakes to Avoid

### ❌ Testing Mistakes

- [ ] Not testing all user roles (anonymous, authenticated, admin)
- [ ] Not testing all input vectors (GET, POST, headers, cookies)
- [ ] Incomplete testing (missing endpoints or parameters)
- [ ] Testing out of scope (infrastructure, OS, containers)
- [ ] Performing DoS attacks
- [ ] Not validating findings (false positives)

### ❌ Reporting Mistakes

- [ ] Missing screenshots (automatic failure)
- [ ] Missing remediation steps (automatic failure)
- [ ] Submitting in wrong format (.docx instead of .pdf)
- [ ] Reporting consequences instead of vulnerabilities
- [ ] Not including CVSS scores
- [ ] Unclear reproduction steps
- [ ] No proof of concept

### ❌ Exam Mistakes

- [ ] Wasting time emailing support for tool issues (use reset instead)
- [ ] Not downloading new VPN file after reset
- [ ] Going out of scope
- [ ] Violating academic honesty policy
- [ ] Being unprofessional with support staff
- [ ] Not taking breaks (leads to mistakes)

---

## Exam Tips & Tricks

### ✅ DO THIS

1. **Start with Reconnaissance**
   - Spend 4-6 hours mapping the application thoroughly
   - Use Burp Suite to crawl everything
   - Analyze JavaScript for hidden endpoints
   - Understand the application flow

2. **Focus on High-Value Vulnerabilities**
   - Prioritize 25-point vulnerabilities
   - Find just 3-4 of these = 75+ points
   - Don't waste time on low-value findings

3. **Test Systematically**
   - Create a testing checklist
   - Test each vulnerability type methodically
   - Document as you go (don't wait until end)

4. **Use Both Automated & Manual Testing**
   - Burp Suite Scanner for automated scanning
   - SQLMap for SQL injection
   - Manual testing for business logic flaws
   - Combination is most effective

5. **Take Care of Yourself**
   - Take breaks every 2-3 hours
   - Eat, sleep, stay hydrated
   - Don't stress (you've got this!)
   - Fresh mind = better testing

6. **Document Everything**
   - Take screenshots as you find vulnerabilities
   - Keep detailed notes
   - Document reproduction steps immediately
   - Don't wait until end to document

7. **Use Your Resets Wisely**
   - If something seems broken, reset
   - Resets are unlimited and faster than support emails
   - Don't waste time troubleshooting
   - Download new VPN file after reset

8. **Treat It Like a Real Engagement**
   - Not a CTF (capture the flag)
   - Focus on realistic, impactful vulnerabilities
   - Professional approach = better results

### ⚠️ COMMON STUDENT MISTAKES

**From TCM:**
> "Students frequently report the consequences of a vulnerability instead of identifying the vulnerability itself."

**Example:**
- ❌ Wrong: "XSS allows attacker to steal cookies and hijack accounts"
- ✅ Correct: "Stored XSS in comment field allows arbitrary JavaScript execution"

**Example:**
- ❌ Wrong: Report "Stored XSS in comments" AND "Stored XSS in profiles" as separate findings
- ✅ Correct: Report as single "Stored XSS" finding with multiple locations

### 🎯 Exam Day Strategy

**Hour 0-6: Reconnaissance**
- Map application
- Identify all endpoints
- Understand functionality
- Set up testing environment

**Hour 6-42: Vulnerability Testing**
- Test high-value vulnerabilities first
- Document findings as you go
- Take screenshots immediately
- Validate all findings

**Hour 42-48: Final Testing & Cleanup**
- Verify all findings are reproducible
- Ensure all screenshots captured
- Complete any remaining testing
- Prepare for report writing

**Hour 48-96: Report Writing**
- Organize findings
- Write clear descriptions
- Include all required elements
- Proofread and validate
- Convert to PDF
- Submit to portal

---

## If You Fail

**Don't panic!** TCM will:
- Provide feedback on your report
- Give hints for your next attempt
- Allow you to retake the exam

**Even if you fail:**
- Still submit your report
- You'll get valuable feedback
- Use it to improve for next attempt

---

## Key Reminders

### Before You Start
- [ ] Read Rules of Engagement completely
- [ ] Understand scope (10.0.0.10 only)
- [ ] Know passing criteria (75+ points)
- [ ] Understand report requirements (PDF, screenshots, remediation)

### During Testing
- [ ] Stay in scope
- [ ] Document as you go
- [ ] Take screenshots immediately
- [ ] Test systematically
- [ ] Take breaks

### Before Submitting Report
- [ ] All findings documented
- [ ] Screenshots for every vulnerability
- [ ] Remediation for every vulnerability
- [ ] CVSS scores calculated
- [ ] Format is PDF
- [ ] Professional quality
- [ ] Proofread

### After Submission
- [ ] Relax (you're done!)
- [ ] Wait for results
- [ ] Learn from feedback

---

## Quick Reference: 25-Point Vulnerabilities

**Find ANY 3-4 of these = 75+ points = PASS**

| Vulnerability | Category | Points | Example |
|---|---|---|---|
| SQL Injection | Injection | 25 | `' OR '1'='1` in login |
| Stored XSS | Injection | 25 | `<script>alert('XSS')</script>` in comment |
| Command Injection | Injection | 25 | `; whoami` in ping field |
| Template Injection | Injection | 25 | `{{7*7}}` in template |
| XXE | Injection | 25 | XML entity in file upload |
| IDOR | Authorization | 25 | `/user/profile/123` → `/user/profile/124` |
| BOLA | Authorization | 25 | Unauthorized object access |
| BFLA | Authorization | 25 | Admin function with regular user |
| SSRF | Network | 25 | Access to internal resources |
| Broken Access Control | Authorization | 25 | General auth bypass |
| Broken Authentication | Authentication | 25 | Login bypass, weak session |
| Open Redirect | Injection | 25 | Redirect to attacker domain |

---

**Good luck on your exam! You've got this! 🚀**

**Last Updated:** January 2026
