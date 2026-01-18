-  Since we already made a account lets try to login.
```shell
┌──(root㉿kali)-[~/pwpa]
└─# curl -X POST http://10.0.0.10/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser1","password":"Password123!"}'
{"message":"Login successful.","success":true}                                                                                          
```

###   Test Brute Force on Login page : Vulner : Broken Authentication
- Here is the request for login page
```http
POST /login HTTP/1.1
Host: 10.0.0.10
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.0.0.10/
Content-Type: application/json
Content-Length: 50
Origin: http://10.0.0.10
Connection: keep-alive
Cookie: connect.sid=s%3ASxCi3ONYEr_xpY1Ou7mZckehJm63XXjQ.Vu489IEbAHVAh1Qp8ZEfxIY32P6aPpUQaePFQFaoR4I
Priority: u=0

{"username":"testuser1","password":"test"}
```
- Wordlist used : `xato-net-10-million-passwords-100.txt` from SecLists.

#### Brute Force Testing Results

**Vulnerability:** Weak Rate Limiting (Broken Authentication - Partial Protection)

**Description:**  
The login endpoint implements rate limiting but allows 50 login attempts per time window. While this provides some protection against automated brute force attacks, it is insufficient for a password manager application where strong authentication controls are critical.

**Impact:**  
Attackers can perform credential stuffing or targeted brute force attacks with up to 50 attempts per time window. For common passwords or weak password policies, this could allow account compromise. The rate limit is too permissive for a security-sensitive application.

**Technical Details:**

**Rate Limiting Headers Observed:**
- `X-RateLimit-Limit: 50` - Maximum requests per time window
- `X-RateLimit-Remaining: XX` - Decrements with each request (48, 46 observed)
- `X-RateLimit-Reset: [timestamp]` - Unix timestamp for limit reset

**Test Results:**
- Multiple invalid login attempts return consistent error messages
- No account lockout after failed attempts
- No CAPTCHA or additional authentication factors
- Rate limiting is enforced but allows 50 attempts

**Proof of Concept:**

**Request (Invalid Login):**
```http
POST /login HTTP/1.1
Host: 10.0.0.10
Content-Type: application/json

{"username":"testuser1","password":"wrongpassword"}
```

**Response (Rate Limited):**
```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 50
X-RateLimit-Remaining: 46
X-RateLimit-Reset: 1768720985

{"message":"Invalid credentials.","success":false}
```

**CVSS v3.1 Score:** 5.3 (Moderate)  
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N  
**Rationale:** Network attack, low complexity, no privileges required, impacts confidentiality (password cracking possible).

**Remediation:**
1. Implement stricter rate limiting (e.g., 5-10 attempts per hour)
2. Add account lockout after failed attempts
3. Implement progressive delays
4. Add CAPTCHA after 3-5 failed attempts
5. Implement multi-factor authentication
6. Log and monitor brute force attempts

**Status:** Confirmed  
**Severity:** Moderate (reportable)  
**Points:** Not 25-point category (Broken Authentication requires complete lack of protection)

---

[Screenshots to be added here]
- Screenshot of Burp Intruder results showing rate limiting
	- ![[Weak rate limiting found on login page.png]]
- Screenshot of response headers with X-RateLimit values
	-  ![[Pasted image 20260118130119.png]]
- Screenshot of multiple failed login attempts

---

**Next Testing:** SQL Injection in Login Username Field