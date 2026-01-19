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