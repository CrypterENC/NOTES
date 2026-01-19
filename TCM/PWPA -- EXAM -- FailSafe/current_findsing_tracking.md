# Current Findings Tracking

## Confirmed Vulnerabilities (75 Points Total)

- **SQL Injection in Registration** (25 points): Allows unauthorized account creation via malformed SQL in username field.
- **SQL Injection in Vault Add** (25 points): Manipulates database queries to add unauthorized vault items.
- **IDOR in Vault Edit** (25 points): Allows editing other users' vault items by manipulating item IDs.
- **CSRF in Account Update** (Reportable): Forces password changes without user consent.
- **Information Disclosure in Error Messages** (Medium): Exposes stack traces and internal paths on malformed requests.

## Negative Findings

- SSTI: Not exploitable (literal string, no template execution).
- LFI: Not exploitable (no file reading from user input).
- Stored XSS: Sanitized in vault display.
- Open Redirect: Not present in login.
- Parameter Pollution: Not exploitable in vault endpoints.
- API IDOR: Not tested or confirmed.
- Session Fixation: Not tested.

## Testing Status

- Homepage: Tested XSS, Info Disclosure.
- Vault: Tested IDOR, XSS, SQLi.
- Account: Tested CSRF.
- API: Partially tested.
- Overall: Core vulns confirmed, report updated.