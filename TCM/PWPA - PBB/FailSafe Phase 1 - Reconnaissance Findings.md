# FailSafe PWPA Exam - Phase 1: Reconnaissance Findings

**Date:** January 18, 2026
**Target:** http://10.0.0.10

---

## Application Overview

**FailSafe** is a web-based password manager designed to help users manage and share passwords securely.

### Initial Connectivity Test
```bash
curl -I http://10.0.0.10
```
**Response:**
```
HTTP/1.1 200 OK
Date: Sun, 18 Jan 2026 06:39:21 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 7634
Connection: keep-alive
X-Powered-By: Express
ETag: W/"1dd2-KW1CYVEDzWSSo/KBW1Y8YFni+FM"
Set-Cookie: connect.sid=s%3AvNWhS0TLMvh3n7qrSiST_iNaDhmW42hr.w7%2FDiJZ5bv%2B541%2BBTIB2iPLFCrit6KBA%2FUdEY4yXWmg; Path=/; HttpOnly
Cache-Control: no-cache
```

**Key Findings:**
- **Status:** 200 OK (Application accessible)
- **Server:** Express.js framework
- **Session:** Uses connect.sid cookies with HttpOnly flag
- **Content-Type:** HTML (web application)

---

## Technology Stack Analysis

### Server Information
- **Web Framework:** Express.js (Node.js)
- **Session Management:** express-session
- **Security Features:** HttpOnly cookies enabled

### Frontend Analysis
From HTML source:
- **UI Framework:** Bootstrap
- **JavaScript:** Modal dialogs for login/registration
- **Forms:** JSON-based POST requests

### API Analysis
- **API Base:** /api (requires authentication)
- **Content-Type:** application/json
- **Authentication:** Session-based (connect.sid cookie)

---

## Endpoint Discovery

### Discovered Endpoints (ffuf Results)

```
:: Matcher: Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

account                 [Status: 200, Size: 17, Words: 2, Lines: 1, Duration: 284ms]
api                     [Status: 401, Size: 48, Words: 2, Lines: 1, Duration: 292ms]
css                     [Status: 301, Size: 173, Words: 7, Lines: 11, Duration: 276ms]
images                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 277ms]
js                      [Status: 301, Size: 171, Words: 7, Lines: 11, Duration: 277ms]
signout                 [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 285ms]
vault                   [Status: 200, Size: 17, Words: 2, Lines: 1, Duration: 290ms]
```

### Endpoint Analysis

#### `/` (Root)
- **Status:** 200 OK
- **Content:** Main application page with login/registration modals
- **Size:** 7634 bytes
- **Authentication:** Not required

#### `/account`
- **Status:** 200 OK
- **Size:** 17 bytes (small response)
- **Authentication:** Unknown (needs testing)
- **Purpose:** Likely user account management

#### `/vault`
- **Status:** 200 OK
- **Size:** 17 bytes (small response)
- **Authentication:** Unknown (needs testing)
- **Purpose:** Password vault (core functionality)

#### `/api`
- **Status:** 401 Unauthorized
- **Size:** 48 bytes
- **Authentication:** Required
- **Response:** `{"success": false, "message": "Not authenticated."}`
- **Purpose:** API endpoint requiring authentication

#### `/signout`
- **Status:** 302 Found (redirect)
- **Size:** 23 bytes
- **Authentication:** Unknown
- **Purpose:** Logout functionality

#### Static Assets
- `/css/*` → 301 redirect to static content
- `/images/*` → 301 redirect to static content
- `/js/*` → 301 redirect to static content

---

## User Interface Analysis

### Main Page Features
- **Login Modal:** Accessible via "log in" button
- **Registration Modal:** Accessible via "sign up" button
- **API Link:** "API" in navigation (links to /api)
- **Bootstrap Framework:** Responsive design

### Authentication Flow
- **Registration:** JSON POST to `/register`
- **Login:** Likely JSON POST to `/login` (needs testing)
- **Session:** Uses connect.sid cookies

---

## API Testing Results

### Registration Endpoint
**Request:**
```http
POST /register HTTP/1.1
Host: 10.0.0.10
Content-Type: application/json
Content-Length: 50

{"username":"testuser1","password":"Password123!"}
```

**Response:**
```http
HTTP/1.1 200 OK
Date: Sun, 18 Jan 2026 06:46:59 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 53
Connection: keep-alive
X-Powered-By: Express
ETag: W/"35-00pyRLWlSzoRujZbDfUAzBG83Eo"
Cache-Control: no-cache

{"message":"Registration successful!","success":true}
```

**Key Findings:**
- Registration successful
- No email field required
- Username + password only
- Potential SQL injection vector (no input validation observed)

---

## Security Observations (Phase 1)

### Positive Security Controls
- HttpOnly flag on session cookies
- Express.js framework (has built-in security)
- JSON API communication (prevents some XSS)

### Potential Security Issues
- No input validation observed in registration
- API accessible without authentication (returns 401)
- Session cookies without Secure flag (HTTP only)
- Small response sizes for /account and /vault (may require auth)

### Testing Vectors Identified
- SQL injection in registration (username field)
- Authentication bypass attempts
- IDOR testing on user-specific endpoints
- API endpoint enumeration

---

## Next Steps (Phase 2)

1. **Test /account endpoint authentication**
2. **Test /vault endpoint authentication**
3. **Test login functionality**
4. **Test SQL injection in registration**
5. **Map authenticated user workflows**
6. **Test API endpoints with authentication**

---

## Data for Report

### Technology Stack (for report)
- **Frontend:** HTML/CSS/JavaScript with Bootstrap
- **Backend:** Node.js with Express.js framework
- **Database:** Unknown (to be determined)
- **Session Management:** express-session
- **Authentication:** Session-based with connect.sid cookies

### Scope Information
- **Target URL:** http://10.0.0.10
- **Environment:** Test/Lab
- **Discovered Endpoints:**
  - / (main page)
  - /register (POST)
  - /account
  - /vault
  - /api
  - /signout
  - Static assets (/css, /images, /js)

### Testing Environment
- **OS:** Kali Linux
- **Tools Used:** curl, ffuf, Burp Suite
- **Network:** Direct access to target

---

**Phase 1 Status:** Complete
**Date Completed:** January 18, 2026
