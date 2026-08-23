# Week 2.1
## Network Applications.
### Examples of Network Applications
1. Email
2. The Web -- [WWW]
3. Instant Messaging
4. Remote Login such as Telnet and SSH
5. P2P File sharing
6. Voice over IP

---

## Creating Network Applications.
- Generally the **Network application or any type of application** lives in Application Layer.
- Runs on **diff end system's** (endpoint systems).
- And **applications are not ran on networking devices** like router..
	- eg: **web server software communication with the browser software.**
- By creating network applications, the **applications on the end system** allows for **rapid app development**, **propagation**.

---

## Application Architecture
- Application Architecture **defines ~={cyan}how the network applications=~ are ~={green}structured and how different components=~ (devices) ~={green}communicates with each other=~.**
### Client - server Architecture.
- In this type of **Architecture** the **~={yellow}server (~={red}a centralized model=~)=~** ~={green}provides resources/services=~ to the ~={blue}**client on there request to consume those services.**=~
#### Components:
| Component  | Role                                              | Example                                  |
| ---------- | ------------------------------------------------- | ---------------------------------------- |
| **Server** | Provides services, stores data, manages resources | Web server, File server, Database server |
| **Client** | Requests services from the server                 | Web browser, Email client, Mobile app    |
#### Advantages ✅ and Disadvantages ❌

| Advantages ✅               | Disadvantages ❌             |
| -------------------------- | --------------------------- |
| **Centralized Management** | **Single Point of Failure** |
| **Data Integrity**         | **High Cost**               |
| **Security**               | **Performance Bottleneck**  |
| **Scalability**            | **Dependency**              |

---

### Peer - to - Peer (P2P) Architecture
- It is a ~={red}**decentralized mode**l=~ where **~={yellow}every device=~** (peer) **~={green}acts as both a client and a server.=~**
- **Peer** **~={cyan}share's resources directly=~** **with each other without a central server**. 
#### Components:

|Component|Role|
|---|---|
|**Peer**|Both client and server — requests and provides resources|
#### Advantages ✅ and Disadvantages ❌

| Advantages ✅                   | Disadvantages ❌ |
| ------------------------------ | --------------- |
| **No Single Point of Failure** | **Security**    |
| **Scalable**                   | **Management**  |
| **Cost-Effective**             | **Unreliable**  |
| **Self-Scalability**           | **Performance** |
# Week 2.2
## Web Overview
- Web page consist of objects (objects can be HTML file, JPEG image) and each of the which can be stored on different Web Servers.
- ~={yellow}**Web page consist of base HTML file**=~ **which includes several referenced objects**, each addressable by a **URL**.
	-  `www.someschool.edu/someDept/pic.gif`
## HTTP Overview
- HTTP **HyperText Transfer Protocol** is an ~={cyan}**application - layer protocol=~ ~={yellow}used for transferring web pages, images, videos, and other resources over the internet.**=~
- HTTP is a client / server model : 
	- Client: **Browser** sends **~={cyan}request and it receives=~** (using HTTP protocol) **and "~={cyan}displays=~" Web Object**.
	- Server: **Web Server** **~={cyan}sends (using the HTTP protocol) objects=~ in ~={green}response to the requests**=~
## HTTP Connections
- An HTTP connection is a ~={green}**TCP-based communication channel**=~ **~={cyan}established between a client=~** (browser) **~={cyan}and a web server=~** to **send HTTP requests and receive HTTP responses**
- **Types of HTTP Connections**

| **Non-Persistent Connection [ HTTP/1.0 ]**                        | **Persistent Connection [ HTTP/1.1 ]**                                |
| ----------------------------------------------------------------- | --------------------------------------------------------------------- |
| A new TCP connection is opened for **each request/response pair** | The same TCP connection is **reused** for multiple requests/responses |

## HTTP Request message
- An **HTTP Request Message** is the ~={yellow}data sent by the **client (browser)** to the **server**=~ to ~={cyan}request a resource or perform an action=~. 
- It is a **text-based, human-readable** message.

- Structure of an HTTP Request : 
```text
+----------------------------------------------+
|  1. Request Line                             |
|     (Method + URL + HTTP Version)            |
+----------------------------------------------+
|  2. Request Headers                          |
|     (Host, User-Agent, Accept, etc.)        |
+----------------------------------------------+
|  3. (Optional) Blank Line                    |
|     (Separates headers from body)           |
+----------------------------------------------+
|  4. (Optional) Request Body                  |
|     (Data sent to the server - POST, PUT)   |
+----------------------------------------------+
```
## HTTP Response status code
- An **HTTP Status Code** is a **3-digit number** ~={cyan}sent by the server as part of the HTTP response. =~
- It indicates the **result of the client's request** — whether it succeeded, failed, or needs further action.
```http
HTTP/1.1 200 OK
│         │   └── Reason Phrase (human-readable)
│         └── Status Code (3-digit number)
└── HTTP Version
```

| Range   | Category      | Description                                                        | Example                   |
| ------- | ------------- | ------------------------------------------------------------------ | ------------------------- |
| **1xx** | Informational | Request received, continuing                                       | 100 Continue              |
| **2xx** | Success       | Request succeeded                                                  | 200 OK                    |
| **3xx** | Redirection   | Further action needed                                              | 301 Moved Permanently     |
| **4xx** | Client Error  | Error on the client side                                           | 404 Not Found             |
| **5xx** | Server Error  | Error on the server side                                           | 500 Internal Server Error |

### 2xx – Success (200–299)
|Code|Reason Phrase|Meaning|
|---|---|---|
|**200**|OK|**Request succeeded.** The response contains the requested data|
|**201**|Created|**Resource created.** Used after POST requests|
|**202**|Accepted|Request accepted but not yet processed (async)|
|**204**|No Content|**Success, but no content in the response body** (used for DELETE)|
|**205**|Reset Content|Success, but client should reset the document view|

### 3xx – Redirection (300–399)
|Code|Reason Phrase|Meaning|
|---|---|---|
|**301**|Moved Permanently|**The resource has permanently moved to a new URL.** Update your bookmarks|
|**302**|Found|**Temporary redirect.** Resource is at a different URL for now|
|**303**|See Other|Redirect to a different URL (use GET to fetch it)|
|**304**|Not Modified|**Cached content is still valid.** Use your cached copy (no body)|
|**307**|Temporary Redirect|Same as 302, but method and body must not change|
|**308**|Permanent Redirect|Same as 301, but method and body must not change|
### 4xx – Client Error (400–499)
| Code    | Reason Phrase          | Meaning                                                             |
| ------- | ---------------------- | ------------------------------------------------------------------- |
| **400** | Bad Request            | **Malformed syntax.** The server cannot understand the request      |
| **401** | Unauthorized           | **Authentication required.** Client must authenticate               |
| **403** | Forbidden              | **Access denied.** The client is authenticated but lacks permission |
| **404** | Not Found              | **Resource not found.** The URL is invalid or does not exist        |
| **405** | Method Not Allowed     | The HTTP method is not supported for this resource                  |
| **406** | Not Acceptable         | Server cannot generate content matching the client's Accept headers |
| **408** | Request Timeout        | Client took too long to send the request                            |
| **409** | Conflict               | Request conflicts with the current state of the resource            |
| **410** | Gone                   | Resource permanently deleted and no forwarding address              |
| **413** | Payload Too Large      | Request body is larger than the server can handle                   |
| **414** | URI Too Long           | The URL is too long for the server to process                       |
| **415** | Unsupported Media Type | The server does not support the Content-Type sent                   |
| **429** | Too Many Requests      | Client has sent too many requests (rate limiting)                   |
### 5xx – Server Error (500–599)
|Code|Reason Phrase|Meaning|
|---|---|---|
|**500**|Internal Server Error|**Generic server-side error.** Something went wrong on the server|
|**501**|Not Implemented|Server does not support the requested method|
|**502**|Bad Gateway|The server, acting as a gateway, received an invalid response from an upstream server|
|**503**|Service Unavailable|**Server overloaded or down for maintenance** (temporary)|
|**504**|Gateway Timeout|The server (gateway) did not receive a timely response from an upstream server|
|**505**|HTTP Version Not Supported|Server does not support the HTTP version used in the request|
## Web Caches
- A **Web Cache** is a **temporary storage location** ~={yellow}that stores copies of web resources=~ (HTML pages, images, CSS, JavaScript, etc.) 
- so that **future requests** ~={green}can be served **faster** without fetching the resource from the original server again.=~

### How Web Caching Works
| Step | Action                                                                                    |
| ---- | ----------------------------------------------------------------------------------------- |
| 1    | **First Request:** Client requests a resource (e.g., `logo.png`) from the server          |
| 2    | **Server Response:** Server sends the resource and includes ~={cyan}**caching headers**=~ |
| 3    | **Cache Saves:** The cache stores a copy of the resource along with its headers           |
| 4    | **Subsequent Request:** Client requests the same resource again                           |
| 5    | **Cache Check:** The cache checks if it has a valid (fresh) copy                          |
| 6    | **If Fresh:** Cache serves the resource directly (faster) → **Cache Hit**                 |
| 7    | **If Stale:** Cache re-fetches from the origin server → **Cache Miss**                    |

# Week 2.3
## Overview of E mail System
- An **Email System** is a **network-based application** ~={green}that allows **users to send, receive, and store electronic messages** (emails) over the Internet.=~
- It follows the Client - Server model and relies on three main protocols:
	- **SMTP** (Sending & Relaying) **used in mail servers.**
	- **POP3** or **IMAP** (Receiving & Storing) **used in client side.**

```text

Work Flow for E-MAIL

[User A (Sender)]
        |        
        |  (1. Sending)      
[Outgoing Mail Server (SMTP)]
        |        
        |  (2. Routing)   
[Recipient's Mail Server (SMTP)]
        |        
        |  (3. Sorting)   
[User B's MailBox (POP3/IMAP)]
        |        
        |  (4. Retrieving)   
[User B (Receiver)]
```

## SMTP (Simple Mail Transfer Protocol)
- **~={yellow}Sends outgoing email from the client (Sender) to the mail server=~ and then ~={green}relays it to the receiver mail server=~.**
- **Ports:** 25 (unencrypted), 587 (submission - recommended), 465 (SMTPS)
- Uses a Persistent TCP connection
## POP3 (Post Office Protocol version3)
- ~={yellow}**Downloads the email from the mail server=~ to the ~={yellow}local device=~ and usually deletes them from the server.**
- **Ports:** 110 (unencrypted), 995 (POP3/SSL)
- Uses a Non Persistent connection.
## IMAP (Internet Message Access Protocol)
- **Synchronizes emails**, **~={green}Keeps all emails on the server=~**, ~={cyan}allowing multiple devices to **view and manage** the same mailbox=~.
- **Ports:** 143 (unencrypted), 993 (IMAPS/SSL)
- Uses a Persistent TCP connection.
# Week 2.4 DNS
## What is DNS ?
- DNS (Domain Name System) it **~={yellow}translates human-readable domain names=~** (like `www.google.com`.
```text
                         [Root]                (.)
                          |
                 +--------+--------+
                 |                 |
              .com              .org           (TLDs)
                 |                 |
          +------+------+          |
          |      |      |          |
       google  amazon  apple    wikipedia      (SLD)
          |      |      |          |
      [www]   [www]  [www]    [www.example]    (Subdomain)
```

## Services Provided
1. **Host Aliasing**
	- Allows **multiple domain names** ~={cyan}to point to the same physical host (server).=~
	- Eg: **Facebook** uses `www.facebook.com` as an **~={cyan}alias for its actual server name=~** (e.g., `fb-edge-01.facebook.com`). 
	- If Facebook changes **the physical server**, ~={green}they just update the CNAME; users don't notice.=~
2. **Mail Server Aliasing**
	- Maps a ~={green}domain to the **mail server** responsible=~ for receiving ~={cyan}emails for that domain=~.
3. **Load Distribution**
	- ~={green}Distributes incoming traffic=~ across ~={cyan}**multiple physical servers** using a single domain name.=~
4. **Translates Host Name to IP address (Main Task of DNS)**
## How it works

```text

                                    (Yes)
[Checks Cache]  -->  { IP FOUND? }  ----->       ------>           ----->         [Connects To                                                                                      Website]
                                     (No)                                               |
                                      |                                                 | 
                                      |                                                 |
                                      |                                                 |
                                                   (Yes)                      
                             [ Send DNS Query    ------>           ----->         [Return IP                                  to Resolvers ]                                    to computer]                                       (No)                                            |
		                              |                                               |                                             |                                               |
                                      |----> Recursive Lookup                         |                                                   |                                         |
                                            |                                         |
                                            | --> [Root NS] --> [TLD NS] --> [Authoritative
						                                                           NS  ]
                                                   
```

## Method of Query
### Recursive Querying
- The **resolver takes full responsibility to find the answer**.
- It~={yellow} **queries other servers on behalf of them client**=~ ~={green}until it gets a final answer=~ (or error).
```text
Client → Resolver (asks for IP)
Resolver → Root → TLD → Authoritative (does all the work)
Resolver → Client (returns final IP)
```
### 2. Iterative Querying
- The **resolver does not take full responsibility**.
- It **~={yellow}return the best answer it has=~** (e.g. a **referral to another server like root, tld, autho**) and expects the client to continue the query.
```text
Client → Resolver (asks)
Resolver → Client (referral to Root)
Client → Root (asks)
Root → Client (referral to TLD)
Client → TLD (asks)
TLD → Client (referral to Authoritative)
Client → Authoritative (asks)
Authoritative → Client (returns IP)
```

# Week 2.5 CDN
## Content Distribution Network
- CDN (Content Delivery Network) is a **~={yellow}large geographically distributed network of specialized servers=~** **~={green}that accelerate the delivery of web content and rich media to internet connected devices.=~**
- **Faster Delivery of services.**
- Helps in **mitigating Denial - of - Service Attack**.
## Why CDN?
### The Problems (without CDN)
| Issue                       | Explanation                                                                 |
| --------------------------- | --------------------------------------------------------------------------- |
| **High Latency**            | A user in India accessing a server in the US faces huge delays (300ms+).    |
| **Network Congestion**      | All traffic hits a single server, causing bottlenecks.                      |
| **Server Overload**         | Millions of requests crash the origin server.                               |
| **Bandwidth Costs**         | Serving the same file (e.g., a 4K video) millions of times costs a fortune. |
| **Single Point of Failure** | If the main server goes down, the entire website goes offline.              |

## CDN Architecture
```text
                  +-----------------------+
                  |   Origin Server       |
                  |   (Master Copy)       |
                  +-----------------------+
                             │
               ┌─────────────┼─────────────┐
               ▼             ▼             ▼
         +----------+  +----------+  +----------+
         | Edge     |  | Edge     |  | Edge     |
         | Server   |  | Server   |  | Server   |
         | (USA)    |  | (EU)     |  | (Asia)   |
         +----------+  +----------+  +----------+
               │             │             │
               ▼             ▼             ▼
          [Users in     [Users in     [Users in
           USA]          Europe]        Asia]
```
## CDN Working
```text
[User in India] 
       │
       ▼ (1. Request: www.netflix.com/video.mp4)
[Local DNS Resolver]
       │
       ▼ (2. DNS resolves to the nearest CDN Edge Server)
[CDN Edge Server (Mumbai, India)]
       │
       ├── (3a. If cached) ──► Serves the video instantly (50ms)
       │
       └── (3b. If NOT cached) ──► Requests from Origin Server (USA)
                                    │
                                    ▼
                              [Origin Server (USA)]
                                    │
                                    ▼ (4. CDN caches it)
                              [CDN Edge Server]
                                    │
                                    ▼ (5. Serves to user)
                              [User watches video]
```
## Real time case study about Netflix adaptation with CDN.
### Content Ingestion
- The raw movie file ( usually a massive 4k or higher resolution master ) is uploaded into Netflix's cloud infrastructure
- E.g. AWS
### Content Processing
- Here the raw file (single master file) is converted into thousands of different versions, **preparing it for every possible** ~={yellow}device=~ and ~={yellow}network condition.=~
- Transcode into **200+ resolutions/bitrates.**
### Uploading version to its CDN
- Then we uploaded those processed versions into the CDN servers.