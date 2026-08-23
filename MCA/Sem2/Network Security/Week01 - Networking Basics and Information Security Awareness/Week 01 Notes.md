## What is the Internet?

> **The Internet is a global system of interconnected computer networks** that uses **standardized protocols (TCP/IP)** to communicate and share **information**.

---

## Key Components Explained
### 1. Hosts / End Systems

- **What they are:** All devices connected to the Internet
- **Examples:**
    
    - Computers (desktops, laptops)
    - Smartphones and tablets
    - Servers (web servers, email servers)
    - IoT devices (smart TVs, cameras, thermostats)
    - Gaming consoles

> **Think of them as:** The "people" of the Internet — they send and receive data.

---
### 2. Communication Links

- **What they are:** The physical or wireless connections that carry data
- **Types:**
    
    - **Wired:** Fiber optic, Ethernet cables, coaxial cables
    - **Wireless:** Wi-Fi, cellular (4G/5G), satellite

- **Transmission Rate:** Measured in **bits per second (bps)**
    
    - Common rates: Mbps (megabits), Gbps (gigabits)

> **Think of them as:** The "roads" and "highways" that data travels on.

---
### 3. Packets

- **What they are:** Data is broken into small chunks called **packets** for transmission
- **Why packets?**
    
    - Efficient use of network resources
    - Allows multiple users to share the same link
    - If a packet is lost, only that packet needs retransmission (not the whole file)

```text
+-------------------+-------------------+-------------------+
|    Header         |    Payload        |    Trailer        |
| (Source/Dest IP,  |  (Actual Data)    | (Error Checking)  |
|  Sequence #, etc.)|                   |                   |
+-------------------+-------------------+-------------------+
```
### 4. Packet Switches

- **What they are:** Devices that forward packets toward their destination
    
- **Two Main Types:**
    
|Type|Function|Example|
|---|---|---|
|**Routers**|Forward packets between different networks|Home router, enterprise routers|
|**Link-Layer Switches**|Forward packets within the same network (LAN)|Network switches in offices|
### 5. Internet Service Providers (ISPs)

- **What they are:** Companies that provide Internet access to end systems
    
- **Tiers of ISPs:**
    
    - **Tier 1:** Global backbone (e.g., AT&T, Verizon, Level 3)
    - **Tier 2:** Regional providers (connect Tier 1 to local ISPs)
    - **Tier 3:** Local ISPs (provide direct access to homes/businesses)

### 6. Protocols

- **What they are:** ~={red}**Rules**=~ and ~={red}**standards**=~ that govern how data is sent and received

- **Why they matter:** Without protocols, ~={yellow}devices couldn't understand each other=~

**Key Protocols:**

| Protocol | Full Form                     | Purpose                                |
| -------- | ----------------------------- | -------------------------------------- |
| **TCP**  | Transmission Control Protocol | Reliable, connection-oriented delivery |
| **IP**   | Internet Protocol             | Addressing and routing packets         |
| **HTTP** | Hypertext Transfer Protocol   | Web browsing                           |
| **FTP**  | File Transfer Protocol        | File transfers                         |
| **SMTP** | Simple Mail Transfer Protocol | Sending emails                         |
| **DNS**  | Domain Name System            | Converts domain names to IP addresses  |
## Protocol Layering 
### What is Protocol Layering?

> **Protocol layering** is the ~={green}**practice of dividing network communication**=~ ~={purple}into **stacked layers**, ~={yellow}where each **layer has a specific job** and **~={red}only communicates=~** with the **layers directly above and below it**=~.=~

### The Benefits
> Layering offers conceptual clarity and structural organization.

## The Internet Protocol Stack (TCP/IP Model)

### What is the Internet Protocol Stack?
> The **Internet Protocol Stack** (also called the **TCP/IP Protocol Suite**) is a **~={green}layered architecture of protocols=~** that **~={cyan}work together to enable communication across the Internet.=~**

It consists of **5 layers**, each with specific responsibilities, from the physical transmission of bits to the applications you use daily.
#### Layer 1: Physical Layer
- Moves **individual bits** (0s and 1s) from one node to another.
- Defines **electrical, mechanical, and procedural** specifications.
- Depends on the **transmission medium** (cable, fiber, radio).
- Protocols are **link-dependent** ( protocols used at the Physical Layer ~={yellow}**depend entirely on the type of physical link**=~ (cable, fiber, wireless) being used to transmit data. )

**Examples:**

- Ethernet cables (Cat5, Cat6)
- Fiber optic cables
- Radio waves (Wi-Fi, Bluetooth)
- Connectors (RJ45, SC, LC)

#### Layer 2: Link Layer (Data Link Layer)
- The Link Layer is responsible for transferring data between **two directly connected neighboring devices (node-to-node)** over a single physical link **(Link Layer)** (e.g., laptop to Wi-Fi router, or router to router).
- Different link-layer protocols can handle a datagram at **different links** along the route.
- Provides **framing**, **error detection**, and **MAC addressing**.
- Each node along the route uses link-layer services.

**Examples:**

- Ethernet
- Wi-Fi (IEEE 802.11)
- PPP (Point-to-Point Protocol)

#### Layer 3: Network Layer (IP Layer)
- While the Link Layer connects neighboring nodes, the Network Layer is responsible for **host-to-host delivery (end-to-end routing)** across different networks.
- Receives transport-layer **segment** and **destination address**.
- Provides **logical addressing** (IP addresses).
- Handles **routing** (finding the best path).
- Often called the **IP Layer**.

**Examples:**

- IP (IPv4 / IPv6)
- ICMP (Internet Control Message Protocol)
- Routing protocols (OSPF, BGP, RIP)

#### Layer 4: Transport Layer

- The Transport Layer provides **process-to-process delivery**, ensuring data gets directly to the specific running application (like Chrome or Spotify) rather than just reaching the computer.
- Provides **end-to-end communication**.
- Two main protocols: **TCP** and **UDP**.
- Transport-layer packets are called **segments** (TCP) or **datagrams** (UDP).

##### TCP (Transmission Control Protocol)
- ✅ Connection-oriented (3-way handshake)
- ✅ Reliable (guaranteed delivery)
- ✅ Flow control (sliding window)

##### UDP (User Datagram Protocol)
- ✅ Connectionless
- ✅ Fast (low overhead)
- ✅ Simple

#### Layer 5: Application Layer
- The Application Layer contains the **network protocols that user applications directly interact with** to send and receive data across the network.
- Provides services directly to **end-users**.
- Uses **ports** to identify specific applications.

**Common Protocols:**

|Protocol|Port|Purpose|
|---|---|---|
|HTTP|80|Web browsing (unencrypted)|
|HTTPS|443|Web browsing (encrypted)|
|SMTP|25 / 587|Sending emails|
|POP3|110|Receiving emails (download)|
|IMAP|143|Receiving emails (sync)|
|FTP|21|File transfer|
|DNS|53|Domain name → IP address|
|DHCP|67 / 68|Automatic IP assignment|
|SSH|22|Secure remote login|
### ISO/OSI Reference Model
> OSI model was proposed by the International Organization for Standardization (ISO) . • Consists of seven layers, serves as a conceptual framework for designing computer networks. 

**Seven Layers:** 
• Application Layer
• Presentation Layer
• Session Layer
• Transport Layer 
• Network Layer
• Data Link Layer 
• Physical Layer

#### Layer 6 - Presentation Layer
**Primary Job:** Makes sure data is in a **readable format** for the Application Layer. It handles the **syntax and semantics** of the data.
**Key Functions (Point-wise):**

- ~={red}**Data Formatting / Translation=~:**
    - Converts data from one format to another (e.g., ASCII to EBCDIC, or Unicode).
    - Ensures big-endian and little-endian systems can understand each other.
- ~={red}**Encryption / Decryption=~:**
    - Scrambles data at the sender's side for security (e.g., SSL/TLS handshake).
    - Decrypts data at the receiver's side back to plaintext.
- **~={red}Compression / Decompression=~:**
    - Reduces file size (e.g., JPEG, GIF, MPEG) for faster transmission.
    - Decompresses at the receiving end to restore original quality.

#### Layer 5 - Session Layer
**Primary Job:** Establishes, manages, and tears down **communication sessions** (dialogues) between two applications.

**Key Functions (Point-wise):**

- ~={red}**Establishment=~:**
    - Creates a logical connection (session) between two devices.
    - Authenticates users and sets up permissions.
    
- **~={red}Management=~ (Dialog Control):**
    - Determines whether communication is **half-duplex** (one way at a time) or **full-duplex** (both ways simultaneously).
    - Keeps the session active and organized.
    
- **~={red}Termination=~:**
    - Properly closes the session when communication is complete to free up resources.
    
- **~={red}Synchronization=~ (Checkpoints):**
    - Adds **checkpoints** (like bookmarks) to large data transfers.
    - If a transfer fails midway, it resumes from the last checkpoint, not from the very beginning.
    
## Data Transfer Methods
### Packet Switching -- ( Store and Forward )
**Definition:** ~={green}Data is broken into small chunks=~ called **packets**. Each **~={yellow}packet is sent independently=~** and may take ~={yellow}**different routes**=~ to reach the destination, where they are reassembled.

#### Key Characteristics
1. **No Dedicated Path** -- Packets find their own way dynamically
2. **Connectionless** -- No setup required (except virtual circuits)
3. **Store-and-Forward** -- Routers store packets briefly and forward them
4. **Efficient** -- Resources used only when data is sent

### Circuit Switching
**Definition:** A **~={green}dedicated communication path=~ (circuit)** is established between sender and receiver before any data is sent. The ~={blue}**path remains reserved for the entire duration of the communication**=~.

#### Key Characteristics
1. **Dedicated Path** -- A physical/logical path is reserved end-to-end
2. **Connection-Oriented** -- Connection must be established first (call setup)
3. **Continuous Stream** -- Data is sent as a stream (no breaking into packets)
4. **Inefficient** -- Resources wasted when no data is sent

