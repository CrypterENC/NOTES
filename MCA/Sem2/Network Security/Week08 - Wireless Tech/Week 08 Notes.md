# 8.1 Introduction to Wi-Fi
## Elements of Wireless Network
## IEEE 802.11 Standards

| Standard | Frequency Range | Data Rate |
| -------- | --------------- | --------- |
| 802.11b  | 2.4             | 11 Mbps   |
| 802.11a  | 5               | 54 Mbps   |
| 802.11g  | 2.4             | 54 Mbps   |
| 802.11n  | 2.5 and 5       | 540 Mbps  |
| 802.11ac | 5               | 1300 Mbps |

## 802.11 Architecture
### What is 802.11 architecture ?
- it defines how wireless devices connect and communicate.
- The core building blocks are :
	- End Devices (phone, laptop, pc)
	- AP (Access Point)
	- BSS (Basic Service Set)
	- ESS 
	- DS (Distributed System)
#### BSS - (Basic Service Set)
> **The BSS (Basic Service Set) is a group of wireless stations that share the same MAC protocol and compete for access to the same wireless medium, typically managed by a single AP.**

- It is the fundamental budling block of 802.11 architecture
- BSS consist of many wireless stations (End Devices) connected to a main base station called Access Point (AP).
- In a typical home network, there is one AP and one router *(typically integrated together as one unit)* that connects the BSS to the internet.
- When a network admin installs a AP, the admin assigns one or two SSID (Service Set Identifier to the ap)

#### ESS - (Extended Service Set)
> ESS is a group of BSS's connected by a wired backbone (DS - Distributed System) to create a single, seamless network with the same SSID.

> Crazy Stuff: **ESS means we got mutliple BSS's (lets say 2) so we got 2 AP's** now normally we will have **2 SSID's for 2 AP**, *in ESS the admin will have to configure both AP's with the same SSID and same password and it becomes 1 SSID.*

##### What is Beacon Frame 
- Then 802.11 standard ~={green}requires that an AP periodically send beacon Frames which includes the AP's **SSID and MAC address.**=~

> e.g. statement  "*The AP sends Beacon Frames constantly so that when I open my Wi-Fi settings on my phone or laptop, the SSID (network name) shows up in the list, allowing me to click on it and connect.*"

#### What is Ad Hoc - Independent BSS(IBSS) 
- **Ad-Hoc mode** (officially called **IBSS - Independent Basic Service Set**) ~={cyan}allows wireless devices to communicate **directly with each other**=~ ~={green}without using an Access Point (AP)=~ or a router.
## 802.11 Frame
- it contains the actual data being transmitted along with control information (source, destination, error checking, payload).

### Structure of 802.11 Frame
```text
+---------------------------------------------------------------+
|                 MAC HEADER (30-34 bytes)                       |
+---------------------------------------------------------------+
|                 FRAME BODY (Payload - 0 to 2312 bytes)        |
+---------------------------------------------------------------+
|                 FCS (Frame Check Sequence - 4 bytes)          |
+---------------------------------------------------------------+
```
#### MAC Header 

| Field                | Size (bytes) | Purpose                                                                         |
| -------------------- | ------------ | ------------------------------------------------------------------------------- |
| **Frame Control**    | 2            | Identifies the of Frame (Management, Control, Data) depending upon the context. |
| **Duration**         | 2            |                                                                                 |
| **Address 1**        | 6            | **Receiver Address (RA)** — Who should receive this frame                       |
| **Address 2**        | 6            | **Transmitter Address (TA)** — Who is sending this frame                        |
| **Address 3**        | 6            | **Destination Address (DA)** or BSSID (depending on context)                    |
| **Sequence Control** | 2            |                                                                                 |
| **Address 4**        | 6            | Used only in **WDS (Wireless Distribution System)** or Ad-Hoc mode              |

#### The 4 Address Combinations (Exam Gold!)

| To DS | From DS | Meaning                                     | Address 1         | Address 2       | Address 3            | Address 4  |
| ----- | ------- | ------------------------------------------- | ----------------- | --------------- | -------------------- | ---------- |
| **0** | **0**   | **Ad-Hoc** (Direct client-to-client, no AP) | Destination       | Source          | BSSID                | Not used   |
| **1** | **0**   | **Client → AP** (Client sending to AP)      | AP (Receiver)     | Client (Sender) | Destination (Router) | Not used   |
| **0** | **1**   | **AP → Client** (AP sending to Client)      | Client (Receiver) | AP (Sender)     | Source (Router)      | Not used   |
| **1** | **1**   | **WDS** (AP-to-AP wireless bridging)        | Receiver AP       | Sender AP       | Destination MAC      | Source MAC |

#### Frame Body
- Contains the **actual Data that is being Transmitted**.
#### Frame Check Sequence (FCS)
- it does Error Detection.
- How it works:
	- The receiver calculates its own CRC and compares it to the FCS.
```text
+----------------------------------------------------------------------------------+
|                              802.11 MAC Frame                                    |
+----------------------------------------------------------------------------------+
| Frame Control | Duration/ID | Address 1 | Address 2 | Address 3 | Seq Ctrl | Addr 4 |
|    (2 bytes)  |   (2 bytes) |  (6 bytes) | (6 bytes) | (6 bytes) | (2 bytes)|(6 bytes)|
+----------------------------------------------------------------------------------+
|                              Frame Body (0 - 2312 bytes)                         |
+----------------------------------------------------------------------------------+
|                                   FCS (4 bytes)                                   |
+----------------------------------------------------------------------------------+
```
### What is the difference in 802.11 Frame and Ethernet Frame

| Feature                | Ethernet Frame (Wired)            | 802.11 Frame (Wireless)<br>              |
| ---------------------- | --------------------------------- | ---------------------------------------- |
| **Medium**             | Wired (Copper/Fiber)              | Wireless (Radio Waves)                   |
| **Collision Handling** | **CSMA/CD** (Collision Detection) | **CSMA/CA** (Collision Avoidance)        |
| **Address Fields**     | 2 addresses (Source + Dest MAC)   | **4 addresses** (Due to roaming and APs) |
| **Reliability**        | High (wired)                      | Lower (interference, signal loss         |

## 802.11 MAC Protocol
- The **802.11 MAC (Medium Access Control) Protocol** defines ~={green}**how wireless devices share the same radio frequency**=~ to ~={yellow}**transmit data without constantly colliding with each other**=~.

> **Think of it like:** A **group conversation** where everyone raises their hand before speaking, and if two people speak at the same time, they both stop, wait a random amount of time, and try again.

#### Big Picture
```text
MULTIPLE ACCESS PROTOCOLS (The Big Family)
│
├── 1. Channel Partitioning (CDMA, FDMA, TDMA)
│
├── 2. Random Access (The Class)
│   │
│   ├── ALOHA
│   ├── CSMA
│   ├── CSMA/CD  → Used in Wired Ethernet (802.3)
│   │
│   └── CSMA/CA  → Used in Wireless Wi-Fi (802.11)  <--- YOUR ANSWER
│
└── 3. Taking Turns (Token Passing, Polling)
```
#### What is Code Division Multiple Access (CDMA)
- It is a technique where multiple devices transmit simultaneously on the same frequency.
	- And each devices uses its own **unique code** to encode its signal. **~={yellow}The receiver knows the code and uses it to extract the specific device's data from the noise.=~**

- **There are three classes of multiple access protocols:**

	- ~={red}**Channel Partitioning (including CDMA)**=~
		- Divides the channel by Time, Frequency, Codes (TDMA, FDMA, CDMA).
	- ~={red}**Random Access Protocols.**=~
		- A **Random Access Protocol** is a set of rules that ~={green}allows **multiple devices** to share the **same communication channel**=~ (medium) ~={yellow}**without any centralized control**.=~ 
		- **Every device competes for the channel and transmits** **whenever it has data**, without asking for permission first.
		- E.g. **Think of it like:** *A group of friends in a room. Anyone can start talking at any time. If two talk at the same time (collision), they stop, wait a random time, and try again.*
	- ~={red}**Taking Turns**=~
		- Devices take turns speaking (Controlled by a token or a master device) - (Token Ring, Polling).

#### What is CSMA/CD (Carrier Sense Multiple Access with Collision Detection)
- A protocol where ~={yellow}devices **listen** to the medium before transmitting=~ (Carrier Sense). 
- If ~={green}**two devices transmit simultaneously** and **a collision occurs**=~, ~={cyan}they **detect the collision**, stop immediately=~, **~={blue}send a jamming signal**,=~ wait a random time (Backoff), and retry.

> **Think of it like:** A group of people **in the same room** talking. If two people start talking at the exact same time, they both hear each other, stop, wait a random moment, and then one starts talking again.

#### What is CDMA/CA (Carrier Sense Multiple Access with Collision Avoidance)
- A protocol where ~={yellow}devices **listen** to the medium before transmitting.=~ 
- If **~={yellow}the medium is free=~**, ~={green}they send a **request (RTS)** to the receiver=~. The ~={cyan}receiver replies with a **clear signal (CTS)**.=~ **~={purple}All other devices hear the CTS and hold off transmitting=~**. ~={blue}This **avoids** collisions before they happen.=~

> **Think of it like:** A **moderated meeting** on Zoom where you click the "Raise Hand" button (RTS). The host (AP) says "Go ahead" (CTS). Everyone else sees that someone is speaking and stays muted.

## Problem with 802.11
### Its "~={red}HIDDEN TERMINAL PROBLEM=~"
- The **Hidden Terminal Problem** occurs ~={blue}when **two devices** (A and C)=~ ~={yellow}are both within range of the **Access Point (B)**=~, ~={cyan}but **cannot detect each other's signals**=~ [A and C]  because they are out of range of each other.
```text
        [Device A]              [Device B]              [Device C]
             |                    (AP)                     |
             |    <--- Can Hear ---> | <--- Can Hear --->  |
             |-----------------------|---------------------|
             |      X (Can't Hear)   |   X (Can't Hear)    |
             |<----------------------|--------------------->|
             |                       |                     |
             |------- Data --------->|                     |
             |                       |<------ Data --------|
             |                       |                     |
             |                  **COLLISION!**             |
```
- **Explanation:**

	- **A** can hear **B** (AP).
	- **C** can hear **B** (AP).
	- **A** and **C** cannot hear each other.
	- **A** starts sending data to B.
	- **C** doesn't hear A's transmission, so it also starts sending to B.
	- **B** receives both signals simultaneously → **Collision** → Both packets are lost.

- ~={red}Solution to this is "**CSMA/CA with RTS and CTS**"=~
	- Wi-Fi (802.11) solves this using a **four-way handshake** before sending the actual data.

| Step  | Device                       | Action                                                                                                |
| ----- | ---------------------------- | ----------------------------------------------------------------------------------------------------- |
| **1** | **A (Sender)**               | Sends an **RTS (Request to Send)** frame to the **AP**.                                               |
| **2** | **B (AP)**                   | Sends a **CTS (Clear to Send)** frame back to A.                                                      |
| **3** | **All devices (C included)** | Hear the CTS frame and **pause** their transmissions (set their **NAV - Network Allocation Vector**). |
| **4** | **A**                        | Safely sends the actual **Data** frame.                                                               |
| **5** | **B (AP)**                   | Sends an **ACK** to confirm successful delivery.                                                      |
# 8.4 Bluetooth
## Bluetooth Technology
- Bluetooth uses **Short Range RF waves** connecting personal devices.
- It operates in the **2.4Ghz ISM band**.
- Uses **~={green}Frequency-Hopping spread spectrum=~** - **FHSS**
	- ~={yellow}**FHSS means the**=~ *signal jumps between different radio frequencies very quickly while transmitting*.
- **Packet‑based protocol**
	- Data is split into small **packets**, each sent in a dedicated **time slot**.
## Working of  Bluetooth (IEEE 802.15.1)
- It uses **Ad Hoc network**
	- That is AP's are not used, devices connect directly with each other.
	- In Bluetooth *for it to work, we have one Master Devices and up to 7 Active Slaves.*
	- Now this is called **Piconet**.
	```text
		           [Slave 1]
	                  │
	[Slave 3] ───── [Master] ───── [Slave 2]
	                  │
	               [Slave 4]
	```

- **Master:** 
	- **~={green}Initiates connection, 
	- **Controls hopping pattern,** 
	- **Manages time slots.=~**
	- ~={green}**it also manages the slaves states like:**=~
```text
[Active]   →  Full communication
[Sniff]    →  Listens at set intervals (reduced power)
[Hold]     →  Temporary idle (no data exchange)
[Park]     →  Maintains connection, but inactive (lowest power)
```

- **Slave:** ~={cyan}**Responds to master, follows its timing.**=~
	- For **SLAVES** of follow the timing they use **Time Division Duplex (TDD)**.

- ~={yellow}**Piconet's can co-exist**=~
```text
   `[Your Piconet]             [Friend's Piconet]
	    [Slave A]                [Slave X]
	       │                         │
	[Slave B] ─ [You Master]   [Slave Y] ─ [Friend Master]
	       │                         │
	    [Slave C]                [Slave Z]`

(Both in same room, different hopping patterns → no collision)
```

- **Scatternet:** **one device belonging to two or more piconets simultaneously.**
```text

	[Master - 1]                   [Master - 2]
	                               
	[Slave A] ─── [Slave B]     [Slave A] ─── [Slave Y]
	            (Slave in both piconets)
	                        
	              ↑ This Laptop connects both piconets → Scatternet
```
## Bluetooth Protocol Stack
```
+----------------------------------+
|          Applications            |  (User apps: file transfer, audio, etc.)
+----------------------------------+
|  RFCOMM / SDP / ATT / GATT       |  (Service discovery, serial emulation, BLE profiles)
+----------------------------------+
|          L2CAP                    |  (Multiplexing, segmentation/reassembly)
+----------------------------------+
|        Link Manager (LMP)        |  (Link setup, authentication, encryption, power control)
+----------------------------------+
|          Baseband                 |  (Physical connection, timing, FHSS, packet handling)
+----------------------------------+
|            Radio                  |  (2.4 GHz, FHSS, Tx/Rx)
+----------------------------------+
```

# 8.5 Zigbee
## Zigbee Technology
- **What is it:** ~={green}**Low-power, low-data-rate wireless communication protocol**=~ for IoT, home automations .
- It is standardized as IEEE ~={cyan}**802.15.4**=~

- ~={cyan}**Devices:**=~
	- **Coordinator** -- One per network – starts and manages the network
	- **Router**          -- Passes data, extends range
	- **End Device**   -- Sends data and sleeps 
## Working of Zigbee
### Hardware Capabilities
- **FFD (Full Function Device):** Always powered, full processing memory. Can take any role (Coordinator, Router, or End Device).
- **RFD (Reduced Function Device):** Battery-powered, limited memory. Designed to sleep. Can _only_ act as an End Device.
### Network setup:
- **One Coordinator** **~={orange}starts the network.=~**
- **Routers** **~={yellow}join and extend the network.=~**
- **End Devices** **~={yellow}join via Coordinator or Router.=~**
### Communication Flow
- **End Device** --> **router** --> **Coordinator** (Data goes up).
- **Coordinator → Router → End Device** (commands come down).
- If one path fails, data finds **another route** (mesh).
### How Devices Send Data
- Device **listens** to the channel. (CSMA-CA).
- If channel is free → sends.
- If busy → waits random time and tries again.
#### Time Management and Synchronization
- **Note:** *before every super frame a beacon frame is sent *
- **Super Frame** is used for this.
	- **What is it**: A specific, repeating interval created by the coordinator to **organize when devices can communicate and when they sleep**.
	- **What does it contain:** Super frame contains **~={green}Active Period (CAP and CFP) and Inactive Period.=~**
		- ~={red}**Active Period** =~is further divided to 2 types:
			- **CAP (Contention Access Period):** Every **~={cyan}End Devices data to Coordinator=~**  and **~={yellow}if there are multiple end devices then they will compete for sending data using CSMA-CA=~** .
			- **CFP (Contention Free Period):** And **~={yellow}if there are any specific data that needed to be sent=~** to the ~={cyan}Coordinator then it allocates **GTS** (reversed path) for it.=~ The Coordinator can ~={orange}allocate up to **7 Guaranteed Time Slots (GTS)**=~ at the end of the Active Period. 
		- ~={red}**Inactive period:**=~
			- During this period the **~={green}radio on the end device is physically turned off,=~** and during this **~={yellow}time the coordinator cannot send alerts to wake it up.=~**
			- So the End Device ~={green}relies on a tiny, ultra-low-power **internal timer**=~ (just like an alarm clock on your phone).
			- Before going to sleep it **~={cyan}calculates exactly how long the Inactive Period will last=~**. When the **timer goes up** the **~={yellow}device powers its radio wakes up for the new super frame.=~**

# 8.6 
## Security in Zigbee Technology
-~={red} **Data Freshness**=~ by freshness Counter
	- So to keep the Data Fresh, **the device keeps a strict sequence number (a frame counter)**, ~={green}So every time a devices **sends a message** or **receives a message** the counter goes up=~. And the Devices remember this number.
- ~={red}**Message Integrity**=~
	- Zigbee uses **~={yellow}AES to generate a Message Integrity Code (MIC)=~**, ~={green}which is appended to the packet.=~ *If an attacker intercepts the packet and flips even a single bit, the receiving device's MIC calculation will fail, and the packet is immediately dropped.*
- ~={red}**Network Level Authentication**=~
	- Uses a shared **Network Key**.
	- Every Device in **network has this key.**
- ~={red}**Device Level Authentication**=~
	- Uses a unique **Link Key**.
	- This is a **private key** ~={yellow}shared only between two specific devices=~ (e.g., the Coordinator and a highly sensitive End Device
- ~={red}**Encryption by 128 bit AES encryption**=~
	- Zigbee uses this core symmetric encryption Standard.
	- It scrambles the **data payload** ~={yellow}so an eavesdropper cannot read it=~.
## Session keys in Zigbee Network
### 128 bit Link Key
- Secures all unicast communication between peers
- Generated using Master Key
	- **It is never used to ~={green}encrypt everyday data=~ like temperature readings. 
	- Its only job is to act as a secure foundation to **generate the Link and Network keys**.**
### 128 bit Network Key
- Secures Broadcast communications
- Generates new network-wide key each time a node joins a network. 
- The Coordinator **usually doesn't generate a brand new Network Key every single time a node joins**, **~={cyan}~={orange}because updating a large network of sleeping devices simultaneously would cause a massive traffic jam.=~=~**
- Instead, **the Coordinator~={green} securely shares the existing Network Key with the new device=~.
- Generated using Master key.