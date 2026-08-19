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
#### BSS - (Basic Service Set)
- It is the fundamental budling block of 802.11 architecture
- BSS consist of many wireless stations (End Devices) connected to a main base station called Access Point (AP).
- In a typical home network, there is one AP and one router *(typically integrated together as one unit)* that connects the BSS to the internet.
- When a network admin installs a AP, the admin assigns one or two SSID (Service Set Identifier to the ap)

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

- There are three classes of multiple access protocols:
	- ~={red}**Channel Partitioning (including CDMA)**=~
		- Divides the channel by Time, Frequency, Codes (TDMA, FDMA, CDMA).
	- ~={red}**Random Access Protocols.**=~
		- A **Random Access Protocol** is a set of rules that ~={green}allows **multiple devices** to share the **same communication channel**=~ (medium) ~={yellow}**without any centralized control**.=~ 
		- **Every device competes for the channel and transmits** **whenever it has data**, without asking for permission first.
		- E.g. **Think of it like:** *A group of friends in a room. Anyone can start talking at any time. If two talk at the same time (collision), they stop, wait a random time, and try again.*
	- ~={red}**Taking Turns**=~
		- Devices take turns speaking (Controlled by a token or a master device) - (Token Ring, Polling).