

# 3.1 TCP and UDP
## UDP: User Datagram Protocol
- **UDP (User Datagram Protocol)** is a **connectionless**, **unreliable** transport layer protocol ~={green}used for fast data transmission.=~
	-  **Connectionless** -- No handshake or connection establishment before sending data.
	-  **Unreliable** -- No guarantee of delivery, order, or error recovery.
	-  **No Congestion control** -- Sends data at whatever rate the application chooses. 
- And due to this, **UDP can send packet very fast.**
## UDP: Use case
- Streaming multimedia apps
- DNS
- SNMP
- HTTP/3
## TCP: Overview
- **TCP (Transmission Control Protocol)** is a **connection-oriented**, **reliable** transport layer protocol ~={green}that ensures **ordered**, **error-checked** delivery of data between applications.=~
	- **Connection-Oriented** -- Establishes a **3-way handshake** before data transfer.
	- **Reliable** -- Guarantees delivery using **ACKs** (packets) and **retransmissions**.
	- **Congestion Control** -- Adjusts sending rate based on network conditions
- TCP supports Full Duplex :
	- Bi-Directional data flow in same connection.
## TCP: Header Format
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------+-------------------------------+
|          Source Port          |       Destination Port        |
+-------------------------------+-------------------------------+
|                        Sequence Number                        |
+-------------------------------+-------------------------------+
|                    Acknowledgment Number                      |
+-------------------------------+-------------------------------+
|  Data |       |C|E|U|A|P|R|S|F|                               |
| Offset| Rsvd |W|C|R|C|S|S|Y|I|            Window             |
|       |       |R|E|G|K|H|T|N|N|                               |
+-------------------------------+-------------------------------+
|           Checksum            |         Urgent Pointer        |
+-------------------------------+-------------------------------+
|                    Options (if any)                           |
+-------------------------------+-------------------------------+
|                         Data (payload)                        |
+-------------------------------+-------------------------------+
```

**Key fields:**

- **Source/Destination Port** – identifies applications.
- **Sequence Number** – orders bytes.
- **Acknowledgment Number** – confirms received bytes.
- **Flags** – SYN, ACK, FIN, RST, PSH, URG.
- **Window** – flow control (receiver’s buffer size).
- **Checksum** – error detection.
- **Urgent Pointer** – for urgent data.
## Principles of reliable data transfer
- Reliable data transfer is the process of ensuring that data sent from one end (sender) is **delivered correctly**, **in order**, and **without duplication** to the receiver, ~={green}even when the underlying network is **unreliable**=~ (e.g., packets can be lost, corrupted, or reordered).

# 3.2 Flow control in TCP
## Flow control in TCP
- **Flow control** is a technique used in TCP to ~={yellow}**match the sender’s transmission rate**=~ to the ~={yellow}**receiver’s ability to consume data**.=~  
- It prevents the **~={green}receiver’s buffer from overflowing=~**, which ~={cyan}would cause packet loss and retransmissions.=~

> **Key idea:** The receiver tells the sender how much data it can accept.



