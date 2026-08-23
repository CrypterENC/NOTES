# 16.1
## Physical LAN Attacks
### Disruption
- Any break of physical network connectivity preventing from the network functioning.
- Common Physical Disruption include, **"power outage"**, **disconnected network cables**
- For Preventing this, **use Backup power** and **restricted access to core networking devices.**
### Interference
- Generally *physical network needs a physical connectivity* **~={yellow}the medium used to convey network traffic can also transport other signals=~**. 
- if **unauthorized signal** called Interference *enters the medium then network devices may be unable to **compare the data from noise data***.
- For Preventing this, we **specific various rules** *on the data received from that medium* and **Data encoding** technique can also be used to avoid the impact of interference.
## Wireless Attacks
- **Packet Sniffing:**
	- **Capturing wireless traffic** directly out of the air. *By **putting a wireless network card into "monitor mode,"** ~={yellow}an attacker can intercept=~ ~={purple}all frames flying around them, **even if they aren't connected to the network.*** =~
	- If the network **uses weak encryption** (like old WEP) **or no encryption,** the attacker can easily read passwords and session cookies.
- **War Driving:**
	- ~={green}**The act of physically moving around a neighborhood or city**=~ (often in a car) *with a laptop, GPS, and network adapter to map out* **~={orange}open or vulnerable Wi-Fi networks.=~** 
	- This is primarily a reconnaissance technique to build a database of targets for future attacks.
- **Impersonation.**
	- **MITM**
		- In wireless networking, this is most commonly known as  **Evil Twin** attack. ~={yellow}The attacker sets up a **Rogue Access Point (AP)** with **the exact same name (SSID)**=~ as a legitimate network (like "Airport_Free_WiFi"). ~={green}**When users connect to the fake AP**,=~ **~={cyan}the attacker sits in the middle, intercepting, reading, or altering all their internet traffic.=~**
	- **Tunneling**:
		- A **technique used to bypass network restrictions, firewalls, or captive portals**.
		- The attacker takes their regular web traffic and encapsulate it inside a protocol that the network _does_ allow out, **such as DNS queries or ICMP (ping)** *packets, allowing them to smuggle data out or get free internet access.*
## Internet Protocol Attacks
- ~={red}**ARP Cache Poisoning Attack:**=~
	- Attacker ~={yellow}**sends forged ARP reply to associate their MAC address to router's the IP**=~ (e.g., default gateway).
	- **By doing this attacker** ~={green}can see all traffic=~ then ~={green}attacker can drop packets which will result in DoS=~.
	- **Prevention** - **Dynamic ARP Inspection** DAI, Static ARP entries, **Encryption (HTTPS/VPN)**
- ~={red}**IP Hijacking :**=~
	- **IP Hijacking** occurs when an **~={yellow}attacker takes control of an IP address that does not belong to them=~**, ~={green}causing internet traffic meant for the legitimate owner=~ ~={cyan}to be sent to the attacker's machine instead.=~
- ~={red}**Replay Attacks**=~
	- Attacker ~={yellow}**captures valid data packets** =~(like login credentials or commands) and **retransmits** them later to fool the system.
	- **By doing this attacker** can **gain unauthorized access** then **attacker can perform a Duplicate transactions.**
	- **Prevention** - Use **timestamps**, Use **session IDs** that expire quickly.**
- ~={red}**Packet Storms**=~
- ~={red}**Fragmentation Attacks**=~

## TCP Hijacking
## SYN Attacks