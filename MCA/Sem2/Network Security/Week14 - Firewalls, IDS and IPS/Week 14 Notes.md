# 14.1 Firewall
## What is Firewall
- A **firewall** 🧱 is a **network security device** (either hardware, software, or both) **that** **~={yellow}monitors=~**, ~={yellow}**filters**=~, and **~={yellow}controls incoming and outgoing network traffic=~** ~={green}based on predetermined security rules=~.
- **~={orange}It establishes a barrier between=~** **~={cyan}a trusted internal network=~** and an **~={cyan}untrusted external network=~** (like the Internet).
## What can be protected
### Your Data - CIA Triad
- **Confidentiality** - ***Ensuring sensitive data, intellectual property, and private records** are accessible only to authorized individuals*
- **Integrity** - ***Preserving the accuracy, consistency, and trustworthiness of data** across its lifecycle by blocking unauthorized alterations, packet tampering.*
- **Availability** - ***Ensuring systems, networks, and services remain accessible and responsive** to **legitimate users when needed**, safeguarding against disruptions like DDoS attacks and packet storms.*
### Your Resources
- Ensures that your Internal endpoints are shielded and your Bandwidth and Processing Power are up to the point so legitimate users can use it.
### Your Reputation
- 🏛️ **Brand Trust & Legal Compliance:** Mitigating intrusions helps avoid data breaches that lead to regulatory penalties, financial loss, and damage to customer trust.
## Firewall Architecture
### Multi-Homed Host Architecture
- **~={orange}A single computer (bastion host) equipped with=~** **~={green}two or more Network Interface Cards (NICs) connected to different networks=~** (e.g., **~={cyan}one connected to the Internet (EXTERNAL)=~**, ~={blue}**the other to the internal LAN**=~).
	- **IP Routing/Forwarding is Disabled:**
		- When the packet reaches the Dual Homed Host, the packet is stopped there and it is inspected and then it is forwarded to the internal LAN.
	- **Proxy Mediation:**
		- Once the packet passes the inspection from **~={cyan}packet has to forwarded from external NIC=~** to the **~={cyan}internal NIC.=~** and for this the host will use proxy service or application filter so that a new connection is created where is packet is forwarded to the internal LAN.
### Screened Host. 
- **A combination of a ~={orange}screening router (packet filter)**=~ **~={green}and a ~={orange}single dedicated bastion host=~ located in the internal network=~** (e.g., **~={cyan}router connected to the Internet (EXTERNAL)=~**, **~={blue}bastion host residing inside the private LAN=~**).
	- **Screening Router Filtering:**
	    - When a packet arrives from the external network, the **~={cyan}screening router filters the traffic=~** and forces all permitted traffic to go **~={orange}only to the bastion host=~**, ~={red}strictly blocking direct access to other internal devices.=~
	- **Bastion Host Proxy & Inspection:**
	    - Once the packet passes through the screening router, it reaches the **~={orange}bastion host=~**, which uses **~={blue}proxy services or application filtering=~** to perform deep inspection before establishing a separate connection to relay the safe data to the destination host on the internal LAN.
### Screened Subnet (DMZ)
- **~={orange}An isolated perimeter network (Demilitarized Zone / DMZ) created by two screening routers=~** **~={green}housing public-facing bastion hosts between the external and internal networks=~** (e.g., **~={cyan}external router facing the Internet=~**, **~={blue}internal router protecting the private LAN=~**).
	- **External Screening Router Filtering:**
	    - Traffic arriving from the Internet hits the **~={cyan}external router, which allows access only to bastion hosts inside the DMZ=~** (such as Web, Mail, or DNS servers) and strictly drops any direct packets heading toward the private internal network.
	- **Internal Screening Router Filtering:**
	    - The **~={blue}internal router inspects and restricts all traffic moving between the DMZ and the private LAN=~**, ensuring that even if an external attacker compromises a server in the DMZ, they cannot directly reach or compromise the internal network.
# 14.2
## Types of Firewall
### Packet Filtering Gateways
- **~={orange}Packet Filtering firewalls=~** **use router with packet filtering rules** which then inspect the packet so that it can grant or deny access **~={yellow}based on source address, destination  address and port.=~**
- They offer minimum security **~={yellow}but at a very low cost=~** and can be an appropriate choice for a **low risk environment**.
- Filter rules are not often easily maintained but with the help of some tools it is possible to create a task and maintain the rules.
### Application Gateways
- An application gateways uses server programs known as **proxies** that run on firewall.
- These **proxies take external requests**, **~={green}examine them, and forward legitimate request to the internal host (user) that needs the appropriate service=~**.
- In application Gateways, **strong user authentication can be enforced.**
- **We can use different proxies for different services to prevent direct access of interwork network.**
- if the required proxy is not there, then the company will have to wait for the proxy vender to create or create a custom proxy.
### Hybrid or Complex Gateways
- A **Hybrid (or Complex) Gateway** 🛡️ combines multiple filtering technologies (usually **Packet Filtering** at Layers 3/4 and **Application Proxies** at Layer 7) to get the best balance of speed and deep security.
- **Security level depends on how they are arranged:**
	- **Series - Maximum Security**
		- Traffic must pass through **both** filters one after the other.
	- **Parallel Mode - Weakest Security**
		- Traffic can enter through **either** the packet filter path or the application proxy path side-by-side.

# 14.3 IDS, IPS, and roles
## Intrusion Detection and Prevention System - (IDPS)
- It is a unified security solution that ~={yellow}**combines the passive monitoring and alerting capabilities**=~ of an **IDS** **~={orange}with the active, real-time blocking mechanisms of an IPS.=~**
- in IDPS we look for 2 things in the network traffic:
	- **Malicious Threats.**
	- **Security Policy Violations.**
- We also log information about them and report them to security administrators.
	- IDS - process of monitoring the events occurring in a computer system or network.
	- IPS - process of performing those intrusion detection and attempting to stop the detect events.

## Functions of IDPS.
- Recording or logging information related to detected events.
- Notify security Admin about them.
- Produce Reports

## Common Detection Techniques.
### Signature-based Detection (Knowledge Based)
- Matches **~={orange}network traffic or system activity=~** **~={green}against a database of known threat patterns, attack strings, or malicious code fingerprints=~** (signatures).
- **Advantage** - It is **~={blue}fast, low CPU usage, produces very low false positives.=~**
- **Disadvantage** - If in **~={blue}case of a new attack=~** (zero day) then its of no use.
### Anomaly - Based Detection (Behavior)'
- In this the system first creates a **BASELINE** **~={orange}by studying the Behavior in the network and the system over a period of time.=~**
- **~={green}If there is a event which has a significant spike from this BASELINE=~**, then it marks it as a intrusion.
- **Advantage** - it is **~={orange}capable of detecting brand new, unknown Zero Day vulnerability.=~**
- **Disadvantage** - **~={green}Prone to high False Positives.=~**
### Stateful Protocol Analysis (SPA)
- In this the ~={yellow}**system compares observed traffic with the vendor - RFC-defined standard**=~ on how the network protocol should behave while looking into there request and response.
- **Advantage** - it knows the protocol context. like if the http header is abnormally huge then it violates the RFC standard.
- **Disadvantage** - **high cpu usage, memory overload.**