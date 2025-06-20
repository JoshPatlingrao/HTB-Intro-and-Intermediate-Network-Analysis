# HTB-Intro-and-Intermediate-Network-Analysis

## Summary
This page is a dedicated repository for my personalised notes for the module and a walkthrough for the problems.

### Tools Used
<div>
  <img src="https://img.shields.io/badge/Wireshark-4A9C2C?style=for-the-badge&logo=wireshark&logoColor=white" alt="Wireshark Badge" />
  <img src="https://img.shields.io/badge/tcpdump-4A9C2C?style=for-the-badge&logo=gnu&logoColor=white" alt="TCPDump Badge" />
  <img src="https://img.shields.io/badge/Linux-E95420?style=for-the-badge&logo=linux&logoColor=white" alt="Linux Badge" />
</div>

## 1.0 Introduction to Network Traffic Analysis

## 2.0 Intermediate Network Traffic Analysis
#### Vocab
- Indicator of Compromise (IoC)
#### Notes
- The attacks will focus on the link layer, IP layer, the transport, the network and application layers
- Take note of patterns and trends within these attacks
- Module covers anomaly detection techniques, log analysis, and investigation of IOCs
  - Student must learn how to identify, report, and respond to threats more effectively and within a shorter time frame

### 2.1 ARP Spoofing and Abnormality Detection
#### Vocab
- Address Resolution Protocol (ARP)

#### Notes
- ARP has a history of being exploited by attackers to launch man-in-the-middle, DOS attacks, various other attacks
  - Which is why this is the first protocol you should always check.
  - Many ARP attacks are on broadcast, makes it easily detectable for packet sniffers like TCPDump or WireShark
 
How ARP Works?
1. PC-A wants to send data to PC-B. It needs to know its MAC address.
2. PC-A will check its internal cache to see if it already knows PC-B's address.
3. If it's now in ARP cache, then PC-A broadcasts ARP REQ to all machines in the subnet.
4. Once it reaches PC-B, it replies with its IP address that's mapped to it's MAC address.
5. PC-A will update its ARP cache.
6. PC-A will beging communication to PC-B.
7. If the network topology is changed or the IP address has expired, then PC-A will need to update its cache again.

ARP Poisoning
- Three main components: the victim's computer, the router, and the attacker's computer.
- Attacker dispatches counterfeit ARP message, both to router and victim.
- Victim will receive an ARP saying that the gateway (router) IP address maps to the attackers MAC address.
- Router will receive an ARP saying that the victim's IP address maps to the attackers MAC address.
- If succesful, both ARP cache of victim and router are corrupted. All traffic is redirected to attacker's computer.
  - If attacker also configures traffic forwarding, then attack escalates from a DoS to man-in-the-middle attack

Defense
- Static IP Entries: prevents easy rewrites and poisoning of ARP cache.
  - Increases maintenance and management for the network
- Switch & Router Port Security: implement network profile controls and other measures to ensure that only authorized devices can connect to specific ports on our network devices, effectively blocking foreign machines from ARP poisoning.
  - Could be bypassed if attacker modifies their IP and MAC address to match an authorized device.
 
Detecting
- Focus on traffic anomalies coming from a specific host
  - Constantly broadcasting ARP requests and replies to another host
- Finetune the analysis. Focus on the REQs and REPs between the attacker's machine, the victim's machine, and the router
  - arp.opcode == 1: For ARP Requests
  - arp.opcode == 2: For ARP Replies
- WireShark might raise - (duplicate use of <IP Address> detected!)
  - Focus on this IP address. It will definitely be mapped to two different MAC addresses.
  - Use 'arp.duplicate-address-detected' to filter for more duplicate IP warnings.

Identify
- Identify the original and legitimate IP to MAC address mapping
  - Find attacker device, that altered its IP address through MAC spoofing
  - It will have a different historical IP address.

#### Walkthrough
Q1. Inspect the ARP_Poison.pcapng file, part of this module's resources, and submit the total count of ARP requests (opcode 1) that originated from the address 08:00:27:53:0c:ba as your answer.
- Open Wireshark, and open the respective capture file
- Filter for:
  - arp.opcode == 1 && eth.src == 08:00:27:53:0c:ba
    - arp.opcode == 1
      - Will filter only for ARP REQ
    - eth.src == 08:00:27:53:0c:ba
      - So all ARP traffic with MAC address source is this one
- Bottom left should show:
  - Packets: 994 : Displayed: 507
- Answer is: 507

### 2.2 ARP Scanning and Denial of Service
#### Vocab
- Man in the Middle (MITM)

#### Notes
- Poisoning and spoofing is the core of most ARP-based DoS and MITM attacks.
- Attackers can still use ARP-based attacks for recon.

ARP Scanning Signs
- Red Flags
  - Broadcast ARP requests sent to sequential IP addresses
    - 192.168.10.1 -> 192.168.10.2 -> 192.168.10.3 -> 192.168.10.4 -> ...
    - A common feature of scanners such as Nmap 
  - Broadcast ARP requests sent to non-existent hosts
    - ARP packets to IP addresses not mapped to any device
  - An unusual volume of ARP traffic originating from a malicious or compromised host
    - Could come from multiple devices
- If multiple active hosts replied, then the attacker's recon was succesful

ARP Scanning for DoS
- Attacker compiles all activbe hosts, and runs a DoS campaign to all these machines
- Will try to contaminate an entire subnet and poison any ARP caches they could.
  - Essentially ARP poisoning but for every device in a network
    - May see multiple duplicate IPs mapped to multiple devices

Defense
- Trace & Identify: find the attacker's machine or compromised host and shut it down.
- Containment: disconnect compromised devices or subnets at a switch or router level
- ARP scanning is often unnoticed, but if deterred then potential data exfiltration could be stopped.

#### Walkthrough
Q1. Inspect the ARP_Poison.pcapng file, part of this module's resources, and submit the first MAC address that was linked with the IP 192.168.10.1 as your answer.
- Open Wireshark, and open the respective capture file
- Filter for:
  - arp.opcode == 2
    - Will filter for ARP REP, since the attacker is scanning with an IP of 192.168.10.5, so there is likely a device with that IP address in the network that will respond.
- Scan the No. 13 packet
- Answer is: 2c:30:33:e2:d5:c3

### 2.3 802.11 (WiFi) Denial of Service
#### Vocab
- Wireless Intrusion Detection System (WIDS)
- Wireless Intrusion Prevention System (WIPS)
- Wifi Protected Access (WPA)

#### Notes
- WiFi is another potential attack vector

Capturing WiFi Traffic
- To capture raw traffic, need WIDS/WIPS or a wireless interface equipped with monitor mode
  - Similar to WireShark's promiscuous mode, it allows viewing of raw WiFiframes and other 'invisible' traffic
 
Deauth Attacks
- A commonplace link-layer precursor attack
- Why?
  - Capture the WPA handshake to perform an offline dictionary attack
  - To cause general DoS conditions
    - Similar effects to DoS where services can't be used due to constant deauthentication
  - Enforce users to disconnect from the network, and potentially join their network to retrieve information
- How?
  - Attacker fabricates an 802.11 deauthentication frame, 'originating' it from a legitimate AP
  - Some devices might disconnect, then attacker can do some sniffing while the devices redo the reauthentication and handshake process
  - This attack works by spoofing/altering the MAC of the frame's sender.
    - Victim's device can't tell the difference without additional controls like IEEE 802.11w (Management Frame Protection)
  - Each deauth request has a reason code explaining the disconnection
    -  Basic tools like aireplay-ng and mdk4 employ reason code 7

Finding Deauth Attacks
- In WireShark, to view traffic from our AP's BSSID (MAC), use 'wlan.bssid == xx:xx:xx:xx:xx:xx'
  - Enter the MAC of the AP
- Additional Filters
  - wlan.fc.type == 00
    - Management type frame
  - wlan.fc.type_subtype == 12
    - Subtype of management frame, for deauth
  - wlan.fixed.reason_code == 7
    - Reason code used by common tools such as aireplay-ng and mdk4
    - Attacker could circumvent this by rotating the reason code, through incrementing or randomization
- Multiple deauth frames is a sign of attack

Defense
- Enable IEEE 802.11w (Management Frame Protection) if possible
- Utilize WPA3-SAE
- Modify our WIDS/WIPS detection rules
- Take note of excessive association requests coming from one (attacker) device
  - Filter:
    -  wlan.fc.type_subtype == 0
    -  wlan.fc.type_subtype == 1
    -  wlan.fc.type_subtype == 11

#### Walkthrough
Q1. Inspect the deauthandbadauth.cap file, part of this module's resources, and submit the total count of deauthentication frames as your answer.
- Open Wireshark, and open the respective capture file
- Filter for:
  - wlan.bssid == f8:14:fe:4d:e6:f1 && wlan.fc.type == 00 && wlan.fc.type_subtype == 12
    - wlan.bssid == f8:14:fe:4d:e6:f1
      - Is the MAC address of the Access Point’s BSSID. Narrow the focus here as it’s a Wi-Fi DoS
    - wlan.fc.type == 00
      - A type of management frame that’s sent out by the legitimate AP or attacker related to deauthentication
      - 00: code is for management type frame
    - wlan.fc.type_subtype == 12
      - The subtype of frame, code is for deauthentication
- Bottom left should show:
  - Packets: 18893 : Displayed: 14592
- Answer is: 14592

### 2.4 Rogue Access Point & Evil-Twin Attacks
#### Vocab
- Robust Security Network (RSN)

#### Notes
- Very difficult to detect

Rogue AP
- Rogue APs primarily used to bypass perimeter controls (network controls and segmentation barriers)
  - Directly connected to the network
- Can infiltrate air-gapped networks.

Evil Twin
- Not connected to the network, most of the time.
  - Are standalone APs, that might have a web server or something else to act as a MITM for wireless clients.
     - Setup to harvest wireless or domain passwords among other pieces of information.
     - Might also encompass a hostile portal attack

Detection
- Use tools like Airodump-ng
- Attacker likely spoofed a legitimate router MAC address in the network
  - Could host a hostile portal attack to extract credentials
  - Could also do a deauth attack to force devices to connect to evil-twin
- Filter:
  - wlan.fc.type_subtype == 8
    - Filter for beacon frames
    - Allows us to tell legit and non-legit APs apart
    - Look in the RSN field of a frame, contains info about supported ciphers
      - This field will be missing in frames coming from attacker's APs
    - Can still check other fields just in case
      - Attacker could match the ciphers being offered by legit APs, giving the frames from attacker's AP an RSN field matching the legit frames
      - In this case, look for more specific info such as vendor based info

Finding Fallen Users
- In case of open network style evil-twin attacks, most higher-level traffic in an unencrypted format are viewable.
- Filter for the evil-twin using the spoofed MAC
  - Since it's 'new' to the network then there should be traces of ARP requests
    - Take note of MAC address and host name

Finding Rogue APs
- Check network device lists
- In case of hotspot-based rogue AP, focus on wireless networks around the area
  - There's likely an unrecognizable wireless network with a strong signal
  - Might lack encryption

#### Walkthrough
Q1. Inspect the rogueap.cap file, part of this module's resources, and enter the MAC address of the Evil Twin attack's victim as your answer.
- Open Wireshark, and open the respective capture file
- Filter for: 
  - wlan.fc.type == 00 && wlan.fc.type_subtype == 8
    - The legitimate AP will have an RSN Information section. Evil Twin won’t.
    - Evil Twin: f8:14:fe:4d:e6:f2
- Filter for:
  - wlan.da == f8:14:fe:4d:e6:f2
    - This is for when the destination MAC address of the AP
  - There are only 2 devices that communicate with the Evil Twin.
    - Legitimate AP
    - Victim Device
- Answer is: 2c:6d:c1:af:eb:91

### 2.5 Fragmentation Attacks
#### Vocab
- Maximum Transmission Unit (MTU)

#### Notes
- IP layer helps move data packets from one device to another
  - This layer doesn’t check if packets are lost, dropped, or tampered with
  - Handled by higher layers - Transport or Application
- Each packet has a source and destination IP address in its header

Key Packet Fields
- Length: Shows the length of the IP header
- Total Length: Shows the length of the entire packet, including relevant data
- Fragment Offset: Has instructions to help reassemble large packets that are split into smaller pieces
- Source and Destination IP Addresses: Identify the sender and receiver of the packet.

Commonly Abused Fields
- Attackers may create or alter packets to disrupt communication
- They might modify packets to bypass IDS
- Study and understand how packet fields can be modified and abused

Abuse of Fragmentation
- How does Fragmentation work?
  - Large packets are split into smaller pieces for easier transfer
  - MTU sets the size for these pieces
  - The last packet is often smaller
  - This field helps the receiving device reassemble packets in the correct order.
- Why?
  - IPS/IDS Evasion: Attackers split malicious packets to bypass detection systems that don’t reassemble packets
    - Done through tools such as nmap scans
    - Without reassembly, the IDS/IPS can't detect that these packet fragments are part of a malicious software or indicator of data exfiltration
  - Firewall Evasion: Fragmented packets can slip past firewalls if they don’t reassemble before checking
  - Resource Exhaustion: Attackers use very small MTU sizes to overwhelm detection systems, causing them to fail due to resource limits
    - These sizes range from 10, 20 bytes and so on
  - DoS: Attackers send oversized packets to crash older systems when reassembled
    -  Packets over 65,535 bytes
- Defense
  - Delayed Reassembly: Firewalls, IDS, or IPS should wait for all packet fragments, reassemble them, and inspect the full packet to catch malicious activity
- Detection
  - Several ICMP requests going to one host from another
    - The start of recon, using tools such as nmap scan
  - Attacker can define MTU size
    - Large volumes of fragmentation from one host to another could be an indicator of attack
    - More obvious is that it sends the fragments from various ports into a single port on target device
      - Destination ports will respond with RST packet to all those ports from attacker and eventually exhaust its resources, a DoS

#### Walkthrough
Q1. Inspect the nmap_frag_fw_bypass.pcapng file, part of this module's resources, and enter the total count of packets that have the TCP RST flag set as your answer.
- Open Wireshark, and open nmap_frag_fw_bypass capture file
- Filter for:
  - tcp.flags.reset == 1
    - This will return TCP packets that have the RST flag
- Bottom left should show:
  - Packets: 266239 : Displayed: 66535
- Answer is: 66535

### 2.6 IP Source & Destination Spoofing Attacks
#### Vocab
- Distributed Denial of Service (DDoS)

#### Notes
- Unusual activity in IPv4 and IPv6 packets often involves the source and destination IP fields.
  - Focus on the source IP:
    - It should be from our local network. If it’s from outside, it may indicate packet crafting
    - It should also be from our subnet. A different IP range suggests malicious activity from within the network
   
Why?
- Decoy Scanning: Attackers change the source IP to match the target’s subnet to bypass firewalls and gather info about a host
  - Attacker might change their source address to match another legitimate host
  - They could also cloak their address with a decoy, but response of RST flags is still sent to them
  - Look for:
    - Initial fragmentation from a fake address
    - Some TCP traffic from the legitimate source address
  - Prevention:
    - Mimic Destination Host: Set up IDS/IPS/Firewall to reassemble packets like the destination host would, to spot malicious activity clearly
    - Monitor Connection Hijacking: Watch for cases where one host starts a connection, but another takes over. This is suspicious because attackers must reveal their true source IP to check if a port is open
    - Set Rules: Define firewall or IDS/IPS rules to detect and block this unusual behavior

- Random Source Attack DDoS: Attackers use random source IPs to flood a target’s port, overwhelming network or host resources
  - Attackers send pings from many fake random source IPs to a non-existent host
  - Similar to a SMURF attack but reversed: the target host pings back all fake sources and gets no reply, causing resource strain
    - Resource exhaustion will increase exponentially with fragmentation
  - The goal is to overload a specific service on a single port.
  - Detect:
    - Random hosts repeatedly target the same port
    - The source ports increase predictably (incrementally) without randomization
    - Packets have the same length, unlike normal traffic where packet lengths vary


- LAND Attacks: Similar to above but the source and destination IPs are set to the same address, causing resource exhaustion or crashes on the target
  - How?
    - The attacker sends a large volume of packets to the target host
    - By reusing the same ports, the attack overwhelms the target
  - Occupying all base ports makes it hard for legitimate connections to reach the affected host

- SMURF Attacks: Attackers send ICMP packets with the victim’s IP as the source, prompting many replies that overwhelm the victim
  - A type of DDoS attack where random hosts overwhelm a victim host
  - How?
    - The attacker sends ICMP requests to many live hosts, faking the source IP as the victim’s IP
    - The live hosts reply to the victim with ICMP responses
    - This floods the victim, causing resource exhaustion
  - Detection
    - Excessive ICMP replies from one or more hosts to the victim
    - Many different hosts pinging a single victim host
  - Fragmentation can be incorporated to accelerate resource exhaustion

- Initialization Vector Generation: In older wireless networks, attackers modify the source and destination IP addresses of captured packets and send it again to generate initialization vectors to build a decryption table for a statistical attack. Look for excessive repeated packets between hosts.

#### Walkthrough
Q1. Inspect the ICMP_smurf.pcapng file, part of this module's resources, and enter the total number of attacking hosts as your answer.
- Open Wireshark, and open ICMP_smurf capture file
- Filter for:
  - icmp
- Manually scan through the entire list.
  - There should only be one IP source that’s constantly sending fragmented ICMP packets to a specific address
  - Info should be displaying – no response found!
    - Endpoint resource has been overloaded
  - The attacker IP is: 192.168.10.5
- Answer is: 1

### 2.7 IP Time-to-Live Attack
#### Notes
- TTL attacks are used to avoid being caught by security systems like firewalls or IDS

How?
- Attacker creates an IP packet with a very low TTL value like 1, 2, or 3
- Each time the packet passes through a router or host, the TTL value decreases by one
- When the TTL reaches zero, the packet is discarded and doesn't reach the security system
- Routers send "Time Exceeded" messages back to the source IP when the packet expires, helping the attacker avoid detection

Detect
- Attackers often change the TTL value in packets during port scanning, which can be hard to detect in small amounts but noticeable
- There might be a [SYN, ACK] message from a legitimate service port to a targeted device, indicating an attacker may have bypassed a firewall rule.
- Check the IPv4 tab in Wireshark, there might be packets with an unusually low TTL value, which is a sign of an attack
- To stop these attacks, set up a rule to filter out or discard packets with a TTL value that’s too low, preventing manipulated packets from getting through

### 2.8 TCP Handshake Abnormalities
#### Notes
- Normal TCP connections use a 3-way handshake to establish communication between devices
  - Client sends SYN, server replies with a SYN,ACK and then client confirms with an ACK
- Pay attention to TCP flags, the markers in the data packets, to spot unusual activity

Flags
- Urgent (URG): indicates urgency with the current data in stream
- Acknowledge (ACK): acknowledges receipt of data
- Push (PSH): tells TCP stack to immediately deliver the received data to the application layer, and bypass buffering
- Reset (RST): used to terminate the TCP connection
- Synchronize (SYN): used to establish an initial connection with TCP.
- Finish (FIN): used to tell the end of a TCP connection. It is used when no more data needs to be sent
- Explicit Congestion Notification (ECN): used to indicate congestion within our network, it lets the hosts know to avoid unnecessary re-transmissions

Detect
- A high number of certain flags might indicate someone is scanning the network
- Unknown or uncommon flags could suggest attacks like TCP RST attacks, hijacking, or attempts to bypass network controls during scanning
- If a single host is trying to connect to many ports or multiple devices, it could be scanning'
  - Might include decoy scans (fake connections to confuse detection) or random source attacks (using fake source addresses)
 
SYN Flags
- Lots of SYN packets in network traffic suggest an nmap scan
- If port is open, the target machine replies with a SYN-ACK packet to continue the connection, but the attacker sends an RST packet to stop it
- If port is closed, the target machine sends an RST packet, which can make it hard to spot the scan.
- Types
  - SYN Scan: The attacker sends SYN packets and ends the connection early with an RST packet
  - SYN Stealth Scan: The attacker partially completes the connection to avoid being detected
 
Null Flags
- Attacker sends TCP packets with no flags to check ports
- If port is open, the target system doesn’t respond because the packet has no flags
- If port is closed, the target system sends an RST packet back.
- Flag looks like [<None>]
- How the target machine responds will indicate if port is open or closed

ACK Flags
- High volume of ACK packets being exchanged between two computers, indicator of ACK scan
- A technique used to check the status of ports on a machine without making a full connection
- If port is open, the target system might not respond, or might send back an RST packet.
- If port is closed, the target system sends back an RST packet.

FIN Flags
- If port is open, the target system doesn’t respond
- If port is closed, the target system sends an RST packet back

Multiple Flags
- If multiple flags are used than it's an Xmas Tree scan
- If port is open, the target system might not respond, or might send back an RST packet
- If port is closed, the target system sends back an RST packet
- Easy to detect, all flags are on

#### Walkthrough
Q1. Inspect the nmap_syn_scan.pcapng file, part of this module's resources, and enter the total count of packets that have the TCP ACK flag set as your answer.
- Open Wireshark, and open nmap_syn_scan capture file
- Filter for: 
  - tcp.flags.ack == 1
    - This will return TCP packets that have the ACK flag
- Bottom left should show:
  - Packets: 848 : Displayed: 429
- Answer is: 429

### 2.9 TCP Connection Resets & Hijacking
#### Notes
- An attacker might try to disrupt your network by using a TCP RST Packet Injection attack (also known as TCP connection termination)

TCP Connection Reset
How?
- Attacker spoofs the source IP address to make it look like it’s coming from a real machine on your network
- They send a TCP packet with the RST flag, which forces the connection to close
- They target a specific port that is already in use on the victim machine.
- Many RST packets directed to a single port

Detect
- Check the MAC address of the device sending the RST packets
- If the IP is supposed to match MAC , but a different MAC is sending the RST packets, that’s suspicious.
  - Attackers might also spoof the MAC address to avoid detection
    - Take note of retransmissions or other network issues, similar to ARP poisoning attacks

TCP Hijacking
How?
- Advanced attacker might use TCP connection hijacking to take over an active connection between two devices
- Attacker monitors the target connection to learn how it works
- They perform sequence number prediction to insert their own packets in the correct order
  - Might use AI for this instead to make it easier
- While injecting packets, they spoof the source IP address to make it look like they are the real device

Control
- Attacker must block or delay ACK packets from reaching the real machine.
  - Attackers employ other techniques such as ARP poisoning to block or redirect traffic
- This prevents the real machine from correcting the connection, allowing the attacker to stay in control

Detect
- Out-of-order packets
- Unexpected IP/MAC combinations
- Interrupted or dropped ACK packets

#### Walkthrough
Q1. Inspect the TCP-hijacking.pcap file, part of this module's resources, and enter the username that has been used through the telnet protocol as your answer.
- Open Wireshark, and open TCP-hijacking capture file
- Filter for: 
  - telnet
    - This will only return packets that used TelNet protocol
- Inspect all 13 packets, right click and follow TCP stream. All should be outputting the same username used in the protocol
- Answer is: administrator

### 2.10 ICMP Tunneling
#### Notes
- Tunneling is a method attackers use to sneak data out of a network or communicate secretly with a compromised system.

How
- Attacker wraps their malicious traffic inside a legitimate protocol to avoid detection
  - Tunneling Methods: SSH, HTTP/s, DNS, Proxy-based, ICMP
- This allows them to bypass firewalls, filters, or other network controls.

Detection
- Tunneling often comes with signs of the attacker having C2 access over one of your machines
- You might see unexpected traffic using allowed protocols going to suspicious destinations

Why?
- Tunneling lets attackers expand control over the network and exfiltrate data, all while hiding behind traffic that looks normal

ICMP Tunneling
- Attacker hides data inside ICMP packets

How
- The attacker puts sensitive information (e.g., files, usernames, passwords) into the data field of ICMP packets
- These packets are sent to another host, hiding the data in plain sight.

Detection
- Filter for ICMP traffic
- Check the size of the data in ICMP requests and replies
  - Normal ICMP packets usually carry around 48 bytes of data
    - Attacker could use fragmentation to mimic this size
  - Suspicious ICMP packets might carry very large payloads, like 38,000 bytes
    - Will contain data the attacker wants to exfiltrate - usernames, passwords, or other readable data
    - Could also contain encoded or encrypted data instead of plain text to hide it further
      - May use encryption such as Base64
      - Can also be decoded with Base64 in Linux terminals to inspect the data
- Large packet sizes or fragmentation in ICMP traffic is a red flag.
- Anything larger than 48 bytes is suspicious, and should be investigated

Prevention
- Block ICMP Requests: if ICMP is not allowed, attackers will not be able to utilize it
- Inspect ICMP Requests and Replies for Data - stripping data, or inspecting data for malicious content on these requests and replies can allow us better insight into our environment, and the ability to prevent this data exfiltration

#### Walkthrough
Q1. Enter the decoded value of the base64-encoded string that was mentioned in this section as your answer.
- Command is found in lesson, but otherwise, open Wireshark, and open ICMP-tunneling capture file
- Filter for: 
  - icmp
    - This will only return packets that used ICMP protocol. Since in this case attacker used ICMP tunneling to exfiltrate data.
- Matching cipher text should be in packets no. 147 or 180
- Open the HTB machine and run this command in the Linux terminal
  - echo 'VGhpcyBpcyBhIHNlY3VyZSBrZXk6IEtleTEyMzQ1Njc4OQo=' | base64 -d
- Answer is: This is a secure key: Key123456789

### 2.11 HTTP/S Service Enumeration
#### Vocab
- Web Application Firewall (WAF)
- Insecure Direct Object Reference (IDOR)

#### Notes
- Unusual or excessive HTTP/HTTPS traffic to your web servers can be a sign that an attacker is probing or trying to exploit vulnerabilities in your server

Why
- Attackers often target the transport layer and the applications running on web servers
- They try to find weaknesses using a technique called fuzzing — sending lots of random or unexpected inputs to see what breaks or leaks information
  - Fuzzing is often used in the early stages of an attack to gather information before launching a more serious exploit
    - Part of recon
  - WAF can help block fuzzing but not everyone has one and ome internal servers may not be protected by a WAF

Detection
- Look for high volumes of HTTP/S traffic coming from a single host
- Check your web server access logs for repeated or unusual requests from the same IP

Directory Fuzzing
- Attacker tries to find hidden or unlisted pages and folders on your website
- They send a large number of HTTP requests to guess file names or directories

Detection
- In Wireshark, filter for http to view web traffic
- To see only requests, use http.request as the filter
- A single host repeatedly sends requests for non-existent pages
  - There will be many 404 responses
  - These requests happen very quickly, often in rapid bursts
- Easy to spot due to the large number of 404 errors from the same host in a short period.
- Can also find this activity in your web server’s access logs

Other Fuzzing Techniques
- Attackers may also fuzz specific parts of your web pages
  - Dynamic or static elements (e.g., changing id=123 to other values)
  - IDOR vulnerabilities — for example, changing return=max to return=min in JSON responses to manipulate data access

Detect
- Filter traffic by host in your analysis tool to narrow down suspicious activity then “Follow HTTP Stream” to see the full conversation between client and server
- A host is sending lots of requests very quickly
  - Requests often look similar but with small changes (like different IDs or parameters)
- Attacker could spread out the requests over time (Slow Fuzzing)
- Attacker could also use multiple IP addresses or hosts to distribute the traffic and stay under the radar

Prevention
- Maintain virtualhost or web access configurations to return the proper response codes to throw off these scanners
- Establish rules to prohibit these IP addresses from accessing our server through a WAF

#### Walkthrough
Q1. Inspect the basic_fuzzing.pcapng file, part of this module's resources, and enter the total number of HTTP packets that are related to GET requests against port 80 as your answer.
- Open Wireshark, and open basic_fuzzing capture file
- Filter for: 
  - http.request.method == GET && tcp.port == 80
    - http.request.method == GET
      - Will filter for HTTP packets that are related to GET
    - tcp.port == 80
      - Will ensure that it will only show HTTP traffic going to port 80
- Bottom left should show:
  - Packets: 2040 : Displayed: 204
- Answer is: 204

### 2.12 Strange HTTP Headers
#### Notes
Detection
- Weird "Host" headers (e.g., Host: )
- Unusual HTTP verbs (like using uncommon methods instead of just GET or POST)
- Changed or odd User-Agent strings (which tell us what browser or tool is being used)

Finding Strange Host Headers
- Filter only HTTP requests and replies to narrow down the traffic
- Exclude requests that use your real server's IP or domain. This helps identify suspicious or unusual Host headers
  - Look for fake or suspicious hosts like
    - 127.0.0.1 (the local loopback address)
    - Admin
    - Other unauthorized names
   
Why
- To trick the server by using different Host headers
- To gain unauthorized access to protected parts of the site
- Often uses tools like Burp Suite to modify these headers

Defense
- Make sure virtual hosts and access controls are properly configured
- Keep web server software up to date to avoid known vulnerabilities

Code 400s & Request Smuggling
- 400 (Bad Request) Errors
  - Can be clues that someone is trying to send malicious requests
  - If HTTP stream of a 400 error is followed there might be strange request formatting from the client
    - Sign of:
      - HTTP Request Smuggling
      - CRLF Injection (Carriage Return Line Feed)
     
How
- Craft one request that looks normal, but sneak in a second hidden request
- If the server is misconfigured, it might process both requests, giving attackers access they shouldn't have
  - Server’s configuration doesn't properly separate or validate incoming requests.
- Review and harden server configuration to avoid these vulnerabilities.

Apache Configuration
- Watching for code 400s can give clear indication to adversarial actions during our traffic analysis efforts
- Code 200 (success) response indicates attacker succeeded with attack

Extra Notes
- CVE-2023-25690

#### Walkthrough
Q1. Inspect the CRLF_and_host_header_manipulation.pcapng file, part of this module's resources, and enter the total number of HTTP packets with response code 400 as your answer.
- Open Wireshark, and open CRLF_and_host_header_manipulation capture file
- Filter for: 
  - http.response.code == 400
    - This will return HTTP packets with a response code of 400
- Bottom left should show:
  - Packets: 327 : Displayed: 7
- Answer is: 7

### 2.13 Cross-Site Scripting (XSS) & Code Injection Detection
#### Notes
- While checking HTTP requests, you might see many requests going to an unknown internal “server.”
  - A sign of XSS
  - A lot of data might be sent, like cookies or session tokens
    - Sometimes it's encoded or encrypted
   
How
- Attacker injects malicious JavaScript into a web page (often through user input)
- When other users visit the page, their browser runs the attacker’s script
- This can let the attacker steal cookies, tokens, or session data
  - You may see it sending data to an external or internal address controlled by the attacker
- May also inject malicious PHP code to try to gain command and control of your server

Defense
- Quickly remove the malicious comment or input
- In serious cases, even take the server offline temporarily to fix the issue

Prevention
- Always sanitize and validate user input
- Do not interpret user input as code
- Use Content Security Policy (CSP) and escape output where needed
- Keep server-side code and plugins secure and up to date

#### Walkthrough
Q1. Inspect the first packet of the XSS_Simple.pcapng file, part of this module's resources, and enter the cookie value that was exfiltrated as your answer.
- Open Wireshark, and open respective capture file
- Inspect the first log, right click and follow the HTTP stream
- Answer is: mZjQ17NLXY8ZNBbJCS0O

### 2.14 SSL Renegotiation Attacks
#### Notes
- HTTP is stateless and unencrypted, but HTTPS adds encryption to secure communication between clients and web servers
- Uses
  - TLS (Transport Layer Security)
  - SSL (Secure Sockets Layer)
 
How HTTPS Works
- Handshake: the client and server agree on encryption settings and they exchange certificates to verify identity
- Encryption Setup: after handshake, they start using the agreed encryption method
- Data Exchange: all web data (pages, images, etc.) is encrypted during transfer
- Decryption: client and server use public and private keys to decrypt the data.

Common HTTPS Attacks
- SSL renegotiation attacks: attackers force the session to use weaker encryption standards
- Other encryption-related threats: for example, the Heartbleed vulnerability, which exploits a flaw in certain SSL/TLS implementations to leak sensitive data

Prevention
- Use strong encryption settings
- Keep TLS/SSL libraries and certificates up to date.

TLS and SSL Handshakes
- To create an encrypted connection, the client and server go through a process called the TLS/SSL handshake. Both are similar
- Client Hello:
  - The client starts the process by sending a message to the server
  - Includes: supported TLS/SSL versions, list of encryption algorithms (cipher suites), random data (called a nonce)
- Server Hello:
  - Server replies with its chosen settings: selected TLS/SSL version, chosen cipher suite, another nonce
- Certificate Exchange:
  - Server sends its digital certificate to prove its identity
  - The certificate contains the server's public key
- Key Exchange:
  - Client creates a premaster secret
  - It encrypts this secret using the server’s public key and sends it to the server
- Session Key Derivation:
  - Both the client and server use: the premaster secret and the two nonces
  - They calculate session keys used to encrypt and decrypt data
- Finished Messages:
  - Both sides send a finished message to confirm the handshake worked
  - These messages are encrypted using the session keys and contain a hash of the previous steps
- Secure Data Exchange:
  - With the handshake complete, encrypted communication begins
  - This includes web pages, images, or other data sent securely
 
SSL Renegotiation Attack
- In Wireshark, use ssl.record.content_type == 22 to show only TLS/SSL handshake traffic

Detection
- Multiple Client Hellos:
  - You may see several "Client Hello" messages from the same client in a short time
  - A strong sign the attacker is forcing renegotiation
  - Goal: Downgrade the encryption to a weaker cipher
    - If a stronger cipher is used in one of the connections, it leaves only weaker ciphers available
- Out-of-Order Handshake Messages:
  - Normally caused by network issues, but in this context a Client Hello appears after the handshake is already complete
  - Can indicate a renegotiation attempt
 
Why
- DoS:
  - Repeated renegotiation uses up server resources, possibly making it crash or become unresponsive.
- Weak Cipher Exploitation:
  - The attacker may try to renegotiate using a weaker encryption algorithm that is easier to break.
- Cryptanalysis:
  - Renegotiation could be part of a larger plan to analyze encryption patterns and discover weaknesses.

#### Walkthrough
Q1. Inspect the SSL_renegotiation_edited.pcapng file, part of this module's resources, and enter the total count of "Client Hello" requests as your answer.
- Open Wireshark, and open respective capture file
- Filter for: 
  - ssl.handshake.type == 1
    - This will shown only the ‘Client Hello’ packets
- Bottom left should show:
  - Packets: 103 : Displayed: 16
- Answer is: 16

### 2.15 Peculiar DNS Traffic
#### Notes
- DNS traffic can be overwhelming, since clients often send many DNS requests.
- It's important to understand DNS to spot malicious behavior hidden in all that traffic.

DNS Query Types
- Forward Lookup (most common)
  - The client asks: “Where is academy.hackthebox.com?”
  - The DNS server replies: “It’s at 192.168.10.6.”
- Reverse Lookup:
  - The client asks: “What is your name, 192.168.10.6?”
  - The DNS server replies: “It’s academy.hackthebox.com.”

Reverse DNS Lookup
- Query Initiation: client sends a reverse query to a DNS server with an IP address.
- Reverse Lookup Zone Check: DNS server checks if it manages the reverse lookup zone for that IP (e.g., 1.2.0.192.in-addr.arpa for IP 192.0.2.1).
- PTR Record Query: DNS server looks for a PTR (Pointer) record tied to the IP.
- Response: If found, DNS server returns the domain name (FQDN) for that IP.

#### Walkthrough
Q1. Enter the decoded value of the triple base64-encoded string that was mentioned in this section as your answer. Answer format: HTB{___}
- Command is found in lesson, but otherwise, open Wireshark, and open DNS-tunneling capture file
- Filter for: 
  - dns
    - This will shown only the DNS protocol packets
- Open packet 11, and copy and paste the TXT field value. This is in Answers tab.
- Run this command in HTB Linux machine:
  - echo 'VTBaU1EyVXhaSFprVjNocldETnNkbVJXT1cxaU0wb3pXVmhLYTFneU1XeFlNMUp2WVZoT1ptTklTbXhrU0ZJMVdETkNjMXBYUm5wYQpXREJMQ2c9PQo=' | base64 -d | base64 -d | base64 -d
  - Attackers can and will double or triple encode, maybe even more.
- Answer is: HTB{Would_you_forward_me_this_pretty_please}

Common DNS Record Types
- A: Maps a domain to an IPv4 address
- AAAA:	Maps a domain to an IPv6 address
- CNAME:	Creates an alias (e.g., hello.com = world.com)
- MX:	Points to the mail server for a domain
- NS:	Identifies the authoritative name server for a domain
- PTR:	Used in reverse lookups, maps IP to domain
- TXT:	Holds text data related to a domain (e.g., SPF records)
- SOA:	Holds admin info about the DNS zone

Why
- Malicious actors may hide activity in DNS traffic
- Knowing how DNS works helps you spot abnormal patterns
  - Unusual PTR lookups
  - Sudden bursts of CNAME or TXT queries
  - Unexpected traffic to odd domain names

DNS Tunneling (Malicious Technique)
- What it is: A method attackers use to bypass firewalls or exfiltrate data by hiding it inside DNS requests and responses.
- How it works:
  - Data (like stolen files or commands) is encoded and sent through DNS queries to a server the attacker controls.
  - It turns DNS traffic into a covert communication channel.
- Purpose: Stealthy communication or data theft.
  - Data Exfiltration: used to sneak stolen data out of a network without triggering security alerts.
  - Command and Control (C2): malware can use DNS tunneling to communicate with its C2 servers, often seen in botnets.
  - Bypassing Firewalls/Proxies: since DNS is usually allowed through networks, tunneling bypasses security controls that only inspect HTTP/HTTPS.
  - Domain Generation Algorithms (DGAs): some malware uses random or rapidly changing domains to communicate.
    - These domains are generated on the fly, making it harder to detect and block them.
- Red flag: High volume of unusual DNS queries, often to strange or repetitive domain names.

DNS Enumeration (Recon Technique)
- What it is: A method used by attackers (or penetration testers) to gather information about a target’s DNS infrastructure.
- How it works:
  - Queries DNS records (like A, MX, NS, TXT, etc.) to learn about servers, services, subdomains, and email setup.
  - May use tools like nslookup, dig, or automated scanners.
- Purpose: Information gathering for future attacks.
- Red flag: Multiple targeted DNS lookups from a single source, especially for subdomains.

Interplanetary File System and DNS Tunneling
- A peer-to-peer (P2P) file sharing protocol designed for decentralized storage and sharing of data.

Why
- Malware Hosting
  - Attackers store malicious files on IPFS, which are then downloaded via URLs like https://cloudflare-ipfs.com/ipfs/<hash>
- Difficult to Detect
  - IPFS is decentralized, meaning content can be hosted on many nodes.
  - Files aren’t easily removed, and content can be fetched from multiple sources.
  - It doesn't rely on a single server, making it harder to block or trace.

Detection
- Monitor for suspicious DNS or HTTP/HTTPS traffic to IPFS gateways, such as:
  - cloudflare-ipfs.com
  - Any URL containing /ipfs/<hash>
- Pay attention to unknown or rarely used URI patterns in network logs.

### 2.16 Strange Telnet & UDP Connections
#### Notes
Telnet
- Telnet is a network protocol for interactive, text-based communication between devices.
- Created in the 1970s (RFC 854), but now largely replaced by SSH due to better security.
- Still used in legacy systems (e.g., Windows NT machines) for remote access.
- Attackers may use it for:
  - Data exfiltration
  - Command and control
  - Tunneling traffic
 
Detect
- Port 23 = Traditional Telnet
  - Common Telnet traffic will appear on TCP port 23 in tools like Wireshark.
  - It's usually unencrypted, making it easy to inspect — unless attackers encrypt or encode it.
- Telnet on Unusual Ports
  - Attackers can run Telnet on non-standard ports (e.g., port 9999).
  - Look for lots of traffic on uncommon ports and inspect the TCP stream for suspicious behavior.
- IPv6 Telnet Connections
  - If your network doesn’t use IPv6, IPv6 traffic could be suspicious.
  - Use Wireshark filters like: ((ipv6.src_host == fe80::xxxx) or (ipv6.dst_host == fe80::xxxx)) and telnet
  - Follow TCP streams to analyze the content.

Why UDP
- Connectionless (no handshake like TCP).
- Faster, but less reliable (no guaranteed delivery).
- Often used by attackers for data exfiltration because it's lightweight and less monitored.
- It just sends data immediately.

Common Use of UDP
- Real-time Apps: video streaming, online games, VoIP (voice/video calls)
- Domain Name System (DNS): domain name lookups use UDP for fast queries
- Dynamic Host Configuration Protocol (DHCP): Assigns IP addresses to devices on the network
- Simple Network Management Protocol (SNMP): Used for monitoring and managing network devices
- Trivial File Transfer Protocol (TFTP): Lightweight file transfer protocol (used by some legacy systems)

#### Walkthrough
Q1. Inspect the telnet_tunneling_ipv6.pcapng file, part of this module's resources, and enter the hidden flag as your answer. Answer format: HTB(___) (Replace all spaces with underscores)
- Open Wireshark, and open respective capture file
- Filter for: 
  - telnet
    - This will only show the TelNet traffic
    - All TelNet traffic in this activity is using Ipv6 address
- Flag is hidden on packet with length 115 and 29 bytes of data.
  - Lesson exemplar is the length 130 and 44 bytes of data.
  - Otherwise, the rest are smaller since there’s no real data in them.
- Answer is: HTB(Ipv6_is_my_best_friend)
