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
#### Notes
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
#### Notes
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

### 2.8 TCP Handshake Abnormalities
#### Notes
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

### 2.11 HTTP/s Service Enumeration
#### Notes
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
#### Walkthrough
Q1. Inspect the first packet of the XSS_Simple.pcapng file, part of this module's resources, and enter the cookie value that was exfiltrated as your answer.
- Open Wireshark, and open respective capture file
- Inspect the first log, right click and follow the HTTP stream
- Answer is: mZjQ17NLXY8ZNBbJCS0O

### 2.14 SSL Renegotiation Attacks
#### Notes
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

### 2.16 Strange Telnet & UDP Connections
#### Notes
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
