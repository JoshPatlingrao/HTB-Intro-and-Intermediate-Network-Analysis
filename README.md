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
#### Notes
#### Walkthrough
Q1. Inspect the ARP_Poison.pcapng file, part of this module's resources, and submit the first MAC address that was linked with the IP 192.168.10.1 as your answer.
- Open Wireshark, and open the respective capture file
- Filter for:
  - arp.opcode == 2
    - Will filter for ARP REP, since the attacker is scanning with an IP of 192.168.10.5, so there is likely a device with that IP address in the network that will respond.
- Scan the No. 13 packet
- Answer is: 2c:30:33:e2:d5:c3

### 2.3 802.11 (WiFi) Denial of Service
#### Notes
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
#### Notes
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
