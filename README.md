# HTB-Intro-and-Intermediate-Network-Analysis

## Summary
This page is a dedicated repository for my personalised notes for the module and a walkthrough for the problems.

### Tools Used
- VM: Linux
- TCPDump
- WireShark

## 1.0 Introduction to Network Traffic Analysis

## 2.0 Intermediate Network Traffic Analysis
### 2.1 ARP Spoofing and Abnormality Detection
#### Notes
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
