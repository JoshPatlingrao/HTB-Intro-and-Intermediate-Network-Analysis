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
    - For ARP REP, since the attacker is scanning with an IP of 192.168.10.5, so there is likely a device with that IP address in the network that will respond.
- Scan the No. 13 packet
- Answer is: 2c:30:33:e2:d5:c3
