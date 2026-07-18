# Lab 02 — Wireshark & Network Analysis

WATCH ME BUILD IT HERE https://canva.link/wireshark-network-analysis-lab

**Platform:** Wireshark (Free) · Local Machine or Azure VM  
**Domain:** Network Traffic Analysis  
**Cert Alignment:** CompTIA Network+ · Security+ · CySA+  
**Estimated Time:** 2–4 hours across multiple sessions  
**Estimated Cost:** $0 — Wireshark is permanently free and open source

---

## Overview

Networks carry every piece of data an organisation produces — emails, database queries, login credentials, file transfers, API calls. When something goes wrong — a service is unreachable, a user reports slow performance, a security alert fires — the network is almost always involved. The only way to know what is actually happening is to look at the packets.

This lab uses Wireshark to capture live network traffic and walks through four core skills: identifying DNS lookups, reading TCP handshakes, spotting cleartext credentials in unencrypted HTTP traffic, and reconstructing full conversations with TCP stream follow.

> **Why this matters for cloud and security roles:** The mental model built here transfers directly to reading Azure Network Watcher logs, VPC flow logs, and any cloud-native traffic inspection tool. SOC analysts use this exact workflow to extract indicators of compromise from packet captures during real investigations.

---

## Architecture

<img width="2720" height="1440" alt="wireshark_lab_architecture" src="https://github.com/user-attachments/assets/4fb3ecd8-3e0b-46ac-8358-157bbdf3cc7f" />


**Trust boundary:** Traffic crosses an untrusted network segment (internet, router) before reaching the local machine's NIC. Once inside the trust boundary, the NIC in promiscuous mode hands every frame to Wireshark, which stores the full capture and lets display filters slice it into the views needed for analysis — without ever discarding the underlying data.

---

## Career Relevance

| Role | How this lab applies |
|---|---|
| Network Engineer | Diagnose connectivity issues by seeing exactly where packets are dropped or delayed |
| SOC Analyst | Identify malicious traffic patterns and extract indicators of compromise from packet captures |
| Cloud Security Engineer | This mental model transfers directly to reading Azure Network Watcher and VPC flow logs |
| Help Desk | Prove a reported network issue is real and identify whether it is client-side or server-side |

---

## What This Lab Covers

| Skill | Real-world application |
|---|---|
| Capture live network traffic | The foundational skill — you cannot analyse what you cannot see |
| Apply display filters | Production captures generate millions of packets; filters find the 10 that matter in seconds |
| Read TCP handshakes | Recognising a normal handshake vs. an incomplete one tells you immediately whether a connection succeeded or failed |
| Identify DNS queries and responses | DNS is involved in virtually every network action — this transfers directly to cloud DNS troubleshooting |
| Spot cleartext credentials in HTTP | Hands-on demonstration of why HTTPS matters |
| Follow TCP streams | Reassemble the full conversation between two hosts — essential for incident investigation |

---

## Key Concepts Reference

> Read this before starting — these terms come up constantly throughout the lab.

| Term | Definition |
|---|---|
| Packet | A small unit of data with a header (source IP, destination IP, port) and a payload, transmitted independently across a network and reassembled at the destination |
| Protocol | A set of rules defining how data is formatted and transmitted — e.g. DNS, HTTP, TCP, ICMP — each with its own port and packet structure |
| TCP three-way handshake | The connection setup sequence: **SYN** ("I want to connect") → **SYN-ACK** ("Acknowledged, here's mine") → **ACK** ("Confirmed, ready to send data") |
| DNS (Domain Name System) | Translates human-readable domain names (e.g. `google.com`) into IP addresses computers use to communicate |
| HTTP vs HTTPS | HTTP is unencrypted — anyone watching the traffic can read it, including submitted credentials. HTTPS adds TLS encryption so captured packets cannot be read |
| Promiscuous mode | A NIC mode that captures every packet on the network segment, not just packets addressed to your machine. Wireshark enables this automatically |
| Display filter vs. capture filter | Capture filters limit what gets recorded; display filters limit what you see *after* capturing, without discarding anything. This lab uses display filters exclusively |

---

## Prerequisites

- A computer running Windows, macOS, or Linux
- Administrative rights to install Wireshark and its packet-capture driver
- No prior networking experience required

---

## Step 1 — Install Wireshark

Wireshark is completely free and open source — no account, no trial, no licence.

| OS | Download | Notes |
|---|---|---|
| Windows | [Windows x64 Installer (.exe)](https://www.wireshark.org/download.html) | Accept all defaults. Install **Npcap** when prompted — required to capture packets |
| macOS | macOS Arm or Intel (.dmg) | Run the installer. If prompted about **ChmodBPF**, allow it — this grants Wireshark access to network interfaces |
| Linux | Use your package manager | `sudo apt install wireshark` (Ubuntu/Debian). Add yourself to the `wireshark` group to capture without root |

```bash
# Linux only — add yourself to the wireshark group (log out and back in after)
sudo usermod -aG wireshark $USER

# Verify Wireshark is installed
wireshark --version
```

---

## Step 2 — Your First Capture

This step builds comfort with the Wireshark interface before doing anything complex.

1. Open Wireshark
2. On the welcome screen, identify the network interfaces — each shows a wavy line reflecting live traffic activity
3. Double-click your active interface (Ethernet or Wi-Fi — pick the one with the most activity)
4. Wireshark starts capturing immediately; packets appear in the list in real time
5. Open a browser and navigate to any website
6. After 30 seconds, click the **red square Stop** button in the toolbar

You now have a packet capture in memory containing every frame that passed through that interface. The volume — hundreds or thousands of packets from 30 seconds of browsing — is exactly why display filters exist.

---

## Step 3 — Essential Display Filters

Type filters into the bar at the top of the window and press Enter. The packet list updates instantly to show only matching traffic.

| Filter | What it shows | When to use it |
|---|---|---|
| `dns` | All DNS queries and responses | Troubleshooting name resolution, spotting unusual domain lookups |
| `http` | Unencrypted HTTP traffic only | Finding cleartext data, debugging web apps without HTTPS |
| `tcp` | All TCP traffic | Starting point for connectivity investigations |
| `tcp.flags.syn == 1` | TCP SYN packets only | Seeing which hosts are attempting to connect to what |
| `tcp.flags.reset == 1` | TCP RST packets | Finding refused or forcibly closed connections |
| `icmp` | All ICMP traffic including ping | Verifying basic reachability between hosts |
| `ip.addr == 192.168.1.1` | All traffic to/from a specific IP | Isolating traffic for a single host in a busy capture |
| `ip.src == 10.0.0.5` | Traffic from a specific source IP only | Isolating outbound traffic from one host |
| `tcp.port == 443` | All HTTPS traffic | Identifying encrypted web traffic by port |
| `http.request` | HTTP GET and POST requests only | Finding web requests — useful for spotting data exfiltration |

---

## Step 4 — Guided Exercises

Each exercise builds on the previous one and teaches a specific real-world analysis skill.

### Exercise A — Capture a DNS Lookup

`nslookup` is a command-line tool that manually triggers a DNS lookup — run it in a terminal, **not** inside Wireshark (Wireshark is a capture/analysis tool only, it has no terminal).

**Opening a terminal:**
- **Windows:** Press the Windows key → type `cmd` → Enter
- **macOS:** `Cmd + Space` → type `Terminal` → Enter
- **Linux:** Right-click desktop → Open Terminal, or `Ctrl + Alt + T`

**Steps:**
1. In Wireshark, start a capture on your active interface
2. Leave Wireshark running, open a separate terminal window
3. In the terminal, run:
   ```bash
   nslookup google.com
   ```
4. The terminal returns the IP address(es) for `google.com` — confirming the lookup worked
5. Switch back to Wireshark → click **Stop**
6. In the filter bar, type `dns` and press Enter
7. Find the query packet — Info column shows `Standard query A google.com`
8. Find the response packet — Info column shows `Standard query response A google.com`
9. Click the response packet → expand **Domain Name System (response)** in the detail pane → check the **Answers** section for the A record IP — confirm it matches your terminal output

> **What you just saw:** Your machine asked for the A record for `google.com`, and the DNS server replied with an IP address your browser then connected to. This invisible lookup happens before every website visit, API call, and email. Unexpected DNS queries to unusual domains in a real capture are often the first sign of malware calling home to a command-and-control server.

### Exercise B — Watch the TCP Three-Way Handshake

1. Start a capture
2. Navigate to `http://example.com` (HTTP, not HTTPS — easier to see the handshake)
3. Stop the capture
4. Run `nslookup example.com` to get its IP, then filter: `tcp and ip.addr == [that IP]`
5. Identify three sequential packets:

| Packet | Flags | Meaning |
|---|---|---|
| 1st | SYN | Your machine: "I want to connect. Here is my sequence number." |
| 2nd | SYN, ACK | The server: "Got your request. Here is mine. Connection accepted." |
| 3rd | ACK | Your machine: "Got it. Connection is open. Ready to send data." |

> If you see a **SYN with no SYN-ACK**, the connection was refused or the server is unreachable. If you see a **RST**, the connection was forcibly closed. These two patterns are the most common things network engineers check first when diagnosing connectivity problems.

### Exercise C — Spot Cleartext Credentials (HTTP)

> **Scope warning:** Educational exercise only. Capture exclusively on networks and systems you own or have explicit permission to test. Never apply this technique against systems you do not own.

1. Set up a test HTTP login form locally, or use a test site running over HTTP (not HTTPS)
2. Start a capture
3. Submit the login form with a test username and password
4. Stop the capture
5. Filter: `http.request.method == POST`
6. Click the POST packet → find the **HTML Form URL Encoded** layer in the detail pane
7. The username and password appear in plaintext

> This is the concrete reason every login form must use HTTPS. Without TLS, anyone on the network path — an ISP, a coffee shop router, an attacker performing a man-in-the-middle — can read credentials exactly as typed. This is how security teams prove the vulnerability exists to developers who resist adding HTTPS.

### Exercise D — Follow a Full TCP Stream

1. Capture traffic while navigating to any HTTP website
2. Find any HTTP packet in the list
3. Right-click → **Follow → TCP Stream**
4. Wireshark reassembles every packet from that connection into a readable conversation — **red text** is the browser's request, **blue text** is the server's response

> This is how incident responders reconstruct what happened during a network event. Individual packets are fragments; the stream view is the complete conversation — what was transferred, what was sent, what the server returned.

---

## Step 5 — Save and Export Captures

Always save interesting captures — they are evidence of skill and serve as portfolio entries.

```bash
# Save a capture for later analysis
File → Save As → choose .pcapng format

# Export only the packets matching your current filter
# (apply your display filter first)
File → Export Specified Packets → Displayed

# Re-open a saved capture
File → Open → select your .pcapng file
```

```bash
# Command-line capture with tshark (included with Wireshark — useful for remote servers)
tshark -i eth0 -w capture.pcapng -c 1000
# -i: interface name   -w: output file   -c: stop after this many packets
```

---

## Verification Checks

| Skill | How to verify |
|---|---|
| DNS capture | Apply the `dns` filter and identify a query packet and its response — they should share matching transaction IDs |
| TCP handshake | Find three sequential packets with SYN, SYN-ACK, and ACK flags — explain what each means without referring to notes |
| Display filters | Filter by IP address, port, and protocol from memory |
| Stream reconstruction | Follow a TCP stream and read the full HTTP request/response as a conversation |
| File management | Save a capture, close Wireshark, reopen it, and confirm all packets load correctly |

---

## Portfolio Artifacts

Save three captures from this lab and include them in this repository:

- `captures/dns-lookup.pcapng` — a DNS query/response pair
- `captures/tcp-handshake.pcapng` — a full SYN → SYN-ACK → ACK sequence
- `captures/stream-follow.pcapng` — a followed TCP stream

Each capture file pairs with a short write-up in this README (or a linked notes file) describing what it shows and what was learned — this is concrete, demonstrable evidence of network analysis skills for interviews.

---

## Resources

- [Wireshark Official Download](https://www.wireshark.org/download.html)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [CompTIA Network+ Certification](https://www.comptia.org/certifications/network)
- [CompTIA Security+ Certification](https://www.comptia.org/certifications/security)

---

*Lab 02 of an ongoing series covering enterprise IT infrastructure, cloud security, and identity management.*
