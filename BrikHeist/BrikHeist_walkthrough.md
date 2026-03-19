# BrikHeist — Walkthrough

## Description

The company organized an Iftar event, and when no one was looking, the last piece of brik vanished. A suspicious shortcut file was recovered from the scene, and the suspect left a message behind:

"that piece was good, sending proof to the boys tonight"

Analyze the shortcut file to identify the machine, then trace the suspect's steps in the network capture.

You are the investigator. Find the truth.

## Overview
This challenge provides three files:
- `report_q1.lnk` — a Windows shortcut file recovered from the scene
- `heist.pcap` — a network capture of suspicious activity
- A netcat server that guides the investigation through 8 questions

The goal is to analyze the LNK file to identify the suspect's machine, then trace their steps in the packet capture.

---

## Step 1 — Connect to the Netcat Server

```bash
nc <host> 5003
```

The server presents the challenge story and asks 8 questions. The first 3 are research questions about LNK files — answer them to unlock the investigation questions.

**Q1:** What does the .lnk extension stand for?
> `Shell Link`

**Q2:** What is the file signature (magic bytes) of a .lnk file?
> `4C 00 00 00`

**Q3:** What command-line tool by Eric Zimmerman is commonly used to parse .lnk files?
> `LECmd`

---

## Step 2 — Analyze the LNK File with LECmd

Download LECmd from `https://ericzimmermanstools.com` and run it against the provided LNK file:

```powershell
.\LECmd.exe -f report_q1.lnk
```

![alt text](image-2.png)

The output reveals the forensic metadata embedded in the shortcut file. Look for the following fields:

- **Machine ID** (under the Tracker Data Block): `DESKTOP-K4DR13`
- **MAC Address** (under the Tracker Data Block): `00:1a:2b:3c:4d:5e`

**Q4:** What is the hostname of the suspect's machine?
> `DESKTOP-K4DR13`

**Q5:** What is the MAC address of the suspect's machine?
> `00:1a:2b:3c:4d:5e`

---

## Step 3 — Investigate the PCAP in Wireshark

Open `heist.pcap` in Wireshark. The capture contains thousands of packets from multiple machines — use the MAC address discovered from the LNK file as a filter to isolate the suspect's traffic:

```
eth.src == 00:1a:2b:3c:4d:5e
```

![alt text](image.png)

You will notice a suspicious TCP stream from `192.168.1.105` going to an unusual destination: `10.10.10.47` on port `9999`.

**Q6:** What is the destination IP the suspect exfiltrated data to?
> `10.10.10.47`

**Q7:** What destination port was used during the exfiltration?
> `9999`

---

## Step 4 — Extract the Transmitted File

Right-click any packet in the suspicious stream and select:

**Follow → TCP Stream**

In the TCP stream window, change **"Show data as"** to **Raw**. Notice the PNG file signature at the very top of the stream:

```
89 50 4E 47 0D 0A 1A 0A ...
```

![alt text](image-1.png)

This confirms the suspect transmitted a PNG image. Click **Save as** and save the raw data with a `.png` extension (e.g. `evidence.png`). Open it to view the transmitted image.

---

## Step 5 — Hash the File

```bash
md5sum evidence.png
```

**Q8:** What is the MD5 hash of the transmitted file?
> `f1ce6995d965c2c98d42a161cbe7af3a`

---

## Step 6 — Retrieve the Flag

After answering all 8 questions correctly on the netcat server, the flag is revealed:

```
Spark{p4ck3ts_d0nt_f0rg3t_wh4t_y0u_34t}
```

---


