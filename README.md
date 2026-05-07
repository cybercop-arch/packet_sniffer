# 🕵️ Packet Sniffer

A lightweight, extensible CLI network packet capture and analysis tool built with **Python 3** and **Scapy**. Captures raw traffic at the link layer, decodes common protocols, and optionally saves to `.pcap` for deep analysis in Wireshark or other tools.

> ⚠️ **For authorised use only.** Always have explicit, written permission before sniffing any network. Unauthorised interception of network traffic is illegal in most jurisdictions.

---

## ✨ Features

| Feature | Detail |
|---|---|
| Raw capture | `AF_PACKET / SOCK_RAW` — full link-layer access |
| Protocol decoding | Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, HTTP |
| BPF filters | Standard Berkeley Packet Filter syntax (`-f "tcp port 443"`) |
| Protocol filter | Only show selected protos (`--protocols tcp,dns,http`) |
| PCAP export | Save any capture straight to `.pcap` (`-o out.pcap`) |
| Verbose mode | Multi-line hex dump + field breakdown (`-v`) |
| Coloured output | ANSI colours per protocol; disable with `--no-color` |
| Graceful exit | `Ctrl-C` prints a capture summary and flushes PCAP |
| Packet count limit | Stop after N packets (`-c 100`) |

---

## 📁 Project Structure

```
packet-sniffer/
├── packet_sniffer.py   # Main capture + analysis script
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## 📋 Requirements

- Python 3.8+
- Linux or WSL2 (raw sockets are Linux-only)
- Root / `sudo` privileges
- Scapy with HTTP layer support

```bash
pip install -r requirements.txt
```

**`requirements.txt`**
```
scapy>=2.5.0
```

---

## 🚀 Usage

### Step 1 — Find your interface

```bash
ip link show
# or
python3 packet_sniffer.py --help
```

### Step 2 — Run with root

```bash
# Basic capture on eth0
sudo python3 packet_sniffer.py

# Specify interface + BPF filter
sudo python3 packet_sniffer.py -i eth0 -f "tcp port 443"

# Capture 100 packets, save to pcap, verbose output
sudo python3 packet_sniffer.py -i eth0 -c 100 -o capture.pcap -v

# Only show DNS and HTTP traffic
sudo python3 packet_sniffer.py -i eth0 --protocols dns,http
```

### All CLI Options

```
usage: packet_sniffer.py [-h] [-i INTERFACE] [-f FILTER] [-c COUNT]
                         [-o OUTPUT] [-v] [--protocols PROTOCOLS] [--no-color]

  -i, --interface   Network interface (default: eth0)
  -f, --filter      BPF filter string  e.g. "tcp port 80"
  -c, --count       Packet limit (0 = unlimited)
  -o, --output      Save to .pcap file
  -v, --verbose     Multi-line field + hex dump
  --protocols       Comma list: tcp,udp,icmp,arp,dns,http
  --no-color        Disable ANSI colour
```

---

## 💬 Sample Output

### Summary mode (default)
```
10:42:31.412  #    1  [TCP  ]  Ether / IP / TCP 192.168.1.5:443 > 192.168.1.2:54123 SA
10:42:31.413  #    2  [DNS  ]  Ether / IP / UDP 192.168.1.2 > 8.8.8.8  query=api.github.com
10:42:31.415  #    3  [HTTP ]  Ether / IP / TCP ...  GET api.github.com/repos
10:42:31.416  #    4  [ARP  ]  Ether / ARP who has 192.168.1.1 says 192.168.1.2
```

### Verbose mode (`-v`)
```
────────────────────────────────────────────────────────────────────────
  #3  10:42:31.415  HTTP
────────────────────────────────────────────────────────────────────────
  IP src      : 192.168.1.2  →  140.82.114.4  (TTL 64)
  TCP         : 54123 → 80  flags=PA  seq=3821  ack=1
  method      : GET
  host        : api.github.com
  path        : /repos/samiksha/packet-sniffer
  hex         : 45 00 02 37 4f 1a 40 00 40 06 ...
────────────────────────────────────────────────────────────────────────
```

---

## 🧠 How It Works

The script uses **Scapy's `sniff()`** function with `store=False` so packets are processed in a callback and immediately discarded from memory — preventing unbounded RAM growth on long captures.

```
Network card (promiscuous)
        │
        ▼
  AF_PACKET / SOCK_RAW   ← link-layer access, no kernel filtering overhead
        │
        ▼
  BPF filter (kernel)    ← early discard before userspace
        │
        ▼
  _process_packet()      ← protocol classification
        │
   ┌────┴────┐
   │         │
summary    verbose       ← formatted terminal output
   │
   ▼
PcapWriter (optional)    ← .pcap file, sync-flushed per packet
```

---

## 🔐 Permissions & Legal

Raw socket capture requires `CAP_NET_RAW`. Always run via:

```bash
sudo python3 packet_sniffer.py
```

Alternatively, grant the capability without full sudo:

```bash
sudo setcap cap_net_raw+eip $(which python3)
```

> Running packet captures on networks you do not own or have written authorisation for is illegal. This tool is intended for **authorised penetration testing, CTF competitions, lab environments, and your own networks only**.

---

## 🐛 Bug Bounty & Security Research Use Cases

Some legitimate research workflows this tool supports:

- **Credential leak detection** — capture unencrypted HTTP Basic Auth headers on a test network
- **DNS exfiltration detection** — monitor unusually long or encoded DNS query names
- **ARP spoofing / MITM detection** — watch for duplicate ARP replies for the same IP
- **Port scanning fingerprinting** — observe SYN-only TCP packets across many ports
- **Cleartext protocol audit** — identify services still using FTP, Telnet, or plain HTTP

Combine captures with Wireshark (`-o capture.pcap`) or **tshark** for deeper protocol analysis during assessments.

---

## 🗺️ Roadmap

- [ ] Colour-coded severity alerts (e.g., cleartext passwords detected)
- [ ] JSON / NDJSON log output for SIEM ingestion
- [ ] Basic statistics dashboard (packets/sec, top talkers)
- [ ] Plugin architecture for custom detectors
- [ ] TLS SNI extraction (without decryption)

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-detector`)
3. Commit with conventional commits (`feat:`, `fix:`, `docs:`)
4. Open a pull request

---

## 📜 License

MIT — free to use, modify, and distribute. See `LICENSE` for details.

---

## 🙋 Author

**Samiksha** — Cybersecurity & Forensics Student · Ethical Hacking Enthusiast
