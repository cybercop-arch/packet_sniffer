# 🕵️‍♂️ Packet Sniffer (Your Own Little Wireshark)

A **simple Python-based packet sniffer** built using **Scapy** and **raw sockets**. It captures raw packets directly from the link layer, allowing you to monitor all incoming and outgoing traffic on a specific network interface (like `eth0`).

---

## 📦 Features

- 🧠 Captures **raw Ethernet frames** using sockets
- 🌐 Converts and parses packets using **Scapy**
- 📥 Displays packet summaries in real-time
- ⚡️ Minimal and lightweight – no GUI, pure CLI
- 🛑 Graceful exit with `Ctrl+C`

---

## 📁 Project Structure

```
packet-sniffer/
│
├── packet\_sniffer.py      # Main script to capture and display network packets
├── README.md              # Documentation
└── requirements.txt       # Dependencies

## 📋 Requirements

- Python 3.x
- Linux or WSL (for raw socket permissions)
- Must be run with **sudo/root privileges**
- Install dependencies:
  
```bash
pip install -r requirements.txt

**`requirements.txt`**

```
scapy

## 🚀 Usage

### 🛠 Step 1: Choose your network interface

Edit this line in `packet_sniffer.py` if you're not using `eth0`:

```python
interface = "eth0"
```

To list all interfaces on your system:

```bash
ip link show
```

---

### 🧪 Step 2: Run the sniffer with root privileges

```bash
sudo python3 packet_sniffer.py
```

It will start printing a summary of every packet captured:

```
Ether / IP / TCP 192.168.0.5:443 > 192.168.0.10:58235 S
Ether / ARP who has 192.168.0.1 says 192.168.0.2
Ether / IP / ICMP echo request 192.168.0.10 > 8.8.8.8
...
```

Stop the capture using `Ctrl+C`.

---

## 🧠 How It Works

* `AF_PACKET` and `SOCK_RAW`: Captures raw data directly from the link layer.
* `sniffer_socket.recvfrom(65535)`: Reads every packet received on the interface.
* `Ether(raw_data)`: Converts the raw bytes into a Scapy-readable packet.
* `packet.summary()`: Displays a concise, one-line summary of the packet.

---

## 🔐 Note on Permissions

Raw sockets require administrative privileges. Always run this tool with:

```bash
sudo python3 packet_sniffer.py
```

---

## 📜 License

MIT License – Feel free to use, modify, and distribute.

---

## 🙋‍♀️ Author

**Samiksha**
Cybersecurity & Forensics Student | Developer | Ethical Hacking Enthusiast

---

## 💬 Example Output

```bash
Ether / IP / TCP 192.168.1.5:443 > 192.168.1.2:54123 S
Ether / ARP who has 192.168.1.1 says 192.168.1.254
Ether / IP / UDP 192.168.1.2:5353 > 224.0.0.251:5353
```

---

## 🧰 Future Ideas

* Add filtering by protocol (e.g., only show TCP or HTTP)
* Save packets to a `.pcap` file
* Implement a basic GUI or web dashboard
* Add timestamping and colored output

---

## 🤝 Contributing

Pull requests are welcome! Please fork the repo and suggest improvements.

```
---

Let me know if you'd like:
- A `requirements.txt` generated separately
- Badge icons (e.g., Python version, license)
- A `.pcap` saving feature added  
- GitHub topics or a repo description

```
