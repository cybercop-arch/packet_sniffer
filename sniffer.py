"""
packet_sniffer.py — A lightweight network packet capture and analysis tool.

Usage:
    sudo python3 packet_sniffer.py [OPTIONS]

Options:
    -i, --interface     Network interface to sniff on (default: eth0)
    -f, --filter        BPF filter string (e.g. "tcp", "udp port 53")
    -c, --count         Number of packets to capture (0 = unlimited)
    -o, --output        Save captured packets to a .pcap file
    -v, --verbose       Show full packet details instead of summary
    --protocols         Comma-separated list to show: tcp,udp,icmp,arp,dns,http
    --no-color          Disable colored output

Examples:
    sudo python3 packet_sniffer.py -i eth0 -f "tcp port 80" -c 100 -o capture.pcap
    sudo python3 packet_sniffer.py -i eth0 --protocols tcp,dns --verbose
    sudo python3 packet_sniffer.py -i wlan0 -f "not arp" -c 50

Author : Samiksha
License: MIT
"""

import argparse
import logging
import os
import signal
import sys
import time
from datetime import datetime

# ── Dependency guard ─────────────────────────────────────────────────────────
try:
    from scapy.all import (
        PcapWriter,
        conf,
        get_if_list,
        sniff,
    )
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
except ImportError:
    sys.exit("[!] Scapy is not installed. Run:  pip install scapy")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("packet_sniffer")

# ── ANSI colour helpers ───────────────────────────────────────────────────────
COLORS = {
    "reset":  "\033[0m",
    "red":    "\033[91m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
}

USE_COLOR = sys.stdout.isatty()

def colorize(text: str, *codes: str) -> str:
    if not USE_COLOR:
        return text
    return "".join(COLORS.get(c, "") for c in codes) + text + COLORS["reset"]


# ── Packet analysis helpers ───────────────────────────────────────────────────

def extract_http_info(packet) -> dict:
    """Return basic HTTP fields if the packet contains an HTTP layer."""
    info = {}
    if packet.haslayer(HTTPRequest):
        layer = packet[HTTPRequest]
        info["method"]  = layer.Method.decode(errors="replace")  if layer.Method  else ""
        info["host"]    = layer.Host.decode(errors="replace")    if layer.Host    else ""
        info["path"]    = layer.Path.decode(errors="replace")    if layer.Path    else ""
    elif packet.haslayer(HTTPResponse):
        layer = packet[HTTPResponse]
        info["status"]  = layer.Status_Code.decode(errors="replace") if layer.Status_Code else ""
    return info


def extract_dns_query(packet) -> str:
    """Return the DNS query name, or an empty string."""
    if packet.haslayer(DNS) and packet[DNS].qr == 0:          # qr == 0 → query
        try:
            return packet[DNSQR].qname.decode(errors="replace").rstrip(".")
        except Exception:
            pass
    return ""


def classify_packet(packet) -> str:
    """Return a short protocol tag for the outermost recognised layer."""
    if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        return "HTTP"
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    return "OTHER"


# ── Main sniffer class ────────────────────────────────────────────────────────

class PacketSniffer:
    """Captures, analyses, and optionally saves network packets."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.interface    = args.interface
        self.bpf_filter   = args.filter
        self.max_count    = args.count          # 0 = unlimited
        self.output_file  = args.output
        self.verbose      = args.verbose
        self.proto_filter = set(p.upper() for p in args.protocols.split(",")) if args.protocols else None

        self.captured     = 0
        self.start_time   = None
        self._pcap_writer = None

        global USE_COLOR
        if args.no_color:
            USE_COLOR = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._validate_interface()
        self._open_pcap_writer()
        self.start_time = time.time()

        log.info("Interface : %s", colorize(self.interface, "cyan", "bold"))
        log.info("BPF filter: %s", self.bpf_filter or "(none)")
        log.info("Output    : %s", self.output_file or "(none)")
        log.info("Max pkts  : %s", self.max_count or "unlimited")
        log.info("Press Ctrl-C to stop.\n")

        signal.signal(signal.SIGINT,  self._handle_exit)
        signal.signal(signal.SIGTERM, self._handle_exit)

        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter or None,
                prn=self._process_packet,
                store=False,
                count=self.max_count if self.max_count else 0,
            )
        finally:
            self._cleanup()

    def _handle_exit(self, *_) -> None:
        self._cleanup()
        sys.exit(0)

    def _cleanup(self) -> None:
        if self._pcap_writer:
            self._pcap_writer.close()
            log.info("Packets saved → %s", self.output_file)
        elapsed = time.time() - (self.start_time or time.time())
        log.info("Captured %d packet(s) in %.1f s.", self.captured, elapsed)

    # ── Validation ────────────────────────────────────────────────────────────

    def _validate_interface(self) -> None:
        if os.geteuid() != 0:
            sys.exit(colorize("[!] Root privileges required. Re-run with sudo.", "red"))
        available = get_if_list()
        if self.interface not in available:
            sys.exit(
                colorize(
                    f"[!] Interface '{self.interface}' not found.\n"
                    f"    Available: {', '.join(available)}",
                    "red",
                )
            )

    # ── PCAP output ───────────────────────────────────────────────────────────

    def _open_pcap_writer(self) -> None:
        if self.output_file:
            self._pcap_writer = PcapWriter(self.output_file, append=False, sync=True)

    # ── Packet processing ─────────────────────────────────────────────────────

    def _process_packet(self, packet) -> None:
        proto = classify_packet(packet)

        # Protocol filter
        if self.proto_filter and proto not in self.proto_filter:
            return

        self.captured += 1

        if self._pcap_writer:
            self._pcap_writer.write(packet)

        self._display_packet(packet, proto)

    def _display_packet(self, packet, proto: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if self.verbose:
            self._display_verbose(packet, proto, ts)
        else:
            self._display_summary(packet, proto, ts)

    def _display_summary(self, packet, proto: str, ts: str) -> None:
        """One-line summary with protocol-specific enrichment."""
        proto_color = {
            "TCP": "green", "UDP": "cyan", "HTTP": "yellow",
            "DNS": "cyan",  "ICMP": "dim", "ARP": "dim",
        }.get(proto, "reset")

        tag = colorize(f"[{proto:<5}]", proto_color, "bold")
        pkt_no = colorize(f"#{self.captured:>5}", "dim")

        enrichment = ""
        if proto == "DNS":
            q = extract_dns_query(packet)
            if q:
                enrichment = colorize(f"  query={q}", "yellow")
        elif proto == "HTTP":
            h = extract_http_info(packet)
            if "method" in h:
                enrichment = colorize(f"  {h['method']} {h['host']}{h['path']}", "yellow")
            elif "status" in h:
                enrichment = colorize(f"  status={h['status']}", "yellow")

        print(f"{ts}  {pkt_no}  {tag}  {packet.summary()}{enrichment}")

    def _display_verbose(self, packet, proto: str, ts: str) -> None:
        """Multi-line detailed dump."""
        sep = colorize("─" * 72, "dim")
        print(f"\n{sep}")
        print(colorize(f"  #{self.captured}  {ts}  {proto}", "bold", "cyan"))
        print(sep)

        if packet.haslayer(IP):
            ip = packet[IP]
            print(f"  {'IP src':<12}: {ip.src}  →  {ip.dst}  (TTL {ip.ttl})")

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = tcp.sprintf("%TCP.flags%")
            print(f"  {'TCP':<12}: {tcp.sport} → {tcp.dport}  flags={flags}  seq={tcp.seq}  ack={tcp.ack}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print(f"  {'UDP':<12}: {udp.sport} → {udp.dport}  len={udp.len}")

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            print(f"  {'ICMP':<12}: type={icmp.type}  code={icmp.code}")

        elif packet.haslayer(ARP):
            arp = packet[ARP]
            op = "who-has" if arp.op == 1 else "is-at"
            print(f"  {'ARP':<12}: {op}  {arp.pdst}  (src {arp.psrc}  /  {arp.hwsrc})")

        if proto == "DNS":
            q = extract_dns_query(packet)
            if q:
                print(f"  {'DNS query':<12}: {q}")

        if proto == "HTTP":
            h = extract_http_info(packet)
            for k, v in h.items():
                print(f"  {k:<12}: {v}")

        # Raw payload preview (first 64 bytes)
        raw = bytes(packet)
        if len(raw) > 0:
            preview = raw[:64].hex(" ")
            print(f"  {'hex':<12}: {preview}{'…' if len(raw) > 64 else ''}")

        print(sep)


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Lightweight packet sniffer — requires root/sudo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-i", "--interface", default="eth0",
                   help="Network interface (default: eth0)")
    p.add_argument("-f", "--filter", default="",
                   help='BPF filter string (e.g. "tcp port 443")')
    p.add_argument("-c", "--count", type=int, default=0,
                   help="Number of packets to capture; 0 = unlimited")
    p.add_argument("-o", "--output", default="",
                   help="Write captured packets to a .pcap file")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show full packet details")
    p.add_argument("--protocols", default="",
                   help="Comma-separated protocol filter: tcp,udp,icmp,arp,dns,http")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colour output")
    return p


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()
    sniffer = PacketSniffer(args)
    sniffer.start()


if __name__ == "__main__":
    main()
