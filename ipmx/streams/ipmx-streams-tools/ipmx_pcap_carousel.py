#!/usr/bin/env python3
# Copyright (C) 2026 Matrox Graphics Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""IPMX PCAP Carousel — stream a PCAP file as chunked UDP multicast and
reassemble it from a tcpdump capture.

Wire format (matches Go's binary.LittleEndian convention):

    Offset  Size  Field
    0       8     Sequence    (uint64, monotonically increasing, never resets)
    8       8     ChunkIndex  (uint64, 0..TotalChunks-1, position within cycle)
    16      8     TotalChunks (uint64, chunks per cycle)
    24      8     FileSize    (uint64, total PCAP file size in bytes)
    32      ...   Payload     (raw bytes from the PCAP file)

Sequence increments forever across cycles for loss detection.
ChunkIndex resets to 0 at the start of each cycle.
A complete cycle is ChunkIndex 0 through TotalChunks-1.
If TotalChunks or FileSize changes, the PCAP has been regenerated.

Usage — send (Python test sender):
    python3 ipmx_pcap_carousel.py send stream.pcap 239.1.0.1 9999

Usage — reassemble from a tcpdump capture:
    tcpdump -i eth0 -w raw.pcap "udp and dst host 239.1.0.1 and dst port 9999"
    python3 ipmx_pcap_carousel.py reassemble raw.pcap stream.pcap [--port 9999]
"""

from __future__ import annotations

import argparse
import math
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Iterator

HEADER_SIZE = 32
HEADER_FMT = "<QQQQ"  # 4 x uint64, little-endian (matches Go binary.LittleEndian)
MAX_CHUNK_PAYLOAD = 1400  # stay well under typical 1500-byte MTU
DEFAULT_PORT = 9999
DEFAULT_MCAST = "239.1.0.1"


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------

def chunk_pcap(
    pcap_data: bytes,
    max_payload: int = MAX_CHUNK_PAYLOAD,
    start_sequence: int = 0,
) -> list[bytes]:
    """Split *pcap_data* into framed UDP datagrams ready to send.

    Each datagram = 32-byte header + up to *max_payload* bytes of file data.
    *start_sequence* is the global Sequence for the first chunk; it
    increments by 1 for each subsequent chunk and never resets.
    """
    file_size = len(pcap_data)
    total_chunks = math.ceil(file_size / max_payload) if file_size > 0 else 1

    datagrams: list[bytes] = []
    for chunk_index in range(total_chunks):
        offset = chunk_index * max_payload
        payload = pcap_data[offset : offset + max_payload]
        header = struct.pack(
            HEADER_FMT,
            start_sequence + chunk_index,
            chunk_index,
            total_chunks,
            file_size,
        )
        datagrams.append(header + payload)

    return datagrams


# ---------------------------------------------------------------------------
# Sender (Python — for testing and standalone use)
# ---------------------------------------------------------------------------

def send_carousel(
    pcap_path: Path,
    mcast_group: str = DEFAULT_MCAST,
    port: int = DEFAULT_PORT,
    loops: int = 0,
    inter_chunk_ms: float = 0.1,
    inter_cycle_ms: float = 100.0,
    ttl: int = 32,
) -> None:
    """Read a PCAP file and send it in a loop as chunked UDP multicast.

    *loops* == 0 means infinite.
    """
    pcap_data = pcap_path.read_bytes()
    total_chunks = math.ceil(len(pcap_data) / MAX_CHUNK_PAYLOAD) if pcap_data else 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

    dest = (mcast_group, port)
    cycle = 0
    global_seq = 0

    try:
        while True:
            datagrams = chunk_pcap(pcap_data, start_sequence=global_seq)
            for dg in datagrams:
                sock.sendto(dg, dest)
                if inter_chunk_ms > 0:
                    time.sleep(inter_chunk_ms / 1000.0)

            global_seq += total_chunks
            cycle += 1
            if loops > 0 and cycle >= loops:
                break

            if inter_cycle_ms > 0:
                time.sleep(inter_cycle_ms / 1000.0)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    print(f"Sent {cycle} cycle(s), {total_chunks} chunks/cycle, "
          f"{len(pcap_data)} bytes, last seq={global_seq - 1}")


def send_unicast(
    pcap_data: bytes,
    host: str = "127.0.0.1",
    port: int = DEFAULT_PORT,
    loops: int = 1,
    inter_chunk_ms: float = 0.0,
) -> int:
    """Send to unicast address (used for loopback testing).

    Returns the next global sequence number after all sends.
    """
    total_chunks = math.ceil(len(pcap_data) / MAX_CHUNK_PAYLOAD) if pcap_data else 1
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dest = (host, port)
    global_seq = 0

    for _ in range(loops):
        datagrams = chunk_pcap(pcap_data, start_sequence=global_seq)
        for dg in datagrams:
            sock.sendto(dg, dest)
            if inter_chunk_ms > 0:
                time.sleep(inter_chunk_ms / 1000.0)
        global_seq += total_chunks

    sock.close()
    return global_seq


# ---------------------------------------------------------------------------
# Reassembly
# ---------------------------------------------------------------------------

def reassemble_from_capture(
    capture_path: Path,
    port: int | None = None,
) -> bytes | None:
    """Read a tcpdump/Wireshark capture and extract the first complete PCAP
    cycle from the carousel framing.

    Returns the original PCAP file bytes, or None if no complete cycle found.
    """
    chunks: dict[int, bytes] = {}
    expected_total: int | None = None
    expected_fsize: int | None = None

    for payload in _iter_udp_payloads(capture_path, port):
        if len(payload) < HEADER_SIZE:
            continue

        seq, chunk_index, total, fsize = struct.unpack(
            HEADER_FMT, payload[:HEADER_SIZE],
        )
        chunk_data = payload[HEADER_SIZE:]

        if total != expected_total or fsize != expected_fsize:
            chunks.clear()
            expected_total = total
            expected_fsize = fsize

        if chunk_index == 0:
            chunks.clear()

        chunks[chunk_index] = chunk_data

        if len(chunks) == total:
            result = b"".join(chunks[i] for i in range(total))
            if len(result) == fsize:
                return result
            chunks.clear()

    return None


def _iter_udp_payloads(
    pcap_path: Path,
    port: int | None,
) -> Iterator[bytes]:
    """Yield raw UDP payloads from a PCAP file.

    Uses the manual parser from ipmx_pcap_reader if available, otherwise
    falls back to scapy.
    """
    try:
        from ipmx_pcap_reader import iter_udp_packets
        for pkt in iter_udp_packets(pcap_path, port):
            yield pkt.payload
    except ImportError:
        from scapy.all import PcapReader, UDP as ScapyUDP  # type: ignore
        with PcapReader(str(pcap_path)) as reader:
            for pkt in reader:
                if not pkt.haslayer(ScapyUDP):
                    continue
                udp = pkt[ScapyUDP]
                if port is not None and udp.dport != port and udp.sport != port:
                    continue
                payload = bytes(udp.payload)
                if payload:
                    yield payload


# ---------------------------------------------------------------------------
# Simulate a capture (for testing without actual network)
# ---------------------------------------------------------------------------

def simulate_capture(
    pcap_data: bytes,
    port: int = DEFAULT_PORT,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "239.1.0.1",
    start_sequence: int = 0,
    cycles: int = 1,
) -> bytes:
    """Create a synthetic tcpdump-style PCAP containing the carousel
    datagrams wrapped in Ethernet/IP/UDP.

    Returns raw PCAP file bytes that can be fed to reassemble_from_capture.
    """
    from scapy.all import (  # type: ignore
        Ether, IP, UDP as ScapyUDP, Raw, wrpcap,
    )
    import tempfile

    total_chunks = math.ceil(len(pcap_data) / MAX_CHUNK_PAYLOAD) if pcap_data else 1
    global_seq = start_sequence

    packets = []
    t = time.time()
    for _ in range(cycles):
        datagrams = chunk_pcap(pcap_data, start_sequence=global_seq)
        for dg in datagrams:
            pkt = (
                Ether(src="02:00:00:00:00:01", dst="01:00:5e:01:00:01")
                / IP(src=src_ip, dst=dst_ip)
                / ScapyUDP(sport=12345, dport=port)
                / Raw(load=dg)
            )
            pkt.time = t
            packets.append(pkt)
            t += 0.0001
        global_seq += total_chunks

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    wrpcap(str(tmp_path), packets)
    result = tmp_path.read_bytes()
    tmp_path.unlink()
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="IPMX PCAP Carousel — send or reassemble streamed PCAPs",
    )
    sub = parser.add_subparsers(dest="command")

    # --- send ---
    p_send = sub.add_parser("send", help="Send a PCAP as chunked UDP multicast")
    p_send.add_argument("pcap", type=Path, help="PCAP file to stream")
    p_send.add_argument("--mcast", default=DEFAULT_MCAST, help="Multicast group")
    p_send.add_argument("--port", type=int, default=DEFAULT_PORT, help="UDP port")
    p_send.add_argument("--loops", type=int, default=0, help="Cycles (0=infinite)")
    p_send.add_argument("--ttl", type=int, default=32, help="Multicast TTL")

    # --- reassemble ---
    p_asm = sub.add_parser(
        "reassemble",
        help="Reassemble original PCAP from a tcpdump capture",
    )
    p_asm.add_argument("capture", type=Path, help="tcpdump capture file")
    p_asm.add_argument("output", type=Path, help="Output PCAP path")
    p_asm.add_argument("--port", type=int, default=None, help="Filter by UDP port")

    args = parser.parse_args()

    if args.command == "send":
        if not args.pcap.exists():
            print(f"Error: {args.pcap} not found", file=sys.stderr)
            return 1
        send_carousel(args.pcap, args.mcast, args.port, args.loops, ttl=args.ttl)
        return 0

    elif args.command == "reassemble":
        if not args.capture.exists():
            print(f"Error: {args.capture} not found", file=sys.stderr)
            return 1

        result = reassemble_from_capture(args.capture, args.port)
        if result is None:
            print("Error: no complete PCAP cycle found in capture", file=sys.stderr)
            return 1

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(result)
        print(f"Reassembled {len(result)} bytes -> {args.output}")
        return 0

    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
