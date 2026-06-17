#!/usr/bin/env python3
# TP-10-1 Sec 13.1 — single-line output (pyshark, positional args)
import binascii
import socket
import struct
import sys
from pathlib import Path

try:
    import pyshark
except Exception:
    print("Error: Requires pyshark (and tshark). Install with: pip install pyshark", file=sys.stderr)
    raise

import asyncio
loop = asyncio.ProactorEventLoop()
asyncio.set_event_loop(loop)

def load_config(path: Path) -> dict:
    data = {}
    for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        if "=" in s:
            k, v = s.split("=", 1)
            data[k.strip()] = v.strip()
    return data

def ip_is_multicast(ip_str: str) -> bool:
    try:
        ip = struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except OSError:
        return False
    return (ip & 0xF0000000) == 0xE0000000

def ipv4_multicast_to_mac(ip_str: str) -> str:
    ipint = struct.unpack("!I", socket.inet_aton(ip_str))[0]
    low23 = ipint & 0x7FFFFF
    o3 = (low23 >> 16) & 0x7F
    o4 = (low23 >> 8) & 0xFF
    o5 = low23 & 0xFF
    return f"01:00:5e:{o3:02x}:{o4:02x}:{o5:02x}"

def parse_hex_bytes(colon_hex: str) -> bytes:
    s = colon_hex.replace(":", "").replace(" ", "")
    if not s:
        return b""
    try:
        return binascii.unhexlify(s)
    except binascii.Error:
        return b""

def looks_like_rtp_from_udp_payload(payload: bytes) -> bool:
    if len(payload) < 12:
        return False
    b0 = payload[0]
    if ((b0 >> 6) & 0x03) != 2:
        return False
    pt = payload[1]
    if 200 <= pt <= 204:
        return False
    return True

def extract_dscp(pkt) -> int:
    for attr in ("dsfield_dscp", "diffserv_dscp", "dsfield_value_dscp"):
        try:
            if hasattr(pkt.ip, attr):
                val = getattr(pkt.ip, attr)
                if val is not None and str(val).strip() != "":
                    return int(str(val))
        except Exception:
            pass
    try:
        tos_str = getattr(pkt.ip, "tos", None)
        if tos_str:
            tos_int = int(str(tos_str), 16) if str(tos_str).lower().startswith("0x") else int(str(tos_str))
            return (tos_int >> 2) & 0x3F
    except Exception:
        pass
    try:
        ds_str = getattr(pkt.ip, "dsfield", None)
        if ds_str:
            ds_int = int(str(ds_str), 16) if str(ds_str).lower().startswith("0x") else int(str(ds_str))
            return (ds_int >> 2) & 0x3F
    except Exception:
        pass
    return -1

def dscp_name(val: int) -> str:
    names = {
        46: "EF",
        34: "AF41", 36: "AF42", 38: "AF43",
        26: "AF31", 28: "AF32", 30: "AF33",
        18: "AF21", 20: "AF22", 22: "AF23",
        10: "AF11", 12: "AF12", 14: "AF13",
         0: "BE"
    }
    return names.get(val, "")

def evaluate_dscp(dscp: int, cfg: dict):
    if dscp < 0:
        return (False, None)
    ctype = (cfg.get("type") or "").strip().lower()
    expected_map = {"video": 36, "audio": 34}  # AF42 / AF41
    if ctype in expected_map:
        exp = expected_map[ctype]
        return (dscp == exp, exp)
    return (True, None)

def find_first_rtp_multicast_with_pyshark(pcap_path: Path):
    dfilter = "udp && ip && ip.dst >= 224.0.0.0 && ip.dst <= 239.255.255.255"
    cap = pyshark.FileCapture(str(pcap_path), display_filter=dfilter, include_raw=False, use_json=True)
    try:
        for pkt in cap:
            if not hasattr(pkt, 'ip') or not hasattr(pkt, 'udp'):
                continue
            dst_ip = getattr(pkt.ip, 'dst', None)
            if not dst_ip or not ip_is_multicast(dst_ip):
                continue
            dst_mac = getattr(getattr(pkt, 'eth', object()), 'dst', "").lower()
            has_rtp = hasattr(pkt, 'rtp')
            payload_bytes = b""
            try:
                udp_payload_field = getattr(pkt.udp, 'payload', None)
                if udp_payload_field:
                    payload_bytes = parse_hex_bytes(str(udp_payload_field))
                elif hasattr(pkt, 'data') and hasattr(pkt.data, 'data'):
                    payload_bytes = parse_hex_bytes(str(pkt.data.data))
            except Exception:
                pass
            if has_rtp or looks_like_rtp_from_udp_payload(payload_bytes):
                dscp = extract_dscp(pkt)
                return {"dst_ip": dst_ip, "dst_mac": dst_mac, "dscp": dscp}
    finally:
        cap.close()
    return None

def main():
    if len(sys.argv) != 3:
        print("Usage: python TP-10-1Sec13.1.py <config.cfg> <file.pcap>", file=sys.stderr)
        sys.exit(2)

    cfg_path = Path(sys.argv[1]); pcap_path = Path(sys.argv[2])
    if not cfg_path.exists():
        print(f"Error: Config not found: {cfg_path}", file=sys.stderr); sys.exit(2)
    if not pcap_path.exists():
        print(f"Error: PCAP not found: {pcap_path}", file=sys.stderr); sys.exit(2)

    cfg = load_config(cfg_path)
    res = find_first_rtp_multicast_with_pyshark(pcap_path)
    if res is None:
        print("No RTP-over-UDP IPv4 multicast RTP packet found in the provided pcap."); sys.exit(1)

    dst_ip = res["dst_ip"]
    frame_dst_mac = res["dst_mac"]
    expected_mac = ipv4_multicast_to_mac(dst_ip)
    mac_status = "MATCH" if frame_dst_mac == expected_mac else "MISMATCH"

    dscp = res.get("dscp", -1)
    compliant, expected = evaluate_dscp(dscp, cfg)

    if dscp < 0:
        dscp_text = "DSCP: NOT PRESENT / UNAVAILABLE"
    elif compliant:
        nm = dscp_name(dscp)
        dscp_text = f"DSCP: COMPLIANT (value={dscp}{', name='+nm if nm else ''})"
    else:
        found_nm = dscp_name(dscp)
        exp_nm = dscp_name(expected) if expected is not None else ""
        found_disp = f"{dscp} ({found_nm})" if found_nm else f"{dscp}"
        exp_disp = f"{expected} ({exp_nm})" if exp_nm else f"{expected}"
        dscp_text = f"DSCP: NON-COMPLIANT (found={found_disp}, expected={exp_disp})"

    print(
        f"(TP10-1, sec 13.1) {dst_ip} | "
        f"MAC mapping: {mac_status} (expected={expected_mac}, frame_dst={frame_dst_mac}) | "
        f"{dscp_text}"
    )

if __name__ == "__main__":
    main()
