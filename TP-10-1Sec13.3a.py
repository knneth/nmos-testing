#!/usr/bin/env python3
"""
TP-10-1Sec13.3a.py
------------------
Processes the first RTCP Sender Report (PT 200) in a capture and (optionally) the
first RTP packet after it (RTP is used only to complete RTCP checks; no separate
RTP line is printed).

Order of output:
1) (TP10-1, sec 13.3) — RTCP line:
     RTCP MAC mapping, DSCP verdict, RTCP port (RTP+1),
     SR_RTP_TS/NEXT_RTP_TS, and timestamp MATCH verdict
2) (TP10-1, sec 13.3) — SR clock conversion line:
     SR_CLK=<sec>  SR_CLKatSamplerate=<ticks>  SR_RTP=<rtp_ts>  DIFF=<rtp_ts - ticks>
     where:
       SR_CLK            = ptp_time_msw + (ptp_time_lsw / 1e9)
       SR_CLKatSamplerate= MOD(ptp_time_msw*Fs, 2^32) + INT(ptp_time_lsw*Fs/1e9), wrapped to 32 bits
                           with Fs taken from SDP a=rtpmap payload (e.g., 90000 for video, 48000 for audio)
       SR_RTP            = SR RTP timestamp
       DIFF              = SR_RTP - SR_CLKatSamplerate  (in Fs ticks)
3) (TP10-1, sec 13.3 InfoBlock) — IPMX↔SDP summary:
     one “matches” line and one “mismatches” block (both with this tag)

Additional InfoBlock checks:
• If IPMX media_info_type == 1 → SDP rtpmap must contain "raw"
• If IPMX media_info_type == 3 → SDP rtpmap must contain "jxsv"
• If SDP media == audio:
    - compare **sample rate** (rtpmap rate) vs IPMX Audio Info Block
    - compare **sample size** (from Lxx or fmtp samplesize) vs IPMX Audio Info Block
    - compare **channel count** (rtpmap channels) vs IPMX Audio Info Block
    - compare **packet time** (SDP ms) vs IPMX Audio Info Block (µs)
    - compare **measuredsamplerate** (fmtp) vs IPMX Audio Info Block

Notes:
• IPv4-only processing; stops after first SR and its next RTP (if any).
• DSCP policy from IPMX media_info_type:
    - media_info_type 1 or 3 → expected DSCP = 36
    - media_info_type 2 or 4 → expected DSCP = 34
• Port checks:
    - RTCP SR UDP dst port must equal (RTP dst port + 1)
"""

from __future__ import annotations
import sys
import re
import pyshark
from typing import Optional, Dict, Tuple, List

import asyncio
loop = asyncio.ProactorEventLoop()
asyncio.set_event_loop(loop)

# ─────────────────────────────────── helpers ───────────────────────────────── #
_ATTR_CANDIDATES_SR  = (
    "rtcp_sr_rtp_timestamp", "rtcp_sr_rtp_ts",
    "timestamp_rtp", "rtp_timestamp", "rtp_ts", "sr_rtp_ts",
)
_ATTR_CANDIDATES_RTP = ("rtp_timestamp", "timestamp", "rtp_ts")
_ATTR_IP_DST         = ("dst", "ip_dst")


def _extract_first_attr(layer, names) -> str | None:
    for name in names:
        if hasattr(layer, name):
            val = getattr(layer, name)
            if val not in ("", None):
                return str(val)
    for attr in dir(layer):
        for probe in names:
            if probe.endswith(attr) or attr.endswith(probe):
                val = getattr(layer, attr)
                if val not in ("", None):
                    return str(val)
    return None


def _str_to_int(val: str | None) -> int | None:
    if val is None:
        return None
    if isinstance(val, int):
        return val
    s = str(val).strip()
    m_hex = re.search(r'0x[0-9a-fA-F]+', s)
    if m_hex:
        try:
            return int(m_hex.group(0), 16)
        except ValueError:
            pass
    m_dec = re.search(r'[-+]?\d+', s)
    if m_dec:
        try:
            return int(m_dec.group(0), 10)
        except ValueError:
            pass
    return None

def _str_to_float(val: str | None) -> float | None:
    """Convert a string to float, safely (for fractional ms like 0.12)."""
    if val is None:
        return None
    try:
        return float(str(val).strip())
    except Exception:
        return None

def _multicast_ipv4_to_mac(ip_str: str | None) -> str | None:
    if ip_str is None:
        return None
    try:
        a, b, c, d = (int(o) for o in ip_str.split('.'))
    except ValueError:
        return None
    if (a & 0xF0) != 0xE0:  # not multicast 224/4
        return None
    low23 = ((b & 0x7F) << 16) | (c << 8) | d
    mac = [0x01, 0x00, 0x5e, (low23 >> 16) & 0x7F, (low23 >> 8) & 0xFF, low23 & 0xFF]
    return ":".join(f"{byte:02x}" for byte in mac)


def _extract_dscp_from_layers(pkt) -> int | None:
    if not hasattr(pkt, "ip"):
        return None
    ip = pkt.ip
    for name in ("dsfield_dscp", "dsfield.dscp", "ip_dsfield_dscp", "dscp"):
        if hasattr(ip, name):
            v = _str_to_int(getattr(ip, name))
            if v is not None:
                return v
    for name in ("dsfield", "ip_dsfield", "ip.dsfield"):
        if hasattr(ip, name):
            full = _str_to_int(getattr(ip, name))
            if full is not None:
                return (full >> 2) & 0x3F
    return None


def _extract_udp_dst_port(pkt) -> Optional[int]:
    if not hasattr(pkt, "udp"):
        return None
    udp = pkt.udp
    for name in ("dstport", "udp_dstport", "udp.dstport", "dport"):
        if hasattr(udp, name):
            v = getattr(udp, name)
            iv = _str_to_int(str(v)) if v not in ("", None) else None
            if iv is not None:
                return iv
    return None


def _field_to_text(v) -> str | None:
    try:
        for attr in ("showname_value", "value", "show"):
            if hasattr(v, attr):
                s = getattr(v, attr)
                if s not in ("", None):
                    return str(s)
    except Exception:
        pass
    if isinstance(v, (list, tuple)):
        parts = []
        for item in v:
            t = _field_to_text(item)
            if t:
                parts.append(t)
        if parts:
            return ", ".join(parts)
    if isinstance(v, (int, float, bool, str)):
        return str(v)
    return None


def _iter_layer_fields(layer):
    seen = set()
    names = getattr(layer, "field_names", None) or [n for n in dir(layer) if not n.startswith("_")]
    for name in names:
        try:
            v = getattr(layer, name)
        except Exception:
            continue
        if callable(v):
            continue
        t = _field_to_text(v)
        if t not in (None, ""):
            seen.add(name)
            yield name, t
    raw = getattr(layer, "_all_fields", None)
    if isinstance(raw, dict):
        for name, v in raw.items():
            if name in seen:
                continue
            t = _field_to_text(v)
            if t not in (None, ""):
                yield name, t


def _get_eth_dst_mac(pkt) -> Optional[str]:
    if not hasattr(pkt, "eth"):
        return None
    eth = pkt.eth
    candidates = [
        "dst", "eth_dst", "eth_dst_resolved",
        "dhost", "eth_dhost", "eth_dhost_resolved",
        "addr", "eth_addr", "eth_address",
    ]
    for name in candidates:
        if hasattr(eth, name):
            v = getattr(eth, name)
            if v not in ("", None):
                s = str(v).lower()
                if ":" in s and len(s) >= 11:
                    return s
    for fname, fval in _iter_layer_fields(eth):
        lf = fname.lower()
        if any(k in lf for k in ("dst", "dhost", "dest")):
            s = str(fval).lower()
            if ":" in s and len(s) >= 11:
                return s
    return None


# ───────────────────────────────── SDP parsing ─────────────────────────────── #
def _parse_sdp(path: Optional[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not path:
        return out

    # Regex for: a=rtpmap:<pt> <encoding>/<rate>[/<channels>]
    rtpmap_re = re.compile(
        r'^a=rtpmap:\s*(\d+)\s+([A-Za-z0-9._-]+)\s*/\s*(\d+)(?:\s*/\s*(\d+))?\s*$',
        re.IGNORECASE
    )

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith(("#", "//", ";")):
                    continue
                low = line.lower()

                if low.startswith("m="):
                    # m=<media> <port> <proto> <fmt> ...
                    body = line[2:].strip()
                    toks = body.split()
                    if toks:
                        out["media"] = toks[0].lower()  # "audio" / "video" / ...
                    if len(toks) >= 2:
                        port = _str_to_int(toks[1])
                        if port is not None:
                            out["rtp_port"] = str(port)
                    continue

                if low.startswith("a=mediaclk:"):
                    out["mediaclk"] = line.split(":", 1)[1].strip()
                    continue

                if low.startswith("a=ts-refclk:"):
                    out["ts_refclk"] = line.split(":", 1)[1].strip()
                    continue

                if low.startswith("a=rtpmap:"):
                    m = rtpmap_re.match(line)
                    if m:
                        codec = m.group(2).strip().lower()
                        rate  = _str_to_int(m.group(3))
                        ch    = _str_to_int(m.group(4)) if m.group(4) else None
                        out["rtpmap_codec"] = codec
                        if rate is not None:
                            out["rtpmap_rate"]  = str(rate)
                        if ch is not None:
                            out["rtpmap_channels"] = str(ch)
                    else:
                        # Fallback parsing
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            payload = parts[1].strip()
                            segs = [s.strip() for s in payload.split('/')]
                            if segs:
                                out["rtpmap_codec"] = segs[0].lower()
                                if len(segs) >= 2:
                                    r = _str_to_int(segs[1])
                                    if r is not None:
                                        out["rtpmap_rate"] = str(r)
                                if len(segs) >= 3:
                                    ch = _str_to_int(segs[2])
                                    if ch is not None:
                                        out["rtpmap_channels"] = str(ch)
                    continue

               
                # a=ptime:<ms> — allow fractional milliseconds like 0.12, 0.25, 1
                if low.startswith("a=ptime:"):
                    try:
                        val = line.split(":", 1)[1].strip()
                        msf = _str_to_float(val)
                        if msf is not None:
                            out["packet_time_ms"] = str(msf)
                    except Exception:
                        pass
                    continue


                if low.startswith("a=fmtp:"):
                    try:
                        params = line.split(None, 1)[1]
                    except IndexError:
                        continue
                    for part in params.split(";"):
                        p = part.strip()
                        if not p or "=" not in p:
                            continue
                        k, v = p.split("=", 1)
                        k = k.strip()
                        v = v.strip()
                        key_map = {
                            "sampling": "sampling",
                            "depth": "depth",
                            "colorimetry": "colorimetry",
                            "TCS": "TCS",
                            "RANGE": "RANGE",
                            "width": "width",
                            "height": "height",
                            "exactframerate": "exactframerate",
                            "measuredpixclk": "measuredpixclk",
                            "measuredsamplerate": "measuredsamplerate",
                            "htotal": "htotal",
                            "vtotal": "vtotal",
                            # audio-oriented extras
                            "samplesize": "samplesize",
                            "sample_size": "samplesize",
                            "ptime": "packet_time_ms",
                            "packet_time": "packet_time_ms",
                            "channels": "rtpmap_channels",  # some offers restate here
                        }
                        k_l = k.lower()
                        stored = False
                        for probe, canon in key_map.items():
                            if k_l == probe.lower():
                                out[canon] = v
                                stored = True
                                break
                        # Normalize packet_time_ms captured from fmtp (keep fractions)
                        if "packet_time_ms" in out:
                            msf = _str_to_float(out["packet_time_ms"])
                            if msf is not None:
                                out["packet_time_ms"] = str(msf)
                            else:
                                out.pop("packet_time_ms", None)
    except OSError:
        pass

    # Derive audio bit depth from rtpmap codec like "l24", if not present
    codec = (out.get("rtpmap_codec") or "").lower()
    if "samplesize" not in out and codec.startswith("l") and len(codec) >= 2:
        n = _str_to_int(codec[1:])  # "l24" -> 24
        if n is not None:
            out["samplesize"] = str(n)

    return out


# ───────────────────── IPMX RTCP SR extension field access ─────────────────── #
def _get_text(layer, name: str) -> Optional[str]:
    if hasattr(layer, name):
        v = getattr(layer, name)
        for attr in ("showname_value", "value", "show"):
            if hasattr(v, attr):
                s = getattr(v, attr)
                if s not in ("", None):
                    return str(s)
        if isinstance(v, (int, float, bool, str)):
            return str(v)
        if v not in ("", None):
            return str(v)
    return None


def _get_ipmx_fields(pkt) -> Dict[str, str]:
    """
    Extracts both video and audio Info Block fields from ipmx_rtcp_info.
    Audio fields per VSF TR-10-3 PCM Digital Audio (type 0x0002).
    """
    out: Dict[str, str] = {}
    if not hasattr(pkt, "ipmx_rtcp_info"):
        return out
    ipmx = pkt.ipmx_rtcp_info

    # Common/IPMX-level
    mapping_common = {
        "mediaclk":             "mediaclk",
        "ts_refclk":            "ts_refclk",
        "media_info_type":      "media_info_type",
        "ptp_time_msw":         "ptp_time_msw",   # seconds
        "ptp_time_lsw":         "ptp_time_lsw",   # nanoseconds
    }
    for canon, field in mapping_common.items():
        val = _get_text(ipmx, field)
        if val not in (None, ""):
            out[canon] = val

    # Video Info Block
    mapping_video = {
        "sampling":             "video_info_sampling",
        "depth":                "video_info_depth",
        "colorimetry":          "video_info_colorimetry",
        "TCS":                  "video_info_tcs",
        "RANGE":                "video_info_range",
        "width":                "video_info_width",
        "height":               "video_info_height",
        "rate_num":             "video_info_rate_num",
        "rate_denom":           "video_info_rate_denom",
        "measuredpixclk":       "video_info_meas_pix_clk",
        "htotal":               "video_info_htotal",
        "vtotal":               "video_info_vtotal",
    }
    for canon, field in mapping_video.items():
        val = _get_text(ipmx, field)
        if val not in (None, ""):
            out[canon] = val

    # Audio Info Block — include explicit Wireshark fields and safe variants
    audio_field_candidates = {
        # Sample rate (Hz)
        "audio_sampling_rate": [
            "audio_info_samp_rate", "audio_info.samp_rate", "samp_rate",
            "audio_info_sampling_rate", "audio_sampling_rate", "sampling_rate",
        ],
        # Sample size (bits)
        "audio_sample_size": [
            "audio_info_samp_size", "audio_info.samp_size", "samp_size",
            "audio_info_sample_size", "audio_sample_size", "sample_size",
        ],
        # Channel count
        "audio_channel_count": [
            "audio_info_chan_count", "audio_info.chan_count", "chan_count",
            "audio_info_channel_count", "audio_channel_count", "channel_count",
        ],
        # Packet time (µs)
        "audio_packet_time": [
            "audio_info_packet_time", "audio_info.packet_time", "packet_time",
            "audio_packet_time",
        ],
        # Measured sample rate (Hz)
        "measuredsamplerate": [
            "audio_info_meas_samp_rate", "audio_info.meas_samp_rate", "meas_samp_rate",
            "audio_info_measured_sample_rate", "audio_info_measuredsamplerate",
            "measured_sample_rate", "measuredsamplerate", "audio_measured_sample_rate",
        ],
        # Optional: channel-order length if needed later
        "audio_channel_order_length": [
            "audio_info_channel_order_length", "channel_order_length"
        ],
    }

    for canon, name_list in audio_field_candidates.items():
        for fname in name_list:
            val = _get_text(ipmx, fname)
            if val not in (None, ""):
                out[canon] = val
                break

    # If measuredsamplerate still missing, do a resilient scan over all fields
    if "measuredsamplerate" not in out:
        for fname, fval in _iter_layer_fields(ipmx):
            n = fname.lower()
            # Accept variations that include: "audio", "meas", ("sampl" or "samp"), and "rate"
            if ("audio" in n) and ("meas" in n) and (("sampl" in n) or ("samp" in n)) and ("rate" in n):
                out["measuredsamplerate"] = fval
                break
            if (("measured" in n) or ("meas" in n)) and (("sample" in n) or ("samp" in n)) and ("rate" in n):
                out["measuredsamplerate"] = fval
                break

    return out


# ─────────────────────────── DSCP policy (IPMX) ───────────────────────────── #
def _media_type_to_expected_dscp(media_info_type: Optional[str]) -> Optional[int]:
    if not media_info_type:
        return None
    m = re.search(r"\((\d+)\)\s*$", str(media_info_type)) or re.search(r"(\d+)\s*$", str(media_info_type))
    if not m:
        return None
    t = int(m.group(1))
    if t in (1, 3):
        return 36
    if t in (2, 4):
        return 34
    return None


def _media_type_number(media_info_type: Optional[str]) -> Optional[int]:
    """Extract the numeric media_info_type from strings like '... (3)' or '3'."""
    if not media_info_type:
        return None
    m = re.search(r"\((\d+)\)\s*$", str(media_info_type)) or re.search(r"(\d+)\s*$", str(media_info_type))
    return int(m.group(1)) if m else None


# ────────────── IPMX↔SDP compact comparison: prepare strings (no print) ───── #
def _prepare_ipmx_sdp_lines(ipmx: Dict[str, str], sdp: Dict[str, str]) -> Tuple[str, List[str]]:
    comparisons = [
        ("mediaclk",      "mediaclk",      False),
        ("ts_refclk",     "ts_refclk",     False),
        ("sampling",      "sampling",      False),
        ("depth",         "depth",         True),
        ("colorimetry",   "colorimetry",   False),
        ("TCS",           "TCS",           False),
        ("RANGE",         "RANGE",         False),
        ("width",         "width",         True),
        ("height",        "height",        True),
        ("measuredpixclk","measuredpixclk",True),
        ("htotal",        "htotal",        True),
        ("vtotal",        "vtotal",        True),
    ]
    matched: List[str] = []
    mismatches: List[str] = []

    def _str_to_int_safe(s: Optional[str]) -> Optional[int]:
        try:
            return _str_to_int(s)
        except Exception:
            return None

    def _eq(ipmx_val: str, sdp_val: str, numeric: bool) -> bool:
        if numeric:
            i1 = _str_to_int_safe(ipmx_val); i2 = _str_to_int_safe(sdp_val)
            return (i1 is not None and i2 is not None and i1 == i2)
        return (ipmx_val or "").strip() == (sdp_val or "").strip()

    # Standard field-by-field comparisons
    for ipmx_key, sdp_key, is_num in comparisons:
        if ipmx_key in ipmx and sdp_key in sdp:
            if _eq(ipmx[ipmx_key], sdp[sdp_key], is_num):
                matched.append(ipmx_key)
            else:
                mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   {ipmx_key}: {ipmx[ipmx_key]} vs {sdp[sdp_key]}")

    # exactframerate vs (rate_num/rate_denom)
    if ("rate_num" in ipmx and "rate_denom" in ipmx) and ("exactframerate" in sdp):
        try:
            num = float(ipmx["rate_num"]); den = float(ipmx["rate_denom"])
            fr_ipmx = num / den if den != 0 else None
        except Exception:
            fr_ipmx = None
        try:
            fr_sdp = float(sdp["exactframerate"])
        except Exception:
            fr_sdp = None
        if fr_ipmx is not None and fr_sdp is not None:
            if abs(fr_ipmx - fr_sdp) == 0.0:
                matched.append("exactframerate")
            else:
                mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   exactframerate: {fr_ipmx:g} vs {fr_sdp:g}")

    # media_info_type ↔ rtpmap codec check (video types)
    mit = _media_type_number(ipmx.get("media_info_type"))
    rtpmap_codec = (sdp.get("rtpmap_codec") or "").lower().strip() if "rtpmap_codec" in sdp else None
    if mit in (1, 3):
        if not rtpmap_codec:
            mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   rtpmap: (missing in SDP) (required for media_info_type={mit})")
        else:
            if mit == 1:
                if "raw" in rtpmap_codec:
                    matched.append("rtpmap")
                else:
                    mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   rtpmap: {rtpmap_codec} (expected contains 'raw' for media_info_type=1)")
            elif mit == 3:
                if "jxsv" in rtpmap_codec:
                    matched.append("rtpmap")
                else:
                    mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   rtpmap: {rtpmap_codec} (expected contains 'jxsv' for media_info_type=3)")

    # AUDIO-specific comparisons
    if (sdp.get("media") == "audio"):
        # (1) Sample rate: IPMX vs SDP rtpmap rate
        sdp_rate = _str_to_int_safe(sdp.get("rtpmap_rate"))
        ipmx_rate = _str_to_int_safe(ipmx.get("audio_sampling_rate"))
        if (sdp_rate is not None) and (ipmx_rate is not None):
            if ipmx_rate == sdp_rate:
                matched.append("audio_samplerate")
            else:
                mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   audio_samplerate: {ipmx_rate} vs {sdp_rate}")
        elif sdp_rate is not None and ipmx_rate is None:
            mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   audio_samplerate: IPMX missing vs {sdp_rate}")
        elif ipmx_rate is not None and sdp_rate is None:
            mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   audio_samplerate: {ipmx_rate} vs SDP missing")

        # (2) Sample size (bits): IPMX vs SDP (from Lxx or fmtp samplesize)
        ipmx_ss = _str_to_int_safe(ipmx.get("audio_sample_size"))
        sdp_ss  = _str_to_int_safe(sdp.get("samplesize"))
        if (sdp_ss is not None) and (ipmx_ss is not None):
            if ipmx_ss == sdp_ss:
                matched.append("audio_samplesize")
            else:
                mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   audio_samplesize: {ipmx_ss} vs {sdp_ss}")
        elif sdp_ss is not None and ipmx_ss is None:
            mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   audio_samplesize: IPMX missing vs {sdp_ss}")
        elif ipmx_ss is not None and sdp_ss is None:
            mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   audio_samplesize: {ipmx_ss} vs SDP missing")

        # (3) Channel count: IPMX vs SDP rtpmap channels
        ipmx_ch = _str_to_int_safe(ipmx.get("audio_channel_count"))
        sdp_ch  = _str_to_int_safe(sdp.get("rtpmap_channels"))
        if (sdp_ch is not None) and (ipmx_ch is not None):
            if ipmx_ch == sdp_ch:
                matched.append("audio_channels")
            else:
                mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   audio_channels: {ipmx_ch} vs {sdp_ch}")
        elif sdp_ch is not None and ipmx_ch is None:
            mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   audio_channels: IPMX missing vs {sdp_ch}")
        elif ipmx_ch is not None and sdp_ch is None:
            mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   audio_channels: {ipmx_ch} vs SDP missing")

        # (4) Packet time: IPMX (µs) vs SDP (ms)
        # (4) Packet time: IPMX (µs) vs SDP (ms)
        ipmx_pt_us = _str_to_int_safe(ipmx.get("audio_packet_time"))  # microseconds
        sdp_pt_ms_val = sdp.get("packet_time_ms")                     # raw string from SDP (may be fractional)
        sdp_pt_ms  = _str_to_float(sdp_pt_ms_val)                     # milliseconds (float if fractional)

        # NEW: display the SDP ptime as read + converted to microseconds
        if sdp_pt_ms is not None:
            sdp_pt_us = int(round(sdp_pt_ms * 1000))
            print(f"(TP10-1, sec 13.3 InfoBlock)   SDP ptime = {sdp_pt_ms_val} ms  ({sdp_pt_us} µs)")
        else:
            print(f"(TP10-1, sec 13.3 InfoBlock)   SDP ptime = (missing or invalid)")

        if (sdp_pt_ms is not None) and (ipmx_pt_us is not None):
            sdp_pt_us = int(round(sdp_pt_ms * 1000))
            if sdp_pt_us == ipmx_pt_us:
                matched.append("audio_packet_time")
            else:
                mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   audio_packet_time: {ipmx_pt_us} µs vs {sdp_pt_us} µs (SDP {sdp_pt_ms_val} ms)")
        elif (sdp_pt_ms is not None) and (ipmx_pt_us is None):
            sdp_pt_us = int(round(sdp_pt_ms * 1000))
            mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   audio_packet_time: IPMX missing vs {sdp_pt_us} µs (SDP {sdp_pt_ms_val} ms)")
        elif (ipmx_pt_us is not None) and (sdp_pt_ms is None):
            mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   audio_packet_time: {ipmx_pt_us} µs vs SDP missing")

        # (5) measuredsamplerate (fmtp) vs IPMX Audio Info Block
        sdp_ms = sdp.get("measuredsamplerate")
        ipmx_ms = ipmx.get("measuredsamplerate")
        if sdp_ms and ipmx_ms:
            i1 = _str_to_int_safe(ipmx_ms)
            i2 = _str_to_int_safe(sdp_ms)
            if (i1 is not None) and (i2 is not None) and (i1 == i2):
                matched.append("measuredsamplerate")
            else:
                mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   measuredsamplerate: {ipmx_ms} vs {sdp_ms}")
        elif sdp_ms and not ipmx_ms:
            mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   measuredsamplerate: IPMX missing vs {sdp_ms}")
        elif ipmx_ms and not sdp_ms:
            mismatches.append(f"(TP10-1, sec 13.3 InfoBlock)   measuredsamplerate: {ipmx_ms} vs SDP missing")

    if matched:
        matches_line = f"(TP10-1, sec 13.3 InfoBlock) IPMX↔SDP matches: {', '.join(matched)}"
    else:
        matches_line = f"(TP10-1, sec 13.3 InfoBlock) IPMX↔SDP matches: (none)"

    if not mismatches:
        mismatches = ["(TP10-1, sec 13.3 InfoBlock) IPMX↔SDP mismatches: (none)"]
    else:
        mismatches.insert(0, "(TP10-1, sec 13.3 InfoBlock) IPMX↔SDP mismatches:")

    return matches_line, mismatches


# ─────────────── PTP→Fs-ticks helper (wrap to 32-bit RTP space) ───────────── #
def _ptp_to_rate_ticks(msw: Optional[int], lsw: Optional[int], fs: Optional[int]) -> Optional[int]:
    """
    Convert PTP time fields (seconds, nanoseconds) to Fs ticks modulo 2^32.
    Formula:
      MOD(msw*Fs, 2^32) + INT(lsw*Fs/1e9), then wrap to 32-bit.
    """
    if msw is None or fs is None:
        return None
    if lsw is None:
        lsw = 0
    part1 = (msw * fs) % (2**32)
    part2 = (lsw * fs) // 1_000_000_000
    return int((part1 + part2) % (2**32))


# ────────────────────────────────── main logic ─────────────────────────────── #
def stream_sr_vs_first_rtp(pcap_file: str, sdp_path: Optional[str] = None) -> None:
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter="rtp or rtcp",
        keep_packets=False,
        use_json=False,
        include_raw=False,
        custom_parameters=["-n"],
    )

    sr_seen     = False
    sr_ts_raw   = sr_ts_int = None
    sr_mac_state = "SR_MAC_UNKNOWN"
    sr_dscp     = None
    sr_udp_dst  = None
    dscp_expected = None

    # Prebuilt second-line (SR clock) text
    sr_clk_line = "(TP10-1, sec 13.3) SR_CLK=NA  SR_CLKatSamplerate=NA  SR_RTP=NA  DIFF=NA"

    sdp_fields   = _parse_sdp(sdp_path) if sdp_path else {}
    sdp_matches_line: Optional[str] = None
    sdp_mismatches_lines: List[str] = []

    try:
        for pkt in cap:
            if not hasattr(pkt, "ip"):
                continue

            # After SR: first RTP to complete checks and print
            if sr_seen and hasattr(pkt, "rtp"):
                rtp_ts_raw = _extract_first_attr(pkt.rtp, _ATTR_CANDIDATES_RTP)
                rtp_ts_int = _str_to_int(rtp_ts_raw)
                ts_verdict = "MATCH" if (rtp_ts_int is not None and rtp_ts_int == sr_ts_int) else "MISMATCH"

                rtp_udp_dst = _extract_udp_dst_port(pkt)
                if sr_udp_dst is not None and rtp_udp_dst is not None:
                    expected_rtcp = rtp_udp_dst + 1
                    rtcp_port_token = "RTCP_PORT_OK" if sr_udp_dst == expected_rtcp else f"RTCP_PORT_MISMATCH({sr_udp_dst} vs {expected_rtcp})"
                else:
                    rtcp_port_token = "RTCP_PORT=NA"

                # DSCP verdict for SR
                if dscp_expected is not None and sr_dscp is not None:
                    sr_dscp_token = "SR_DSCP_OK" if sr_dscp == dscp_expected else f"SR_DSCP_MISMATCH({sr_dscp} vs {dscp_expected})"
                else:
                    sr_dscp_token = "SR_DSCP=NA"

                # 1) RTCP line
                print(
                    f"(TP10-1, sec 13.3) {sr_mac_state}  {sr_dscp_token}  "
                    f"{rtcp_port_token}  SR_RTP_TS={sr_ts_raw}  NEXT_RTP_TS={rtp_ts_raw}  → {ts_verdict}"
                )
                # 2) SR clock line (prebuilt at SR time)
                print(sr_clk_line)
                # 3) InfoBlock
                if sdp_matches_line:
                    print(sdp_matches_line)
                for line in sdp_mismatches_lines:
                    print(line)
                return

            # Detect first RTCP Sender Report (PT=200)
            if not sr_seen and hasattr(pkt, "rtcp") and getattr(pkt.rtcp, "pt", None) == "200":
                sr_seen = True
                sr_ts_raw = _extract_first_attr(pkt.rtcp, _ATTR_CANDIDATES_SR)
                sr_ts_int = _str_to_int(sr_ts_raw)

                # SR MAC mapping
                sr_mac_dst = _get_eth_dst_mac(pkt)
                sr_ip_dst  = _extract_first_attr(pkt.ip, _ATTR_IP_DST)
                sr_exp_mac = _multicast_ipv4_to_mac(sr_ip_dst)
                if sr_exp_mac and sr_mac_dst:
                    sr_mac_state = "SR_MAC_OK" if sr_mac_dst == sr_exp_mac else "SR_MAC_MISMATCH"
                else:
                    sr_mac_state = "SR_MAC_UNKNOWN"

                # DSCP & UDP dst for SR
                sr_dscp    = _extract_dscp_from_layers(pkt)
                sr_udp_dst = _extract_udp_dst_port(pkt)

                # IPMX fields and DSCP expectation
                ipmx_fields = _get_ipmx_fields(pkt)
                dscp_expected = _media_type_to_expected_dscp(ipmx_fields.get("media_info_type"))

                # Build SR clock line once (and reuse later)
                msw = _str_to_int(ipmx_fields.get("ptp_time_msw")) if "ptp_time_msw" in ipmx_fields else None
                lsw = _str_to_int(ipmx_fields.get("ptp_time_lsw")) if "ptp_time_lsw" in ipmx_fields else None
                # SR_CLK seconds string
                if msw is not None:
                    if lsw is None:
                        lsw = 0
                    sr_clk_sec = f"{(float(msw) + float(lsw)/1_000_000_000.0):.9f}"
                else:
                    sr_clk_sec = "NA"

                # Fs from SDP rtpmap
                fs = _str_to_int(sdp_fields.get("rtpmap_rate")) if "rtpmap_rate" in sdp_fields else None

                # SR_CLKatSamplerate and DIFF
                clk_ticks = _ptp_to_rate_ticks(msw, lsw, fs)
                x_str = str(clk_ticks) if clk_ticks is not None else "NA"
                y_str = sr_ts_raw if sr_ts_raw is not None else "NA"
                if (clk_ticks is not None) and (sr_ts_int is not None):
                    z_str = str(sr_ts_int - clk_ticks)
                else:
                    z_str = "NA"

                sr_clk_line = f"(TP10-1, sec 13.3) SR_CLK={sr_clk_sec}  SR_CLKatSamplerate={x_str}  SR_RTP={y_str}  DIFF={z_str}"

                # Prepare InfoBlock now (printed later)
                if sdp_fields:
                    sdp_matches_line, sdp_mismatches_lines = _prepare_ipmx_sdp_lines(ipmx_fields, sdp_fields)

        # End of capture — SR seen but no RTP arrived
        if sr_seen:
            if dscp_expected is not None and sr_dscp is not None:
                sr_dscp_token = "SR_DSCP_OK" if sr_dscp == dscp_expected else f"SR_DSCP_MISMATCH({sr_dscp} vs {dscp_expected})"
            else:
                sr_dscp_token = "SR_DSCP=NA"
            print(
                f"(TP10-1, sec 13.3) {sr_mac_state}  {sr_dscp_token}  "
                f"RTCP_PORT=NA  SR_RTP_TS={sr_ts_raw}  NEXT_RTP_TS=NA  → NA"
            )
            print(sr_clk_line)
            if sdp_matches_line:
                print(sdp_matches_line)
            for line in sdp_mismatches_lines:
                print(line)

    finally:
        cap.close()


# ───────────────────────────────── entrypoint ─────────────────────────────── #
if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: python TP-10-1Sec13.3a.py <file.pcap|pcapng> [file.sdp]")
    pcap = sys.argv[1]
    sdp  = sys.argv[2] if len(sys.argv) >= 3 else None
    stream_sr_vs_first_rtp(pcap, sdp)
