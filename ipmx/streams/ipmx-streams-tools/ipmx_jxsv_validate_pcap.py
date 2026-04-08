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
"""Validate a JPEG XS (jxsv) IPMX PCAP against VSF TR-10-15a requirements.

Checks RFC 9134 RTP payload header conformance, TR-10-11 constant bit-rate
compressed video transport, TR-10-9 frame-to-frame timing, and the JPEG XS
Media Info Block (type 0x0008) in RTCP Sender Reports.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from fractions import Fraction

import ipmx_parse_rtp_pcap
import ipmx_validate_encryption
from ipmx_validate_encryption import detect_encryption
from ipmx_validate_common import (
    CLOCK_RATE,
    Requirement,
    RequirementResult,
    SenderReportInfo,
    check_sdp_ipmx_fmtp,
    check_sr_initial_rtp_clock,
    check_sr_ntp_self_consistent,
    check_sr_ntp_vs_capture_rate,
    check_sr_rc_zero,
    check_sr_rtp_timestamp_nominal,
    compute_nominal_period,
    cross_validate_exactframerate,
    extract_exact_framerate_from_sr,
    interval_variation_in_window,
    nominal_ticks_per_period_from_seconds,
    parse_exactframerate_arg,
    parse_sender_reports,
    resolve_exact_ticks_per_frame,
    simulate_cmax_leaky_bucket,
    summarize_results,
    untestable,
    unwrap_rtp_timestamps,
)
from MatroxSdp import MatroxSdp, MatroxSdpEnums, MediaDescriptor


# ---------------------------------------------------------------------------
# ISO/IEC 21122-2 Ppih / Plev mapping tables
# ---------------------------------------------------------------------------

# Profile name (as used in SDP fmtp) → Ppih 16-bit value
SDP_PROFILE_TO_PPIH: dict[str, int] = {
    "Light422.10":       0x1500,
    "Light444.12":       0x1A00,
    "LightSubline422.10": 0x2500,
    "Main420.12":        0x3240,
    "Main422.10":        0x3540,
    "Main444.12":        0x3A40,
    "Main4444.12":       0x3E40,
    "High420.12":        0x4240,
    "High444.12":        0x4A40,
    "High4444.12":       0x4E40,
    "CHigh444.12":       0x4A44,
    "TDC444.12":         0x4A45,
    "TDCMLS444.12":      0x6A45,
    "MLS.12":            0x6EC0,
    "MLS.16":            0x6ED0,
    "LightBayer":        0x9300,
    "MainBayer":         0xB340,
    "HighBayer":         0xC340,
}

# Level name → Plev high byte (bits 15..8)
SDP_LEVEL_TO_PLEV_HI: dict[str, int] = {
    "1k-1":  0x04,
    "2k-1":  0x10,
    "4k-1":  0x20,
    "4k-2":  0x24,
    "4k-3":  0x28,
    "8k-1":  0x30,
    "8k-2":  0x34,
    "8k-3":  0x38,
    "10k-1": 0x40,
    "Bayer2k-1":  0x04,
    "Bayer4k-1":  0x10,
    "Bayer8k-1":  0x20,
    "Bayer8k-2":  0x24,
    "Bayer8k-3":  0x28,
    "Bayer16k-1": 0x30,
    "Bayer16k-2": 0x34,
    "Bayer16k-3": 0x38,
    "Bayer20k-1": 0x40,
}

# Sublevel name → Plev low byte (bits 7..0)
SDP_SUBLEVEL_TO_PLEV_LO: dict[str, int] = {
    "Full":         0x80,
    "Sublev12bpp":  0x10,
    "Sublev9bpp":   0x0C,
    "Sublev6bpp":   0x08,
    "Sublev4bpp":   0x06,
    "Sublev3bpp":   0x04,
    "Sublev2bpp":   0x03,
}


def sdp_profile_to_ppih(profile_str: str) -> int | None:
    """Convert an SDP profile string to its ISO 21122-2 Ppih value."""
    return SDP_PROFILE_TO_PPIH.get(profile_str)


def sdp_level_sublevel_to_plev(level_str: str, sublevel_str: str) -> int | None:
    """Convert SDP level + sublevel strings to the ISO 21122-2 Plev 16-bit value."""
    hi = SDP_LEVEL_TO_PLEV_HI.get(level_str)
    lo = SDP_SUBLEVEL_TO_PLEV_LO.get(sublevel_str)
    if hi is None or lo is None:
        return None
    return (hi << 8) | lo


PPIH_TO_PROFILE_NAME: dict[int, str] = {v: k for k, v in SDP_PROFILE_TO_PPIH.items()}


# ---------------------------------------------------------------------------
# ISO/IEC 21122 picture segment parsing
#
# Per RFC 9134 §3.4, a JPEG XS picture segment is:
#   Video Support (VS) box  +  Color Specification (CS) box  +  codestream
#
# The VS box (type "jpvs") is an ISOBMFF container (ISO/IEC 21122-3) that
# may contain a "jxpl" sub-box carrying Ppih/Plev.  The codestream starts
# with SOC (0xFF10) and contains the PIH marker segment with dimensions
# and coding parameters.
# ---------------------------------------------------------------------------

class JXSMarker(int, Enum):
    """ISO/IEC 21122-1 Table A.1 — marker codes."""
    SOC = 0xFF10
    EOC = 0xFF11
    PIH = 0xFF12
    CDT = 0xFF13
    WGT = 0xFF14
    COM = 0xFF15
    NLT = 0xFF16
    CWD = 0xFF17
    CTS = 0xFF18
    CRG = 0xFF19
    SLH = 0xFF20
    CAP = 0xFF50


# PIH body layout (after marker + Lpih):
#   Lcod(4) + Ppih(2) + Plev(2) + Wf(2) + Hf(2) + Hsl(2) +
#   Nc(1) + Ng(1) + Ss(1) + Bpc(1) + Fq(1) + Br(1) + NlxNly(1) + flags(1)
# ISO/IEC 21122-1 Table A.6 — PIH body is 24 bytes after the 2-byte Lpih.
PIH_BODY_SIZE = 24


@dataclass
class JXSVCodestreamInfo:
    """Key fields from the JPEG XS picture segment (VS box + PIH).

    Field names and sizes per ISO/IEC 21122-1 Table A.6.
    """
    ppih: int       # Ppih  u(16) — profile (ISO/IEC 21122-2)
    plev: int       # Plev  u(16) — level + sublevel (ISO/IEC 21122-2)
    width: int      # Wf    u(16) — frame width in sample grid positions
    height: int     # Hf    u(16) — frame height in sample grid positions
    cw: int         # Cw    u(16) — precinct width (0 = image-wide)
    hsl: int        # Hsl   u(16) — slice height in precincts
    nc: int         # Nc    u(8)  — number of components
    ng: int         # Ng    u(8)  — coefficients per code group
    ss: int         # Ss    u(8)  — code groups per significance group
    bw: int         # Bw    u(8)  — nominal wavelet coefficient bit precision
    fq: int         # Fq    u(4)  — fractional bits in wavelet coefficients
    br: int         # Br    u(4)  — bits to encode bitplane count in raw
    fslc: int       # Fslc  u(1)  — slice coding mode
    ppoc: int       # Ppoc  u(3)  — progression order
    cpih: int       # Cpih  u(4)  — colour transformation
    nlx: int        # NLx   u(4)  — horizontal wavelet decomposition levels
    nly: int        # NLy   u(4)  — vertical wavelet decomposition levels
    qpih: int       # Qpih  u(4)  — inverse quantizer type
    fs: int         # Fs    u(2)  — sign handling strategy
    rm: int         # Rm    u(2)  — run mode


def _parse_isobmff_boxes(data: bytes) -> tuple[int | None, int | None, int]:
    """Walk the VS and CS boxes preceding the codestream.

    Per RFC 9134 §3.4, a JPEG XS picture segment is:
      Video Support box + Color Specification box + codestream

    The VS box (``jpvs``) is a container whose sub-boxes (``jpvi``,
    ``jxpl``, etc.) may appear in any order chosen by the sender.
    Per RFC 9134 §4.4, once the sender fixes a layout for the first
    frame, all subsequent frames must retain the same box ordering
    and byte offsets.

    This parser is order-agnostic: it walks all boxes, descends into
    known containers, extracts ``jxpl`` wherever it appears, and
    terminates when it encounters SOC (0xFF10).

    Returns ``(ppih, plev, codestream_offset)``.
    """
    ppih: int | None = None
    plev: int | None = None
    container_types = {b"jpvs"}

    offset = 0
    while offset + 8 <= len(data):
        # SOC (0xFF10) followed by another marker (0xFFxx) cannot be a
        # valid ISOBMFF box header, so this is an unambiguous test.
        word0 = int.from_bytes(data[offset : offset + 2], "big")
        if word0 == JXSMarker.SOC:
            return ppih, plev, offset

        box_size = int.from_bytes(data[offset : offset + 4], "big")
        box_type = data[offset + 4 : offset + 8]

        if box_size < 8:
            break

        if box_type in container_types:
            offset += 8  # descend into container children
            continue

        if box_type == b"jxpl" and box_size >= 12:
            ppih = int.from_bytes(data[offset + 8 : offset + 10], "big")
            plev = int.from_bytes(data[offset + 10 : offset + 12], "big")

        offset += box_size

    return ppih, plev, offset


def _find_pih_in_codestream(data: bytes) -> int | None:
    """Return the offset of the PIH marker body within a raw codestream.

    ``data`` must start at SOC.  Scans forward through marker segments
    (CAP, COM, etc.) until PIH is found.
    """
    if len(data) < 2:
        return None
    soc = int.from_bytes(data[0:2], "big")
    if soc != JXSMarker.SOC:
        return None

    offset = 2  # past SOC
    while offset + 2 <= len(data):
        marker = int.from_bytes(data[offset : offset + 2], "big")
        if marker == JXSMarker.PIH:
            return offset + 2  # body starts after the marker word
        if marker < 0xFF00:
            return None
        if offset + 4 > len(data):
            return None
        seg_len = int.from_bytes(data[offset + 2 : offset + 4], "big")
        if seg_len < 2:
            return None
        offset += 2 + seg_len

    return None


def _parse_pih_body(data: bytes, offset: int) -> JXSVCodestreamInfo | None:
    """Parse the PIH marker segment body starting at ``offset``.

    ISO/IEC 21122-1 Table A.6 layout (26 bytes total including Lpih):
      Lpih(2) + Lcod(4) + Ppih(2) + Plev(2) + Wf(2) + Hf(2) + Cw(2) +
      Hsl(2) + Nc(1) + Ng(1) + Ss(1) + Bw(1) +
      [Fq(4)+Br(4)] + [Fslc(1)+Ppoc(3)+Cpih(4)] +
      [NLx(4)+NLy(4)] + [Qpih(4)+Fs(2)+Rm(2)]
    """
    o = offset
    if len(data) < o + 2 + PIH_BODY_SIZE:
        return None

    lpih = int.from_bytes(data[o : o + 2], "big")
    if lpih < 2 + PIH_BODY_SIZE:
        return None
    o += 2  # past Lpih

    o += 4  # Lcod (4 bytes) — skip
    ppih   = int.from_bytes(data[o     : o + 2], "big"); o += 2
    plev   = int.from_bytes(data[o     : o + 2], "big"); o += 2
    width  = int.from_bytes(data[o     : o + 2], "big"); o += 2
    height = int.from_bytes(data[o     : o + 2], "big"); o += 2
    cw     = int.from_bytes(data[o     : o + 2], "big"); o += 2
    hsl    = int.from_bytes(data[o     : o + 2], "big"); o += 2
    nc     = data[o]; o += 1
    ng     = data[o]; o += 1
    ss     = data[o]; o += 1
    bw     = data[o]; o += 1
    fq_br  = data[o]; o += 1
    fslc_ppoc_cpih = data[o]; o += 1
    nlx_nly = data[o]; o += 1
    qpih_fs_rm = data[o]

    return JXSVCodestreamInfo(
        ppih=ppih,
        plev=plev,
        width=width,
        height=height,
        cw=cw,
        hsl=hsl,
        nc=nc,
        ng=ng,
        ss=ss,
        bw=bw,
        fq=(fq_br >> 4) & 0x0F,
        br=fq_br & 0x0F,
        fslc=(fslc_ppoc_cpih >> 7) & 1,
        ppoc=(fslc_ppoc_cpih >> 4) & 0x07,
        cpih=fslc_ppoc_cpih & 0x0F,
        nlx=(nlx_nly >> 4) & 0x0F,
        nly=nlx_nly & 0x0F,
        qpih=(qpih_fs_rm >> 4) & 0x0F,
        fs=(qpih_fs_rm >> 2) & 0x03,
        rm=qpih_fs_rm & 0x03,
    )


def parse_jxsv_codestream_header(data: bytes) -> JXSVCodestreamInfo | None:
    """Parse JPEG XS picture segment info from the payload data after the
    JXSV RTP payload header.

    Per RFC 9134 §3.4, the picture segment is:
      VS box (``jpvs``) + CS box (``colr``) + codestream (SOC…EOC)

    Ppih/Plev are taken from the ``jxpl`` sub-box inside the VS box when
    present; otherwise they fall back to the PIH marker in the codestream.
    Dimensions and coding parameters always come from the PIH.

    Returns *None* if the data is too short or unparseable.
    """
    if len(data) < 4:
        return None

    first_word = int.from_bytes(data[0:2], "big")

    if first_word == JXSMarker.SOC:
        cs_offset = 0
        box_ppih: int | None = None
        box_plev: int | None = None
    else:
        box_ppih, box_plev, cs_offset = _parse_isobmff_boxes(data)

    pih_offset = _find_pih_in_codestream(data[cs_offset:])
    if pih_offset is None:
        return None

    info = _parse_pih_body(data, cs_offset + pih_offset)
    if info is None:
        return None

    if box_ppih is not None and info.ppih == 0:
        info.ppih = box_ppih
    if box_plev is not None and info.plev == 0:
        info.plev = box_plev

    return info


def extract_codestream_info(packets: list[dict[str, Any]]) -> JXSVCodestreamInfo | None:
    """Extract codestream info from the first frame's first packet."""
    for pkt in packets:
        hdr = pkt.get("codestream_header")
        if hdr is not None:
            return parse_jxsv_codestream_header(hdr)
    return None


# ---------------------------------------------------------------------------
# JXSV-specific validation context
# ---------------------------------------------------------------------------

@dataclass
class JXSVFrameInfo:
    """Per-frame summary extracted from ``process_jxsv_stream``."""
    index: int
    timestamp: int
    f_counter: int
    interlace: str
    packet_count: int
    total_payload_bytes: int
    first_capture_time: float | None
    last_capture_time: float | None
    marker_seen: bool
    issues: list[str] = field(default_factory=list)


@dataclass
class SdpJxsvParams:
    """JXSV-relevant parameters extracted from an SDP transport file."""
    media: MediaDescriptor
    ppih: int | None
    plev: int | None
    transmode: int | None   # 0=out-of-order-allowed, 1=sequential-only
    packetmode: int | None  # 0=codestream, 1=slice
    profile_str: str
    level_str: str
    sublevel_str: str


@dataclass
class JXSVValidationContext:
    pcap: Path
    stream_info: ipmx_parse_rtp_pcap.RtpStreamInfo | None
    stream: ipmx_parse_rtp_pcap.JXSVStreamState
    frames: list[JXSVFrameInfo]
    frames_by_ts: dict[int, JXSVFrameInfo]
    packets: list[dict[str, Any]]
    sender_reports: list[SenderReportInfo]
    dst_port: int | None
    sdp: SdpJxsvParams | None = None
    exact_framerate: Fraction | None = None
    encrypted: bool = False
    codestream: JXSVCodestreamInfo | None = None


def _frame_from_report(d: dict[str, Any]) -> JXSVFrameInfo:
    return JXSVFrameInfo(
        index=d["frame_index"],
        timestamp=d["timestamp"],
        f_counter=d["f_counter"],
        interlace=d.get("interlace", "progressive"),
        packet_count=d["packet_count"],
        total_payload_bytes=d["total_payload_bytes"],
        first_capture_time=d.get("first_capture_time"),
        last_capture_time=d.get("last_capture_time"),
        marker_seen=d.get("marker_seen", False),
        issues=list(d.get("issues", [])),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_media_block(sr: SenderReportInfo, block_type: int) -> Any:
    if sr.ipmx_info is None:
        return None
    for block in sr.ipmx_info.media_blocks:
        if block.media_info_type == block_type:
            return block
    return None


# ---------------------------------------------------------------------------
# SDP loader
# ---------------------------------------------------------------------------

def load_sdp_jxsv_params(sdp_path: Path) -> SdpJxsvParams:
    """Parse an SDP file and extract JXSV-relevant parameters."""
    sdp = MatroxSdp()
    err = sdp.decode(sdp_path.read_text())
    if err:
        raise SystemExit(f"SDP parse error: {err}")

    md = sdp.primary_media
    if md.encoding_name != MatroxSdpEnums.EncodingJxsv:
        raise SystemExit(
            f"SDP encoding is '{md.encoding_name}', expected 'jxsv'"
        )

    profile_str = str(md.profile) if md.profile is not None else ""
    level_str = str(md.level) if md.level is not None else ""
    sublevel_str = str(md.sub_level) if md.sub_level is not None else ""

    ppih = sdp_profile_to_ppih(profile_str) if profile_str else None
    plev = sdp_level_sublevel_to_plev(level_str, sublevel_str) if (level_str and sublevel_str) else None

    transmode: int | None = None
    if md.jxsv_trans_mode is not None:
        transmode = 1 if md.jxsv_trans_mode == MatroxSdpEnums.SequentialOnly else 0

    packetmode: int | None = None
    if md.jxsv_packet_mode is not None:
        packetmode = 0 if md.jxsv_packet_mode == MatroxSdpEnums.CodeStream else 1

    return SdpJxsvParams(
        media=md,
        ppih=ppih,
        plev=plev,
        transmode=transmode,
        packetmode=packetmode,
        profile_str=profile_str,
        level_str=level_str,
        sublevel_str=sublevel_str,
    )


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def build_context(args: argparse.Namespace) -> JXSVValidationContext:
    si = ipmx_parse_rtp_pcap.detect_rtp_stream(
        args.pcap,
        port=args.port,
        ssrc=getattr(args, "ssrc", None),
        dst_ip=getattr(args, "dst_ip", None),
    )

    packets_report, frames_report, stream, _ = ipmx_parse_rtp_pcap.process_jxsv_stream(
        args.pcap,
        si.dst_port if si else args.port,
        args.payload_type,
        args.max_frames,
        args.wallclock_backstep_threshold,
        stream_info=si,
    )

    frames = [_frame_from_report(d) for d in frames_report]
    frames_by_ts = {f.timestamp: f for f in frames}

    sender_reports = parse_sender_reports(
        args.pcap, args.rtcp_port, stream_info=si,
    )

    sdp_params: SdpJxsvParams | None = None
    if getattr(args, "sdp", None) is not None:
        sdp_params = load_sdp_jxsv_params(args.sdp)

    exact_fr: Fraction | None = None
    if getattr(args, "exactframerate", None):
        exact_fr = parse_exactframerate_arg(args.exactframerate)

    encrypted = any(
        detect_encryption(meta.get("ext_elements"))
        for meta in packets_report
        if meta.get("ext_elements")
    )

    cs_info: JXSVCodestreamInfo | None = None
    if not encrypted:
        cs_info = extract_codestream_info(packets_report)

    return JXSVValidationContext(
        pcap=args.pcap,
        stream_info=si,
        stream=stream,
        frames=frames,
        frames_by_ts=frames_by_ts,
        packets=packets_report,
        sender_reports=sender_reports,
        dst_port=si.dst_port if si else None,
        sdp=sdp_params,
        exact_framerate=exact_fr,
        encrypted=encrypted,
        codestream=cs_info,
    )


# ---------------------------------------------------------------------------
# RFC 9134 — RTP payload header checks
# ---------------------------------------------------------------------------

def check_rfc9134_t_bit(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """T bit SHALL be identical for all packets (RFC 9134 §4.3)."""
    if not ctx.packets:
        return False, "No JXSV packets detected"
    issues = [i for i in ctx.stream.issues if "T bit changed" in i]
    if issues:
        return False, issues[0]
    return True, f"T bit constant ({ctx.stream.first_t}) across {ctx.stream.packet_count} packets"


def check_rfc9134_k_bit(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """K bit SHALL be identical for all packets (RFC 9134 §4.3)."""
    if not ctx.packets:
        return False, "No JXSV packets detected"
    issues = [i for i in ctx.stream.issues if "K bit changed" in i]
    if issues:
        return False, issues[0]
    return True, f"K bit constant ({ctx.stream.first_k}) across {ctx.stream.packet_count} packets"


def check_rfc9134_t0_requires_k1(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """T=0 (non-sequential) SHALL use K=1 (slice mode) (RFC 9134 §4.3).

    T=1 means packets are sent sequentially; T=0 means they may arrive
    out of codestream order.  When T=0 the slice packetization mode
    (K=1) is required so receivers can reorder.
    """
    if ctx.stream.first_t is None or ctx.stream.first_k is None:
        return False, "No JXSV packets detected"
    if ctx.stream.first_t == 0 and ctx.stream.first_k != 1:
        return False, "T=0 (non-sequential) requires K=1 (slice packetization mode)"
    return True, f"T/K combination valid (T={ctx.stream.first_t}, K={ctx.stream.first_k})"


def check_rfc9134_interlace(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """I=01 is reserved and SHALL NOT be used (RFC 9134 §4.3)."""
    violations = 0
    for pkt in ctx.packets:
        jxsv = pkt.get("jxsv", {})
        if jxsv.get("I") == 1:
            violations += 1
    if violations:
        return False, f"{violations} packets use reserved I=01 value"
    return True, "No packets use reserved I=01"


def check_rfc9134_marker_last(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """L SHALL be set whenever M is set (RFC 9134 §4.3)."""
    violations = 0
    for pkt in ctx.packets:
        jxsv = pkt.get("jxsv", {})
        if pkt.get("marker") and not jxsv.get("L"):
            violations += 1
    if violations:
        return False, f"{violations} packets have M=1 but L=0"
    return True, "L is set on all packets where M is set"


def check_rfc9134_codestream_lm(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """In codestream mode, L and M SHALL have identical values (RFC 9134 §4.3)."""
    if ctx.stream.first_k != ipmx_parse_rtp_pcap.JXSVPacketizationMode.CODESTREAM:
        return True, "Not codestream mode; L/M equivalence not required"
    violations = 0
    for pkt in ctx.packets:
        jxsv = pkt.get("jxsv", {})
        l_bit = jxsv.get("L", 0)
        m_bit = 1 if pkt.get("marker") else 0
        if l_bit != m_bit:
            violations += 1
    if violations:
        return False, f"{violations} packets have L != M in codestream mode"
    return True, "L and M are identical for all packets in codestream mode"


def check_rfc9134_p_counter(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """P counter SHALL start at 0 and increment by 1 within a packetization unit."""
    issues = []
    for frm in ctx.frames:
        for issue in frm.issues:
            if "Packet index gap" in issue:
                issues.append(issue)
    if issues:
        return False, f"{len(issues)} packet index gap(s): {issues[0]}"
    return True, "P counter progression correct in all frames"


def check_rfc9134_frame_issues(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Aggregate per-frame RFC 9134 issues, excluding truncated capture frames."""
    complete = _complete_frames(ctx)
    total = len(ctx.stream.issues)
    for frm in complete:
        total += len(frm.issues)
    if total:
        sample = (ctx.stream.issues + [i for f in complete for i in f.issues])[:5]
        return False, f"{total} issue(s) in {len(complete)} complete frame(s); first: {sample[0]}"
    return True, f"No RFC 9134 conformance issues across {len(complete)} complete frames"


def check_rfc9134_timestamp(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """All packets of the same frame SHALL have the same RTP timestamp."""
    violations = 0
    for frm in ctx.frames:
        ts_set: set[int] = set()
        for pkt in ctx.packets:
            if pkt.get("timestamp") == frm.timestamp:
                ts_set.add(pkt["timestamp"])
        if len(ts_set) > 1:
            violations += 1
    if violations:
        return False, f"{violations} frames have inconsistent timestamps"
    return True, "All packets within each frame share the same RTP timestamp"


def check_rfc9134_clock_rate(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """RTP timestamp clock SHALL be 90 kHz (RFC 9134 §4.2, TR-10-11 §9)."""
    timestamps = [f.timestamp for f in ctx.frames]
    if len(timestamps) < 2:
        return untestable("Not enough frames to verify clock rate")
    unwrapped = unwrap_rtp_timestamps(timestamps)
    deltas = [b - a for a, b in zip(unwrapped, unwrapped[1:]) if b > a]
    if not deltas:
        return False, "No positive timestamp deltas observed"
    deltas.sort()
    median_delta = deltas[len(deltas) // 2]
    nominal = compute_nominal_period(timestamps)
    if nominal is None:
        return False, "Cannot determine nominal period"
    expected_ticks = nominal * CLOCK_RATE
    if abs(median_delta - expected_ticks) / expected_ticks > 0.01:
        return False, f"Median delta {median_delta} ticks inconsistent with 90 kHz clock"
    return True, f"Timestamp increments consistent with 90 kHz clock (median delta {median_delta} ticks)"


# ---------------------------------------------------------------------------
# TR-10-11 — Constant bit-rate compressed video transport
# ---------------------------------------------------------------------------

def check_udp_port_even(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """UDP destination port SHALL be even and > 1024 (TR-10-11 §7)."""
    if ctx.dst_port is None:
        return untestable("Destination port not available")
    issues = []
    if ctx.dst_port % 2 != 0:
        issues.append(f"port {ctx.dst_port} is odd")
    if ctx.dst_port <= 1024:
        issues.append(f"port {ctx.dst_port} is not > 1024")
    if issues:
        return False, "; ".join(issues)
    return True, f"Destination port {ctx.dst_port} is even and > 1024"


def check_udp_port_above_5000(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """UDP destination port SHOULD be > 5000 (TR-10-11 §7)."""
    if ctx.dst_port is None:
        return untestable("Destination port not available")
    if ctx.dst_port <= 5000:
        return False, f"Destination port {ctx.dst_port} is not > 5000"
    return True, f"Destination port {ctx.dst_port} is > 5000"


def check_sr_present(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """RTCP Sender Reports SHALL be present (TR-10-11 §12)."""
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports detected"
    return True, f"{len(ctx.sender_reports)} Sender Report(s) detected"


def check_ipmx_info_block(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """SR SHALL include an IPMX Info Block (tag 0x5831) (TR-10-11 §12)."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    missing = sum(1 for sr in ctx.sender_reports if sr.ipmx_info is None)
    if missing:
        return False, f"{missing}/{len(ctx.sender_reports)} SRs lack IPMX Info Block"
    return True, "All SRs contain an IPMX Info Block"


def check_mib_0x0003(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """SR SHALL contain Media Info Block type 0x0003 (TR-10-11 §12)."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    missing = sum(1 for sr in ctx.sender_reports if find_media_block(sr, 0x0003) is None)
    if missing:
        return False, f"{missing}/{len(ctx.sender_reports)} SRs lack MIB 0x0003"
    return True, "All SRs contain MIB 0x0003 (ConstantSize Compressed Video)"


# ---------------------------------------------------------------------------
# TR-10-15a — JPEG XS Media Info Block (type 0x0008)
# ---------------------------------------------------------------------------

def check_mib_0x0008_present(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """SR SHALL carry MIB type 0x0008 (TR-10-15a §8)."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    missing = sum(1 for sr in ctx.sender_reports if find_media_block(sr, 0x0008) is None)
    if missing:
        return False, f"{missing}/{len(ctx.sender_reports)} SRs lack MIB 0x0008"
    return True, "All SRs contain MIB 0x0008 (JPEG XS)"


def check_mib_0x0008_follows_0x0003(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """MIB 0x0008 SHALL immediately follow MIB 0x0003 (TR-10-15a §8)."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    any_has_0x0008 = any(
        find_media_block(sr, 0x0008) is not None for sr in ctx.sender_reports
    )
    if not any_has_0x0008:
        return untestable("No MIB 0x0008 present — ordering cannot be verified")
    violations = 0
    for sr in ctx.sender_reports:
        if sr.ipmx_info is None:
            violations += 1
            continue
        blocks = sr.ipmx_info.media_blocks
        idx_0003 = None
        idx_0008 = None
        for i, blk in enumerate(blocks):
            if blk.media_info_type == 0x0003 and idx_0003 is None:
                idx_0003 = i
            if blk.media_info_type == 0x0008 and idx_0008 is None:
                idx_0008 = i
        if idx_0003 is None or idx_0008 is None:
            violations += 1
        elif idx_0008 != idx_0003 + 1:
            violations += 1
    if violations:
        return False, f"{violations}/{len(ctx.sender_reports)} SRs: MIB 0x0008 does not immediately follow 0x0003"
    return True, "MIB 0x0008 immediately follows MIB 0x0003 in all SRs"


def _any_mib_0x0008(ctx: JXSVValidationContext) -> bool:
    """Return True if at least one SR contains MIB 0x0008."""
    return any(
        find_media_block(sr, 0x0008) is not None for sr in ctx.sender_reports
    )


def check_mib_0x0008_length(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """MIB 0x0008 length SHALL be 2 (32-bit words minus one) (TR-10-15a §8)."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    if not _any_mib_0x0008(ctx):
        return untestable("No MIB 0x0008 present — length cannot be verified")
    violations = []
    for sr in ctx.sender_reports:
        blk = find_media_block(sr, 0x0008)
        if blk is None:
            continue
        if blk.length_words != 2:
            violations.append(f"length_words={blk.length_words}, expected 2")
    if violations:
        return False, f"{len(violations)} MIB 0x0008 block(s) with wrong length: {violations[0]}"
    return True, "All MIB 0x0008 blocks have length=2"


def check_mib_0x0008_reserved(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Reserved bits in MIB 0x0008 SHALL be 0 (TR-10-15a §8)."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    if not _any_mib_0x0008(ctx):
        return untestable("No MIB 0x0008 present — reserved bits cannot be verified")
    violations = 0
    for sr in ctx.sender_reports:
        blk = find_media_block(sr, 0x0008)
        if blk is None or len(blk.payload) < 4:
            continue
        field0 = int.from_bytes(blk.payload[0:4], "big")
        reserved_mask = 0x3FFFFFFF
        if field0 & reserved_mask:
            violations += 1
    if violations:
        return False, f"{violations} MIB 0x0008 block(s) have non-zero reserved bits"
    return True, "All reserved bits in MIB 0x0008 are zero"


def check_mib_transmode_matches_rtp(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """T-bit in MIB 0x0008 SHALL match T-bit in RTP payload header."""
    if ctx.stream.first_t is None:
        return untestable("No JXSV packets to compare")
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    if not _any_mib_0x0008(ctx):
        return untestable("No MIB 0x0008 present — transmode cannot be verified")
    mismatches = 0
    for sr in ctx.sender_reports:
        blk = find_media_block(sr, 0x0008)
        if blk is None or blk.decoded is None:
            continue
        mib_t = blk.decoded.get("transmode")
        if mib_t is not None and mib_t != ctx.stream.first_t:
            mismatches += 1
    if mismatches:
        return False, f"{mismatches} SR(s): MIB transmode differs from RTP T-bit ({ctx.stream.first_t})"
    return True, f"MIB transmode matches RTP T-bit ({ctx.stream.first_t})"


def check_mib_packetmode_matches_rtp(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Packetmode in MIB 0x0008 SHALL match K-bit in RTP payload header."""
    if ctx.stream.first_k is None:
        return untestable("No JXSV packets to compare")
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    if not _any_mib_0x0008(ctx):
        return untestable("No MIB 0x0008 present — packetmode cannot be verified")
    mismatches = 0
    for sr in ctx.sender_reports:
        blk = find_media_block(sr, 0x0008)
        if blk is None or blk.decoded is None:
            continue
        mib_k = blk.decoded.get("packetmode")
        if mib_k is not None and mib_k != ctx.stream.first_k:
            mismatches += 1
    if mismatches:
        return False, f"{mismatches} SR(s): MIB packetmode differs from RTP K-bit ({ctx.stream.first_k})"
    return True, f"MIB packetmode matches RTP K-bit ({ctx.stream.first_k})"


# ---------------------------------------------------------------------------
# SDP transport file cross-validation
# ---------------------------------------------------------------------------

def check_sdp_ppih_vs_mib(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Ppih in MIB 0x0008 SHALL match the SDP profile (→ Ppih via ISO 21122-2)."""
    if ctx.sdp is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if ctx.sdp.ppih is None:
        return untestable(
            f"Cannot map SDP profile '{ctx.sdp.profile_str}' to a Ppih value"
        )
    if not ctx.sender_reports:
        return False, "No Sender Reports to verify Ppih"
    if not _any_mib_0x0008(ctx):
        return untestable("No MIB 0x0008 present — Ppih cannot be verified against SDP")
    mismatches = 0
    for sr in ctx.sender_reports:
        blk = find_media_block(sr, 0x0008)
        if blk is None or blk.decoded is None:
            continue
        mib_ppih = blk.decoded.get("ppih")
        if mib_ppih is not None and mib_ppih != ctx.sdp.ppih:
            mismatches += 1
    if mismatches:
        return False, (
            f"{mismatches} SR(s): MIB Ppih differs from SDP "
            f"(SDP profile={ctx.sdp.profile_str} → Ppih=0x{ctx.sdp.ppih:04X})"
        )
    return True, (
        f"MIB Ppih=0x{ctx.sdp.ppih:04X} matches SDP profile "
        f"'{ctx.sdp.profile_str}'"
    )


def check_sdp_plev_vs_mib(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Plev in MIB 0x0008 SHALL match the SDP level+sublevel (→ Plev via ISO 21122-2)."""
    if ctx.sdp is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if ctx.sdp.plev is None:
        return untestable(
            f"Cannot map SDP level='{ctx.sdp.level_str}' "
            f"sublevel='{ctx.sdp.sublevel_str}' to a Plev value"
        )
    if not ctx.sender_reports:
        return False, "No Sender Reports to verify Plev"
    if not _any_mib_0x0008(ctx):
        return untestable("No MIB 0x0008 present — Plev cannot be verified against SDP")
    mismatches = 0
    for sr in ctx.sender_reports:
        blk = find_media_block(sr, 0x0008)
        if blk is None or blk.decoded is None:
            continue
        mib_plev = blk.decoded.get("plev")
        if mib_plev is not None and mib_plev != ctx.sdp.plev:
            mismatches += 1
    if mismatches:
        return False, (
            f"{mismatches} SR(s): MIB Plev differs from SDP "
            f"(SDP level={ctx.sdp.level_str}, sublevel={ctx.sdp.sublevel_str} "
            f"→ Plev=0x{ctx.sdp.plev:04X})"
        )
    return True, (
        f"MIB Plev=0x{ctx.sdp.plev:04X} matches SDP level='{ctx.sdp.level_str}' "
        f"sublevel='{ctx.sdp.sublevel_str}'"
    )


# ---------------------------------------------------------------------------
# Codestream-based checks (PIH parsing)
# ---------------------------------------------------------------------------

IPMX_REQUIRED_PPIH = 0x4A40  # High444.12


def check_codestream_profile(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """IPMX Sender SHALL support High444.12 profile (TR-10-15a §7, TR-08 §8.1)."""
    if ctx.encrypted:
        return untestable("Payload encrypted — codestream not accessible")
    if ctx.codestream is None:
        return untestable("Could not parse codestream header from first frame")
    ppih = ctx.codestream.ppih
    name = PPIH_TO_PROFILE_NAME.get(ppih, f"unknown(0x{ppih:04X})")
    if ppih == IPMX_REQUIRED_PPIH:
        return True, f"Codestream Ppih=0x{ppih:04X} ({name}) — High444.12 as required"
    return False, (
        f"Codestream Ppih=0x{ppih:04X} ({name}) — "
        f"expected High444.12 (0x{IPMX_REQUIRED_PPIH:04X})"
    )


def check_codestream_ppih_vs_sdp(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Codestream Ppih SHALL match the profile declared in SDP."""
    if ctx.encrypted:
        return untestable("Payload encrypted — codestream not accessible")
    if ctx.codestream is None:
        return untestable("Could not parse codestream header from first frame")
    if ctx.sdp is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if ctx.sdp.ppih is None:
        return untestable(
            f"Cannot map SDP profile='{ctx.sdp.profile_str}' to a Ppih value"
        )
    cs_ppih = ctx.codestream.ppih
    sdp_ppih = ctx.sdp.ppih
    cs_name = PPIH_TO_PROFILE_NAME.get(cs_ppih, f"0x{cs_ppih:04X}")
    sdp_name = PPIH_TO_PROFILE_NAME.get(sdp_ppih, f"0x{sdp_ppih:04X}")
    if cs_ppih == sdp_ppih:
        return True, (
            f"Codestream Ppih=0x{cs_ppih:04X} ({cs_name}) matches "
            f"SDP profile='{ctx.sdp.profile_str}'"
        )
    return False, (
        f"Codestream Ppih=0x{cs_ppih:04X} ({cs_name}) differs from "
        f"SDP profile='{ctx.sdp.profile_str}' (→ Ppih=0x{sdp_ppih:04X}, {sdp_name})"
    )


def check_codestream_plev_vs_sdp(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Codestream Plev SHALL match the level+sublevel declared in SDP."""
    if ctx.encrypted:
        return untestable("Payload encrypted — codestream not accessible")
    if ctx.codestream is None:
        return untestable("Could not parse codestream header from first frame")
    if ctx.sdp is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if ctx.sdp.plev is None:
        return untestable(
            f"Cannot map SDP level='{ctx.sdp.level_str}' "
            f"sublevel='{ctx.sdp.sublevel_str}' to a Plev value"
        )
    cs_plev = ctx.codestream.plev
    sdp_plev = ctx.sdp.plev
    if cs_plev == sdp_plev:
        return True, (
            f"Codestream Plev=0x{cs_plev:04X} matches "
            f"SDP level='{ctx.sdp.level_str}' sublevel='{ctx.sdp.sublevel_str}'"
        )
    return False, (
        f"Codestream Plev=0x{cs_plev:04X} differs from "
        f"SDP level='{ctx.sdp.level_str}' sublevel='{ctx.sdp.sublevel_str}' "
        f"(→ Plev=0x{sdp_plev:04X})"
    )


def check_codestream_ppih_vs_mib(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Codestream Ppih SHALL match the Ppih in MIB 0x0008."""
    if ctx.encrypted:
        return untestable("Payload encrypted — codestream not accessible")
    if ctx.codestream is None:
        return untestable("Could not parse codestream header from first frame")
    if not ctx.sender_reports:
        return untestable("No Sender Reports available")
    if not _any_mib_0x0008(ctx):
        return untestable("No MIB 0x0008 present — cannot verify Ppih against codestream")
    cs_ppih = ctx.codestream.ppih
    cs_name = PPIH_TO_PROFILE_NAME.get(cs_ppih, f"0x{cs_ppih:04X}")
    mismatches = 0
    checked = 0
    for sr in ctx.sender_reports:
        blk = find_media_block(sr, 0x0008)
        if blk is None or blk.decoded is None:
            continue
        mib_ppih = blk.decoded.get("ppih")
        if mib_ppih is not None:
            checked += 1
            if mib_ppih != cs_ppih:
                mismatches += 1
    if checked == 0:
        return untestable("MIB 0x0008 present but no Ppih field found")
    if mismatches:
        return False, (
            f"{mismatches}/{checked} SR(s): MIB Ppih differs from "
            f"codestream Ppih=0x{cs_ppih:04X} ({cs_name})"
        )
    return True, (
        f"MIB Ppih=0x{cs_ppih:04X} ({cs_name}) matches codestream "
        f"across {checked} SR(s)"
    )


def check_codestream_plev_vs_mib(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Codestream Plev SHALL match the Plev in MIB 0x0008."""
    if ctx.encrypted:
        return untestable("Payload encrypted — codestream not accessible")
    if ctx.codestream is None:
        return untestable("Could not parse codestream header from first frame")
    if not ctx.sender_reports:
        return untestable("No Sender Reports available")
    if not _any_mib_0x0008(ctx):
        return untestable("No MIB 0x0008 present — cannot verify Plev against codestream")
    cs_plev = ctx.codestream.plev
    mismatches = 0
    checked = 0
    for sr in ctx.sender_reports:
        blk = find_media_block(sr, 0x0008)
        if blk is None or blk.decoded is None:
            continue
        mib_plev = blk.decoded.get("plev")
        if mib_plev is not None:
            checked += 1
            if mib_plev != cs_plev:
                mismatches += 1
    if checked == 0:
        return untestable("MIB 0x0008 present but no Plev field found")
    if mismatches:
        return False, (
            f"{mismatches}/{checked} SR(s): MIB Plev differs from "
            f"codestream Plev=0x{cs_plev:04X}"
        )
    return True, f"MIB Plev=0x{cs_plev:04X} matches codestream across {checked} SR(s)"


def check_codestream_dimensions_vs_sdp(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Codestream width/height SHALL match SDP width/height."""
    if ctx.encrypted:
        return untestable("Payload encrypted — codestream not accessible")
    if ctx.codestream is None:
        return untestable("Could not parse codestream header from first frame")
    if ctx.sdp is None:
        return untestable("No SDP transport file provided (use --sdp)")
    md = ctx.sdp.media
    sdp_w = md.width
    sdp_h = md.height
    if sdp_w is None or sdp_h is None:
        return untestable("SDP does not specify width/height")
    cs_w = ctx.codestream.width
    cs_h = ctx.codestream.height
    if cs_w == sdp_w and cs_h == sdp_h:
        return True, f"Codestream {cs_w}x{cs_h} matches SDP"
    return False, f"Codestream {cs_w}x{cs_h} differs from SDP {sdp_w}x{sdp_h}"


def check_sdp_transmode_vs_rtp(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """SDP transmode SHALL match the T-bit in the RTP payload header (RFC 9134 §7)."""
    if ctx.sdp is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if ctx.sdp.transmode is None:
        return untestable("SDP does not specify transmode")
    if ctx.stream.first_t is None:
        return untestable("No JXSV packets to compare")
    if ctx.sdp.transmode != ctx.stream.first_t:
        return False, (
            f"SDP transmode={ctx.sdp.transmode} differs from "
            f"RTP T-bit={ctx.stream.first_t}"
        )
    return True, f"SDP transmode={ctx.sdp.transmode} matches RTP T-bit"


def check_sdp_packetmode_vs_rtp(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """SDP packetmode SHALL match the K-bit in the RTP payload header (RFC 9134 §7)."""
    if ctx.sdp is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if ctx.sdp.packetmode is None:
        return untestable("SDP does not specify packetmode")
    if ctx.stream.first_k is None:
        return untestable("No JXSV packets to compare")
    if ctx.sdp.packetmode != ctx.stream.first_k:
        return False, (
            f"SDP packetmode={ctx.sdp.packetmode} differs from "
            f"RTP K-bit={ctx.stream.first_k}"
        )
    return True, f"SDP packetmode={ctx.sdp.packetmode} matches RTP K-bit"


def check_sdp_port_vs_stream(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """SDP port SHALL match the detected RTP destination port."""
    if ctx.sdp is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if ctx.stream_info is None:
        return untestable("RTP stream not detected")
    sdp_port = ctx.sdp.media.port
    if sdp_port != ctx.stream_info.dst_port:
        return False, (
            f"SDP port={sdp_port} differs from detected "
            f"RTP port={ctx.stream_info.dst_port}"
        )
    return True, f"SDP port={sdp_port} matches detected RTP port"


def check_sdp_dst_ip_vs_stream(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """SDP connection address SHALL match the detected destination IP."""
    if ctx.sdp is None:
        return untestable("No SDP transport file provided (use --sdp)")
    if ctx.stream_info is None:
        return untestable("RTP stream not detected")
    sdp_ip = ctx.sdp.media.connection_address
    if not sdp_ip:
        return untestable("SDP does not specify a connection address")
    if sdp_ip != ctx.stream_info.dst_ip:
        return False, (
            f"SDP connection address={sdp_ip} differs from detected "
            f"dst_ip={ctx.stream_info.dst_ip}"
        )
    return True, f"SDP connection address={sdp_ip} matches detected dst_ip"


# ---------------------------------------------------------------------------
# TR-10-9 — Frame-to-frame timing (applicable to CBR compressed video)
# ---------------------------------------------------------------------------

def _check_interval_tr10_9(
    times: list[float], label: str,
) -> tuple[bool, str] | tuple[bool, str, bool]:
    """TR-10-9 §11.2 requires measurement over a 2-second window."""
    if len(times) < 3:
        return untestable(f"Not enough {label} to assess interval")
    duration = times[-1] - times[0]
    if duration < 2.0:
        return untestable(
            f"Capture duration {duration*1000:.0f}ms < 2s required by TR-10-9 "
            f"({len(times)} {label}, need longer capture)"
        )
    passed, details = interval_variation_in_window(times, window=2.0, tolerance=0.002)
    if not passed and details.startswith("Not enough"):
        return untestable(details)
    return passed, details


def check_frame_interval_tr10_9(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """First-packet capture times SHALL have max-min variation <= 2ms over 2s."""
    times = [
        f.first_capture_time
        for f in ctx.frames
        if f.first_capture_time is not None
    ]
    return _check_interval_tr10_9(times, "frames")  # type: ignore[return-value]


def check_sr_interval_tr10_9(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """SR capture times SHALL have max-min variation <= 2ms over 2s."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    times = [sr.capture_time for sr in ctx.sender_reports]
    return _check_interval_tr10_9(times, "SRs")  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# SR-to-frame cross-validation
# ---------------------------------------------------------------------------

def check_sr_mapping(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Each frame SHALL have a corresponding Sender Report."""
    if not ctx.sender_reports:
        return False, "No RTCP Sender Reports detected"
    sr_timestamps = {sr.rtp_timestamp for sr in ctx.sender_reports}
    missing = [f.timestamp for f in ctx.frames if f.timestamp not in sr_timestamps]
    if missing:
        return False, f"Missing SRs for {len(missing)}/{len(ctx.frames)} frames"
    unknown = [sr for sr in ctx.sender_reports if sr.rtp_timestamp not in ctx.frames_by_ts]
    if unknown:
        last_frame_time = max(
            (f.first_capture_time for f in ctx.frames if f.first_capture_time is not None),
            default=0.0,
        )
        real_unknown = [sr for sr in unknown if sr.capture_time <= last_frame_time]
        if real_unknown:
            return False, f"SRs reference {len(real_unknown)} unknown RTP timestamps"
    return True, "SRs present for all frames"


def check_sr_before_frame(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Sender Report SHALL arrive before the first media packet of the frame."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    violations = 0
    for sr in ctx.sender_reports:
        frm = ctx.frames_by_ts.get(sr.rtp_timestamp)
        if frm is None or frm.first_capture_time is None:
            continue
        if sr.capture_time > frm.first_capture_time:
            violations += 1
    if violations:
        return False, f"{violations} SR(s) arrive after the first media packet"
    return True, "All SRs arrive before the first media packet of their frame"


def check_sr_order(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Sender Reports SHALL be in presentation order."""
    if not ctx.sender_reports:
        return False, "No Sender Reports"
    indices = []
    for sr in ctx.sender_reports:
        frm = ctx.frames_by_ts.get(sr.rtp_timestamp)
        if frm is None:
            continue
        indices.append(frm.index)
    if indices != sorted(indices):
        return False, "SRs are not in presentation order"
    return True, "SRs are in presentation order"


def _check_sr_diff_jxsv(ctx: JXSVValidationContext) -> tuple[bool, str] | tuple[bool, str, bool]:
    """SR RTP timestamp deltas SHALL match nominal frame increment (TR-10-1 §13.3b)."""
    rtp_timestamps = [f.timestamp for f in ctx.frames]
    exact_ticks = resolve_exact_ticks_per_frame(
        ctx.exact_framerate,
        ctx.sender_reports,
        rtp_timestamps,
    )
    return check_sr_rtp_timestamp_nominal(ctx.sender_reports, exact_ticks)


def check_sr_interval(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """SR interval SHOULD match the nominal frame interval."""
    if len(ctx.sender_reports) < 3:
        return untestable("Not enough SRs to assess interval")
    timestamps_sr = [sr.capture_time for sr in ctx.sender_reports]
    intervals = [b - a for a, b in zip(timestamps_sr, timestamps_sr[1:]) if b > a]
    if not intervals:
        return False, "SR intervals unavailable"
    intervals.sort()
    mid = intervals[len(intervals) // 2]
    nominal = compute_nominal_period([f.timestamp for f in ctx.frames])
    if nominal is None:
        return False, "Not enough frames to derive nominal period"
    tolerance = max(0.001, nominal * 0.01)
    if abs(mid - nominal) > tolerance:
        return False, f"SR interval {mid:.6f}s differs from nominal {nominal:.6f}s"
    return True, f"SR interval {mid:.6f}s matches nominal {nominal:.6f}s"


def check_au_interval_const(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """Frame (AU) RTP timestamp intervals SHOULD be constant."""
    timestamps = [f.timestamp for f in ctx.frames]
    if len(timestamps) < 3:
        return untestable("Not enough frames to assess AU interval")
    unwrapped = unwrap_rtp_timestamps(timestamps)
    deltas = [
        (cur - prev) / CLOCK_RATE
        for prev, cur in zip(unwrapped, unwrapped[1:])
        if cur > prev
    ]
    if not deltas:
        return False, "AU intervals unavailable"
    deltas.sort()
    mid = deltas[len(deltas) // 2]
    max_dev = max(abs(d - mid) for d in deltas)
    tolerance = max(0.001, mid * 0.01)
    if max_dev > tolerance:
        return False, f"AU interval variation {max_dev:.6f}s exceeds {tolerance:.6f}s"
    return True, f"AU interval variation {max_dev:.6f}s within {tolerance:.6f}s"


def _complete_frames(ctx: JXSVValidationContext) -> list[JXSVFrameInfo]:
    """Return only frames that are fully captured (have marker and no seq gaps)."""
    frames = list(ctx.frames)
    if frames and not frames[-1].marker_seen:
        frames = frames[:-1]
    if frames and frames[0].packet_count == 1 and not frames[0].marker_seen:
        frames = frames[1:]
    return frames


def check_constant_packets_per_frame(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """In CBR codestream mode the packet count per frame SHALL be constant (RFC 9134 §4.1)."""
    if ctx.stream.first_k != ipmx_parse_rtp_pcap.JXSVPacketizationMode.CODESTREAM:
        return True, "Not codestream mode; constant packet count not strictly required"
    frames = _complete_frames(ctx)
    if len(frames) < 2:
        return untestable("Not enough complete frames to assess packet count constancy")
    counts = [f.packet_count for f in frames]
    if len(set(counts)) == 1:
        return True, f"All {len(frames)} complete frames have {counts[0]} packets"
    return False, f"Packet count varies across {len(frames)} complete frames: min={min(counts)}, max={max(counts)}"


def check_constant_frame_size(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """In CBR mode the payload size per frame SHALL be constant (TR-10-11 / RFC 9134 §4.1)."""
    frames = _complete_frames(ctx)
    if len(frames) < 2:
        return untestable("Not enough complete frames to assess frame size constancy")
    sizes = [f.total_payload_bytes for f in frames]
    if len(set(sizes)) == 1:
        return True, f"All {len(frames)} complete frames have {sizes[0]} payload bytes"
    return False, f"Frame payload size varies across {len(frames)} complete frames: min={min(sizes)}, max={max(sizes)}"


# ---------------------------------------------------------------------------
# Requirement list
# ---------------------------------------------------------------------------

def check_rtp_seq_complete(ctx: JXSVValidationContext) -> tuple[bool, str]:
    """RTP sequence numbers SHALL be contiguous (no missing packets)."""
    seq = ctx.stream.seq_analysis
    if seq.total_received == 0:
        return False, "No RTP packets received"
    if seq.complete:
        return True, seq.summary()
    return False, f"PCAP is incomplete: {seq.summary()}"


def build_requirements(ctx: JXSVValidationContext) -> list[Requirement]:
    reqs: list[Requirement] = []

    def add(req_id: str, level: str, text: str, check: Any) -> None:
        reqs.append(Requirement(req_id=req_id, level=level, text=text, check=check))

    # --- PCAP completeness ---
    add("RTP-SEQ", "shall",
        "RTP sequence numbers SHALL be contiguous — missing packets indicate an incomplete PCAP capture.",
        lambda c=ctx: check_rtp_seq_complete(c))

    # --- RFC 9134: RTP payload header ---
    add("RFC9134-T", "shall",
        "The T-bit value SHALL be identical for all packets of the RTP stream (RFC 9134 §4.3).",
        lambda c=ctx: check_rfc9134_t_bit(c))
    add("RFC9134-K", "shall",
        "The K-bit value SHALL be identical for all packets of the RTP stream (RFC 9134 §4.3).",
        lambda c=ctx: check_rfc9134_k_bit(c))
    add("RFC9134-T0K1", "shall",
        "If T=0 (non-sequential), the slice packetization mode SHALL be used (K=1) (RFC 9134 §4.3).",
        lambda c=ctx: check_rfc9134_t0_requires_k1(c))
    add("RFC9134-I", "shall",
        "I=01 is reserved for future use and SHALL NOT be used (RFC 9134 §4.3).",
        lambda c=ctx: check_rfc9134_interlace(c))
    add("RFC9134-ML", "shall",
        "The L bit SHALL be set whenever the M bit (RTP marker) is set (RFC 9134 §4.3).",
        lambda c=ctx: check_rfc9134_marker_last(c))
    add("RFC9134-CS-LM", "shall",
        "In codestream packetization mode, L and M SHALL have identical values (RFC 9134 §4.3).",
        lambda c=ctx: check_rfc9134_codestream_lm(c))
    add("RFC9134-P", "shall",
        "The P counter SHALL start at 0 and increment by 1 within each packetization unit (RFC 9134 §4.3).",
        lambda c=ctx: check_rfc9134_p_counter(c))
    add("RFC9134-TS", "shall",
        "All packets belonging to the same video frame SHALL have the same RTP timestamp (RFC 9134 §4.2).",
        lambda c=ctx: check_rfc9134_timestamp(c))
    add("RFC9134-CLK", "shall",
        "A 90 kHz clock rate SHALL be used for the RTP timestamp (RFC 9134 §4.2, TR-10-11 §9).",
        lambda c=ctx: check_rfc9134_clock_rate(c))
    add("RFC9134-CBR-PKT", "shall",
        "In CBR codestream mode, the number of RTP packets per frame SHALL be constant (RFC 9134 §4.1).",
        lambda c=ctx: check_constant_packets_per_frame(c))
    add("RFC9134-ISSUES", "shall",
        "The JPEG XS RTP stream SHALL comply with RFC 9134 (aggregate conformance).",
        lambda c=ctx: check_rfc9134_frame_issues(c))

    # --- TR-10-11: Constant bit-rate compressed video transport ---
    add("TR-10-11-7a", "shall",
        "UDP destination port SHALL be even and > 1024 (TR-10-11 §7).",
        lambda c=ctx: check_udp_port_even(c))
    add("TR-10-11-12a", "shall",
        "IPMX Senders SHALL send RTCP Sender Reports (TR-10-11 §12).",
        lambda c=ctx: check_sr_present(c))
    add("TR-10-11-12b", "shall",
        "RTCP Sender Reports SHALL include an IPMX Info Block (TR-10-11 §12).",
        lambda c=ctx: check_ipmx_info_block(c))
    add("TR-10-11-12c", "shall",
        "The Media Info Block type for CBR compressed video SHALL be 0x0003 (TR-10-11 §12).",
        lambda c=ctx: check_mib_0x0003(c))
    add("TR-10-11-CBR", "shall",
        "In CBR mode the compressed frame payload size SHALL be constant (TR-10-11).",
        lambda c=ctx: check_constant_frame_size(c))

    # --- TR-10-15a: JPEG XS Media Info Block ---
    add("TR-10-15a-MIB", "shall",
        "RTCP SR SHALL carry an additional Media Info Block of type 0x0008 (TR-10-15a §8).",
        lambda c=ctx: check_mib_0x0008_present(c))
    add("TR-10-15a-ORDER", "shall",
        "MIB 0x0008 SHALL immediately follow MIB 0x0003 in the IPMX Info Block (TR-10-15a §8).",
        lambda c=ctx: check_mib_0x0008_follows_0x0003(c))
    add("TR-10-15a-LEN", "shall",
        "MIB 0x0008 length SHALL be 2 (32-bit words minus one) (TR-10-15a §8).",
        lambda c=ctx: check_mib_0x0008_length(c))
    add("TR-10-15a-RSVD", "shall",
        "Reserved bits in MIB 0x0008 SHALL be set to 0 (TR-10-15a §8).",
        lambda c=ctx: check_mib_0x0008_reserved(c))
    add("TR-10-15a-T", "shall",
        "T-bit in MIB 0x0008 SHALL match the T-bit in the RFC 9134 RTP payload header (TR-10-15a Table 1).",
        lambda c=ctx: check_mib_transmode_matches_rtp(c))
    add("TR-10-15a-K", "shall",
        "Packetmode in MIB 0x0008 SHALL match the K-bit in the RFC 9134 RTP payload header (TR-10-15a Table 1).",
        lambda c=ctx: check_mib_packetmode_matches_rtp(c))
    add("TR-10-15a-PPIH", "shall",
        "Ppih in MIB 0x0008 SHALL correspond to the JPEG XS Ppih parameter (TR-10-15a Table 1).",
        lambda c=ctx: check_sdp_ppih_vs_mib(c))
    add("TR-10-15a-PLEV", "shall",
        "Plev in MIB 0x0008 SHALL correspond to the JPEG XS Plev parameter (TR-10-15a Table 1).",
        lambda c=ctx: check_sdp_plev_vs_mib(c))
    add("TR-10-15a-RFC", "shall",
        "The JPEG XS coded stream SHALL be encapsulated into RTP per RFC 9134 (TR-10-15a §6).",
        lambda c=ctx: check_rfc9134_frame_issues(c))
    add("TR-10-15a-NMOS-TX", "shall",
        "An IPMX Sender SHALL comply with NMOS BCP-006-01 (TR-10-15a §6).",
        lambda _: untestable("NMOS API behavior not observable in PCAP"))
    add("TR-10-15a-NMOS-RX", "shall",
        "An IPMX Receiver SHALL communicate capabilities through BCP-004-01 (TR-10-15a §6).",
        lambda _: untestable("Receiver capability not observable in PCAP"))
    add("TR-10-15a-PROFILE", "shall",
        "JPEG XS Sender SHALL support High444.12 profile per TR-08 §8.1 (TR-10-15a §7).",
        lambda c=ctx: check_codestream_profile(c))

    # --- Codestream ↔ SDP / MIB cross-validation ---
    add("CS-PPIH-SDP", "shall",
        "Codestream Ppih SHALL match the profile declared in SDP.",
        lambda c=ctx: check_codestream_ppih_vs_sdp(c))
    add("CS-PLEV-SDP", "shall",
        "Codestream Plev SHALL match the level+sublevel declared in SDP.",
        lambda c=ctx: check_codestream_plev_vs_sdp(c))
    add("CS-PPIH-MIB", "shall",
        "Codestream Ppih SHALL match the Ppih in MIB 0x0008.",
        lambda c=ctx: check_codestream_ppih_vs_mib(c))
    add("CS-PLEV-MIB", "shall",
        "Codestream Plev SHALL match the Plev in MIB 0x0008.",
        lambda c=ctx: check_codestream_plev_vs_mib(c))
    add("CS-DIM-SDP", "shall",
        "Codestream width/height SHALL match SDP width/height.",
        lambda c=ctx: check_codestream_dimensions_vs_sdp(c))

    # --- TR-10-11/TR-10-1: SR-to-frame cross-validation ---
    add("TR-10-1-SR-MAP", "shall",
        "Each frame SHALL have a corresponding RTCP Sender Report.",
        lambda c=ctx: check_sr_mapping(c))
    add("TR-10-1-SR-BEFORE", "shall",
        "Sender Report SHALL arrive before the first media packet of the associated frame.",
        lambda c=ctx: check_sr_before_frame(c))
    add("TR-10-1-SR-ORDER", "shall",
        "Sender Reports SHALL be in presentation (RTP timestamp) order.",
        lambda c=ctx: check_sr_order(c))
    add("TR-10-1-SR-DIFF", "shall",
        "SR RTP timestamp deltas SHALL match the nominal frame increment (TR-10-1 §13.3b).",
        lambda c=ctx: _check_sr_diff_jxsv(c))
    add("TR-10-1-FR-XVAL", "shall",
        "CLI --exactframerate SHALL match MIB rate_numerator/rate_denominator when both present.",
        lambda c=ctx: cross_validate_exactframerate(c.exact_framerate, c.sender_reports))

    # --- TR-10-9: Frame-to-frame timing (applicable to CBR compressed) ---
    add("TR-10-9-11.2a", "shall",
        "First-packet capture times SHALL have max-min variation <= 2ms over any 2s window (TR-10-9 §11.2).",
        lambda c=ctx: check_frame_interval_tr10_9(c))
    add("TR-10-9-11.2b", "shall",
        "SR capture times SHALL have max-min variation <= 2ms over any 2s window (TR-10-9 §11.2).",
        lambda c=ctx: check_sr_interval_tr10_9(c))
    add("TR-10-9-11.2c", "shall",
        "For a Baseband IPMX Sender the frame interval SHALL correspond to baseband input timing.",
        lambda _: untestable("Baseband input not observable"))
    add("TR-10-9-11.2d", "shall",
        "For non-baseband IPMX Senders the frame interval SHALL correspond to the nominal frame rate.",
        lambda _: untestable("Sender type not observable"))

    # --- SDP transport file cross-validation (when --sdp is provided) ---
    add("SDP-PORT", "shall",
        "SDP destination port SHALL match the detected RTP stream port.",
        lambda c=ctx: check_sdp_port_vs_stream(c))
    add("SDP-DST-IP", "shall",
        "SDP connection address SHALL match the detected destination IP.",
        lambda c=ctx: check_sdp_dst_ip_vs_stream(c))
    add("SDP-TRANSMODE", "shall",
        "SDP transmode SHALL match the T-bit in the RTP payload header (RFC 9134 §7).",
        lambda c=ctx: check_sdp_transmode_vs_rtp(c))
    add("SDP-PACKETMODE", "shall",
        "SDP packetmode SHALL match the K-bit in the RTP payload header (RFC 9134 §7).",
        lambda c=ctx: check_sdp_packetmode_vs_rtp(c))

    # --- SHOULD requirements ---
    add("TR-10-11-7b", "should",
        "UDP destination port SHOULD be > 5000 (TR-10-11 §7).",
        lambda c=ctx: check_udp_port_above_5000(c))
    add("TR-10-15a-SR-INT", "should",
        "Encoder SHOULD transmit Sender Reports at the nominal frame interval.",
        lambda c=ctx: check_sr_interval(c))
    add("TR-10-15a-AU-INT", "should",
        "Coded frames SHOULD be produced at the nominal interval.",
        lambda c=ctx: check_au_interval_const(c))
    add("TR-10-1-NTP-RATE", "should",
        "SR NTP deltas SHOULD match PCAP capture deltas — sender and capture clocks should advance at the same rate.",
        lambda c=ctx: check_sr_ntp_vs_capture_rate(c.sender_reports))
    add("TR-10-1-NTP-SELF", "should",
        "SR NTP timestamps SHOULD be self-consistent — inter-SR intervals should match the nominal frame period.",
        lambda c=ctx: check_sr_ntp_self_consistent(c.sender_reports))
    add("TR-10-1-8.6-INIT-RTP", "shall",
        "First SR RTP timestamp shall be synchronized with the Internal Clock (TR-10-1 §8.6).",
        lambda c=ctx: check_sr_initial_rtp_clock(c.sender_reports, CLOCK_RATE))
    add("TR-10-1-8.7-RC", "should",
        "RTCP SR reception report count (RC) should be 0 (TR-10-1 §8.7).",
        lambda c=ctx: check_sr_rc_zero(c.sender_reports))
    add("TR-10-1-10.1-IPMX-FMTP", "shall",
        "SDP a=fmtp line shall contain the IPMX keyword (TR-10-1 §10.1).",
        lambda c=ctx: check_sdp_ipmx_fmtp(c.sdp.media if c.sdp is not None else None))

    return reqs


# ---------------------------------------------------------------------------
# Validation runner and output
# ---------------------------------------------------------------------------

def run_validation(ctx: JXSVValidationContext) -> list[RequirementResult]:
    results: list[RequirementResult] = []
    for req in build_requirements(ctx):
        result = req.check(ctx) if callable(req.check) else (False, "No check")
        passed = False
        details = "No check"
        testable = True
        if isinstance(result, tuple):
            if len(result) == 3:
                passed, details, testable = result
            elif len(result) >= 2:
                passed, details = result[:2]
        else:
            passed = bool(result)
        results.append(
            RequirementResult(
                req_id=req.req_id,
                level=req.level,
                text=req.text,
                passed=bool(passed),
                details=str(details),
                testable=bool(testable),
            )
        )
    return results


def _summarize_for_output(results: list[RequirementResult]) -> str:
    if not results:
        return "0/0 passed, 0 failed"
    testable = [r for r in results if r.testable]
    if len(testable) == len(results):
        return summarize_results(results)
    passed = sum(1 for r in testable if r.passed)
    failed = len(testable) - passed
    cannot_test = len(results) - len(testable)
    return f"{passed}/{len(testable)} passed, {failed} failed, {cannot_test} cannot test"


def _filter_results(
    results: list[RequirementResult],
    *,
    full_report: bool,
    pass_report: bool,
    fail_report: bool,
    cannot_report: bool,
) -> list[RequirementResult]:
    if full_report:
        return results
    if pass_report or fail_report or cannot_report:
        filtered: list[RequirementResult] = []
        for res in results:
            if res.testable and pass_report and res.passed:
                filtered.append(res)
            elif res.testable and fail_report and not res.passed:
                filtered.append(res)
            elif (not res.testable) and cannot_report:
                filtered.append(res)
        return filtered
    return [r for r in results if r.testable and not r.passed]


def print_results(
    results: list[RequirementResult],
    *,
    full_report: bool,
    pass_report: bool,
    fail_report: bool,
    cannot_report: bool,
) -> None:
    all_shall = [r for r in results if r.level == "shall"]
    all_should = [r for r in results if r.level == "should"]
    all_info = [r for r in results if r.level == "info"]
    filtered = _filter_results(
        results,
        full_report=full_report,
        pass_report=pass_report,
        fail_report=fail_report,
        cannot_report=cannot_report,
    )
    disp_shall = [r for r in filtered if r.level == "shall"]
    disp_should = [r for r in filtered if r.level == "should"]
    disp_info = [r for r in filtered if r.level == "info"]
    print("SHALL requirements")
    print(_summarize_for_output(all_shall))
    for res in disp_shall:
        status = "PASS" if res.passed else ("CANNOT_TEST" if not res.testable else "FAIL")
        print(f"{status} {res.req_id}: {res.text}")
        print(f"DETAILS: {res.details}")
    print("\nSHOULD requirements")
    print(_summarize_for_output(all_should))
    for res in disp_should:
        status = "PASS" if res.passed else ("CANNOT_TEST" if not res.testable else "FAIL")
        print(f"{status} {res.req_id}: {res.text}")
        print(f"DETAILS: {res.details}")
    if all_info:
        print("\nINFO")
        for res in disp_info:
            print(f"INFO {res.req_id}: {res.text}")
            print(f"DETAILS: {res.details}")


# ---------------------------------------------------------------------------
# CMAX Network Compatibility Model check (TR-10-1 §8.1)
# ---------------------------------------------------------------------------

def _resolve_exactframerate(ctx: JXSVValidationContext) -> Fraction | None:
    """Resolve exact framerate from CLI > MIB."""
    if ctx.exact_framerate is not None:
        return ctx.exact_framerate
    return extract_exact_framerate_from_sr(ctx.sender_reports)


def _run_cmax_check(ctx: JXSVValidationContext) -> list[RequirementResult]:
    """Simulate the ST 2110-21 CMAX leaky bucket for JXSV (constant packet count)."""
    results: list[RequirementResult] = []

    exact_fr = _resolve_exactframerate(ctx)
    if exact_fr is None:
        results.append(RequirementResult(
            req_id="TR-10-1-8.1-CMAX", level="shall",
            text="CINST shall not exceed CMAX (TR-10-1 §8.1 / ST 2110-21 §6.6.1).",
            passed=False, details="No exact framerate available", testable=False,
        ))
        return results

    complete_frames = [f for f in ctx.frames if f.marker_seen]
    if not complete_frames:
        results.append(RequirementResult(
            req_id="TR-10-1-8.1-CMAX", level="shall",
            text="CINST shall not exceed CMAX (TR-10-1 §8.1 / ST 2110-21 §6.6.1).",
            passed=False, details="No complete frames", testable=False,
        ))
        return results

    npackets = complete_frames[0].packet_count
    tframe = Fraction(1, exact_fr)
    capture_times = [
        p["capture_time"] for p in ctx.packets
        if p.get("capture_time") is not None
    ]

    sim = simulate_cmax_leaky_bucket(capture_times, npackets, tframe)

    details = (
        f"NPACKETS={npackets}, CMAX={sim.cmax}, "
        f"TDRAIN={sim.tdrain * 1e6:.1f} us, "
        f"max CINST={sim.max_cinst}"
    )
    if not sim.passed:
        details += f", {sim.violation_count}/{sim.total_packets} packet(s) exceeded CMAX"

    results.append(RequirementResult(
        req_id="TR-10-1-8.1-CMAX", level="shall",
        text="CINST shall not exceed CMAX (TR-10-1 §8.1 / ST 2110-21 §6.6.1).",
        passed=sim.passed, details=details,
    ))
    return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="PCAP file containing JXSV RTP/RTCP")
    parser.add_argument("--port", type=int, help="RTP destination port (auto-detected if omitted)")
    parser.add_argument("--rtcp-port", type=int, help="RTCP destination port (default: RTP port + 1)")
    parser.add_argument("--ssrc", type=lambda x: int(x, 0), help="SSRC (decimal or 0x hex; auto-detected if omitted)")
    parser.add_argument("--dst-ip", dest="dst_ip", help="Destination IP address (auto-detected if omitted)")
    parser.add_argument("--sdp", type=Path, help="SDP transport file for cross-validation (Ppih, Plev, transmode, packetmode)")
    parser.add_argument("--payload-type", type=int, help="Filter by RTP payload type")
    parser.add_argument("--max-frames", type=int, help="Limit number of frames processed")
    parser.add_argument(
        "--wallclock-backstep-threshold",
        type=float,
        help="Backward capture-time jump (seconds) threshold for wallclock disruption detection",
    )
    parser.add_argument("--full-report", action="store_true", help="Show all requirements")
    parser.add_argument("--pass-report", action="store_true", help="Show only passing requirements")
    parser.add_argument("--fail-report", action="store_true", help="Show only failing requirements")
    parser.add_argument("--cannot-test-report", action="store_true", help="Show only untestable requirements")
    parser.add_argument(
        "--exactframerate",
        type=str,
        help="Exact framerate as integer or num/den (e.g. 60, 60000/1001)",
    )
    parser.add_argument(
        "--cmax",
        action="store_true",
        help="Enable CMAX Network Compatibility Model check (TR-10-1 §8.1)",
    )
    parser.add_argument(
        "--hkep",
        action="store_true",
        help="Stream uses HDCP Key Exchange Protocol (HKEP) encryption",
    )
    parser.add_argument(
        "--pep",
        action="store_true",
        help="Stream uses Privacy Encryption Protocol (PEP) encryption",
    )
    args = parser.parse_args()

    if not args.pcap.exists():
        raise SystemExit(f"{args.pcap} does not exist")
    if args.max_frames is not None and args.max_frames <= 0:
        raise SystemExit("--max-frames must be positive")

    if getattr(args, "sdp", None) is not None and not args.sdp.exists():
        raise SystemExit(f"SDP file {args.sdp} does not exist")

    ctx = build_context(args)
    if ctx.encrypted:
        print("[INFO] Encryption detected — payload content is not accessible.")
        print("       Codestream checks will be marked as untestable.\n")
    if ctx.stream_info is not None:
        si = ctx.stream_info
        print(f"Detected RTP stream: dst={si.dst_ip}:{si.dst_port} "
              f"SSRC=0x{si.ssrc:08X} ({si.ssrc}) RTCP port={si.rtcp_port}")
    else:
        print("WARNING: Could not auto-detect RTP stream parameters")
    seq = ctx.stream.seq_analysis
    print(f"RTP: {seq.summary()}")
    print(f"     {len(ctx.frames)} frames")
    print(f"RTCP: {len(ctx.sender_reports)} Sender Report(s)")
    if ctx.sdp is not None:
        s = ctx.sdp
        ppih_str = f"0x{s.ppih:04X}" if s.ppih is not None else "unknown"
        plev_str = f"0x{s.plev:04X}" if s.plev is not None else "unknown"
        print(f"SDP:  profile={s.profile_str} level={s.level_str} "
              f"sublevel={s.sublevel_str}")
        print(f"      Ppih={ppih_str} Plev={plev_str} "
              f"transmode={s.transmode} packetmode={s.packetmode}")
    if ctx.codestream is not None:
        cs = ctx.codestream
        cs_profile = PPIH_TO_PROFILE_NAME.get(cs.ppih, f"unknown(0x{cs.ppih:04X})")
        print(f"Codestream: Ppih=0x{cs.ppih:04X} ({cs_profile}) "
              f"Plev=0x{cs.plev:04X} {cs.width}x{cs.height} "
              f"Nc={cs.nc} NLx={cs.nlx} NLy={cs.nly}")
    elif not ctx.encrypted:
        print("Codestream: could not parse PIH from first frame")
    if not seq.complete:
        print(f"WARNING: {seq.total_missing} RTP packet(s) missing — "
              f"PCAP is incomplete, some checks may be unreliable")
    print()
    results = run_validation(ctx)

    enc_results = ipmx_validate_encryption.run_encryption_checks(
        packets=ctx.packets,
        sender_reports=ctx.sender_reports,
        sdp_media=ctx.sdp.media if ctx.sdp is not None else None,
        flags=ipmx_validate_encryption.EncryptionFlags(
            hkep=args.hkep, pep=args.pep,
        ),
    )
    results.extend(enc_results)

    if args.cmax:
        results.extend(_run_cmax_check(ctx))

    print_results(
        results,
        full_report=args.full_report,
        pass_report=args.pass_report,
        fail_report=args.fail_report,
        cannot_report=args.cannot_test_report,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
