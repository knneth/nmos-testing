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
"""Augment an RTP PCAP with IPMX RTCP Sender Reports."""

from __future__ import annotations

import argparse
import json
import math
import shutil
import struct
import sys
from decimal import Decimal, InvalidOperation
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from fractions import Fraction

from scapy.all import Ether, rdpcap, wrpcap, conf as scapy_conf
from scapy.layers.inet import IP, UDP

import ipmx_pcap_reader
import ipmx_sender_report
import ipmx_parse_rtp_pcap
from ipmx_am824 import (
    compute_audio_sender_report_interval_packets,
    resolve_nominal_packet_time_us,
)
from ipmx_validate_encryption import detect_encryption, EncExtLValue
from ipmx_validate_common import (
    infer_ticks_per_frame_from_rtp,
    parse_exactframerate_arg,
    rtp_timestamp_to_ipmx_ptp,
    run_ffmpeg_trace_lenient,
    unix_to_ipmx_ptp,
    unwrap_rtp_timestamps,
    write_elementary_stream,
    CLOCK_RATE,
)

EPSILON = 1e-4

ETHERNET_HEADER_SIZE = ipmx_pcap_reader.ETHERNET_HEADER_SIZE
AUDIO_SR_TIME_MARGIN = 1e-6
PCM_MIB_TYPE = 0x0002


@dataclass
class FrameInfo:
    index: int
    timestamp: int
    first_packet_time: float


@dataclass
class AudioPacketInfo:
    packet_index: int
    seq: int
    timestamp: int
    capture_time: float
    payload_bytes: int


@dataclass
class AudioSenderReportPoint:
    packet_index: int
    timestamp: int
    packet_count: int
    octet_count: int
    packet_capture_time: float
    sr_capture_time: float


@dataclass
class WallclockDisruption:
    index: int
    previous_capture_time: float
    current_capture_time: float
    capture_delta: float
    previous_timestamp: int
    current_timestamp: int
    rtp_delta: float


@dataclass
class TimestampDisruption:
    index: int
    previous_timestamp: int
    current_timestamp: int
    rtp_delta: float


def quantize_pcap_time(timestamp: float) -> float:
    seconds = math.floor(timestamp)
    usec = int((timestamp - seconds) * 1_000_000)
    return seconds + usec / 1_000_000


def min_au_offset(
    frames: Sequence[FrameInfo],
    sr_times: Sequence[float],
    skip_indices: set[int],
    *,
    quantize: bool = True,
) -> float | None:
    min_offset: float | None = None
    for idx, (frame, sr_time) in enumerate(zip(frames, sr_times)):
        if idx in skip_indices:
            continue
        effective_sr = quantize_pcap_time(sr_time) if quantize else sr_time
        offset = frame.first_packet_time - effective_sr
        if min_offset is None or offset < min_offset:
            min_offset = offset
    return min_offset


def checksum(data: bytes) -> int:
    total = 0
    for i in range(0, len(data), 2):
        word = data[i] << 8
        if i + 1 < len(data):
            word |= data[i + 1]
        else:
            word |= 0
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def parse_indices(value: str) -> list[int]:
    if not value:
        return []
    parts = [x.strip() for x in value.split(",")]
    indexes: list[int] = []
    for part in parts:
        if not part:
            continue
        indexes.append(int(part))
    return indexes


def parse_audio_ptime_arg(value: str) -> int:
    try:
        milliseconds = Decimal(value)
    except InvalidOperation as exc:
        raise argparse.ArgumentTypeError(f"Invalid ptime '{value}'") from exc
    if milliseconds <= 0:
        raise argparse.ArgumentTypeError("ptime must be > 0 ms")
    microseconds = milliseconds * Decimal(1000)
    if microseconds != microseconds.to_integral_value():
        raise argparse.ArgumentTypeError(
            "ptime must resolve to an integer number of microseconds"
        )
    return int(microseconds)


def build_ip_header(
    src_ip: bytes,
    dst_ip: bytes,
    total_length: int,
    ttl: int,
    tos: int,
    identification: int,
) -> bytes:
    version_ihl = (4 << 4) | 5
    flags_fragment = 0
    header = bytearray(20)
    header[0] = version_ihl
    header[1] = tos
    header[2:4] = total_length.to_bytes(2, "big")
    header[4:6] = identification.to_bytes(2, "big")
    header[6:8] = flags_fragment.to_bytes(2, "big")
    header[8] = ttl
    header[9] = 17  # UDP
    header[10:12] = b"\x00\x00"
    header[12:16] = src_ip
    header[16:20] = dst_ip
    header[10:12] = checksum(header).to_bytes(2, "big")
    return bytes(header)


def build_udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    length = 8 + payload_len
    return struct.pack(">HHHH", src_port, dst_port, length, 0)


def is_vcl(codec: str, nal_type: int) -> bool:
    if codec == "h264":
        return 1 <= nal_type <= 5
    return 0 <= nal_type <= 31


def compute_frames_from_packets(
    packets: Sequence[ipmx_parse_rtp_pcap.RTPPacket],
    codec: str,
    *,
    encrypted: bool = False,
) -> list["FrameInfo"]:
    first_seen: dict[int, float] = {}
    order: list[int] = []
    seen_ts: set[int] = set()
    skip_nal_filter = encrypted or codec == "jxsv"
    for pkt in packets:
        if pkt.capture_time is None:
            continue
        if not skip_nal_filter:
            packet_nal_types = ipmx_parse_rtp_pcap.extract_packet_nal_types(
                codec, pkt.payload,
            )
            if not any(is_vcl(codec, nal_type) for nal_type in packet_nal_types):
                continue
        ts = int(pkt.timestamp)
        current = first_seen.get(ts)
        if current is None or pkt.capture_time < current:
            first_seen[ts] = pkt.capture_time
        if ts not in seen_ts:
            seen_ts.add(ts)
            order.append(ts)
    return [
        FrameInfo(index=i, timestamp=ts, first_packet_time=first_seen[ts])
        for i, ts in enumerate(order)
    ]


def unwrap_rtp_timestamps(frames: Sequence[FrameInfo]) -> list[int]:
    if not frames:
        return []
    result: list[int] = []
    wraps = 0
    prev = frames[0].timestamp
    for frame in frames:
        current = frame.timestamp
        if current < prev and (prev - current) > 0x80000000:
            wraps += 1
        result.append(current + wraps * (1 << 32))
        prev = current
    return result


def build_sr_schedule(
    frames: Sequence[FrameInfo], clock_rate: int, sr_margin: float
) -> tuple[list[float], list[float]]:
    if not frames:
        return [], []
    unwrapped = unwrap_rtp_timestamps(frames)
    base_ts = unwrapped[0]
    elapsed = [(ts - base_ts) / clock_rate for ts in unwrapped]

    # Keep RTP-timeline spacing, then shift the whole schedule so every SR
    # is still emitted before the corresponding AU hits the wire.
    base_time_candidates = [
        frame.first_packet_time - EPSILON - rel + sr_margin
        for frame, rel in zip(frames, elapsed)
    ]
    base_time = min(base_time_candidates)
    sr_times = [base_time + rel - sr_margin for rel in elapsed]
    return sr_times, elapsed


def nominal_period_from_timestamps(
    frames: Sequence["FrameInfo"], clock_rate: int
) -> float:
    if len(frames) < 2:
        return 1.0 / 60
    periods = []
    for previous, current in zip(frames, frames[1:]):
        delta = (current.timestamp - previous.timestamp) & 0xFFFFFFFF
        periods.append(delta / clock_rate)
    periods.sort()
    mid = len(periods) // 2
    if len(periods) % 2:
        return periods[mid]
    return (periods[mid - 1] + periods[mid]) / 2.0


def find_wallclock_disruption(
    frames: Sequence[FrameInfo], clock_rate: int, backstep_threshold: float
) -> WallclockDisruption | None:
    for idx in range(1, len(frames)):
        previous = frames[idx - 1]
        current = frames[idx]
        capture_delta = current.first_packet_time - previous.first_packet_time
        if capture_delta >= -backstep_threshold:
            continue
        rtp_delta = ((current.timestamp - previous.timestamp) & 0xFFFFFFFF) / clock_rate
        return WallclockDisruption(
            index=idx,
            previous_capture_time=previous.first_packet_time,
            current_capture_time=current.first_packet_time,
            capture_delta=capture_delta,
            previous_timestamp=previous.timestamp,
            current_timestamp=current.timestamp,
            rtp_delta=rtp_delta,
        )
    return None


def find_timestamp_disruption(
    frames: Sequence[FrameInfo], clock_rate: int
) -> TimestampDisruption | None:
    if len(frames) < 2:
        return None
    prev = frames[0].timestamp
    for idx in range(1, len(frames)):
        current = frames[idx].timestamp
        if current < prev and (prev - current) < 0x80000000:
            rtp_delta = ((current - prev) & 0xFFFFFFFF) / clock_rate
            return TimestampDisruption(
                index=idx,
                previous_timestamp=prev,
                current_timestamp=current,
                rtp_delta=rtp_delta,
            )
        prev = current
    return None


def collect_rtp_packets(
    pcap: Path,
    port: int | None,
    codec: str,
    max_access_units: int | None,
) -> list[ipmx_parse_rtp_pcap.RTPPacket]:
    packets: list[ipmx_parse_rtp_pcap.RTPPacket] = []
    for pkt in ipmx_parse_rtp_pcap.iter_rtp_packets_stream(pcap, port):
        packets.append(pkt)
    return packets


def collect_audio_packets(
    packets: Sequence[ipmx_parse_rtp_pcap.RTPPacket],
) -> list[AudioPacketInfo]:
    audio_packets: list[AudioPacketInfo] = []
    for index, packet in enumerate(packets):
        if packet.capture_time is None:
            continue
        audio_packets.append(
            AudioPacketInfo(
                packet_index=index,
                seq=packet.seq,
                timestamp=packet.timestamp,
                capture_time=packet.capture_time,
                payload_bytes=len(packet.payload),
            )
        )
    return audio_packets


def update_audio_media_info_block(
    info_block: ipmx_sender_report.IPMXInfoBlock,
    *,
    sample_rate: int,
    nchan: int,
    signaled_ptime_us: int,
    channel_order: str,
    measured_sample_rate: int,
    sample_size: int,
    media_info_type: int = 0x0004,
) -> ipmx_sender_report.IPMXInfoBlock:
    nominal_ptime_us = resolve_nominal_packet_time_us(sample_rate, signaled_ptime_us)
    if nominal_ptime_us is None:
        raise SystemExit(
            f"Unsupported audio ptime {signaled_ptime_us} us for sample_rate={sample_rate}"
        )
    blocks = list(info_block.media_info_blocks)
    updated = False
    for block in blocks:
        if isinstance(block, ipmx_sender_report.AudioMediaInfoBlock):
            block.sampling_rate = sample_rate
            block.sample_size = sample_size
            block.channel_count = nchan
            block.packet_time = nominal_ptime_us
            block.measured_sample_rate = measured_sample_rate
            block.channel_order = channel_order
            block.media_info_type = media_info_type
            updated = True
    if not updated:
        blocks.append(
            ipmx_sender_report.AudioMediaInfoBlock(
                sampling_rate=sample_rate,
                sample_size=sample_size,
                channel_count=nchan,
                packet_time=nominal_ptime_us,
                measured_sample_rate=measured_sample_rate,
                channel_order=channel_order,
                media_info_type=media_info_type,
            )
        )
    object.__setattr__(info_block, "media_info_blocks", blocks)
    return info_block


def build_audio_sr_schedule(
    packets: Sequence[AudioPacketInfo],
    interval_packets: int,
) -> list[AudioSenderReportPoint]:
    if interval_packets <= 0:
        raise SystemExit(f"Audio sender report interval must be >= 1, got {interval_packets}")
    if not packets:
        return []
    selected_indexes = range(0, len(packets), interval_packets)
    schedule: list[AudioSenderReportPoint] = []
    packet_count = 0
    octet_count = 0
    cumulative_packets: list[int] = []
    cumulative_octets: list[int] = []
    for packet in packets:
        packet_count += 1
        octet_count += packet.payload_bytes
        cumulative_packets.append(packet_count)
        cumulative_octets.append(octet_count)

    previous_sr_time: float | None = None
    previous_packet_time: float | None = None
    for packet_index in selected_indexes:
        packet = packets[packet_index]
        if previous_sr_time is None:
            sr_time = packet.capture_time - AUDIO_SR_TIME_MARGIN
        else:
            lower_bound = max(previous_sr_time + AUDIO_SR_TIME_MARGIN, previous_packet_time + AUDIO_SR_TIME_MARGIN)
            upper_bound = packet.capture_time - AUDIO_SR_TIME_MARGIN
            midpoint = previous_packet_time + ((packet.capture_time - previous_packet_time) / 2.0)
            sr_time = min(max(midpoint, lower_bound), upper_bound)
            if sr_time >= upper_bound:
                sr_time = upper_bound
            if sr_time <= lower_bound:
                sr_time = lower_bound
            if not (previous_packet_time < sr_time < packet.capture_time):
                raise SystemExit(
                    "Unable to place audio sender report between associated RTP packets "
                    f"for packet_index={packet.packet_index}"
                )
        schedule.append(
            AudioSenderReportPoint(
                packet_index=packet.packet_index,
                timestamp=packet.timestamp,
                packet_count=cumulative_packets[packet_index],
                octet_count=cumulative_octets[packet_index],
                packet_capture_time=packet.capture_time,
                sr_capture_time=sr_time,
            )
        )
        previous_sr_time = sr_time
        previous_packet_time = packet.capture_time
    return schedule


def build_audio_sender_reports(
    schedule: Sequence[AudioSenderReportPoint],
    info_block: ipmx_sender_report.IPMXInfoBlock,
    ssrc: int,
    rtcp_src_port: int,
    rtcp_dst_port: int,
    first_ip: bytes,
    second_ip: bytes,
    ttl: int,
    tos: int,
    ip_id_start: int,
    eth_src: bytes,
    eth_dst: bytes,
    clock_rate: int = 48000,
) -> tuple[list[dict[str, object]], int, int]:
    reports: list[dict[str, object]] = []
    packet_count = 0
    octet_count = 0
    ip_id = ip_id_start
    for point in schedule:
        report = ipmx_sender_report.SenderReport(
            ssrc=ssrc,
            ntp_seconds=0,
            ntp_fraction=0,
            rtp_timestamp=point.timestamp,
            packet_count=point.packet_count,
            octet_count=point.octet_count,
            info_block=info_block,
        )
        ntp_sec, ntp_frac = rtp_timestamp_to_ipmx_ptp(
            point.timestamp, point.sr_capture_time, clock_rate,
        )
        report.ntp_seconds = ntp_sec
        report.ntp_fraction = ntp_frac
        rtcp_payload = report.to_bytes()
        udp_header = build_udp_header(rtcp_src_port, rtcp_dst_port, len(rtcp_payload))
        ip_total = 20 + len(udp_header) + len(rtcp_payload)
        ip_header = build_ip_header(first_ip, second_ip, ip_total, ttl, tos, ip_id)
        packet_data = eth_dst + eth_src + b"\x08\x00" + ip_header + udp_header + rtcp_payload
        reports.append(
            {
                "time": point.sr_capture_time,
                "data": packet_data,
                "orig_len": len(packet_data),
            }
        )
        packet_count = point.packet_count
        octet_count = point.octet_count
        ip_id = (ip_id + 1) & 0xFFFF
    return reports, packet_count, octet_count


def build_sender_reports(
    frames: Sequence["FrameInfo"],
    sr_times: Sequence[float],
    packets_by_timestamp: dict[int, list[ipmx_parse_rtp_pcap.RTPPacket]],
    info_block: ipmx_sender_report.IPMXInfoBlock,
    ssrc: int,
    rtcp_src_port: int,
    rtcp_dst_port: int,
    first_ip: bytes,
    second_ip: bytes,
    ttl: int,
    tos: int,
    ip_id_start: int,
    eth_src: bytes,
    eth_dst: bytes,
    skip_indices: set[int],
    clock_rate: int = CLOCK_RATE,
) -> tuple[list[dict[str, object]], int, int]:
    reports: list[dict[str, object]] = []
    packet_count = 0
    octet_count = 0
    ip_id = ip_id_start
    for frame, sr_time in zip(frames, sr_times):
        packet_list = packets_by_timestamp.get(frame.timestamp)
        if packet_list is None:
            raise SystemExit(f"No RTP packets found for timestamp {frame.timestamp}")
        frame_packets = len(packet_list)
        frame_octets = sum(len(pkt.payload) for pkt in packet_list)
        packet_count += frame_packets
        octet_count += frame_octets
        if frame.index in skip_indices:
            continue
        report = ipmx_sender_report.SenderReport(
            ssrc=ssrc,
            ntp_seconds=0,
            ntp_fraction=0,
            rtp_timestamp=frame.timestamp,
            packet_count=packet_count,
            octet_count=octet_count,
            info_block=info_block,
        )
        ntp_sec, ntp_frac = rtp_timestamp_to_ipmx_ptp(
            frame.timestamp, sr_time, clock_rate,
        )
        report.ntp_seconds = ntp_sec
        report.ntp_fraction = ntp_frac
        rtcp_payload = report.to_bytes()
        udp_header = build_udp_header(rtcp_src_port, rtcp_dst_port, len(rtcp_payload))
        ip_total = 20 + len(udp_header) + len(rtcp_payload)
        ip_header = build_ip_header(first_ip, second_ip, ip_total, ttl, tos, ip_id)
        packet_data = eth_dst + eth_src + b"\x08\x00" + ip_header + udp_header + rtcp_payload
        reports.append(
            {
                "time": sr_time,
                "data": packet_data,
                "orig_len": len(packet_data),
            }
        )
        ip_id = (ip_id + 1) & 0xFFFF
    return reports, packet_count, octet_count


def extract_param_sets_from_packets(
    packets: Sequence[ipmx_parse_rtp_pcap.RTPPacket], codec: str
) -> tuple[dict[str, bytes], list[bytes]]:
    """Reassemble NALUs and extract parameter sets (VPS/SPS/PPS).

    Returns (param_sets, nalus) where *nalus* is the full list of
    reassembled NALUs (with Annex-B start codes) suitable for writing
    an elementary stream via :func:`write_elementary_stream`.
    """
    context = ipmx_parse_rtp_pcap.ParseContext()
    fragments: dict[tuple[int, int, int], list[ipmx_parse_rtp_pcap.FragmentState]] = {}
    nalus: list[bytes] = []
    nalus_meta: list[dict[str, object]] = []
    for pkt in packets:
        if not pkt.payload:
            continue
        packet_meta: dict[str, object] = {"nal_types": []}
        ipmx_parse_rtp_pcap.process_payload(
            codec, pkt, fragments, nalus, nalus_meta, packet_meta, context
        )

    param_sets: dict[str, bytes] = {}
    for nalu in nalus:
        payload = nalu[4:] if nalu.startswith(ipmx_parse_rtp_pcap.START_CODE) else nalu
        if codec == "h265":
            if len(payload) < 2:
                continue
            nal_type = (payload[0] & 0x7E) >> 1
            if nal_type == 32 and "vps" not in param_sets:
                param_sets["vps"] = payload
            elif nal_type == 33 and "sps" not in param_sets:
                param_sets["sps"] = payload
            elif nal_type == 34 and "pps" not in param_sets:
                param_sets["pps"] = payload
        else:
            if not payload:
                continue
            nal_type = payload[0] & 0x1F
            if nal_type == 7 and "sps" not in param_sets:
                param_sets["sps"] = payload
            elif nal_type == 8 and "pps" not in param_sets:
                param_sets["pps"] = payload
        if codec == "h265":
            if all(k in param_sets for k in ("vps", "sps", "pps")):
                break
        else:
            if all(k in param_sets for k in ("sps", "pps")):
                break
    return param_sets, nalus


def _reverse_bits_32(n: int) -> int:
    """Reverse the 32 bits of an integer.

    SPS bitstream stores flag[j] at bit (31-j) in a big-endian 32-bit read;
    the MIB uses the standard integer convention where flag[j] is at bit j.
    """
    result = 0
    for i in range(32):
        result = (result << 1) | ((n >> i) & 1)
    return result


def _parse_h265_sps_ptl(sps_nalu: bytes) -> dict[str, object] | None:
    """Extract profile_tier_level from raw H.265 SPS, EPB-aware, MIB convention."""
    if len(sps_nalu) < 15:
        return None
    # Strip emulation prevention bytes from RBSP (after 2-byte NAL header)
    raw = sps_nalu[2:]
    out = bytearray()
    i = 0
    while i < len(raw):
        if i + 2 < len(raw) and raw[i] == 0 and raw[i + 1] == 0 and raw[i + 2] == 3:
            out.append(0)
            out.append(0)
            i += 3
        else:
            out.append(raw[i])
            i += 1
    rbsp = bytes(out)
    if len(rbsp) < 13:
        return None
    ptl_byte = rbsp[1]
    bitstream_compat = int.from_bytes(rbsp[2:6], "big")
    return {
        "profile_space": (ptl_byte >> 6) & 0x03,
        "tier_flag": (ptl_byte >> 5) & 0x01,
        "profile_id": ptl_byte & 0x1F,
        "profile_compatibility_indicator": _reverse_bits_32(bitstream_compat),
        "interop_constraints": bytes(rbsp[6:12]),
        "level_id": rbsp[12],
    }


CHROMA_IDC_TO_SAMPLING: dict[int, str] = {
    0: "YCbCr-4:0:0",
    1: "YCbCr-4:2:0",
    2: "YCbCr-4:2:2",
    3: "YCbCr-4:4:4",
}

HEVC_SUB_WIDTH_C: dict[int, int] = {0: 1, 1: 2, 2: 2, 3: 1}
HEVC_SUB_HEIGHT_C: dict[int, int] = {0: 1, 1: 2, 2: 1, 3: 1}


def _extract_sps_fields_from_trace(
    nalus: list[bytes], codec: str
) -> dict[str, Any] | None:
    """Extract SPS fields via ffmpeg trace_headers on the reassembled elementary stream.

    Returns a flat ``{field_name: int_value}`` dict for the first SPS found,
    or *None* when ffmpeg is unavailable or no SPS is present.
    """
    if not nalus:
        return None
    if shutil.which("ffmpeg") is None:
        return None
    suffix = ".265" if codec == "h265" else ".264"
    stream_path = write_elementary_stream(nalus, suffix)
    try:
        trace_log = ipmx_parse_rtp_pcap.run_ffmpeg_trace(stream_path, 1)
    except SystemExit:
        trace_log = run_ffmpeg_trace_lenient(stream_path, 1)
    headers, _ = ipmx_parse_rtp_pcap.parse_trace_headers(trace_log)
    for header in headers:
        if header.get("type") == "SPS":
            raw_fields = header["fields"]
            result: dict[str, Any] = {}
            for key, val in raw_fields.items():
                if isinstance(val, dict):
                    v = val.get("value")
                    if v is not None:
                        try:
                            result[key] = int(v)
                        except (ValueError, TypeError):
                            result[key] = v
                else:
                    result[key] = val
            return result
    return None


def _hevc_display_resolution(sps: dict[str, Any]) -> tuple[int, int]:
    """Compute display width/height from H.265 SPS accounting for conformance cropping."""
    w = sps.get("pic_width_in_luma_samples", 0)
    h = sps.get("pic_height_in_luma_samples", 0)
    if sps.get("conformance_window_flag"):
        chroma = sps.get("chroma_format_idc", 1)
        sub_w = HEVC_SUB_WIDTH_C.get(chroma, 1)
        sub_h = HEVC_SUB_HEIGHT_C.get(chroma, 1)
        w -= (sps.get("conf_win_left_offset", 0) + sps.get("conf_win_right_offset", 0)) * sub_w
        h -= (sps.get("conf_win_top_offset", 0) + sps.get("conf_win_bottom_offset", 0)) * sub_h
    return w, h


H264_SUB_WIDTH_C: dict[int, int] = {0: 1, 1: 2, 2: 2, 3: 1}
H264_SUB_HEIGHT_C: dict[int, int] = {0: 1, 1: 2, 2: 1, 3: 1}


def _h264_display_resolution(sps: dict[str, Any]) -> tuple[int, int]:
    """Compute display width/height from H.264 SPS accounting for frame cropping."""
    w = (sps.get("pic_width_in_mbs_minus1", 0) + 1) * 16
    frame_mbs_only = sps.get("frame_mbs_only_flag", 1)
    h = (sps.get("pic_height_in_map_units_minus1", 0) + 1) * 16 * (2 - frame_mbs_only)
    if sps.get("frame_cropping_flag"):
        chroma = sps.get("chroma_format_idc", 1)
        sub_w = H264_SUB_WIDTH_C.get(chroma, 1)
        sub_h = H264_SUB_HEIGHT_C.get(chroma, 1) * (2 - frame_mbs_only)
        w -= (sps.get("frame_crop_left_offset", 0) + sps.get("frame_crop_right_offset", 0)) * sub_w
        h -= (sps.get("frame_crop_top_offset", 0) + sps.get("frame_crop_bottom_offset", 0)) * sub_h
    return w, h


def _patch_video_media_info_from_stream(
    info_block: ipmx_sender_report.IPMXInfoBlock,
    codec: str,
    nalus: list[bytes],
    exact_framerate: Fraction | None,
) -> bool:
    """Patch VideoMediaInfoBlock fields from the stream's SPS via ffmpeg trace.

    Returns *True* when patching succeeded, *False* otherwise.
    """
    sps_fields = _extract_sps_fields_from_trace(nalus, codec)
    if not sps_fields:
        return False

    if codec == "h265":
        width, height = _hevc_display_resolution(sps_fields)
    else:
        width, height = _h264_display_resolution(sps_fields)

    chroma_idc = sps_fields.get("chroma_format_idc", 1)
    bit_depth = sps_fields.get("bit_depth_luma_minus8", 0) + 8
    sampling = CHROMA_IDC_TO_SAMPLING.get(chroma_idc, "YCbCr-4:2:0")

    for block in info_block.media_info_blocks:
        if isinstance(block, ipmx_sender_report.VideoMediaInfoBlock):
            block.width = width
            block.height = height
            block.sampling_format = sampling
            block.bit_depth = bit_depth
            block.htotal = width
            block.vtotal = height
            if exact_framerate and width > 0 and height > 0:
                block.measured_pixel_clock = int(width * height * exact_framerate)
    return True


def enrich_info_block(
    info_block: ipmx_sender_report.IPMXInfoBlock,
    codec: str,
    param_sets: dict[str, bytes],
) -> None:
    for block in info_block.media_info_blocks:
        if codec == "h265" and isinstance(block, ipmx_sender_report.H265MediaInfoBlock):
            sps = param_sets.get("sps")
            if sps:
                ptl = _parse_h265_sps_ptl(sps)
                if ptl:
                    block.profile_space = ptl["profile_space"]  # type: ignore[assignment]
                    block.profile_id = ptl["profile_id"]  # type: ignore[assignment]
                    block.level_id = ptl["level_id"]  # type: ignore[assignment]
                    block.tier_flag = ptl["tier_flag"]  # type: ignore[assignment]
                    block.profile_compatibility_indicator = ptl["profile_compatibility_indicator"]  # type: ignore[assignment]
                    block.interop_constraints = ptl["interop_constraints"]  # type: ignore[assignment]
            if not block.sprop_vps and param_sets.get("vps"):
                block.sprop_vps = param_sets["vps"]
            if not block.sprop_sps and sps:
                block.sprop_sps = sps
            if not block.sprop_pps and param_sets.get("pps"):
                block.sprop_pps = param_sets["pps"]
        elif codec == "h264" and isinstance(block, ipmx_sender_report.H264MediaInfoBlock):
            sps = param_sets.get("sps")
            if sps and len(sps) >= 4:
                block.profile_level_id = bytes(sps[1:4])
            if not block.sprop_parameter_sets and sps:
                block.sprop_parameter_sets = sps
            if not block.sprop_level_parameter_sets and param_sets.get("pps"):
                block.sprop_level_parameter_sets = param_sets["pps"]


def patch_info_block_rate(
    info_block: ipmx_sender_report.IPMXInfoBlock,
    rate: Fraction,
) -> None:
    """Set rate_numerator/rate_denominator on every VideoMediaInfoBlock."""
    for block in info_block.media_info_blocks:
        if isinstance(block, ipmx_sender_report.VideoMediaInfoBlock):
            block.rate_numerator = rate.numerator
            block.rate_denominator = rate.denominator


def infer_exact_framerate_from_frames(
    frames: Sequence["FrameInfo"],
    clock_rate: int = CLOCK_RATE,
) -> Fraction | None:
    """Infer the exact framerate from frame RTP timestamps."""
    if len(frames) < 3:
        return None
    rtp_ts = [f.timestamp for f in frames]
    ticks = infer_ticks_per_frame_from_rtp(rtp_ts)
    if ticks is None:
        return None
    return Fraction(clock_rate) / ticks


def prepare_sender_report_info_block(
    config_path: Path | None, media: str
) -> ipmx_sender_report.IPMXInfoBlock:
    if config_path:
        with open(config_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        data = ipmx_sender_report.load_config(None, media)
    info = data.get("info_block", data)
    return ipmx_sender_report.IPMXInfoBlock.from_dict(info)  # type: ignore[arg-type]


def _detect_ext_ids(
    packets: Sequence[ipmx_parse_rtp_pcap.RTPPacket],
) -> tuple[int | None, int | None]:
    """Return (full_ext_id, short_ext_id) observed in the RTP extension headers."""
    full_id: int | None = None
    short_id: int | None = None
    for pkt in packets:
        if not pkt.ext_elements:
            continue
        for elem in pkt.ext_elements:
            l_field = elem.length - 1
            if l_field == EncExtLValue.FULL and full_id is None:
                full_id = elem.ext_id
            elif l_field == EncExtLValue.SHORT and short_id is None:
                short_id = elem.ext_id
        if full_id is not None and short_id is not None:
            break
    return full_id, short_id


def _ensure_mib(
    info_block: ipmx_sender_report.IPMXInfoBlock,
    mib_cls: type[ipmx_sender_report.IPMXMediaInfoBlock],
    mib_type: int,
    *,
    f_id: int = 0,
    s_id: int = 0,
) -> None:
    """Append an MIB of the given type if one is not already present."""
    for block in info_block.media_info_blocks:
        if getattr(block, "media_info_type", None) == mib_type:
            return
    blocks = list(info_block.media_info_blocks)
    blocks.append(mib_cls.from_dict({
        "media_info_type": mib_type,
        "f_id": f_id,
        "s_id": s_id,
    }))  # type: ignore[arg-type]
    object.__setattr__(info_block, "media_info_blocks", blocks)


def _is_rtcp_packet(data: bytes | bytearray) -> bool:
    """Heuristic: return True if *data* is an Ethernet/IP/UDP frame carrying RTCP.

    RTCP Sender Reports have payload type 200 (0xC8) in the second byte of the
    RTCP header.  We check the UDP payload after stripping Ethernet + IP + UDP.
    """
    if len(data) < ETHERNET_HEADER_SIZE + 20 + 8 + 2:
        return False
    ip_start = ETHERNET_HEADER_SIZE
    ihl = (data[ip_start] & 0x0F) * 4
    if data[ip_start + 9] != 17:
        return False
    udp_start = ip_start + ihl
    rtcp_start = udp_start + 8
    if rtcp_start + 2 > len(data):
        return False
    pt = data[rtcp_start + 1]
    return pt == 200


def _export_info_block(
    info_block: ipmx_sender_report.IPMXInfoBlock, path: Path
) -> None:
    """Write the fully-enriched info block to a JSON file for later reuse."""
    data = {"info_block": info_block.to_dict()}
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(f"Exported info block config to {path}")


def _promote_video_mib_to_0x0003(
    info_block: ipmx_sender_report.IPMXInfoBlock,
) -> None:
    """Change any MIB 0x0005 to 0x0003 (ConstantSize Compressed Video).

    JXSV streams require MIB 0x0003 per TR-10-11 §12, and MIB 0x0008 must
    immediately follow it per TR-10-15a §8.
    """
    for block in info_block.media_info_blocks:
        if getattr(block, "media_info_type", None) == 0x0005:
            object.__setattr__(block, "media_info_type", 0x0003)
            return


def _enrich_jxsv_mib_from_codestream(
    info_block: ipmx_sender_report.IPMXInfoBlock,
    rtp_packets: Sequence[ipmx_parse_rtp_pcap.RTPPacket],
) -> bool:
    """Patch the MIB 0x0008 Ppih/Plev from the first frame's codestream header."""
    from ipmx_jxsv_validate_pcap import parse_jxsv_codestream_header

    for pkt in rtp_packets:
        if not pkt.payload or len(pkt.payload) < 6:
            continue
        cs_data = bytes(pkt.payload[4:])
        info = parse_jxsv_codestream_header(cs_data)
        if info is not None:
            _patch_jxsv_mib(info_block, info.ppih, info.plev,
                            transmode=1, packetmode=0)
            return True
    return False


def _enrich_jxsv_mib_from_sdp(
    info_block: ipmx_sender_report.IPMXInfoBlock,
    sdp_path: Path,
) -> bool:
    """Patch the MIB 0x0008 Ppih/Plev from the SDP transport file."""
    from ipmx_jxsv_validate_pcap import load_sdp_jxsv_params

    params = load_sdp_jxsv_params(sdp_path)
    ppih = params.ppih or 0
    plev = params.plev or 0
    transmode = params.transmode if params.transmode is not None else 1
    packetmode = params.packetmode if params.packetmode is not None else 0
    _patch_jxsv_mib(info_block, ppih, plev, transmode=transmode,
                     packetmode=packetmode)
    return True


def _enrich_video_mib_from_sdp(
    info_block: ipmx_sender_report.IPMXInfoBlock,
    sdp_path: Path,
    exact_fr: Fraction | None,
) -> bool:
    """Patch the video signal MIB (0x0003/0x0005) from SDP attributes.

    Used as a fallback for any video codec when stream-based MIB enrichment
    cannot be performed (e.g. encrypted payload that cannot be parsed).
    When the SDP does not carry explicit htotal/vtotal values (normal case),
    htotal is set to width and vtotal is set to height, which is the minimum
    valid signal geometry and satisfies the htotal>=width / vtotal>=height
    invariant checked by TR-10-1-MIB-SIG.
    """
    from MatroxSdp import MatroxSdp

    sdp = MatroxSdp()
    err = sdp.decode(sdp_path.read_text())
    if err:
        return False
    md = sdp.primary_media
    for block in info_block.media_info_blocks:
        if getattr(block, "media_info_type", None) not in (0x0003, 0x0005):
            continue
        if md.width:
            object.__setattr__(block, "width", md.width)
        if md.height:
            object.__setattr__(block, "height", md.height)
        if md.depth:
            object.__setattr__(block, "bit_depth", md.depth)
        if md.sampling is not None:
            object.__setattr__(block, "sampling_format", str(md.sampling))
        # htotal/vtotal are rarely present in SDPs; fall back to width/height so that
        # the MIB invariant htotal>=width / vtotal>=height is always satisfied.
        htotal = md.h_total if md.h_total else md.width
        vtotal = md.v_total if md.v_total else md.height
        if htotal:
            object.__setattr__(block, "htotal", htotal)
        if vtotal:
            object.__setattr__(block, "vtotal", vtotal)
        if md.measured_pix_clk:
            object.__setattr__(block, "measured_pixel_clock", md.measured_pix_clk)
        elif exact_fr is not None and htotal and vtotal:
            object.__setattr__(block, "measured_pixel_clock", int(htotal * vtotal * exact_fr))
        if md.colorimetry is not None:
            object.__setattr__(block, "colorimetry", str(md.colorimetry))
        if md.transfer_characteristic is not None:
            object.__setattr__(block, "tcs", str(md.transfer_characteristic))
        if md.color_range is not None:
            object.__setattr__(block, "range", str(md.color_range))
        if md.exact_frame_rate_numerator and md.exact_frame_rate_denominator:
            object.__setattr__(block, "rate_numerator", md.exact_frame_rate_numerator)
            object.__setattr__(block, "rate_denominator", md.exact_frame_rate_denominator)
        return True
    return False


# Keep the old name as an alias so existing callers are not broken.
_enrich_jxsv_video_mib_from_sdp = _enrich_video_mib_from_sdp


def _enrich_h265_codec_mib_from_sdp(
    info_block: ipmx_sender_report.IPMXInfoBlock,
    sdp_path: Path,
) -> bool:
    """Patch H.265 codec MIB (0x0009) fixed fields from SDP fmtp attributes.

    Used as a fallback when the H.265 bitstream cannot be parsed (e.g. HKEP-
    encrypted payload).  Sets profile-id, level-id, interop-constraints and
    tx-mode from the SDP so that TR-10-15b-150 (MIB vs SDP fmtp consistency)
    can pass.
    """
    from MatroxSdp import MatroxSdp

    sdp = MatroxSdp()
    err = sdp.decode(sdp_path.read_text())
    if err:
        return False
    md = sdp.primary_media
    for block in info_block.media_info_blocks:
        if getattr(block, "media_info_type", None) != 0x0009:
            continue
        if md.h265_profile_space is not None:
            object.__setattr__(block, "profile_space", int(md.h265_profile_space))
        if md.h265_profile_id:
            object.__setattr__(block, "profile_id", int(md.h265_profile_id))
        if md.h265_level_id:
            object.__setattr__(block, "level_id", int(md.h265_level_id))
        if md.h265_tier_flag is not None:
            object.__setattr__(block, "tier_flag", int(bool(md.h265_tier_flag)))
        if md.h265_profile_compatibility_indicator:
            try:
                pci_int = int(str(md.h265_profile_compatibility_indicator), 16)
                object.__setattr__(block, "profile_compatibility_indicator", pci_int)
            except (ValueError, TypeError):
                pass
        if md.h265_interop_constraints:
            try:
                ic_hex = str(md.h265_interop_constraints).replace("-", "")
                object.__setattr__(block, "interop_constraints", bytes.fromhex(ic_hex))
            except (ValueError, TypeError):
                pass
        if md.h265_tx_mode is not None:
            tx_str = str(md.h265_tx_mode)
            if len(tx_str) == 4:
                object.__setattr__(block, "tx_mode", tx_str.encode())
        return True
    return False


def _patch_jxsv_mib(
    info_block: ipmx_sender_report.IPMXInfoBlock,
    ppih: int,
    plev: int,
    *,
    transmode: int = 1,
    packetmode: int = 0,
) -> None:
    """Ensure MIB 0x0008 exists and update its Ppih/Plev/transmode/packetmode."""
    for block in info_block.media_info_blocks:
        if getattr(block, "media_info_type", None) == 0x0008:
            object.__setattr__(block, "ppih", ppih)
            object.__setattr__(block, "plev", plev)
            object.__setattr__(block, "transmode", transmode)
            object.__setattr__(block, "packetmode", packetmode)
            return
    blocks = list(info_block.media_info_blocks)
    blocks.append(ipmx_sender_report.JXSVMediaInfoBlock(
        ppih=ppih, plev=plev, transmode=transmode, packetmode=packetmode,
    ))
    object.__setattr__(info_block, "media_info_blocks", blocks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="Original RTP PCAP")
    parser.add_argument("--codec", required=True, choices=["h264", "h265", "jxsv", "am824", "pcm"])
    parser.add_argument("--port", type=int, help="Filter RTP packets by UDP port")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("with_srs.pcap"),
        help="PCAP to write that merges the original packets with the new SRs",
    )
    parser.add_argument(
        "--clock-rate",
        type=int,
        default=90_000,
        help="RTP clock rate for converting timestamps to seconds",
    )
    parser.add_argument(
        "--sr-margin",
        type=float,
        help="Minimal distance (seconds) that SRs must precede the first media packet (defaults to the nominal period)",
    )
    parser.add_argument(
        "--sr-media",
        choices=["video", "pcm", "aes3", "h264", "h265", "jxsv"],
        help="Media block to inject inside the IPMX info block (defaults to codec-specific block)",
    )
    parser.add_argument(
        "--sample-rate",
        type=int,
        help="Audio sample rate in Hz for --codec am824",
    )
    parser.add_argument(
        "--nchan",
        type=int,
        help="AM824 nchan / audio channel count for --codec am824",
    )
    parser.add_argument(
        "--ptime",
        type=parse_audio_ptime_arg,
        help="Audio packet time in milliseconds (rounded SDP form, e.g. 1, 0.33, 0.12)",
    )
    parser.add_argument(
        "--channel-order",
        type=str,
        help="Audio channel-order string for --codec am824",
    )
    parser.add_argument(
        "--measured-sample-rate",
        type=int,
        help="Measured sample rate for the audio MIB (defaults to --sample-rate)",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=24,
        help="Audio sample size for the MIB (default: 24)",
    )
    parser.add_argument(
        "--sdp",
        type=Path,
        help="SDP transport file; used to derive JXSV MIB parameters (Ppih/Plev) "
             "when the payload is encrypted and the codestream is not accessible",
    )
    parser.add_argument(
        "--sender-report-config",
        type=Path,
        help="JSON file describing the IPMX Media Info Block payload (takes precedence over --sr-media)",
    )
    parser.add_argument(
        "--skip-sr",
        type=parse_indices,
        default=[],
        help="Comma-separated frame indexes (0-based) for which the SR is omitted (invalid scenario)",
    )
    parser.add_argument(
        "--late-sr",
        type=parse_indices,
        default=[],
        help="Comma-separated frame indexes that are intentionally delayed past the first packet",
    )
    parser.add_argument(
        "--late-delay",
        type=float,
        default=0.01,
        help="Amount of seconds to push a late SR past the first packet",
    )
    parser.add_argument(
        "--rtcp-src-port",
        type=int,
        help="Override source UDP port for RTCP SRs (default: same as RTP source port)",
    )
    parser.add_argument(
        "--rtcp-dst-port",
        type=int,
        help="Override destination UDP port for RTCP SRs (default: RTP dest port + 1)",
    )
    parser.add_argument(
        "--debug-au-offset",
        action="store_true",
        help="Print the per-access-unit AU offset (TR-10-15b) inferred from each SR",
    )
    parser.add_argument(
        "--wallclock-backstep-threshold",
        type=float,
        help=(
            "Backward capture-time jump (seconds) considered a wallclock disruption; "
            "default is max(0.050, 3 * nominal period)"
        ),
    )
    parser.add_argument(
        "--max-access-units",
        type=int,
        help="Process only the first N access units to speed up analysis",
    )
    parser.add_argument(
        "--exactframerate",
        type=str,
        help="Exact framerate as integer or num/den (e.g. 60, 60000/1001); "
             "overrides/patches the MIB rate_numerator/rate_denominator",
    )
    parser.add_argument(
        "--hkep",
        action="store_true",
        help="Stream uses HKEP encryption; adds an HKEP MIB (0x0010) to each SR",
    )
    parser.add_argument(
        "--pep",
        action="store_true",
        help="Stream uses PEP encryption; adds a PEP MIB (0x0011) to each SR",
    )
    parser.add_argument(
        "--strip-existing-rtcp",
        action="store_true",
        help="Remove existing RTCP packets from the capture before injecting new SRs "
             "(useful when the original capture already contains incomplete SRs)",
    )
    parser.add_argument(
        "--export-sender-report-config",
        type=Path,
        help="Export the fully-enriched info block to a JSON file (for reuse "
             "with --sender-report-config on encrypted captures)",
    )
    args = parser.parse_args()

    if not args.pcap.exists():
        raise SystemExit(f"{args.pcap} does not exist")
    if args.max_access_units is not None and args.max_access_units <= 0:
        raise SystemExit("--max-access-units must be a positive integer")
    if (
        args.wallclock_backstep_threshold is not None
        and args.wallclock_backstep_threshold <= 0
    ):
        raise SystemExit("--wallclock-backstep-threshold must be a positive value")

    tmp_root = Path(__file__).resolve().parent / "tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    scapy_packets = rdpcap(str(args.pcap))
    if not scapy_packets:
        raise SystemExit("PCAP contains no packets")
    first_raw = bytes(scapy_packets[0])
    eth_dst = first_raw[:6]
    eth_src = first_raw[6:12]
    ip_header = first_raw[ETHERNET_HEADER_SIZE : ETHERNET_HEADER_SIZE + 20]
    ttl = ip_header[8]
    tos = ip_header[1]
    ip_id_start = int.from_bytes(ip_header[4:6], "big")
    src_ip = ip_header[12:16]
    dst_ip = ip_header[16:20]

    rtp_packets = collect_rtp_packets(
        args.pcap,
        args.port,
        args.codec,
        args.max_access_units,
    )
    if not rtp_packets:
        raise SystemExit("Unable to locate any RTP packets in the capture")

    media_choice = args.sr_media or (
        "aes3" if args.codec == "am824"
        else "pcm" if args.codec == "pcm"
        else args.codec
    )
    info_block = prepare_sender_report_info_block(args.sender_report_config, media_choice)

    if args.codec == "am824":
        if args.sample_rate is None or args.ptime is None:
            raise SystemExit("--codec am824 requires --sample-rate and --ptime")
        if args.sender_report_config is None and (
            args.nchan is None or not args.channel_order
        ):
            raise SystemExit(
                "--codec am824 without --sender-report-config requires --nchan and --channel-order"
            )

        measured_sample_rate = args.measured_sample_rate or args.sample_rate
        if args.nchan is None:
            audio_blocks = [
                block
                for block in info_block.media_info_blocks
                if isinstance(block, ipmx_sender_report.AudioMediaInfoBlock)
            ]
            if not audio_blocks:
                raise SystemExit(
                    "--sender-report-config does not contain an audio MIB and --nchan was not provided"
                )
            args.nchan = audio_blocks[0].channel_count
        if not args.channel_order:
            audio_blocks = [
                block
                for block in info_block.media_info_blocks
                if isinstance(block, ipmx_sender_report.AudioMediaInfoBlock)
            ]
            if not audio_blocks or not audio_blocks[0].channel_order:
                raise SystemExit(
                    "--sender-report-config does not contain channel_order and --channel-order was not provided"
                )
            args.channel_order = audio_blocks[0].channel_order

        info_block = update_audio_media_info_block(
            info_block,
            sample_rate=args.sample_rate,
            nchan=args.nchan,
            signaled_ptime_us=args.ptime,
            channel_order=args.channel_order,
            measured_sample_rate=measured_sample_rate,
            sample_size=args.sample_size,
        )

        ssrc_value = rtp_packets[0].ssrc
        rtp_src_port = rtp_packets[0].src_port or 0
        rtp_dst_port = rtp_packets[0].dst_port or 0
        rtcp_src_port = args.rtcp_src_port or rtp_src_port
        rtcp_dst_port = args.rtcp_dst_port or (rtp_dst_port + 1)

        if args.export_sender_report_config:
            _export_info_block(info_block, args.export_sender_report_config)

        audio_packets = collect_audio_packets(rtp_packets)
        if not audio_packets:
            raise SystemExit("Unable to locate any timestamped RTP packets for AM824 audio")
        interval_packets = compute_audio_sender_report_interval_packets(
            args.sample_rate,
            args.ptime,
        )
        if interval_packets is None:
            raise SystemExit(
                f"Unsupported AM824 ptime {args.ptime} us for sample_rate={args.sample_rate}"
            )
        schedule = build_audio_sr_schedule(audio_packets, interval_packets)
        if not schedule:
            raise SystemExit("Unable to construct AM824 sender report schedule")

        skip_set = set(args.skip_sr)
        if any(idx < 0 or idx >= len(schedule) for idx in skip_set):
            raise SystemExit("skip-sr indexes must refer to valid AM824 sender-report positions")
        late_set = set(args.late_sr)
        if any(idx < 0 or idx >= len(schedule) for idx in late_set):
            raise SystemExit("late-sr indexes must refer to valid AM824 sender-report positions")
        if skip_set or late_set:
            adjusted_schedule: list[AudioSenderReportPoint] = []
            for idx, point in enumerate(schedule):
                if idx in skip_set:
                    continue
                if idx in late_set:
                    point.sr_capture_time = point.packet_capture_time + args.late_delay
                adjusted_schedule.append(point)
            schedule = adjusted_schedule

        # Inject HKEP/PEP MIBs into the info_block before building SRs.
        # This must happen here (inside the AM824 branch) because the AM824
        # branch returns before reaching the general-codec _ensure_mib calls.
        if args.hkep or args.pep:
            full_ext_id, short_ext_id = _detect_ext_ids(rtp_packets)
            f_id = full_ext_id if full_ext_id is not None else 0
            s_id = short_ext_id if short_ext_id is not None else 0
            if f_id and not s_id:
                s_id = f_id + 1
            elif s_id and not f_id:
                f_id = s_id - 1 if s_id > 1 else 1
            if f_id or s_id:
                print(f"Encryption extension IDs detected: f_id={f_id} s_id={s_id}")
        else:
            f_id = s_id = 0
        if args.hkep:
            _ensure_mib(info_block, ipmx_sender_report.HKEPMediaInfoBlock, 0x0010, f_id=f_id, s_id=s_id)
        if args.pep:
            _ensure_mib(info_block, ipmx_sender_report.PEPMediaInfoBlock, 0x0011, f_id=f_id, s_id=s_id)

        sr_reports, packet_count, octet_count = build_audio_sender_reports(
            schedule,
            info_block,
            ssrc_value,
            rtcp_src_port,
            rtcp_dst_port,
            src_ip,
            dst_ip,
            ttl,
            tos,
            ip_id_start,
            eth_src,
            eth_dst,
            clock_rate=args.sample_rate,
        )

        if args.strip_existing_rtcp:
            original_count = len(scapy_packets)
            scapy_packets = [p for p in scapy_packets if not _is_rtcp_packet(bytes(p))]
            stripped = original_count - len(scapy_packets)
            if stripped:
                print(f"Stripped {stripped} existing RTCP packet(s) from capture")

        for report in sr_reports:
            sr_pkt = Ether(report["data"])
            sr_pkt.time = report["time"]
            scapy_packets.append(sr_pkt)
        scapy_packets.sort(key=lambda p: float(p.time))

        args.output.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(args.output), scapy_packets)

        nominal_ptime_us = resolve_nominal_packet_time_us(args.sample_rate, args.ptime)
        print(f"AM824 SR interval      : every {interval_packets} RTP packets")
        if nominal_ptime_us is not None:
            print(f"Nominal packet time    : {nominal_ptime_us} us")
        print(f"RTP packets            : {len(audio_packets)}")
        print(f"Final packet/octet cnt : {packet_count} / {octet_count}")
        if late_set:
            print(f"Late SR indexes        : {sorted(late_set)} (+{args.late_delay:.3f}s each)")
        if skip_set:
            print(f"Missing SR indexes     : {sorted(skip_set)}")
        print(f"Inserted SRs           : {len(sr_reports)}")
        print(f"Wrote augmented PCAP   : {args.output}")
        return 0

    if args.codec == "pcm":
        if args.sample_rate is None or args.ptime is None:
            raise SystemExit("--codec pcm requires --sample-rate and --ptime")
        if args.sender_report_config is None and (
            args.nchan is None or not args.channel_order
        ):
            raise SystemExit(
                "--codec pcm without --sender-report-config requires --nchan and --channel-order"
            )

        measured_sample_rate = args.measured_sample_rate or args.sample_rate
        if args.nchan is None:
            audio_blocks = [
                block
                for block in info_block.media_info_blocks
                if isinstance(block, ipmx_sender_report.AudioMediaInfoBlock)
            ]
            if not audio_blocks:
                raise SystemExit(
                    "--sender-report-config does not contain an audio MIB and --nchan was not provided"
                )
            args.nchan = audio_blocks[0].channel_count
        if not args.channel_order:
            audio_blocks = [
                block
                for block in info_block.media_info_blocks
                if isinstance(block, ipmx_sender_report.AudioMediaInfoBlock)
            ]
            if not audio_blocks or not audio_blocks[0].channel_order:
                raise SystemExit(
                    "--sender-report-config does not contain channel_order and --channel-order was not provided"
                )
            args.channel_order = audio_blocks[0].channel_order

        info_block = update_audio_media_info_block(
            info_block,
            sample_rate=args.sample_rate,
            nchan=args.nchan,
            signaled_ptime_us=args.ptime,
            channel_order=args.channel_order,
            measured_sample_rate=measured_sample_rate,
            sample_size=args.sample_size,
            media_info_type=PCM_MIB_TYPE,
        )

        ssrc_value = rtp_packets[0].ssrc
        rtp_src_port = rtp_packets[0].src_port or 0
        rtp_dst_port = rtp_packets[0].dst_port or 0
        rtcp_src_port = args.rtcp_src_port or rtp_src_port
        rtcp_dst_port = args.rtcp_dst_port or (rtp_dst_port + 1)

        if args.export_sender_report_config:
            _export_info_block(info_block, args.export_sender_report_config)

        audio_packets = collect_audio_packets(rtp_packets)
        if not audio_packets:
            raise SystemExit("Unable to locate any timestamped RTP packets for PCM audio")
        interval_packets = compute_audio_sender_report_interval_packets(
            args.sample_rate,
            args.ptime,
        )
        if interval_packets is None:
            raise SystemExit(
                f"Unsupported PCM ptime {args.ptime} us for sample_rate={args.sample_rate}"
            )
        schedule = build_audio_sr_schedule(audio_packets, interval_packets)
        if not schedule:
            raise SystemExit("Unable to construct PCM sender report schedule")

        skip_set = set(args.skip_sr)
        if any(idx < 0 or idx >= len(schedule) for idx in skip_set):
            raise SystemExit("skip-sr indexes must refer to valid PCM sender-report positions")
        late_set = set(args.late_sr)
        if any(idx < 0 or idx >= len(schedule) for idx in late_set):
            raise SystemExit("late-sr indexes must refer to valid PCM sender-report positions")
        if skip_set or late_set:
            adjusted_schedule: list[AudioSenderReportPoint] = []
            for idx, point in enumerate(schedule):
                if idx in skip_set:
                    continue
                if idx in late_set:
                    point.sr_capture_time = point.packet_capture_time + args.late_delay
                adjusted_schedule.append(point)
            schedule = adjusted_schedule

        if args.hkep or args.pep:
            full_ext_id, short_ext_id = _detect_ext_ids(rtp_packets)
            f_id = full_ext_id if full_ext_id is not None else 0
            s_id = short_ext_id if short_ext_id is not None else 0
            if f_id and not s_id:
                s_id = f_id + 1
            elif s_id and not f_id:
                f_id = s_id - 1 if s_id > 1 else 1
            if f_id or s_id:
                print(f"Encryption extension IDs detected: f_id={f_id} s_id={s_id}")
        else:
            f_id = s_id = 0
        if args.hkep:
            _ensure_mib(info_block, ipmx_sender_report.HKEPMediaInfoBlock, 0x0010, f_id=f_id, s_id=s_id)
        if args.pep:
            _ensure_mib(info_block, ipmx_sender_report.PEPMediaInfoBlock, 0x0011, f_id=f_id, s_id=s_id)

        sr_reports, packet_count, octet_count = build_audio_sender_reports(
            schedule,
            info_block,
            ssrc_value,
            rtcp_src_port,
            rtcp_dst_port,
            src_ip,
            dst_ip,
            ttl,
            tos,
            ip_id_start,
            eth_src,
            eth_dst,
            clock_rate=args.sample_rate,
        )

        if args.strip_existing_rtcp:
            original_count = len(scapy_packets)
            scapy_packets = [p for p in scapy_packets if not _is_rtcp_packet(bytes(p))]
            stripped = original_count - len(scapy_packets)
            if stripped:
                print(f"Stripped {stripped} existing RTCP packet(s) from capture")

        for report in sr_reports:
            sr_pkt = Ether(report["data"])
            sr_pkt.time = report["time"]
            scapy_packets.append(sr_pkt)
        scapy_packets.sort(key=lambda p: float(p.time))

        args.output.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(args.output), scapy_packets)

        nominal_ptime_us = resolve_nominal_packet_time_us(args.sample_rate, args.ptime)
        print(f"PCM SR interval        : every {interval_packets} RTP packets")
        if nominal_ptime_us is not None:
            print(f"Nominal packet time    : {nominal_ptime_us} us")
        print(f"RTP packets            : {len(audio_packets)}")
        print(f"Final packet/octet cnt : {packet_count} / {octet_count}")
        if late_set:
            print(f"Late SR indexes        : {sorted(late_set)} (+{args.late_delay:.3f}s each)")
        if skip_set:
            print(f"Missing SR indexes     : {sorted(skip_set)}")
        print(f"Inserted SRs           : {len(sr_reports)}")
        print(f"Wrote augmented PCAP   : {args.output}")
        return 0

    encrypted = args.hkep or args.pep
    if not encrypted:
        encrypted = any(
            detect_encryption(pkt.ext_elements) for pkt in rtp_packets
        )
    if encrypted:
        print("[INFO] Encryption detected — payload content is not accessible.")

    frames = compute_frames_from_packets(
        rtp_packets, args.codec, encrypted=encrypted,
    )
    if args.max_access_units is not None:
        frames = frames[: args.max_access_units]
    if not frames:
        raise SystemExit(
            "No frames were detected in the capture"
            + (" (encrypted stream — all packets grouped by RTP timestamp)" if encrypted else "")
        )

    period = nominal_period_from_timestamps(frames, args.clock_rate)
    backstep_threshold = (
        args.wallclock_backstep_threshold
        if args.wallclock_backstep_threshold is not None
        else max(0.050, 3.0 * period)
    )
    disruption = find_wallclock_disruption(frames, args.clock_rate, backstep_threshold)
    if disruption is not None:
        original_count = len(frames)
        frames = frames[: disruption.index]
        if len(frames) < 1:
            raise SystemExit(
                "Wallclock disruption detected before the first access unit could be processed; "
                "capture appears invalid, please recapture."
            )
        print(
            "Wallclock disruption detected in capture timeline: "
            f"AU {disruption.index - 1} -> AU {disruption.index}, "
            f"capture delta {disruption.capture_delta:.6f}s while RTP advanced "
            f"{disruption.rtp_delta:.6f}s. "
            f"Only processing AUs [0..{len(frames) - 1}] and skipping the rest. "
            "Please recapture to get a continuous wallclock timeline.",
            file=sys.stderr,
        )
        if len(frames) != original_count:
            period = nominal_period_from_timestamps(frames, args.clock_rate)
    truncated_on_disruption = disruption is not None and len(frames) != original_count

    timestamp_disruption = find_timestamp_disruption(frames, args.clock_rate)
    if timestamp_disruption is not None:
        original_count = len(frames)
        frames = frames[: timestamp_disruption.index]
        if len(frames) < 1:
            raise SystemExit(
                "RTP timestamp discontinuity detected before the first access unit; "
                "capture appears invalid, please recapture."
            )
        if len(frames) != original_count:
            period = nominal_period_from_timestamps(frames, args.clock_rate)
        truncated_on_disruption = True

    sr_margin = args.sr_margin if args.sr_margin is not None else period
    sr_times, elapsed = build_sr_schedule(frames, args.clock_rate, sr_margin)

    if args.late_sr:
        late_set = set(args.late_sr)
        for idx in late_set:
            if 0 <= idx < len(sr_times):
                sr_times[idx] += args.late_delay
    else:
        late_set = set()

    skip_set = set(args.skip_sr)
    if any(idx < 0 or idx >= len(frames) for idx in skip_set):
        raise SystemExit("skip-sr indexes must refer to valid frame positions")

    adjustment = 0.0
    if not late_set:
        min_offset = min_au_offset(frames, sr_times, skip_set, quantize=True)
        if min_offset is not None and min_offset < 0:
            adjustment = -min_offset + EPSILON
            sr_times = [t - adjustment for t in sr_times]
            print(
                f"Adjusted SR schedule earlier by {adjustment:.6f}s to avoid negative AU offsets.",
                file=sys.stderr,
            )

    if args.debug_au_offset:
        print("Access-unit AU offset (TR-10-15b):")
        print("idx  timestamp     rtp_elapsed  SR_time      first_packet    au_offset")
        for idx, frame in enumerate(frames):
            sr_time = sr_times[idx]
            effective_sr = quantize_pcap_time(sr_time)
            au_offset = frame.first_packet_time - effective_sr
            print(
                f"{idx:4d} {frame.timestamp:11d} {elapsed[idx]:11.6f} {sr_time:11.6f} "
                f"{frame.first_packet_time:13.6f} {au_offset:10.6f}"
            )

    effective_au_limit = len(frames)
    ssrc_value = rtp_packets[0].ssrc
    rtp_src_port = rtp_packets[0].src_port or 0
    rtp_dst_port = rtp_packets[0].dst_port or 0

    rtcp_src_port = args.rtcp_src_port or rtp_src_port
    rtcp_dst_port = args.rtcp_dst_port or (rtp_dst_port + 1)

    packets_by_ts: dict[int, list[ipmx_parse_rtp_pcap.RTPPacket]] = {}
    for pkt in rtp_packets:
        packets_by_ts.setdefault(pkt.timestamp, []).append(pkt)

    exact_fr: Fraction | None = None
    if getattr(args, "exactframerate", None):
        exact_fr = parse_exactframerate_arg(args.exactframerate)
        patch_info_block_rate(info_block, exact_fr)
        print(f"MIB rate patched from --exactframerate: {exact_fr.numerator}/{exact_fr.denominator}")
    else:
        inferred = infer_exact_framerate_from_frames(frames, args.clock_rate)
        if inferred is not None:
            exact_fr = inferred
            patch_info_block_rate(info_block, inferred)
            print(f"MIB rate patched from stream: {inferred.numerator}/{inferred.denominator}")

    if media_choice == "jxsv":
        _promote_video_mib_to_0x0003(info_block)

    if encrypted:
        print("       Skipping payload-dependent MIB enrichment (payload not accessible).")
        if media_choice == "jxsv" and args.sdp:
            if _enrich_jxsv_mib_from_sdp(info_block, args.sdp):
                print("MIB 0x0008 (JXSV) patched from SDP transport file")
            if _enrich_jxsv_video_mib_from_sdp(info_block, args.sdp, exact_fr):
                print("MIB video signal patched from SDP transport file")
        elif media_choice in ("h265", "h264") and args.sdp:
            # For encrypted H.26x streams the payload cannot be parsed; use the SDP
            # to populate both the video signal MIB (htotal/vtotal/pixclk) and the
            # codec MIB (profile-id/level-id/…) so that TR-10-1-MIB-SIG and
            # TR-10-15b-150 can pass.
            if _enrich_video_mib_from_sdp(info_block, args.sdp, exact_fr):
                print("MIB video signal patched from SDP transport file (fallback)")
            if media_choice == "h265":
                if _enrich_h265_codec_mib_from_sdp(info_block, args.sdp):
                    print("MIB H.265 codec block patched from SDP transport file (fallback)")
    elif media_choice in ("h265", "h264"):
        param_sets, nalus = extract_param_sets_from_packets(rtp_packets, media_choice)
        if param_sets:
            enrich_info_block(info_block, media_choice, param_sets)
        if nalus and _patch_video_media_info_from_stream(
            info_block, media_choice, nalus, exact_fr
        ):
            print("MIB video signal patched from stream SPS")
    elif media_choice == "jxsv":
        if _enrich_jxsv_mib_from_codestream(info_block, rtp_packets):
            print("MIB 0x0008 (JXSV) patched from codestream header")
        elif args.sdp:
            if _enrich_jxsv_mib_from_sdp(info_block, args.sdp):
                print("MIB 0x0008 (JXSV) patched from SDP transport file (fallback)")
        if args.sdp:
            if _enrich_jxsv_video_mib_from_sdp(info_block, args.sdp, exact_fr):
                print("MIB video signal patched from SDP transport file")

    if args.hkep or args.pep:
        full_ext_id, short_ext_id = _detect_ext_ids(rtp_packets)
        f_id = full_ext_id if full_ext_id is not None else 0
        s_id = short_ext_id if short_ext_id is not None else 0
        if f_id and not s_id:
            s_id = f_id + 1
        elif s_id and not f_id:
            f_id = s_id - 1 if s_id > 1 else 1
        if f_id or s_id:
            print(f"Encryption extension IDs detected: f_id={f_id} s_id={s_id}")
    else:
        f_id = s_id = 0

    if args.hkep:
        _ensure_mib(
            info_block, ipmx_sender_report.HKEPMediaInfoBlock, 0x0010,
            f_id=f_id, s_id=s_id,
        )
    if args.pep:
        _ensure_mib(
            info_block, ipmx_sender_report.PEPMediaInfoBlock, 0x0011,
            f_id=f_id, s_id=s_id,
        )

    if args.export_sender_report_config:
        _export_info_block(info_block, args.export_sender_report_config)

    sr_reports, packet_count, octet_count = build_sender_reports(
        frames,
        sr_times,
        packets_by_ts,
        info_block,
        ssrc_value,
        rtcp_src_port,
        rtcp_dst_port,
        src_ip,
        dst_ip,
        ttl,
        tos,
        ip_id_start,
        eth_src,
        eth_dst,
        skip_set,
        clock_rate=args.clock_rate,
    )

    if truncated_on_disruption and frames:
        last_ts = frames[-1].timestamp
        last_packets = packets_by_ts.get(last_ts, [])
        if last_packets:
            last_time = max(
                pkt.capture_time for pkt in last_packets if pkt.capture_time is not None
            )
            scapy_packets = [p for p in scapy_packets if float(p.time) <= last_time + EPSILON]

    if args.strip_existing_rtcp:
        original_count = len(scapy_packets)
        scapy_packets = [p for p in scapy_packets if not _is_rtcp_packet(bytes(p))]
        stripped = original_count - len(scapy_packets)
        if stripped:
            print(f"Stripped {stripped} existing RTCP packet(s) from capture")

    for report in sr_reports:
        sr_pkt = Ether(report["data"])
        sr_pkt.time = report["time"]
        scapy_packets.append(sr_pkt)
    scapy_packets.sort(key=lambda p: float(p.time))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(args.output), scapy_packets)

    inserted_indices = [i for i in range(len(frames)) if i not in skip_set]
    sr_deltas = [
        frames[idx].first_packet_time - quantize_pcap_time(sr_times[idx])
        for idx in inserted_indices
    ]
    if sr_deltas:
        au_offset_min = min(sr_deltas)
        au_offset_max = max(sr_deltas)
    else:
        au_offset_min = au_offset_max = 0.0
    print(f"Nominal period         : {period:.6f}s ({args.clock_rate} Hz RTP clock)")
    print(f"Sender report delay    : {sr_margin:.6f}s")
    print(f"Encoder delay (assumed): {sr_margin:.6f}s")
    if adjustment:
        print(f"SR schedule adjustment : {adjustment:.6f}s (applied)")
    print(f"AU offset (min/max)    : {au_offset_min:.6f}s / {au_offset_max:.6f}s")
    if disruption is not None:
        print(
            "Wallclock disruption  : "
            f"AU {disruption.index - 1} -> AU {disruption.index}, "
            f"capture delta {disruption.capture_delta:.6f}s, "
            f"RTP delta {disruption.rtp_delta:.6f}s (processing truncated)"
        )
    if timestamp_disruption is not None:
        print(
            "RTP timestamp backstep : "
            f"AU {timestamp_disruption.index - 1} -> AU {timestamp_disruption.index}, "
            f"RTP delta {timestamp_disruption.rtp_delta:.6f}s (processing truncated)"
        )
    if args.max_access_units is not None:
        print(f"Processed AUs          : {len(frames)} (limit={args.max_access_units})")
    if late_set:
        print(f"Late SR indexes     : {sorted(late_set)} (+{args.late_delay:.3f}s each)")
    if skip_set:
        print(f"Missing SR indexes  : {sorted(skip_set)}")
    print(f"Inserted SRs        : {len(sr_reports)}")
    print(f"Wrote augmented PCAP : {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
