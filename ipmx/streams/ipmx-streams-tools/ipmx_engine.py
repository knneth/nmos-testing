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
"""IPMX Engine — JSON stdin/stdout interface for stream generation, validation,
and receiver analysis.

Commands:
  generate  — Encode a stream from an SDP and produce a PCAP with Sender Reports
  validate  — Validate a PCAP against a known SDP (offline certification)
  receive   — Analyse a PCAP as a live receiver: extract MIBs, generate SDP,
              validate bitstream

Usage:
  echo '{"command":"validate","pcap":"test.pcap","sdp":"v=0\\r\\n..."}' | python3 ipmx_engine.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# SDP → StreamConfig  (inverse of generate_sdp)
# ---------------------------------------------------------------------------

def _sampling_to_pix_fmt(sampling: str, depth: int) -> str:
    s = sampling.upper().replace("-", "").replace(":", "")
    if "420" in s:
        return "yuv420p10le" if depth > 8 else "yuv420p"
    if "422" in s:
        return "yuv422p10le" if depth > 8 else "yuv422p"
    if "444" in s:
        return "yuv444p10le" if depth > 8 else "yuv444p"
    return "yuv420p"


def _vbv_from_level_h265(level_id: int, bitrate_kbps: int) -> tuple[int, int, str]:
    """Return (vbv_maxrate_kbps, vbv_bufsize_kbit, nal_hrd) from H.265 level."""
    level_limits = {
        30: (350, 350), 60: (1500, 1500), 63: (3000, 3000),
        90: (6000, 6000), 93: (10000, 10000),
        120: (12000, 12000), 123: (20000, 20000),
        150: (25000, 25000), 153: (40000, 40000),
        156: (60000, 60000),
        180: (60000, 60000), 183: (100000, 100000),
        186: (160000, 160000),
    }
    max_br, max_cpb = level_limits.get(level_id, (bitrate_kbps, bitrate_kbps))
    vbv_maxrate = min(bitrate_kbps, max_br) if bitrate_kbps > 0 else max_br
    vbv_bufsize = min(bitrate_kbps, max_cpb) if bitrate_kbps > 0 else max_cpb
    nal_hrd = "cbr" if bitrate_kbps >= max_br * 0.9 else "vbr"
    return vbv_maxrate, vbv_bufsize, nal_hrd


def _vbv_from_level_h264(level_idc: int, bitrate_kbps: int) -> tuple[int, int, str]:
    """Return (vbv_maxrate_kbps, vbv_bufsize_kbit, nal_hrd) from H.264 level."""
    level_limits = {
        10: (64, 175), 11: (192, 500), 12: (384, 1000), 13: (768, 2000),
        20: (2000, 2000), 21: (4000, 4000), 22: (4000, 4000),
        30: (10000, 10000), 31: (14000, 14000), 32: (20000, 20000),
        40: (20000, 25000), 41: (50000, 62500), 42: (50000, 62500),
        50: (135000, 135000), 51: (240000, 240000), 52: (240000, 240000),
    }
    max_br, max_cpb = level_limits.get(level_idc, (bitrate_kbps, bitrate_kbps))
    vbv_maxrate = min(bitrate_kbps, max_br) if bitrate_kbps > 0 else max_br
    vbv_bufsize = min(bitrate_kbps, max_cpb) if bitrate_kbps > 0 else max_cpb
    nal_hrd = "cbr" if bitrate_kbps >= max_br * 0.9 else "vbr"
    return vbv_maxrate, vbv_bufsize, nal_hrd


def derive_stream_config(
    sdp_text: str,
    random_access_duration: float,
    random_access_count: int,
) -> dict[str, Any]:
    """Parse an SDP string and derive a StreamConfig-compatible dict."""
    from MatroxSdp import MatroxSdp, MatroxSdpEnums

    E = MatroxSdpEnums

    sdp = MatroxSdp()
    err = sdp.decode(sdp_text)
    if err:
        raise ValueError(f"SDP decode error: {err}")

    m = sdp.medias[0]

    enc = str(m.encoding_name) if m.encoding_name else ""
    if enc.upper() == "H265":
        codec = "h265"
    elif enc.upper() == "H264":
        codec = "h264"
    elif enc.upper() == "AM824":
        sample_rate = m.sample_rate or m.clock_rate or 0
        ptime_us = m.p_time_us or 0
        if sample_rate <= 0:
            raise ValueError("AM824 SDP is missing sample rate")
        if ptime_us <= 0:
            raise ValueError("AM824 SDP is missing ptime")
        if not m.channels:
            raise ValueError("AM824 SDP is missing channel count")
        if not m.channel_order:
            raise ValueError("AM824 SDP is missing channel-order")
        return {
            "codec": "am824",
            "payload_type": m.payload_type or m.format_code or 96,
            "sample_rate": sample_rate,
            "nchan": m.channels,
            "ptime_us": ptime_us,
            "channel_order": m.channel_order,
            "measured_sample_rate": m.measured_sample_rate or sample_rate,
            "port": m.port or 15_000,
            "description": sdp.session_information or sdp.session_name or "AM824 stream",
            "hkep": bool(m.hkep),
            "pep": bool(m.privacy),
        }
    elif enc.upper() in {"L16", "L20", "L24"}:
        from ipmx_pcm import bit_depth_from_encoding
        sample_rate = m.sample_rate or m.clock_rate or 0
        ptime_us = m.p_time_us or 0
        if sample_rate <= 0:
            raise ValueError("PCM SDP is missing sample rate")
        if ptime_us <= 0:
            raise ValueError("PCM SDP is missing ptime")
        if not m.channels:
            raise ValueError("PCM SDP is missing channel count")
        bit_depth = bit_depth_from_encoding(enc)
        return {
            "codec": "pcm",
            "payload_type": m.payload_type or m.format_code or 96,
            "sample_rate": sample_rate,
            "nchan": m.channels,
            "bit_depth": bit_depth,
            "ptime_us": ptime_us,
            "channel_order": m.channel_order or "",
            "measured_sample_rate": m.measured_sample_rate or sample_rate,
            "port": m.port or 16_000,
            "description": sdp.session_information or sdp.session_name or "PCM stream",
            "hkep": bool(m.hkep),
            "pep": bool(m.privacy),
        }
    else:
        raise ValueError(f"Unsupported codec: {enc}")

    width = m.width
    height = m.height
    depth = m.depth or 8
    fps_num = m.exact_frame_rate_numerator
    fps_den = m.exact_frame_rate_denominator or 1
    sampling = str(m.sampling) if m.sampling else "YCbCr-4:2:0"
    bitrate_kbps = m.bitrate_kbits or 0

    pix_fmt = _sampling_to_pix_fmt(sampling, depth)

    fps = Fraction(fps_num, fps_den)
    keyint = max(1, round(float(fps) * random_access_duration))
    frame_count = keyint * random_access_count

    if codec == "h265":
        level_id = m.h265_level_id if hasattr(m, "h265_level_id") and m.h265_level_id else 0
        vbv_maxrate, vbv_bufsize, nal_hrd = _vbv_from_level_h265(level_id, bitrate_kbps)
    else:
        pli = m.codec_profile_level_id or ""
        level_idc = int(pli[4:6], 16) if len(pli) >= 6 else 0
        vbv_maxrate, vbv_bufsize, nal_hrd = _vbv_from_level_h264(level_idc, bitrate_kbps)

    if vbv_maxrate == 0:
        vbv_maxrate = 20000
    if vbv_bufsize == 0:
        vbv_bufsize = vbv_maxrate

    hkep = m.hkep
    pep = m.privacy

    return {
        "codec": codec,
        "width": width,
        "height": height,
        "fps_num": fps_num,
        "fps_den": fps_den,
        "pix_fmt": pix_fmt,
        "sampling": sampling,
        "bit_depth": depth,
        "interlace": m.interlaced,
        "vbv_maxrate": vbv_maxrate,
        "vbv_bufsize": vbv_bufsize,
        "vbv_init": 1.0 if nal_hrd == "cbr" else 0.9,
        "keyint": keyint,
        "nal_hrd": nal_hrd,
        "frame_count": frame_count,
        "hkep": hkep,
        "pep": pep,
        "exactframerate": f"{fps_num}/{fps_den}" if fps_den != 1 else str(fps_num),
    }


# ---------------------------------------------------------------------------
# MIBs → SDP  (for the receive command)
# ---------------------------------------------------------------------------

def generate_sdp_from_mibs(
    sender_reports: list,
    reference_sdp_text: str | None = None,
) -> str:
    """Build an SDP transport file from decoded Sender Report Media Info Blocks.

    If *reference_sdp_text* is provided, uses it as a base and overlays
    MIB-derived fields.  Otherwise builds a minimal SDP from scratch.
    """
    from MatroxSdp import MatroxSdp, MatroxSdpEnums, auto_lookup_enum
    from MatroxSdpWrite import encode as sdp_encode

    E = MatroxSdpEnums

    if not sender_reports:
        raise ValueError("No sender reports found in PCAP")

    sr = sender_reports[0]

    video_mib: dict[str, Any] = {}
    audio_mib: dict[str, Any] = {}
    audio_mib_type: int | None = None
    codec_mib: dict[str, Any] = {}
    hkep_present = False
    pep_present = False
    codec = ""

    for blk in sr.raw_blocks:
        d = blk.decoded if blk.decoded else {}
        if blk.media_info_type in (0x0001, 0x0003, 0x0005):
            video_mib = dict(d)
        elif blk.media_info_type in (0x0002, 0x0004):
            audio_mib = dict(d)
            audio_mib_type = blk.media_info_type
            if blk.media_info_type == 0x0004:
                codec = "am824"
            elif blk.media_info_type == 0x0002:
                codec = "pcm"
        elif blk.media_info_type == 0x0009:
            codec_mib = dict(d)
            codec = "h265"
        elif blk.media_info_type == 0x000A:
            codec_mib = dict(d)
            codec = "h264"
        elif blk.media_info_type == 0x0010:
            hkep_present = True
        elif blk.media_info_type == 0x0011:
            pep_present = True

    if reference_sdp_text:
        sdp = MatroxSdp()
        err = sdp.decode(reference_sdp_text)
        if err:
            raise ValueError(f"Reference SDP decode error: {err}")
    else:
        sdp = MatroxSdp()
        sdp.username = "-"
        sdp.session_id = 1
        sdp.session_version = 1
        sdp.origin_address = "127.0.0.1"
        sdp.session_name = "IPMX Received Stream"
        sdp.connection_address = "127.0.0.1"
        sdp.connection_ttl = 0

    if sr.ipmx_info:
        ts_refclk = sr.ipmx_info.ts_refclk or ""
        if ts_refclk.startswith("localmac="):
            sdp.ts_ref_clock_source = E.LocalMac.value
            sdp.ts_ref_clock_local_mac_address = ts_refclk.split("=", 1)[1]
        elif ts_refclk.startswith("ptp="):
            sdp.ts_ref_clock_source = E.PTP.value
        else:
            sdp.ts_ref_clock_source = E.LocalMac.value
            sdp.ts_ref_clock_local_mac_address = "00-00-00-00-00-00"

        mediaclk = sr.ipmx_info.mediaclk or ""
        if mediaclk == "sender":
            sdp.media_clock_type = E.Sender.value
        elif mediaclk.startswith("direct="):
            sdp.media_clock_type = E.Direct.value

    m = sdp.medias[0]
    m.protocol = E.ProtocolRTP_AVP.value
    if not m.port:
        m.port = 15000
    if not m.media_name:
        m.media_name = "primary"

    if codec == "am824" and audio_mib:
        config = _build_am824_stream_config(
            name="engine_receive_am824",
            description=sdp.session_information or sdp.session_name or "IPMX Received AM824 Stream",
            sample_rate=int(audio_mib["sampling_rate"]),
            nchan=int(audio_mib["channel_count"]),
            ptime_us=int(audio_mib["packet_time"]),
            payload_type=m.payload_type or m.format_code or 96,
            channel_order=str(audio_mib["channel_order"]),
            duration_seconds=6,
        )
        m.type = E.Audio.value
        m.format_code = config.payload_type
        m.payload_type = config.payload_type
        m.encoding_name = E.EncodingAM824.value
        m.sample_rate = config.sample_rate
        m.channels = config.nchan
        m.channel_order = str(audio_mib["channel_order"])
        m.p_time_us = int(audio_mib["packet_time"])
        m.measured_sample_rate = int(audio_mib["measured_sample_rate"])
        m.ipmx = True
        m.sender_type = E.SenderType2110TPN.value
        if not m.max_udp:
            m.max_udp = config.payload_bytes_per_packet
    elif codec == "pcm" and audio_mib:
        sample_size = int(audio_mib.get("sample_size", 24))
        _enc_map = {16: E.EncodingL16, 20: E.EncodingL20, 24: E.EncodingL24}
        encoding_enum = _enc_map.get(sample_size, E.EncodingL24)
        pt = m.payload_type or m.format_code or 96
        m.type = E.Audio.value
        m.format_code = pt
        m.payload_type = pt
        m.encoding_name = encoding_enum.value
        m.sample_rate = int(audio_mib["sampling_rate"])
        m.channels = int(audio_mib["channel_count"])
        m.channel_order = str(audio_mib.get("channel_order", ""))
        m.p_time_us = int(audio_mib["packet_time"])
        m.measured_sample_rate = int(audio_mib.get("measured_sample_rate", m.sample_rate))
        m.ipmx = True
        m.sender_type = E.SenderType2110TPN.value
        from ipmx_pcm import bytes_per_sample as _pcm_bps
        if not m.max_udp:
            from ipmx_am824 import resolve_packet_samples_per_packet
            spp = resolve_packet_samples_per_packet(m.sample_rate, m.p_time_us)
            if spp is not None:
                m.max_udp = spp * m.channels * _pcm_bps(sample_size)
            else:
                m.max_udp = 1460
    else:
        m.type = E.Video.value
        m.format_code = 98
        m.payload_type = 98
        m.clock_rate = 90000

        if codec == "h265":
            m.encoding_name = E.EncodingH265.value
        elif codec == "h264":
            m.encoding_name = E.EncodingH264.value

        if video_mib:
            if video_mib.get("width"):
                m.width = video_mib["width"]
            if video_mib.get("height"):
                m.height = video_mib["height"]
            if video_mib.get("bit_depth"):
                m.depth = video_mib["bit_depth"]
            if video_mib.get("rate_numerator") and video_mib.get("rate_denominator"):
                m.exact_frame_rate_numerator = video_mib["rate_numerator"]
                m.exact_frame_rate_denominator = video_mib["rate_denominator"]
            if video_mib.get("sampling_format"):
                m.sampling = auto_lookup_enum(video_mib["sampling_format"])
            if video_mib.get("colorimetry"):
                m.colorimetry = auto_lookup_enum(video_mib["colorimetry"])
            if video_mib.get("tcs_string"):
                m.transfer_characteristic = auto_lookup_enum(video_mib["tcs_string"])
            if video_mib.get("range_string"):
                m.color_range = auto_lookup_enum(video_mib["range_string"])
            if video_mib.get("htotal"):
                m.h_total = video_mib["htotal"]
            if video_mib.get("vtotal"):
                m.v_total = video_mib["vtotal"]
            if video_mib.get("measured_pixel_clock"):
                m.measured_pix_clk = video_mib["measured_pixel_clock"]
            m.interlaced = bool(video_mib.get("interlace", False))

        m.ipmx = True
        m.sender_type = E.SenderType2110TPW.value
        if not m.max_udp:
            m.max_udp = 1460

        if codec == "h265" and codec_mib:
            from generate_video_test_streams import _populate_h265_fmtp
            _populate_h265_fmtp(m, codec_mib)
        elif codec == "h264" and codec_mib:
            from generate_video_test_streams import _populate_h264_fmtp
            _populate_h264_fmtp(m, codec_mib)

    m.hkep = hkep_present
    m.privacy = pep_present

    sdp.primary_media_name = m.media_name
    sdp.primary_media = m

    return sdp_encode(sdp)


def compare_sdp(old_text: str | None, new_text: str) -> bool:
    """Return True if the SDP content changed (ignoring session version)."""
    if old_text is None:
        return True
    old_lines = [
        l for l in old_text.strip().splitlines()
        if not l.startswith("o=")
    ]
    new_lines = [
        l for l in new_text.strip().splitlines()
        if not l.startswith("o=")
    ]
    return old_lines != new_lines


# ---------------------------------------------------------------------------
# Command: generate
# ---------------------------------------------------------------------------

def do_generate(request: dict[str, Any]) -> dict[str, Any]:
    sdp_text = request.get("sdp", "")
    pcap_path = request.get("pcap", "")
    random_access_duration = request.get("random_access_duration", 1.0)
    random_access_count = request.get("random_access_count", 6)

    if not sdp_text:
        return {"status": "error", "error": "sdp is required for generate"}
    if not pcap_path:
        return {"status": "error", "error": "pcap is required for generate"}

    cfg_dict = derive_stream_config(sdp_text, random_access_duration, random_access_count)

    if cfg_dict["codec"] == "am824":
        from generate_audio_test_streams import (
            generate_one_config, EncryptionMode, _encryption_suffix,
        )

        final_pcap = Path(pcap_path)
        final_pcap.parent.mkdir(parents=True, exist_ok=True)

        # Align the carousel cycle to a whole number of AES3 blocks (192 frames each).
        # A receiver can only reconstruct the channel status word from a block boundary
        # (B=1, F=1), so the AES3 block is the audio equivalent of a video IDR frame.
        #
        # Mirrors the video formula exactly:
        #   video:  keyint = round(fps × random_access_duration)
        #   audio:  blocks_per_cycle = round(sample_rate × random_access_duration / 192)
        #
        # Total samples = blocks_per_cycle × 192 × random_access_count
        # Duration      = total_samples / sample_rate   (float, exact)
        from ipmx_am824 import AES3_BLOCK_PERIOD
        sample_rate = int(cfg_dict["sample_rate"])
        blocks_per_cycle = max(1, round(sample_rate * float(random_access_duration) / AES3_BLOCK_PERIOD))
        total_samples = blocks_per_cycle * AES3_BLOCK_PERIOD * int(random_access_count)
        duration_seconds = total_samples / sample_rate

        config = _build_am824_stream_config(
            name="engine_generated_am824",
            description=cfg_dict["description"],
            sample_rate=int(cfg_dict["sample_rate"]),
            nchan=int(cfg_dict["nchan"]),
            ptime_us=int(cfg_dict["ptime_us"]),
            payload_type=int(cfg_dict["payload_type"]),
            channel_order=str(cfg_dict["channel_order"]),
            duration_seconds=duration_seconds,
        )

        # Mirror the video codec pattern: read hkep/pep from the config dict (derived from SDP).
        hkep = cfg_dict.get("hkep", False)
        pep  = cfg_dict.get("pep",  False)
        if hkep and pep:
            enc_mode = EncryptionMode.HKEP_PEP
        elif hkep:
            enc_mode = EncryptionMode.HKEP
        elif pep:
            enc_mode = EncryptionMode.PEP
        else:
            enc_mode = EncryptionMode.CLEAR
        encryption_modes = (
            [EncryptionMode.CLEAR, enc_mode]
            if enc_mode != EncryptionMode.CLEAR
            else [EncryptionMode.CLEAR]
        )

        with tempfile.TemporaryDirectory(prefix="ipmx_engine_audio_") as tmp:
            tmp_dir = Path(tmp)
            ok = generate_one_config(
                config,
                tmp_dir,
                {},
                int(cfg_dict["port"]),
                verbose=False,
                encryption_modes=encryption_modes,
            )
            if not ok:
                return {"status": "error", "error": "AM824 generation failed"}
            suffix = _encryption_suffix(enc_mode)
            generated_pcap = tmp_dir / f"{config.name}{suffix}.pcap"
            shutil.copy2(generated_pcap, final_pcap)

        actual_duration = config.packet_count * config.ptime.value / 1_000_000.0

    elif cfg_dict["codec"] == "pcm":
        from generate_pcm_test_streams import (
            generate_one_config as generate_pcm_one_config,
            EncryptionMode as PcmEncryptionMode,
            _encryption_suffix as _pcm_encryption_suffix,
        )
        from generate_audio_test_streams import parse_channel_order_groups
        from ipmx_pcm import PcmStreamConfig
        from ipmx_am824 import PtimePreset

        final_pcap = Path(pcap_path)
        final_pcap.parent.mkdir(parents=True, exist_ok=True)

        sample_rate = int(cfg_dict["sample_rate"])
        nchan = int(cfg_dict["nchan"])
        ptime_us = int(cfg_dict["ptime_us"])
        bit_depth_val = int(cfg_dict["bit_depth"])

        _pt_map = {125: PtimePreset.PTIME_125US, 1000: PtimePreset.PTIME_1MS}
        ptime_enum = _pt_map.get(ptime_us)
        if ptime_enum is None:
            return {"status": "error", "error": f"Unsupported PCM ptime {ptime_us} us"}

        duration_seconds = float(random_access_count) * float(random_access_duration)

        channel_order_str = str(cfg_dict.get("channel_order", ""))
        if channel_order_str:
            channel_order_groups = parse_channel_order_groups(channel_order_str)
        else:
            from ipmx_am824 import ChannelOrderGroup
            channel_order_groups = (ChannelOrderGroup.ST,)

        pcm_config = PcmStreamConfig(
            name="engine_generated_pcm",
            description=cfg_dict.get("description", "Generated by IPMX engine"),
            bit_depth=bit_depth_val,
            nchan=nchan,
            channel_order_groups=channel_order_groups,
            sample_rate=sample_rate,
            ptime=ptime_enum,
            payload_type=int(cfg_dict["payload_type"]),
            duration_seconds=duration_seconds,
        )

        hkep = cfg_dict.get("hkep", False)
        pep = cfg_dict.get("pep", False)
        if hkep and pep:
            enc_mode = PcmEncryptionMode.HKEP_PEP
        elif hkep:
            enc_mode = PcmEncryptionMode.HKEP
        elif pep:
            enc_mode = PcmEncryptionMode.PEP
        else:
            enc_mode = PcmEncryptionMode.CLEAR
        encryption_modes = (
            [PcmEncryptionMode.CLEAR, enc_mode]
            if enc_mode != PcmEncryptionMode.CLEAR
            else [PcmEncryptionMode.CLEAR]
        )

        with tempfile.TemporaryDirectory(prefix="ipmx_engine_pcm_") as tmp:
            tmp_dir = Path(tmp)
            ok = generate_pcm_one_config(
                pcm_config,
                tmp_dir,
                int(cfg_dict["port"]),
                verbose=False,
                encryption_modes=encryption_modes,
            )
            if not ok:
                return {"status": "error", "error": "PCM generation failed"}
            suffix = _pcm_encryption_suffix(enc_mode)
            generated_pcap = tmp_dir / f"{pcm_config.name}{suffix}.pcap"
            shutil.copy2(generated_pcap, final_pcap)

        actual_duration = pcm_config.packet_count * ptime_us / 1_000_000.0

    else:
        import generate_video_test_streams as gen
        from generate_video_test_streams import (
            StreamConfig,
            generate_source,
            encode_stream,
            capture_rtp,
            inject_sender_reports,
        )

        fps = Fraction(cfg_dict["fps_num"], cfg_dict["fps_den"])
        desired_frames = cfg_dict["frame_count"]
        gen.DURATION_SECONDS = desired_frames / float(fps)

        cfg = StreamConfig(
            name="engine_generated",
            description="Generated by IPMX engine",
            codec=cfg_dict["codec"],
            width=cfg_dict["width"],
            height=cfg_dict["height"],
            fps_num=cfg_dict["fps_num"],
            fps_den=cfg_dict["fps_den"],
            pix_fmt=cfg_dict["pix_fmt"],
            sampling=cfg_dict["sampling"],
            bit_depth=cfg_dict["bit_depth"],
            interlace=cfg_dict["interlace"],
            vbv_maxrate=cfg_dict["vbv_maxrate"],
            vbv_bufsize=cfg_dict["vbv_bufsize"],
            vbv_init=cfg_dict["vbv_init"],
            keyint=cfg_dict["keyint"],
            nal_hrd=cfg_dict["nal_hrd"],
        )

        actual_duration = gen.DURATION_SECONDS

        with tempfile.TemporaryDirectory(prefix="ipmx_engine_") as tmp:
            tmp_dir = Path(tmp)
            source_raw = tmp_dir / "source.yuv"
            encoded_mp4 = tmp_dir / "encoded.mp4"
            rtp_pcap = tmp_dir / "rtp.pcap"
            final_pcap = Path(pcap_path)

            final_pcap.parent.mkdir(parents=True, exist_ok=True)

            generate_source(
                source_raw, cfg.width, cfg.height,
                cfg.fps_num, cfg.fps_den, cfg.pix_fmt, cfg.frame_count,
            )

            encode_stream(source_raw, encoded_mp4, cfg)

            port = 18000
            capture_rtp(encoded_mp4, rtp_pcap, port,
                        hdcp_scramble=cfg_dict["hkep"],
                        privacy_scramble=cfg_dict["pep"])

            # Write SDP to a file so inject_sender_reports can use it as a
            # fallback for signal-MIB population when payloads are encrypted
            # and the NALU-based path cannot extract SPS/PPS fields.
            sdp_file = tmp_dir / "transport.sdp"
            sdp_file.write_text(sdp_text)

            inject_sender_reports(
                rtp_pcap, final_pcap, cfg.codec,
                exactframerate=cfg_dict["exactframerate"],
                hkep=cfg_dict["hkep"],
                pep=cfg_dict["pep"],
                sdp_path=sdp_file,
            )

    return {
        "status": "ok",
        "generate": {
            "duration_seconds": actual_duration,
        },
    }


# ---------------------------------------------------------------------------
# Command: validate
# ---------------------------------------------------------------------------

def _parse_validator_output(output: str) -> dict[str, Any]:
    """Parse the text output of a validator into structured results."""
    shall_pass = shall_fail = shall_untestable = 0
    should_pass = should_fail = should_untestable = 0
    failures: list[str] = []
    warnings: list[str] = []
    first_summary = True

    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("SHALL requirements") or stripped.startswith("SHOULD requirements"):
            continue

        summary = _try_parse_summary(stripped)
        if summary is not None:
            p, f, u = summary
            if first_summary:
                shall_pass, shall_fail, shall_untestable = p, f, u
                first_summary = False
            else:
                should_pass, should_fail, should_untestable = p, f, u
            continue

        if stripped.startswith("FAIL "):
            failures.append(stripped)
        elif stripped.startswith("WARN "):
            warnings.append(stripped)

    passed = shall_fail == 0 and not failures

    return {
        "passed": passed,
        "shall": {"pass": shall_pass, "fail": shall_fail, "untestable": shall_untestable},
        "should": {"pass": should_pass, "fail": should_fail, "untestable": should_untestable},
        "failures": failures,
        "warnings": warnings,
    }


def _try_parse_summary(line: str) -> tuple[int, int, int] | None:
    try:
        parts = line.strip().split(",")
        passed = int(parts[0].split("/")[0])
        failed = int(parts[1].strip().split()[0])
        untestable = int(parts[2].strip().split()[0])
        return passed, failed, untestable
    except (IndexError, ValueError):
        return None


def _detect_codec_from_sdp(sdp_text: str) -> str:
    for line in sdp_text.splitlines():
        ll = line.lower()
        if "h265" in ll:
            return "h265"
        if "h264" in ll:
            return "h264"
        if "jxsv" in ll:
            return "jxsv"
        if "am824" in ll:
            return "am824"
        if any(enc in ll for enc in (" l16/", " l20/", " l24/", " l16 ", " l20 ", " l24 ")):
            return "pcm"
    return ""


def _format_ptime_arg(ptime_us: int) -> str:
    milliseconds = Decimal(ptime_us) / Decimal(1000)
    return format(milliseconds.normalize(), "f")


def _build_am824_stream_config(
    *,
    name: str,
    description: str,
    sample_rate: int,
    nchan: int,
    ptime_us: int,
    payload_type: int,
    channel_order: str,
    duration_seconds: float,
):
    from generate_audio_test_streams import build_dynamic_audio_stream_config

    return build_dynamic_audio_stream_config(
        name=name,
        description=description,
        channel_order=channel_order,
        sample_rate=sample_rate,
        ptime_us=ptime_us,
        duration_seconds=duration_seconds,
        payload_type=payload_type,
        expected_nchan=nchan,
    )


def _append_am824_validator_args(
    cmd: list[str],
    *,
    sdp_text: str,
    request: dict[str, Any],
    sender_reports: list[Any] | None = None,
) -> None:
    from MatroxSdp import MatroxSdp

    sdp = MatroxSdp()
    err = sdp.decode(sdp_text)
    if err:
        raise ValueError(f"SDP decode error: {err}")
    media = sdp.primary_media or (sdp.medias[0] if sdp.medias else None)
    if media is None:
        raise ValueError("SDP contains no media descriptor")

    port = int(request.get("port", media.port or 0) or 0)
    rtcp_port = int(request.get("rtcp_port", port + 1 if port else 0) or 0)
    payload_type = int(request.get("payload_type", media.payload_type or media.format_code or 0) or 0)
    sample_rate = int(request.get("sample_rate", media.sample_rate or media.clock_rate or 0) or 0)
    nchan = int(request.get("nchan", media.channels or 0) or 0)
    ptime_us = int(request.get("ptime_us", media.p_time_us or 0) or 0)
    channel_order = str(request.get("channel_order", media.channel_order or "") or "")
    measured_sample_rate = int(
        request.get("measured_sample_rate", media.measured_sample_rate or sample_rate or 0) or 0
    )
    sample_size = request.get("sample_size")
    ssrc = request.get("ssrc")
    dst_ip = request.get("dst_ip")

    if port:
        cmd.extend(["--port", str(port)])
    if rtcp_port:
        cmd.extend(["--rtcp-port", str(rtcp_port)])
    if ssrc is not None:
        cmd.extend(["--ssrc", str(ssrc)])
    if dst_ip:
        cmd.extend(["--dst-ip", str(dst_ip)])
    if payload_type:
        cmd.extend(["--payload-type", str(payload_type)])
    if sample_rate:
        cmd.extend(["--sample-rate", str(sample_rate)])
    if nchan:
        cmd.extend(["--nchan", str(nchan)])
    if ptime_us:
        cmd.extend(["--ptime", _format_ptime_arg(ptime_us)])
    if channel_order:
        cmd.extend(["--channel-order", channel_order])
    if measured_sample_rate:
        cmd.extend(["--measured-sample-rate", str(measured_sample_rate)])
    # Resolve sample_size from direct request value or by scanning MIBs.
    resolved_sample_size: int | None = None
    if sample_size is not None:
        resolved_sample_size = int(sample_size)
    elif sender_reports:
        for report in sender_reports:
            for block in report.raw_blocks:
                if block.media_info_type == 0x0004 and block.decoded is not None and "sample_size" in block.decoded:
                    resolved_sample_size = int(block.decoded["sample_size"])
                    break
            if resolved_sample_size is not None:
                break
    if resolved_sample_size is not None:
        cmd.extend(["--sample-size", str(resolved_sample_size)])

    if bool(media.hkep):
        cmd.append("--hkep")
    if bool(media.privacy):
        cmd.append("--pep")

    if request.get("expect_stream_start"):
        cmd.append("--expect-stream-start")


def _append_pcm_validator_args(
    cmd: list[str],
    *,
    sdp_text: str,
    request: dict[str, Any],
    sender_reports: list[Any] | None = None,
) -> None:
    from MatroxSdp import MatroxSdp

    sdp = MatroxSdp()
    err = sdp.decode(sdp_text)
    if err:
        raise ValueError(f"SDP decode error: {err}")
    media = sdp.primary_media or (sdp.medias[0] if sdp.medias else None)
    if media is None:
        raise ValueError("SDP contains no media descriptor")

    port = int(request.get("port", media.port or 0) or 0)
    rtcp_port = int(request.get("rtcp_port", port + 1 if port else 0) or 0)
    payload_type = int(request.get("payload_type", media.payload_type or media.format_code or 0) or 0)
    sample_rate = int(request.get("sample_rate", media.sample_rate or media.clock_rate or 0) or 0)
    nchan = int(request.get("nchan", media.channels or 0) or 0)
    ptime_us = int(request.get("ptime_us", media.p_time_us or 0) or 0)
    channel_order = str(request.get("channel_order", media.channel_order or "") or "")
    measured_sample_rate = int(
        request.get("measured_sample_rate", media.measured_sample_rate or sample_rate or 0) or 0
    )
    sample_size = request.get("sample_size")
    bit_depth = request.get("bit_depth")
    ssrc = request.get("ssrc")
    dst_ip = request.get("dst_ip")

    if port:
        cmd.extend(["--port", str(port)])
    if rtcp_port:
        cmd.extend(["--rtcp-port", str(rtcp_port)])
    if ssrc is not None:
        cmd.extend(["--ssrc", str(ssrc)])
    if dst_ip:
        cmd.extend(["--dst-ip", str(dst_ip)])
    if payload_type:
        cmd.extend(["--payload-type", str(payload_type)])
    if sample_rate:
        cmd.extend(["--sample-rate", str(sample_rate)])
    if nchan:
        cmd.extend(["--nchan", str(nchan)])
    if ptime_us:
        cmd.extend(["--ptime", _format_ptime_arg(ptime_us)])
    if channel_order:
        cmd.extend(["--channel-order", channel_order])
    if measured_sample_rate:
        cmd.extend(["--measured-sample-rate", str(measured_sample_rate)])

    resolved_sample_size: int | None = None
    if sample_size is not None:
        resolved_sample_size = int(sample_size)
    elif sender_reports:
        for report in sender_reports:
            for block in report.raw_blocks:
                if block.media_info_type == 0x0002 and block.decoded is not None and "sample_size" in block.decoded:
                    resolved_sample_size = int(block.decoded["sample_size"])
                    break
            if resolved_sample_size is not None:
                break
    if resolved_sample_size is not None:
        cmd.extend(["--sample-size", str(resolved_sample_size)])

    resolved_bit_depth: int | None = None
    if bit_depth is not None:
        resolved_bit_depth = int(bit_depth)
    elif media.encoding_name is not None:
        enc_str = str(media.encoding_name) if hasattr(media.encoding_name, "s") else str(media.encoding_name)
        enc_upper = enc_str.upper() if hasattr(enc_str, "upper") else enc_str
        _depth_map = {"L16": 16, "L20": 20, "L24": 24}
        resolved_bit_depth = _depth_map.get(enc_upper)
    if resolved_bit_depth is not None:
        cmd.extend(["--bit-depth", str(resolved_bit_depth)])

    if bool(media.hkep):
        cmd.append("--hkep")
    if bool(media.privacy):
        cmd.append("--pep")

    if request.get("expect_stream_start"):
        cmd.append("--expect-stream-start")


def do_validate(request: dict[str, Any]) -> dict[str, Any]:
    pcap_path = request.get("pcap", "")
    sdp_text = request.get("sdp", "")
    hrd = request.get("hrd", False)
    hrd_sim = request.get("hrd_sim", False)
    hrd_timing = request.get("hrd_timing", False)
    cmax = request.get("cmax", False)
    allow_superset = request.get("allow_superset_profile", False)

    if not pcap_path:
        return {"status": "error", "error": "pcap is required for validate"}
    if not sdp_text:
        return {"status": "error", "error": "sdp is required for validate"}

    pcap = Path(pcap_path)
    if not pcap.exists():
        return {"status": "error", "error": f"PCAP not found: {pcap_path}"}

    codec = _detect_codec_from_sdp(sdp_text)
    if not codec:
        return {"status": "error", "error": "Cannot detect codec from SDP"}

    validators = {
        "h265": SCRIPT_DIR / "ipmx_h265_validate_pcap.py",
        "h264": SCRIPT_DIR / "ipmx_h264_validate_pcap.py",
        "jxsv": SCRIPT_DIR / "ipmx_jxsv_validate_pcap.py",
        "am824": SCRIPT_DIR / "ipmx_am824_validate_pcap.py",
        "pcm": SCRIPT_DIR / "ipmx_pcm_validate_pcap.py",
    }
    validator = validators.get(codec)
    if not validator or not validator.exists():
        return {"status": "error", "error": f"Validator not found for codec {codec}"}

    hkep = "a=hkep" in sdp_text.lower() or "hkep" in sdp_text.lower()
    pep = "a=privacy" in sdp_text.lower()

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".sdp", delete=False, dir=str(SCRIPT_DIR),
    ) as sdp_file:
        sdp_file.write(sdp_text)
        sdp_path = Path(sdp_file.name)

    try:
        cmd: list[str] = [
            sys.executable, str(validator), str(pcap),
            "--sdp", str(sdp_path),
        ]
        if codec == "am824":
            _append_am824_validator_args(cmd, sdp_text=sdp_text, request=request)
        elif codec == "pcm":
            _append_pcm_validator_args(cmd, sdp_text=sdp_text, request=request)
        else:
            if allow_superset:
                cmd.append("--allow-superset-profile")
            if hkep:
                cmd.append("--hkep")
            if pep:
                cmd.append("--pep")
            if hrd_timing:
                cmd.append("--hrd-timing")
            elif hrd_sim:
                cmd.append("--hrd-sim")
            elif hrd:
                cmd.append("--hrd")
            if cmax:
                cmd.append("--cmax")

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = proc.stdout + proc.stderr
        validation = _parse_validator_output(output)
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "Validator timed out"}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}
    finally:
        sdp_path.unlink(missing_ok=True)

    return {
        "status": "ok",
        "validation": validation,
    }


# ---------------------------------------------------------------------------
# Command: receive
# ---------------------------------------------------------------------------

def do_receive(request: dict[str, Any]) -> dict[str, Any]:
    pcap_path = request.get("pcap", "")
    sdp_text = request.get("sdp") or None
    hrd = request.get("hrd", False)
    hrd_sim = request.get("hrd_sim", False)
    cmax = request.get("cmax", False)
    allow_superset = request.get("allow_superset_profile", False)

    if not pcap_path:
        return {"status": "error", "error": "pcap is required for receive"}

    pcap = Path(pcap_path)
    if not pcap.exists():
        return {"status": "error", "error": f"PCAP not found: {pcap_path}"}

    import ipmx_validate_common as common

    sender_reports = common.parse_sender_reports(pcap, port=None)
    if not sender_reports:
        return {
            "status": "error",
            "error": "No sender reports found in PCAP",
        }

    try:
        new_sdp_text = generate_sdp_from_mibs(sender_reports, sdp_text)
    except Exception as exc:
        return {"status": "error", "error": f"SDP generation from MIBs failed: {exc}"}

    sdp_changed = compare_sdp(sdp_text, new_sdp_text)

    codec = _detect_codec_from_sdp(new_sdp_text)

    validators = {
        "h265": SCRIPT_DIR / "ipmx_h265_validate_pcap.py",
        "h264": SCRIPT_DIR / "ipmx_h264_validate_pcap.py",
        "jxsv": SCRIPT_DIR / "ipmx_jxsv_validate_pcap.py",
        "am824": SCRIPT_DIR / "ipmx_am824_validate_pcap.py",
        "pcm": SCRIPT_DIR / "ipmx_pcm_validate_pcap.py",
    }
    validator = validators.get(codec)
    validation: dict[str, Any] | None = None

    if validator and validator.exists():
        hkep = any(
            blk.media_info_type == 0x0010
            for sr in sender_reports for blk in sr.raw_blocks
        )
        pep = any(
            blk.media_info_type == 0x0011
            for sr in sender_reports for blk in sr.raw_blocks
        )

        is_first_activation = sdp_text is not None and not sdp_changed

        cmd: list[str] = [sys.executable, str(validator), str(pcap)]

        if codec in ("am824", "pcm"):
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".sdp", delete=False, dir=str(SCRIPT_DIR),
            ) as sdp_file:
                sdp_file.write(new_sdp_text)
                sdp_tmp = Path(sdp_file.name)
            cmd.extend(["--sdp", str(sdp_tmp)])
            if codec == "am824":
                _append_am824_validator_args(
                    cmd,
                    sdp_text=new_sdp_text,
                    request=request,
                    sender_reports=sender_reports,
                )
            else:
                _append_pcm_validator_args(
                    cmd,
                    sdp_text=new_sdp_text,
                    request=request,
                    sender_reports=sender_reports,
                )
        else:
            if is_first_activation:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".sdp", delete=False, dir=str(SCRIPT_DIR),
                ) as sdp_file:
                    sdp_file.write(sdp_text)
                    sdp_tmp = Path(sdp_file.name)
                cmd.extend(["--sdp", str(sdp_tmp)])
            else:
                sdp_tmp = None

            cmd.append("--allow-superset-profile")
            if hkep:
                cmd.append("--hkep")
            if pep:
                cmd.append("--pep")
            if hrd_sim:
                cmd.append("--hrd-sim")
            elif hrd:
                cmd.append("--hrd")
            if cmax:
                cmd.append("--cmax")

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            output = proc.stdout + proc.stderr
            validation = _parse_validator_output(output)
        except subprocess.TimeoutExpired:
            validation = {
                "passed": False,
                "shall": {"pass": 0, "fail": 0, "untestable": 0},
                "should": {"pass": 0, "fail": 0, "untestable": 0},
                "failures": ["Validator timed out"],
                "warnings": [],
            }
        except Exception as exc:
            validation = {
                "passed": False,
                "shall": {"pass": 0, "fail": 0, "untestable": 0},
                "should": {"pass": 0, "fail": 0, "untestable": 0},
                "failures": [str(exc)],
                "warnings": [],
            }
        finally:
            if sdp_tmp:
                sdp_tmp.unlink(missing_ok=True)

    result: dict[str, Any] = {
        "status": "ok",
        "receive": {
            "sdp": new_sdp_text,
            "sdp_changed": sdp_changed,
        },
    }
    if validation is not None:
        result["validation"] = validation

    return result


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> int:
    try:
        request = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        json.dump({"status": "error", "error": f"Invalid JSON input: {exc}"}, sys.stdout)
        return 1

    command = request.get("command", "")

    saved_stdout_fd = os.dup(1)
    saved_stderr_fd = os.dup(2)
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull_fd, 1)
    os.dup2(devnull_fd, 2)
    os.close(devnull_fd)

    try:
        if command == "generate":
            result = do_generate(request)
        elif command == "validate":
            result = do_validate(request)
        elif command == "receive":
            result = do_receive(request)
        else:
            result = {"status": "error", "error": f"Unknown command: {command}"}
    except Exception as exc:
        result = {"status": "error", "error": str(exc)}
    finally:
        # Flush Python's internal buffers while fd 1/2 still point to /dev/null,
        # so any print() output from sub-routines (e.g. generate_one_config) is
        # discarded rather than leaking into the JSON output line below.
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(saved_stdout_fd, 1)
        os.dup2(saved_stderr_fd, 2)
        os.close(saved_stdout_fd)
        os.close(saved_stderr_fd)
        sys.stdout = os.fdopen(1, "w", closefd=False)
        sys.stderr = os.fdopen(2, "w", closefd=False)

    json.dump(result, sys.stdout)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0 if result.get("status") == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
