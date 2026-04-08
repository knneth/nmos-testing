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
"""Generate IPMX-compliant H.265 and H.264 test PCAP streams.

Produces ready-to-validate PCAPs with Sender Reports for a representative
set of proAV configurations.  Each base configuration is optionally produced
in four encryption variants: clear, HKEP, PEP, and HKEP+PEP.

Workflow per configuration:
  1. Generate a synthetic colour-bars source at the target resolution/fps.
  2. Encode with libx265 or libx264 with full HRD parameters.
  3. Capture RTP via loopback socket (no root required).
  4. Inject IPMX Sender Reports.
  5. Export the MIB config JSON (from the clear variant).
  6. For encrypted variants: re-capture with scramble flags, inject SRs
     using the exported config.

Run:
  python3 generate_video_test_streams.py [--output-dir DIR] [--codec h264|h265]
      [--config NAME] [--encryption MODE] [--list] [-v]

Requires: ffmpeg (with libx265 and/or libx264), scapy
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time as time_mod
from dataclasses import dataclass, field
from enum import Enum
from fractions import Fraction
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "test-streams"
DURATION_SECONDS = 6


# ---------------------------------------------------------------------------
# Encryption modes
# ---------------------------------------------------------------------------

class EncryptionMode(Enum):
    CLEAR = "clear"
    HKEP = "hkep"
    PEP = "pep"
    HKEP_PEP = "hkep_pep"


ALL_ENCRYPTION_MODES = list(EncryptionMode)


# ---------------------------------------------------------------------------
# Stream configuration
# ---------------------------------------------------------------------------

@dataclass
class StreamConfig:
    name: str
    description: str
    codec: str                  # "h265" or "h264"
    width: int
    height: int
    fps_num: int                # framerate numerator
    fps_den: int                # framerate denominator (1 or 1001)
    pix_fmt: str                # ffmpeg pixel format
    sampling: str               # IPMX sampling string
    bit_depth: int
    interlace: bool
    vbv_maxrate: int            # kbps
    vbv_bufsize: int            # kbit
    vbv_init: float
    keyint: int
    nal_hrd: str                # "cbr" or "vbr"
    preset: str = "ultrafast"
    extra_x265: str = ""
    extra_x264: str = ""

    @property
    def fps_fraction(self) -> Fraction:
        return Fraction(self.fps_num, self.fps_den)

    @property
    def fps_display(self) -> str:
        f = self.fps_fraction
        if f.denominator == 1:
            return str(f.numerator)
        approx = float(f)
        if abs(approx - round(approx)) < 0.1:
            return str(round(approx))
        return f"{approx:.2f}"

    @property
    def frame_count(self) -> int:
        return round(float(self.fps_fraction) * DURATION_SECONDS)

    @property
    def exactframerate_arg(self) -> str:
        if self.fps_den == 1:
            return str(self.fps_num)
        return f"{self.fps_num}/{self.fps_den}"

    @property
    def ffmpeg_rate(self) -> str:
        if self.fps_den == 1:
            return str(self.fps_num)
        return f"{self.fps_num}/{self.fps_den}"


# ---------------------------------------------------------------------------
# H.265 configurations — representative proAV market
# ---------------------------------------------------------------------------

H265_CONFIGS: list[StreamConfig] = [
    # --- 1080p ---
    StreamConfig(
        name="h265_1080p60_420_8_cbr_20m",
        description="1080p60 4:2:0 8-bit CBR 20 Mbps — standard signage/conferencing",
        codec="h265", width=1920, height=1080,
        fps_num=60, fps_den=1, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=20000, vbv_bufsize=20000, vbv_init=1.0,
        keyint=60, nal_hrd="cbr",
    ),
    StreamConfig(
        name="h265_1080p5994_420_8_cbr_20m",
        description="1080p59.94 4:2:0 8-bit CBR 20 Mbps — NTSC-compatible broadcast",
        codec="h265", width=1920, height=1080,
        fps_num=60000, fps_den=1001, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=20000, vbv_bufsize=20000, vbv_init=1.0,
        keyint=60, nal_hrd="cbr",
    ),
    StreamConfig(
        name="h265_1080p50_420_8_cbr_20m",
        description="1080p50 4:2:0 8-bit CBR 20 Mbps — PAL/EBU broadcast",
        codec="h265", width=1920, height=1080,
        fps_num=50, fps_den=1, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=20000, vbv_bufsize=20000, vbv_init=1.0,
        keyint=50, nal_hrd="cbr",
    ),
    StreamConfig(
        name="h265_1080p30_420_8_vbr_10m",
        description="1080p30 4:2:0 8-bit VBR 10 Mbps — camera/surveillance feed",
        codec="h265", width=1920, height=1080,
        fps_num=30, fps_den=1, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=10000, vbv_bufsize=5000, vbv_init=0.9,
        keyint=30, nal_hrd="vbr",
    ),
    StreamConfig(
        name="h265_1080p25_420_8_vbr_8m",
        description="1080p25 4:2:0 8-bit VBR 8 Mbps — PAL camera feed",
        codec="h265", width=1920, height=1080,
        fps_num=25, fps_den=1, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=8000, vbv_bufsize=4000, vbv_init=0.9,
        keyint=25, nal_hrd="vbr",
    ),
    StreamConfig(
        name="h265_1080p60_420_10_cbr_30m",
        description="1080p60 4:2:0 10-bit CBR 30 Mbps — HDR-capable contribution",
        codec="h265", width=1920, height=1080,
        fps_num=60, fps_den=1, pix_fmt="yuv420p10le",
        sampling="YCbCr-4:2:0", bit_depth=10, interlace=False,
        vbv_maxrate=30000, vbv_bufsize=30000, vbv_init=1.0,
        keyint=60, nal_hrd="cbr",
    ),
    StreamConfig(
        name="h265_1080p60_422_10_cbr_40m",
        description="1080p60 4:2:2 10-bit CBR 40 Mbps — broadcast contribution",
        codec="h265", width=1920, height=1080,
        fps_num=60, fps_den=1, pix_fmt="yuv422p10le",
        sampling="YCbCr-4:2:2", bit_depth=10, interlace=False,
        vbv_maxrate=40000, vbv_bufsize=40000, vbv_init=1.0,
        keyint=60, nal_hrd="cbr",
    ),
    StreamConfig(
        name="h265_1080p60_444_8_cbr_50m",
        description="1080p60 4:4:4 8-bit CBR 50 Mbps — computer graphics/KVM",
        codec="h265", width=1920, height=1080,
        fps_num=60, fps_den=1, pix_fmt="yuv444p",
        sampling="YCbCr-4:4:4", bit_depth=8, interlace=False,
        vbv_maxrate=50000, vbv_bufsize=50000, vbv_init=1.0,
        keyint=60, nal_hrd="cbr",
    ),
    StreamConfig(
        name="h265_1080p60_420_8_lowlat_10m",
        description="1080p60 4:2:0 8-bit CBR 10 Mbps low-latency (small CPB)",
        codec="h265", width=1920, height=1080,
        fps_num=60, fps_den=1, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=10000, vbv_bufsize=1000, vbv_init=0.5,
        keyint=60, nal_hrd="cbr",
    ),
    # --- 720p ---
    StreamConfig(
        name="h265_720p60_420_8_vbr_5m",
        description="720p60 4:2:0 8-bit VBR 5 Mbps — low-bandwidth preview",
        codec="h265", width=1280, height=720,
        fps_num=60, fps_den=1, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=5000, vbv_bufsize=2500, vbv_init=0.9,
        keyint=60, nal_hrd="vbr",
    ),
    # --- 2160p (4K) ---
    StreamConfig(
        name="h265_2160p60_420_8_cbr_40m",
        description="2160p60 4:2:0 8-bit CBR 40 Mbps — 4K signage",
        codec="h265", width=3840, height=2160,
        fps_num=60, fps_den=1, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=40000, vbv_bufsize=40000, vbv_init=1.0,
        keyint=60, nal_hrd="cbr",
    ),
    StreamConfig(
        name="h265_2160p30_420_10_cbr_30m",
        description="2160p30 4:2:0 10-bit CBR 30 Mbps — 4K HDR cinema playback",
        codec="h265", width=3840, height=2160,
        fps_num=30, fps_den=1, pix_fmt="yuv420p10le",
        sampling="YCbCr-4:2:0", bit_depth=10, interlace=False,
        vbv_maxrate=30000, vbv_bufsize=30000, vbv_init=1.0,
        keyint=30, nal_hrd="cbr",
    ),
    StreamConfig(
        name="h265_2160p5994_420_10_cbr_50m",
        description="2160p59.94 4:2:0 10-bit CBR 50 Mbps — 4K broadcast",
        codec="h265", width=3840, height=2160,
        fps_num=60000, fps_den=1001, pix_fmt="yuv420p10le",
        sampling="YCbCr-4:2:0", bit_depth=10, interlace=False,
        vbv_maxrate=50000, vbv_bufsize=50000, vbv_init=1.0,
        keyint=60, nal_hrd="cbr",
    ),
]

# ---------------------------------------------------------------------------
# H.264 configurations — representative proAV market
# ---------------------------------------------------------------------------

H264_CONFIGS: list[StreamConfig] = [
    StreamConfig(
        name="h264_1080p60_420_8_cbr_20m",
        description="1080p60 4:2:0 8-bit CBR 20 Mbps — standard AV-over-IP",
        codec="h264", width=1920, height=1080,
        fps_num=60, fps_den=1, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=20000, vbv_bufsize=20000, vbv_init=1.0,
        keyint=60, nal_hrd="cbr", preset="superfast",
    ),
    StreamConfig(
        name="h264_1080p5994_420_8_cbr_20m",
        description="1080p59.94 4:2:0 8-bit CBR 20 Mbps — NTSC broadcast",
        codec="h264", width=1920, height=1080,
        fps_num=60000, fps_den=1001, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=20000, vbv_bufsize=20000, vbv_init=1.0,
        keyint=60, nal_hrd="cbr", preset="superfast",
    ),
    StreamConfig(
        name="h264_1080p50_420_8_cbr_15m",
        description="1080p50 4:2:0 8-bit CBR 15 Mbps — PAL broadcast",
        codec="h264", width=1920, height=1080,
        fps_num=50, fps_den=1, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=15000, vbv_bufsize=15000, vbv_init=1.0,
        keyint=50, nal_hrd="cbr", preset="superfast",
    ),
    StreamConfig(
        name="h264_1080p30_420_8_vbr_10m",
        description="1080p30 4:2:0 8-bit VBR 10 Mbps — camera feed",
        codec="h264", width=1920, height=1080,
        fps_num=30, fps_den=1, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=10000, vbv_bufsize=5000, vbv_init=0.9,
        keyint=30, nal_hrd="vbr", preset="superfast",
        extra_x264="nal-hrd=vbr",
    ),
    StreamConfig(
        name="h264_1080p60_422_10_cbr_40m",
        description="1080p60 4:2:2 10-bit CBR 40 Mbps — broadcast (High 4:2:2)",
        codec="h264", width=1920, height=1080,
        fps_num=60, fps_den=1, pix_fmt="yuv422p10le",
        sampling="YCbCr-4:2:2", bit_depth=10, interlace=False,
        vbv_maxrate=40000, vbv_bufsize=40000, vbv_init=1.0,
        keyint=60, nal_hrd="cbr", preset="superfast",
    ),
    StreamConfig(
        name="h264_1080p60_420_8_lowlat_8m",
        description="1080p60 4:2:0 8-bit CBR 8 Mbps low-latency",
        codec="h264", width=1920, height=1080,
        fps_num=60, fps_den=1, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=8000, vbv_bufsize=800, vbv_init=0.5,
        keyint=60, nal_hrd="cbr", preset="superfast",
    ),
    StreamConfig(
        name="h264_720p60_420_8_cbr_8m",
        description="720p60 4:2:0 8-bit CBR 8 Mbps — preview/confidence",
        codec="h264", width=1280, height=720,
        fps_num=60, fps_den=1, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=8000, vbv_bufsize=8000, vbv_init=1.0,
        keyint=60, nal_hrd="cbr", preset="superfast",
    ),
    StreamConfig(
        name="h264_2160p30_420_8_cbr_30m",
        description="2160p30 4:2:0 8-bit CBR 30 Mbps — 4K legacy",
        codec="h264", width=3840, height=2160,
        fps_num=30, fps_den=1, pix_fmt="yuv420p",
        sampling="YCbCr-4:2:0", bit_depth=8, interlace=False,
        vbv_maxrate=30000, vbv_bufsize=30000, vbv_init=1.0,
        keyint=30, nal_hrd="cbr", preset="superfast",
    ),
]

ALL_CONFIGS = H265_CONFIGS + H264_CONFIGS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_python39() -> str:
    if sys.version_info >= (3, 9):
        return sys.executable
    for name in ("python3.9", "python3.10", "python3.11", "python3.12"):
        path = shutil.which(name)
        if path is not None:
            return path
    return sys.executable


_PYTHON = _find_python39()

# Matrox ffmpeg selection (adds -hdcp_scramble / -privacy_scramble to the RTP muxer).
#
#   1. /usr/local/bin/ffmpeg — installed Matrox build (preferred); after running
#      ldconfig its libraries are registered system-wide, so no LD_LIBRARY_PATH needed.
#   2. ../ffmpeg-matrox/src/matrox-build/ffmpeg — in-tree sandbox/CI build; dynamically
#      linked against the system libavformat so LD_LIBRARY_PATH must be prepended with
#      the local matrox-build library directories.
#   3. System ffmpeg on PATH — standard build, no HDCP/privacy support (fallback).
_MATROX_BUILD_DIR = Path(__file__).resolve().parent.parent / "ffmpeg-matrox" / "src" / "matrox-build"
_MATROX_FFMPEG_BIN = _MATROX_BUILD_DIR / "ffmpeg"

if Path("/usr/local/bin/ffmpeg").exists():
    # Case 1: properly installed; ldconfig has registered /usr/local/lib.
    _FFMPEG = "/usr/local/bin/ffmpeg"
    _FFMPEG_ENV: dict | None = None
elif _MATROX_FFMPEG_BIN.exists():
    # Case 2: in-tree build; prepend per-subdirectory library paths.
    _FFMPEG = str(_MATROX_FFMPEG_BIN)
    _lib_dirs = os.pathsep.join(
        str(_MATROX_BUILD_DIR / d)
        for d in ("libavformat", "libavcodec", "libavutil", "libswscale", "libswresample")
    )
    _FFMPEG_ENV = os.environ.copy()
    existing = _FFMPEG_ENV.get("LD_LIBRARY_PATH", "")
    _FFMPEG_ENV["LD_LIBRARY_PATH"] = (_lib_dirs + os.pathsep + existing) if existing else _lib_dirs
else:
    # Case 3: fallback — no HDCP/privacy support.
    _FFMPEG = shutil.which("ffmpeg") or "ffmpeg"
    _FFMPEG_ENV = None


def _source_key(cfg: StreamConfig) -> tuple[int, int, int, str]:
    """Cache key for the raw YUV source: (width, height, fps_num, pix_fmt)."""
    return (cfg.width, cfg.height, cfg.fps_num, cfg.pix_fmt)


def generate_source(
    output: Path,
    width: int,
    height: int,
    fps_num: int,
    fps_den: int,
    pix_fmt: str,
    frames: int,
) -> None:
    rate = str(fps_num) if fps_den == 1 else f"{fps_num}/{fps_den}"
    cmd = [
        _FFMPEG, "-hide_banner", "-loglevel", "error", "-y",
        "-f", "lavfi", "-i",
        f"smptebars=rate={rate}:size={width}x{height}",
        "-frames:v", str(frames),
        "-pix_fmt", pix_fmt,
        "-c:v", "rawvideo",
        str(output),
    ]
    subprocess.run(cmd, check=True, env=_FFMPEG_ENV)


def encode_h265(source: Path, output_mp4: Path, cfg: StreamConfig) -> None:
    x265_parts = [
        f"vbv-maxrate={cfg.vbv_maxrate}",
        f"vbv-bufsize={cfg.vbv_bufsize}",
        f"vbv-init={cfg.vbv_init}",
        f"keyint={cfg.keyint}",
        f"min-keyint={cfg.keyint}",
        "scenecut=0",
        "bframes=0",
        "hrd=1",
        f"nal-hrd={cfg.nal_hrd}",
        "vui-hrd-info=1",
        "vui-timing-info=1",
        "repeat-headers=1",
        "aud=1",
        "open-gop=0",
    ]
    if cfg.nal_hrd == "cbr":
        x265_parts.append(f"bitrate={cfg.vbv_maxrate}")
        x265_parts.append("strict-cbr=1")
    if cfg.extra_x265:
        x265_parts.append(cfg.extra_x265)
    x265_params = ":".join(x265_parts)

    fps_arg = cfg.ffmpeg_rate
    tick_rate_str = f"{cfg.fps_num}/{cfg.fps_den}"
    cmd = [
        _FFMPEG, "-hide_banner", "-loglevel", "error", "-y",
        "-r", fps_arg,
        "-f", "rawvideo", "-pix_fmt", cfg.pix_fmt,
        "-s", f"{cfg.width}x{cfg.height}",
        "-i", str(source),
        "-frames:v", str(cfg.frame_count),
        "-c:v", "libx265",
        "-preset", cfg.preset,
        "-x265-params", x265_params,
        "-pix_fmt", cfg.pix_fmt,
        "-color_range", "tv",
        "-colorspace", "bt709",
        "-color_primaries", "bt709",
        "-color_trc", "bt709",
        "-bsf:v", f"hevc_metadata=tick_rate={tick_rate_str}",
        "-video_track_timescale", "90000",
        "-an",
        str(output_mp4),
    ]
    subprocess.run(cmd, check=True, env=_FFMPEG_ENV)


def _h264_profile_for_config(cfg: StreamConfig) -> str:
    if cfg.bit_depth > 8 or "422" in cfg.sampling:
        return "high422"
    if "444" in cfg.sampling:
        return "high444"
    return "high"


def encode_h264(source: Path, output_mp4: Path, cfg: StreamConfig) -> None:
    x264_base = [
        f"vbv-maxrate={cfg.vbv_maxrate}",
        f"vbv-bufsize={cfg.vbv_bufsize}",
        f"keyint={cfg.keyint}",
        f"min-keyint={cfg.keyint}",
        "scenecut=0",
        "bframes=0",
        f"nal-hrd={cfg.nal_hrd}",
        "aud=1",
        "repeat-headers=1",
        "open-gop=0",
        "force-cfr=1",
    ]
    if cfg.nal_hrd == "cbr":
        x264_base.append(f"bitrate={cfg.vbv_maxrate}")
    if cfg.extra_x264:
        for param in cfg.extra_x264.split(":"):
            key = param.split("=")[0] if "=" in param else param
            x264_base = [
                p for p in x264_base
                if not p.startswith(key + "=") and p != key
            ]
            x264_base.append(param)
    x264_params = ":".join(x264_base)

    fps_arg = cfg.ffmpeg_rate
    profile = _h264_profile_for_config(cfg)
    cmd = [
        _FFMPEG, "-hide_banner", "-loglevel", "error", "-y",
        "-r", fps_arg,
        "-f", "rawvideo", "-pix_fmt", cfg.pix_fmt,
        "-s", f"{cfg.width}x{cfg.height}",
        "-i", str(source),
        "-frames:v", str(cfg.frame_count),
        "-c:v", "libx264",
        "-profile:v", profile,
        "-preset", cfg.preset,
        "-x264-params", x264_params,
        "-pix_fmt", cfg.pix_fmt,
        "-color_range", "tv",
        "-colorspace", "bt709",
        "-color_primaries", "bt709",
        "-color_trc", "bt709",
        "-video_track_timescale", "90000",
        "-an",
        str(output_mp4),
    ]
    subprocess.run(cmd, check=True, env=_FFMPEG_ENV)


def encode_stream(source: Path, output_mp4: Path, cfg: StreamConfig) -> None:
    if cfg.codec == "h264":
        encode_h264(source, output_mp4, cfg)
    else:
        encode_h265(source, output_mp4, cfg)


def capture_rtp(
    input_mp4: Path,
    pcap_path: Path,
    port: int,
    *,
    hdcp_scramble: bool = False,
    privacy_scramble: bool = False,
) -> int:
    """Capture RTP via loopback socket (no root required)."""
    import socket as sock_mod
    import threading

    from scapy.all import Ether, IP, UDP, Raw, PcapWriter  # type: ignore[import-untyped]

    packets: list[tuple[float, bytes, int]] = []
    stop = threading.Event()

    def recv_loop() -> None:
        s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_DGRAM)
        s.bind(("127.0.0.1", port))
        s.settimeout(0.2)
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(65535)
            except sock_mod.timeout:
                continue
            packets.append((time_mod.time(), data, addr[1]))
        s.close()

    thr = threading.Thread(target=recv_loop, daemon=True)
    thr.start()

    cmd = [
        _FFMPEG, "-hide_banner", "-loglevel", "error",
        "-re", "-i", str(input_mp4),
        "-c:v", "copy", "-payload_type", "96",
        "-an", "-f", "rtp",
    ]
    if hdcp_scramble:
        cmd.extend(["-hdcp_scramble", "1"])
    if privacy_scramble:
        cmd.extend(["-privacy_scramble", "1"])
    cmd.append(f"rtp://127.0.0.1:{port}")

    subprocess.run(cmd, check=True, env=_FFMPEG_ENV)
    time_mod.sleep(0.5)
    stop.set()
    thr.join(timeout=2.0)

    if not packets:
        raise RuntimeError("No RTP packets captured")

    writer = PcapWriter(str(pcap_path), sync=True)
    for cap_time, payload, src_port in packets:
        pkt = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="127.0.0.1", dst="127.0.0.1")
            / UDP(sport=src_port, dport=port)
            / Raw(load=payload)
        )
        pkt.time = cap_time
        writer.write(pkt)
    writer.close()
    return len(packets)


def inject_sender_reports(
    pcap_in: Path,
    pcap_out: Path,
    codec: str,
    *,
    exactframerate: str | None = None,
    hkep: bool = False,
    pep: bool = False,
    sender_report_config: Path | None = None,
    export_sender_report_config: Path | None = None,
    sdp_path: Path | None = None,
) -> None:
    cmd = [
        _PYTHON,
        str(SCRIPT_DIR / "ipmx_add_sender_reports_pcap.py"),
        str(pcap_in),
        "--codec", codec,
        "--output", str(pcap_out),
    ]
    if exactframerate:
        cmd.extend(["--exactframerate", exactframerate])
    if hkep:
        cmd.append("--hkep")
    if pep:
        cmd.append("--pep")
    if sender_report_config:
        cmd.extend(["--sender-report-config", str(sender_report_config)])
    if export_sender_report_config:
        cmd.extend(["--export-sender-report-config", str(export_sender_report_config)])
    if sdp_path:
        cmd.extend(["--sdp", str(sdp_path)])
    subprocess.run(cmd, check=True)


# ---------------------------------------------------------------------------
# SDP transport file generation
# ---------------------------------------------------------------------------

def _sprop_bytes_to_base64(hex_str: str) -> str:
    """Convert a hex-encoded sprop (VPS/SPS/PPS/parameter-sets) to base64."""
    if not hex_str:
        return ""
    return base64.b64encode(bytes.fromhex(hex_str)).decode("ascii")


def _compute_measured_pixclk(cfg: StreamConfig, sr_config: dict) -> int:
    """Return measured pixel clock from SR config or compute from signal params."""
    mibs = sr_config.get("info_block", {}).get("media_info_blocks", [])
    for mib in mibs:
        if mib.get("media_info_type") == 5:
            val = mib.get("measured_pixel_clock", 0)
            if val:
                return val
    htotal = cfg.width
    vtotal = cfg.height
    fps = Fraction(cfg.fps_num, cfg.fps_den)
    return int(htotal * vtotal * fps)


def _decode_tx_mode(tx_mode_raw: str) -> str:
    """Decode a tx_mode field from MIB (may be hex-encoded ASCII)."""
    if not tx_mode_raw:
        return ""
    if isinstance(tx_mode_raw, str) and len(tx_mode_raw) == 8:
        try:
            tx_bytes = bytes.fromhex(tx_mode_raw)
            tx_str = tx_bytes.decode("ascii", errors="replace").rstrip("\x00")
            if tx_str:
                return tx_str
        except ValueError:
            pass
    return tx_mode_raw


def generate_sdp(
    cfg: StreamConfig,
    sr_config_path: Path,
    sdp_path: Path,
    *,
    port: int = 15000,
    hkep: bool = False,
    pep: bool = False,
) -> None:
    """Generate an IPMX-compliant SDP transport file for a stream config.

    Builds a MatroxSdp object from the stream config and exported SR config
    JSON, then serialises it via MatroxSdpWrite.encode().
    """
    from MatroxSdp import (
        MatroxSdp,
        MatroxSdpEnums,
        ExtmapDescriptor,
        HkepDescriptor,
        PrivacyDescriptor,
        auto_lookup_enum,
    )
    from MatroxSdpWrite import encode as sdp_encode

    E = MatroxSdpEnums

    with open(sr_config_path, "r", encoding="utf-8") as fh:
        sr_config = json.load(fh)

    mibs = sr_config.get("info_block", {}).get("media_info_blocks", [])
    video_mib: dict = {}
    codec_mib: dict = {}
    for mib in mibs:
        mt = mib.get("media_info_type", 0)
        if mt == 5:
            video_mib = mib
        elif mt in (9, 10):
            codec_mib = mib

    # --- Session level ---
    sdp = MatroxSdp()
    sdp.username = "-"
    ntp_epoch_offset = 2_208_988_800
    ntp_timestamp = int(time_mod.time()) + ntp_epoch_offset
    sdp.session_id = ntp_timestamp
    sdp.session_version = ntp_timestamp
    sdp.origin_address = "127.0.0.1"
    sdp.session_name = "IPMX Test Stream"
    sdp.session_information = cfg.description
    sdp.connection_address = "127.0.0.1"
    sdp.connection_ttl = 0
    sdp.ts_ref_clock_source = E.LocalMac.value
    sdp.ts_ref_clock_local_mac_address = "00-20-FC-32-2F-40"
    sdp.media_clock_type = E.Sender.value

    # --- Media level ---
    m = sdp.medias[0]
    m.type = E.Video.value
    m.port = port
    m.protocol = E.ProtocolRTP_AVP.value
    m.format_code = 96
    m.payload_type = 96
    m.clock_rate = 90000
    m.media_name = "primary"

    if cfg.codec == "h265":
        m.encoding_name = E.EncodingH265.value
    else:
        m.encoding_name = E.EncodingH264.value

    m.width = cfg.width
    m.height = cfg.height
    m.depth = cfg.bit_depth
    m.exact_frame_rate_numerator = cfg.fps_num
    m.exact_frame_rate_denominator = cfg.fps_den
    m.sampling = auto_lookup_enum(cfg.sampling)
    m.colorimetry = auto_lookup_enum(video_mib.get("colorimetry", "BT709"))
    m.sender_type = E.SenderType2110TPW.value
    m.max_udp = 1460
    m.transfer_characteristic = auto_lookup_enum(video_mib.get("tcs_string", "SDR"))
    m.color_range = auto_lookup_enum(video_mib.get("range_string", "NARROW"))

    m.ipmx = True
    m.measured_pix_clk = _compute_measured_pixclk(cfg, sr_config)
    m.v_total = video_mib.get("vtotal", cfg.height)
    m.h_total = video_mib.get("htotal", cfg.width)

    if cfg.interlace:
        m.interlaced = True

    # --- Codec-specific fmtp ---
    if cfg.codec == "h265":
        _populate_h265_fmtp(m, codec_mib)
    else:
        _populate_h264_fmtp(m, codec_mib)

    # --- HKEP ---
    if hkep:
        hd = HkepDescriptor()
        hd.address = "127.0.0.1"
        hd.port = 3497
        hd.node_id = "a0b1c2d3-e4f5-6789-abcd-ef0123456789"
        hd.port_id = "00-00-00-00-01"
        m.hkep_desc[0] = hd
        m.hkep = True

    # --- Privacy ---
    if pep:
        pd = PrivacyDescriptor()
        pd.protocol = auto_lookup_enum("RTP")
        pd.mode = auto_lookup_enum("AES-128-CTR")
        pd.iv = "0000000000000000"
        pd.key_generator = "00000000000000000000000000000000"
        pd.key_version = "00000001"
        pd.key_id = "0000000000000001"
        m.privacy_desc = pd
        m.privacy = True

    # --- Encryption extmap (RFC 8285 one-byte header) ---
    # When both HKEP and PEP are active, only HDCP extmap entries are declared.
    ext_idx = 0
    if hkep:
        full = ExtmapDescriptor()
        full.id = 1
        full.direction = "sendonly"
        full.uri = "urn:ietf:params:rtp-hdrext:HDCP-Full-IV-Counter-metadata"
        m.ext_map[ext_idx] = full
        ext_idx += 1
        short = ExtmapDescriptor()
        short.id = 2
        short.direction = "sendonly"
        short.uri = "urn:ietf:params:rtp-hdrext:HDCP-Short-IV-Counter-metadata"
        m.ext_map[ext_idx] = short
        ext_idx += 1
    elif pep:
        full = ExtmapDescriptor()
        full.id = 1
        full.direction = "sendonly"
        full.uri = "urn:ietf:params:rtp-hdrext:PEP-Full-IV-Counter"
        m.ext_map[ext_idx] = full
        ext_idx += 1
        short = ExtmapDescriptor()
        short.id = 2
        short.direction = "sendonly"
        short.uri = "urn:ietf:params:rtp-hdrext:PEP-Short-IV-Counter"
        m.ext_map[ext_idx] = short
        ext_idx += 1

    sdp.primary_media_name = "primary"
    sdp.primary_media = m

    sdp_text = sdp_encode(sdp)
    sdp_path.parent.mkdir(parents=True, exist_ok=True)
    sdp_path.write_text(sdp_text, encoding="utf-8")


def _populate_h265_fmtp(m: "MediaDescriptor", mib: dict) -> None:
    """Populate H.265-specific fmtp fields on a MediaDescriptor from MIB 0x0009."""
    from MatroxSdp import auto_lookup_enum

    m.h265_profile_space = mib.get("profile_space", 0)
    m.h265_profile_id = mib.get("profile_id", 0)
    m.h265_level_id = mib.get("level_id", 0)
    m.h265_tier_flag = bool(mib.get("tier_flag", 0))

    pci = mib.get("profile_compatibility_indicator", 0)
    if isinstance(pci, int):
        m.h265_profile_compatibility_indicator = f"{pci:08X}"
    else:
        m.h265_profile_compatibility_indicator = str(pci)

    ic = mib.get("interop_constraints", "")
    if isinstance(ic, str) and ic:
        m.h265_interop_constraints = ic.upper()
    elif isinstance(ic, int):
        m.h265_interop_constraints = f"{ic:012X}"

    tx_str = _decode_tx_mode(mib.get("tx_mode", ""))
    if tx_str:
        m.h265_tx_mode = auto_lookup_enum(tx_str)

    for field_name, attr_name in [
        ("sprop_vps", "h265_vps"),
        ("sprop_sps", "h265_sps"),
        ("sprop_pps", "h265_pps"),
    ]:
        hex_val = mib.get(field_name, "")
        if hex_val:
            b64 = _sprop_bytes_to_base64(hex_val)
            if b64:
                setattr(m, attr_name, b64)


def _populate_h264_fmtp(m: "MediaDescriptor", mib: dict) -> None:
    """Populate H.264-specific fmtp fields on a MediaDescriptor from MIB 0x000A."""
    pli_raw = mib.get("profile_level_id", "")
    if isinstance(pli_raw, str) and pli_raw:
        m.codec_profile_level_id = pli_raw.upper()
    elif isinstance(pli_raw, bytes):
        m.codec_profile_level_id = pli_raw.hex().upper()

    m.h264_packetization_mode = mib.get("packetization_mode", 1)

    hex_val = mib.get("sprop_parameter_sets", "")
    if hex_val:
        b64 = _sprop_bytes_to_base64(hex_val)
        if b64:
            m.h264_parameter_sets = b64


# ---------------------------------------------------------------------------
# Per-config generation pipeline
# ---------------------------------------------------------------------------

def _encryption_suffix(mode: EncryptionMode) -> str:
    if mode == EncryptionMode.CLEAR:
        return ""
    return f"_{mode.value}"


def generate_one_config(
    cfg: StreamConfig,
    output_dir: Path,
    source_cache: dict[tuple, Path],
    encryption_modes: list[EncryptionMode],
    base_port: int,
    verbose: bool,
) -> bool:
    """Generate all requested encryption variants for one config.

    Returns True if all variants succeeded.
    """
    codec_dir = output_dir / cfg.codec
    codec_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = output_dir / ".tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    ok = True

    # --- Step 1: generate raw source (cached by resolution/fps/pixfmt) ---
    src_key = _source_key(cfg)
    if src_key not in source_cache:
        src_path = tmp_dir / f"source_{cfg.width}x{cfg.height}_{cfg.fps_num}_{cfg.pix_fmt}.yuv"
        if not src_path.exists():
            print(f"    Generating source {cfg.width}x{cfg.height} @ {cfg.fps_display}fps {cfg.pix_fmt} ...")
            generate_source(
                src_path, cfg.width, cfg.height,
                cfg.fps_num, cfg.fps_den, cfg.pix_fmt, cfg.frame_count,
            )
        source_cache[src_key] = src_path
    source = source_cache[src_key]

    # --- Step 2: encode to MP4 (once per base config) ---
    mp4 = tmp_dir / f"{cfg.name}.mp4"
    if not mp4.exists():
        print(f"    Encoding {cfg.codec} ({cfg.preset}, {cfg.nal_hrd}, "
              f"maxrate={cfg.vbv_maxrate}k, bufsize={cfg.vbv_bufsize}k) ...")
        try:
            encode_stream(source, mp4, cfg)
        except subprocess.CalledProcessError as exc:
            print(f"    ** ENCODE FAILED: {exc}")
            return False

    # --- Step 3: clear variant (always needed for config export) ---
    clear_rtp = tmp_dir / f"{cfg.name}_rtp.pcap"
    clear_pcap = codec_dir / f"{cfg.name}.pcap"
    config_json = codec_dir / f"{cfg.name}_sr_config.json"

    need_clear_capture = (
        not clear_pcap.exists()
        or not config_json.exists()
        or any(m != EncryptionMode.CLEAR for m in encryption_modes)
    )

    if need_clear_capture and not clear_rtp.exists():
        print(f"    Capturing RTP (clear) ...")
        try:
            n = capture_rtp(mp4, clear_rtp, base_port)
            print(f"    Captured {n} packets")
        except Exception as exc:
            print(f"    ** CAPTURE FAILED: {exc}")
            return False

    if EncryptionMode.CLEAR in encryption_modes and not clear_pcap.exists():
        print(f"    Injecting SRs (clear) + exporting config ...")
        try:
            inject_sender_reports(
                clear_rtp, clear_pcap, cfg.codec,
                exactframerate=cfg.exactframerate_arg,
                export_sender_report_config=config_json,
            )
        except subprocess.CalledProcessError as exc:
            print(f"    ** SR INJECT FAILED (clear): {exc}")
            ok = False
    elif need_clear_capture and not config_json.exists():
        print(f"    Injecting SRs (clear, for config export only) ...")
        try:
            inject_sender_reports(
                clear_rtp, clear_pcap, cfg.codec,
                exactframerate=cfg.exactframerate_arg,
                export_sender_report_config=config_json,
            )
        except subprocess.CalledProcessError as exc:
            print(f"    ** SR INJECT FAILED (config export): {exc}")
            return False

    # --- Step 3b: generate SDP for clear variant ---
    if EncryptionMode.CLEAR in encryption_modes and config_json.exists():
        clear_sdp = codec_dir / f"{cfg.name}.sdp"
        if not clear_sdp.exists():
            print(f"    Generating SDP (clear) ...")
            try:
                generate_sdp(cfg, config_json, clear_sdp, port=base_port)
            except Exception as exc:
                print(f"    ** SDP GENERATION FAILED (clear): {exc}")
                ok = False

    # --- Step 4: encrypted variants ---
    enc_variants: list[tuple[EncryptionMode, bool, bool]] = [
        (EncryptionMode.HKEP, True, False),
        (EncryptionMode.PEP, False, True),
        (EncryptionMode.HKEP_PEP, True, True),
    ]

    for mode, hdcp, privacy in enc_variants:
        if mode not in encryption_modes:
            continue
        suffix = _encryption_suffix(mode)
        enc_rtp = tmp_dir / f"{cfg.name}{suffix}_rtp.pcap"
        enc_pcap = codec_dir / f"{cfg.name}{suffix}.pcap"

        hkep_flag = hdcp
        pep_flag = privacy

        if not enc_pcap.exists():
            if not config_json.exists():
                print(f"    ** Cannot generate {mode.value}: missing config JSON")
                ok = False
                continue

            print(f"    Capturing RTP ({mode.value}) ...")
            try:
                n = capture_rtp(
                    mp4, enc_rtp, base_port + 2,
                    hdcp_scramble=hdcp, privacy_scramble=privacy,
                )
                print(f"    Captured {n} packets")
            except Exception as exc:
                print(f"    ** CAPTURE FAILED ({mode.value}): {exc}")
                ok = False
                continue

            print(f"    Injecting SRs ({mode.value}) ...")
            try:
                inject_sender_reports(
                    enc_rtp, enc_pcap, cfg.codec,
                    exactframerate=cfg.exactframerate_arg,
                    hkep=hkep_flag,
                    pep=pep_flag,
                    sender_report_config=config_json,
                )
            except subprocess.CalledProcessError as exc:
                print(f"    ** SR INJECT FAILED ({mode.value}): {exc}")
                ok = False
                continue

        enc_sdp = codec_dir / f"{cfg.name}{suffix}.sdp"
        if not enc_sdp.exists() and config_json.exists():
            print(f"    Generating SDP ({mode.value}) ...")
            try:
                generate_sdp(
                    cfg, config_json, enc_sdp,
                    port=base_port + 2,
                    hkep=hkep_flag, pep=pep_flag,
                )
            except Exception as exc:
                print(f"    ** SDP GENERATION FAILED ({mode.value}): {exc}")
                ok = False

    return ok


# ---------------------------------------------------------------------------
# CLI and main
# ---------------------------------------------------------------------------

def parse_encryption_arg(value: str) -> list[EncryptionMode]:
    if value == "all":
        return list(EncryptionMode)
    modes: list[EncryptionMode] = []
    for part in value.split(","):
        part = part.strip()
        try:
            modes.append(EncryptionMode(part))
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"Unknown encryption mode '{part}'. "
                f"Valid: {', '.join(m.value for m in EncryptionMode)}, all"
            )
    return modes


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--codec", choices=["h264", "h265"],
        help="Generate only configs for a specific codec",
    )
    parser.add_argument(
        "--config", type=str,
        help="Generate only a specific config by name",
    )
    parser.add_argument(
        "--encryption", type=parse_encryption_arg, default="all",
        help="Encryption variants to generate: clear, hkep, pep, hkep_pep, all (default: all)",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List all available configurations and exit",
    )
    parser.add_argument(
        "--clean", action="store_true",
        help="Remove temporary files (.tmp directory) after generation",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.list:
        print(f"{'Name':<45} {'Codec':<6} {'Description'}")
        print("-" * 100)
        for cfg in ALL_CONFIGS:
            print(f"{cfg.name:<45} {cfg.codec:<6} {cfg.description}")
        print(f"\n{len(ALL_CONFIGS)} configurations total")
        print(f"Encryption variants: {', '.join(m.value for m in EncryptionMode)}")
        return 0

    # Filter configs
    configs = ALL_CONFIGS
    if args.codec:
        configs = [c for c in configs if c.codec == args.codec]
    if args.config:
        configs = [c for c in configs if c.name == args.config]
        if not configs:
            available = [c.name for c in ALL_CONFIGS]
            raise SystemExit(
                f"Unknown config '{args.config}'. Use --list to see available configs."
            )

    # Check prerequisites
    if shutil.which("ffmpeg") is None:
        raise SystemExit("ffmpeg not found in PATH")

    try:
        check = subprocess.run(
            ["ffmpeg", "-hide_banner", "-encoders"],
            capture_output=True, text=True,
        )
        has_x265 = "libx265" in check.stdout
        has_x264 = "libx264" in check.stdout
    except Exception:
        raise SystemExit("Cannot probe ffmpeg encoders")

    try:
        import scapy  # noqa: F401
    except ImportError:
        raise SystemExit("scapy is required: pip install scapy")

    encryption_modes = args.encryption
    enc_needs_scramble = any(
        m in encryption_modes
        for m in (EncryptionMode.HKEP, EncryptionMode.PEP, EncryptionMode.HKEP_PEP)
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)

    source_cache: dict[tuple, Path] = {}
    total = 0
    success = 0
    skipped = 0

    print(f"Output directory: {args.output_dir}")
    print(f"Encryption modes: {', '.join(m.value for m in encryption_modes)}")
    print(f"Configs to generate: {len(configs)}")
    print(f"Duration per stream: {DURATION_SECONDS}s")
    print()

    for idx, cfg in enumerate(configs):
        total += 1
        if cfg.codec == "h265" and not has_x265:
            print(f"[{idx+1}/{len(configs)}] SKIP {cfg.name} — libx265 not available")
            skipped += 1
            continue
        if cfg.codec == "h264" and not has_x264:
            print(f"[{idx+1}/{len(configs)}] SKIP {cfg.name} — libx264 not available")
            skipped += 1
            continue

        print(f"[{idx+1}/{len(configs)}] {cfg.name}")
        print(f"  {cfg.description}")

        port = 15000 + idx * 4
        try:
            ok = generate_one_config(
                cfg, args.output_dir, source_cache,
                encryption_modes, port, args.verbose,
            )
            if ok:
                success += 1
            else:
                print(f"  ** Some variants failed for {cfg.name}")
        except Exception as exc:
            print(f"  ** EXCEPTION: {exc}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    if args.clean:
        tmp_dir = args.output_dir / ".tmp"
        if tmp_dir.exists():
            print(f"\nCleaning up {tmp_dir} ...")
            shutil.rmtree(tmp_dir, ignore_errors=True)

    print()
    print("=" * 60)
    print(f"Generated: {success}/{total} configs ({skipped} skipped)")

    # Summary of output files
    for codec in ("h265", "h264"):
        codec_dir = args.output_dir / codec
        if codec_dir.exists():
            pcaps = sorted(codec_dir.glob("*.pcap"))
            jsons = sorted(codec_dir.glob("*.json"))
            sdps = sorted(codec_dir.glob("*.sdp"))
            if pcaps:
                print(f"  {codec}/: {len(pcaps)} PCAPs, {len(sdps)} SDPs, {len(jsons)} config JSONs")

    print("=" * 60)
    return 0 if success == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
