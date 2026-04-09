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

"""Emit an RTP stream via FFmpeg and capture it as a PCAP for analysis.

This helper runs `ffmpeg` in copy mode so no re-encoding happens, and pipes the
RTP output into `tcpdump` so the packets can be inspected with Wireshark or other
tools. It is currently tuned for the H.265 sample stream; the same steps can be
reused for H.264 by choosing a different payload type and codec flag.
"""

from __future__ import annotations

import argparse
import signal
import shutil
import subprocess
import time
from pathlib import Path


def ensure_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise SystemExit(f"{name} is not found in PATH; install it and retry")


def build_ffmpeg_cmd(
    input_path: Path,
    dest_ip: str,
    dest_port: int,
    payload_type: int,
    frames: int | None,
    realtime: bool,
    sdp_file: Path | None,
) -> list[str]:
    cmd = [
        "ffmpeg",
        "-hide_banner",
        "-loglevel",
        "info",
        "-y",
    ]
    if realtime:
        cmd.append("-re")
    cmd += ["-i", str(input_path)]
    if frames:
        cmd += ["-frames:v", str(frames)]
    cmd += ["-c:v", "copy"]
    if payload_type:
        cmd += ["-payload_type", str(payload_type)]
    if sdp_file:
        cmd += ["-sdp_file", str(sdp_file)]
    cmd += ["-f", "rtp", f"rtp://{dest_ip}:{dest_port}"]
    return cmd


def build_tcpdump_cmd(interface: str, dest_ip: str, dest_port: int, pcap_path: Path) -> list[str]:
    filter_expr = f"udp port {dest_port}"
    if dest_ip:
        filter_expr += f" and host {dest_ip}"
    return [
        "tcpdump",
        "-n",
        "-q",
        "-i",
        interface,
        "-w",
        str(pcap_path),
        filter_expr,
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture an FFmpeg RTP session into a PCAP file for later inspection."
    )
    parser.add_argument("input", type=Path, help="Source elementary stream (e.g., *.265)")
    parser.add_argument(
        "--pcap",
        type=Path,
        default=Path("rtp_capture.pcap"),
        help="Destination PCAP (default: rtp_capture.pcap)",
    )
    parser.add_argument(
        "--interface",
        default="lo",
        help="Interface to capture on (default: lo for loopback)",
    )
    parser.add_argument("--dest-ip", default="127.0.0.1", help="Destination IP that ffmpeg streams to")
    parser.add_argument("--dest-port", type=int, default=5004, help="Destination port of the RTP stream")
    parser.add_argument("--frames", type=int, help="Limit ffmpeg to N video frames")
    parser.add_argument(
        "--payload-type",
        type=int,
        default=98,
        help="RTP payload type (H.265 typically uses 98; H.264 uses 96)",
    )
    parser.add_argument(
        "--no-realtime",
        action="store_true",
        help="Disable -re (emit as fast as possible instead of realtime)",
    )
    parser.add_argument(
        "--sdp",
        type=Path,
        help="Optional SDP file that ffmpeg writes for the stream",
    )
    args = parser.parse_args()

    if not args.input.exists():
        parser.error(f"{args.input} does not exist")

    args.pcap.parent.mkdir(parents=True, exist_ok=True)

    for tool in ("ffmpeg", "tcpdump"):
        ensure_tool(tool)

    ffmpeg_cmd = build_ffmpeg_cmd(
        input_path=args.input,
        dest_ip=args.dest_ip,
        dest_port=args.dest_port,
        payload_type=args.payload_type,
        frames=args.frames,
        realtime=not args.no_realtime,
        sdp_file=args.sdp,
    )
    tcpdump_cmd = build_tcpdump_cmd(args.interface, args.dest_ip, args.dest_port, args.pcap)

    print("Starting tcpdump:", " ".join(tcpdump_cmd))
    try:
        tcpdump_proc = subprocess.Popen(
            tcpdump_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        raise SystemExit(f"Failed to start tcpdump: {exc}") from exc
    time.sleep(0.3)
    if tcpdump_proc.poll() is not None:
        _, stderr_data = tcpdump_proc.communicate()
        message = stderr_data.strip() or "permission denied (tcpdump requires elevated privileges)"
        raise SystemExit(f"tcpdump exited immediately ({tcpdump_proc.returncode}): {message}")

    print("Starting ffmpeg:", " ".join(ffmpeg_cmd))
    ffmpeg_proc = subprocess.Popen(ffmpeg_cmd)

    try:
        ffmpeg_return = ffmpeg_proc.wait()
    except KeyboardInterrupt:
        ffmpeg_proc.terminate()
        tcpdump_proc.send_signal(signal.SIGINT)
        raise
    finally:
        if tcpdump_proc.poll() is None:
            tcpdump_proc.send_signal(signal.SIGINT)
            tcpdump_proc.wait()
        tcpdump_proc.communicate()

    if ffmpeg_return:
        raise SystemExit(f"ffmpeg exited with status {ffmpeg_return}")

    print(f"PCAP written to {args.pcap}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
