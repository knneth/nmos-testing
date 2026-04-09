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
"""Generate ST 2110-30 PCM audio test streams (clear and encrypted variants).

Each base configuration is optionally produced in four encryption variants:
clear, HKEP, PEP, and HKEP+PEP.

Unlike AM824, PCM encryption is performed natively by ffmpeg via
``-hdcp_scramble`` and ``-privacy_scramble`` flags, so encrypted RTP
payloads are captured directly from ffmpeg (same approach as video).

Workflow per configuration:
  1. Generate synthetic PCM RTP packets (Python) or capture from ffmpeg.
  2. Write a clear RTP-only PCAP.
  3. Inject IPMX Sender Reports into the clear PCAP and export the SR config.
  4. For encrypted variants: capture from ffmpeg with -hdcp_scramble/-privacy_scramble,
     then inject SRs with the appropriate --hkep / --pep flags.
  5. Write SDP transport files for each variant.

Run:
  python3 generate_pcm_test_streams.py [--output-dir DIR]
      [--config NAME] [--encryption MODE] [--list] [-v]
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket as sock_mod
import subprocess
import sys
import threading
import time as time_mod
from enum import Enum
from pathlib import Path

from ipmx_pcm import (
    ChannelOrderGroup,
    PcmBitDepth,
    PcmStreamConfig,
    PtimePreset,
    build_channel_order,
    build_channel_order_config,
    build_pcm_packets,
    bytes_per_sample,
    deterministic_ssrc,
    encoding_name_for_depth,
    generate_pcm_sdp,
    smoke_parse_pcm_outputs,
    write_pcm_pcap,
)
from ipmx_am824 import (
    compute_audio_sender_report_interval_packets,
    resolve_nominal_packet_time_us,
)

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "pcm-streams"
DEFAULT_SAMPLE_RATE = 48_000
DEFAULT_DURATION_SECONDS = 6
DEFAULT_PAYLOAD_TYPE = 96
DEFAULT_BASE_PORT = 16_000
DEFAULT_BASE_SRC_PORT = 46_000
from ffmpeg_location import find_ffmpeg

_FFMPEG, _FFMPEG_ENV = find_ffmpeg()
_SR_INJECTOR = SCRIPT_DIR / "ipmx_add_sender_reports_pcap.py"
_PCM_VALIDATOR = SCRIPT_DIR / "ipmx_pcm_validate_pcap.py"


class EncryptionMode(Enum):
    CLEAR    = "clear"
    HKEP     = "hkep"
    PEP      = "pep"
    HKEP_PEP = "hkep_pep"


ALL_ENCRYPTION_MODES = list(EncryptionMode)


def _encryption_suffix(mode: EncryptionMode) -> str:
    if mode == EncryptionMode.CLEAR:
        return ""
    return f"_{mode.value}"


ALL_CONFIGS: list[PcmStreamConfig] = [
    PcmStreamConfig(
        name="pcm_2ch_48k24_1ms",
        description="2-channel L24 PCM at 48 kHz, 1 ms ptime",
        bit_depth=24,
        nchan=2,
        channel_order_groups=(ChannelOrderGroup.ST,),
        sample_rate=48_000,
        ptime=PtimePreset.PTIME_1MS,
        payload_type=DEFAULT_PAYLOAD_TYPE,
        duration_seconds=DEFAULT_DURATION_SECONDS,
    ),
    PcmStreamConfig(
        name="pcm_2ch_48k16_1ms",
        description="2-channel L16 PCM at 48 kHz, 1 ms ptime",
        bit_depth=16,
        nchan=2,
        channel_order_groups=(ChannelOrderGroup.ST,),
        sample_rate=48_000,
        ptime=PtimePreset.PTIME_1MS,
        payload_type=DEFAULT_PAYLOAD_TYPE,
        duration_seconds=DEFAULT_DURATION_SECONDS,
    ),
    PcmStreamConfig(
        name="pcm_8ch_48k24_125us",
        description="8-channel L24 PCM at 48 kHz, 125 us ptime",
        bit_depth=24,
        nchan=8,
        channel_order_groups=(ChannelOrderGroup.GROUP_71,),
        sample_rate=48_000,
        ptime=PtimePreset.PTIME_125US,
        payload_type=DEFAULT_PAYLOAD_TYPE,
        duration_seconds=DEFAULT_DURATION_SECONDS,
    ),
    PcmStreamConfig(
        name="pcm_2ch_96k24_1ms",
        description="2-channel L24 PCM at 96 kHz, 1 ms ptime",
        bit_depth=24,
        nchan=2,
        channel_order_groups=(ChannelOrderGroup.ST,),
        sample_rate=96_000,
        ptime=PtimePreset.PTIME_1MS,
        payload_type=DEFAULT_PAYLOAD_TYPE,
        duration_seconds=DEFAULT_DURATION_SECONDS,
    ),
]


def _ffmpeg_codec_for_depth(bit_depth: int) -> str:
    """Return the ffmpeg PCM codec name for a given bit depth."""
    return {16: "pcm_s16be", 20: "pcm_s24be", 24: "pcm_s24be"}[bit_depth]


def capture_pcm_rtp(
    config: PcmStreamConfig,
    pcap_path: Path,
    port: int,
    *,
    hdcp_scramble: bool = False,
    privacy_scramble: bool = False,
) -> int:
    """Capture PCM RTP via loopback socket using ffmpeg."""
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

    exprs = "|".join(
        f"0.35*sin(2*PI*{330 + ch * 220}*t)"
        for ch in range(config.nchan)
    )
    cmd = [
        _FFMPEG, "-hide_banner", "-loglevel", "error",
        "-f", "lavfi",
        "-i", f"aevalsrc={exprs}:s={config.sample_rate}:d={config.duration_seconds}",
        "-ar", str(config.sample_rate),
        "-ac", str(config.nchan),
        "-c:a", _ffmpeg_codec_for_depth(config.bit_depth),
        "-payload_type", str(config.payload_type),
        "-f", "rtp",
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


def _inject_pcm_sender_reports(
    *,
    rtp_only_pcap: Path,
    final_pcap: Path,
    config: PcmStreamConfig,
    dst_port: int,
    channel_order: str,
    sr_config_path: Path | None = None,
    export_sr_config_path: Path | None = None,
    hkep: bool = False,
    pep: bool = False,
) -> None:
    cmd = [
        sys.executable,
        str(_SR_INJECTOR),
        str(rtp_only_pcap),
        "--codec", "pcm",
        "--port", str(dst_port),
        "--output", str(final_pcap),
        "--sample-rate", str(config.sample_rate),
        "--nchan", str(config.nchan),
        "--ptime", str(config.ptime.value / 1000),
        "--channel-order", channel_order,
        "--measured-sample-rate", str(config.sample_rate),
        "--sample-size", str(config.bit_depth),
    ]
    if export_sr_config_path is not None:
        cmd.extend(["--export-sender-report-config", str(export_sr_config_path)])
    if sr_config_path is not None:
        cmd.extend(["--sender-report-config", str(sr_config_path)])
    if hkep:
        cmd.append("--hkep")
    if pep:
        cmd.append("--pep")
    subprocess.run(cmd, check=True)


def _validate_final_capture(
    *,
    pcap_path: Path,
    sdp_path: Path,
    config: PcmStreamConfig,
    dst_port: int,
    channel_order: str,
    hkep: bool = False,
    pep: bool = False,
) -> None:
    cmd = [
        sys.executable,
        str(_PCM_VALIDATOR),
        str(pcap_path),
        "--port", str(dst_port),
        "--rtcp-port", str(dst_port + 1),
        "--ssrc", hex(deterministic_ssrc(config.name)),
        "--payload-type", str(config.payload_type),
        "--sdp", str(sdp_path),
        "--sample-rate", str(config.sample_rate),
        "--nchan", str(config.nchan),
        "--ptime", str(config.ptime.value / 1000),
        "--channel-order", channel_order,
        "--sample-size", str(config.bit_depth),
        "--measured-sample-rate", str(config.sample_rate),
        "--bit-depth", str(config.bit_depth),
        "--expect-stream-start",
    ]
    if hkep:
        cmd.append("--hkep")
    if pep:
        cmd.append("--pep")
    subprocess.run(cmd, check=True)


def generate_one_config(
    config: PcmStreamConfig,
    output_dir: Path,
    base_port: int,
    verbose: bool,
    encryption_modes: list[EncryptionMode] | None = None,
) -> bool:
    if encryption_modes is None:
        encryption_modes = [EncryptionMode.CLEAR]

    output_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = output_dir / ".tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    port = base_port
    src_port = DEFAULT_BASE_SRC_PORT + (base_port - DEFAULT_BASE_PORT)
    channel_order = build_channel_order(config)

    rtp_packets = build_pcm_packets(config)
    rtp_only_pcap = tmp_dir / f"{config.name}_rtp_only.pcap"
    sr_config_path = output_dir / f"{config.name}_sr_config.json"
    rtcp_src_port = src_port
    rtcp_dst_port = port + 1

    if verbose:
        print(f"    Writing {len(rtp_packets)} RTP packets")

    write_pcm_pcap(
        rtp_only_pcap,
        rtp_packets,
        dst_port=port,
        src_port=src_port,
        capture_interval=config.ptime.value / 1_000_000.0,
    )

    clear_sdp_text = generate_pcm_sdp(config, port=port, channel_order=channel_order)
    smoke_result = smoke_parse_pcm_outputs(
        config=config,
        sdp_text=clear_sdp_text,
        pcap_path=rtp_only_pcap,
        dst_port=port,
    )

    ok = True

    clear_pcap = output_dir / f"{config.name}.pcap"
    clear_sdp  = output_dir / f"{config.name}.sdp"

    need_clear = (
        not clear_pcap.exists()
        or not sr_config_path.exists()
        or any(m != EncryptionMode.CLEAR for m in encryption_modes)
    )

    if need_clear and not clear_pcap.exists():
        print(f"    Injecting SRs (clear) + exporting config ...")
        try:
            _inject_pcm_sender_reports(
                rtp_only_pcap=rtp_only_pcap,
                final_pcap=clear_pcap,
                config=config,
                dst_port=port,
                channel_order=channel_order,
                export_sr_config_path=sr_config_path,
            )
        except subprocess.CalledProcessError as exc:
            print(f"    ** SR INJECT FAILED (clear): {exc}")
            return False

    if EncryptionMode.CLEAR in encryption_modes:
        clear_sdp.write_text(clear_sdp_text, encoding="utf-8")
        _validate_final_capture(
            pcap_path=clear_pcap,
            sdp_path=clear_sdp,
            config=config,
            dst_port=port,
            channel_order=channel_order,
        )
        interval_packets = compute_audio_sender_report_interval_packets(
            config.sample_rate, config.ptime.value,
        )
        manifest = {
            "name": config.name,
            "description": config.description,
            "sample_rate": config.sample_rate,
            "bit_depth": config.bit_depth,
            "ptime_us": config.ptime.value,
            "payload_type": config.payload_type,
            "nchan": config.nchan,
            "duration_seconds": config.duration_seconds,
            "packet_count": config.packet_count,
            "payload_bytes_per_packet": config.payload_bytes_per_packet,
            "ssrc": deterministic_ssrc(config.name),
            "rtp_src_port": src_port,
            "rtp_dst_port": port,
            "rtcp_src_port": rtcp_src_port,
            "rtcp_dst_port": rtcp_dst_port,
            "channel_order": channel_order,
            "sample_size": config.bit_depth,
            "measured_sample_rate": config.sample_rate,
            "sender_report_media_info_type": 0x0002,
            "sender_report_interval_packets": interval_packets,
            "sender_report_config_path": str(sr_config_path),
            "smoke_parse": smoke_result,
        }
        manifest_path = output_dir / f"{config.name}_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # --- Encrypted variants (ffmpeg-native encryption) ---
    enc_variants: list[tuple[EncryptionMode, bool, bool]] = [
        (EncryptionMode.HKEP,     True,  False),
        (EncryptionMode.PEP,      False, True),
        (EncryptionMode.HKEP_PEP, True,  True),
    ]

    for mode, hkep_flag, pep_flag in enc_variants:
        if mode not in encryption_modes:
            continue
        suffix   = _encryption_suffix(mode)
        enc_pcap = output_dir / f"{config.name}{suffix}.pcap"
        enc_sdp  = output_dir / f"{config.name}{suffix}.sdp"

        if not enc_pcap.exists():
            if not sr_config_path.exists():
                print(f"    ** Cannot generate {mode.value}: missing SR config JSON")
                ok = False
                continue

            enc_rtp_pcap = tmp_dir / f"{config.name}{suffix}_rtp_only.pcap"

            print(f"    Capturing encrypted RTP ({mode.value}) via ffmpeg ...")
            try:
                n = capture_pcm_rtp(
                    config, enc_rtp_pcap, port,
                    hdcp_scramble=hkep_flag,
                    privacy_scramble=pep_flag,
                )
                if verbose:
                    print(f"    Captured {n} RTP packet(s)")
            except Exception as exc:
                print(f"    ** CAPTURE FAILED ({mode.value}): {exc}")
                ok = False
                continue

            print(f"    Injecting SRs ({mode.value}) ...")
            try:
                _inject_pcm_sender_reports(
                    rtp_only_pcap=enc_rtp_pcap,
                    final_pcap=enc_pcap,
                    config=config,
                    dst_port=port,
                    channel_order=channel_order,
                    sr_config_path=sr_config_path,
                    hkep=hkep_flag,
                    pep=pep_flag,
                )
            except subprocess.CalledProcessError as exc:
                print(f"    ** SR INJECT FAILED ({mode.value}): {exc}")
                ok = False
                continue

        enc_sdp_text = generate_pcm_sdp(
            config, port=port, channel_order=channel_order,
            hkep=hkep_flag, pep=pep_flag,
        )
        enc_sdp.write_text(enc_sdp_text, encoding="utf-8")

        try:
            _validate_final_capture(
                pcap_path=enc_pcap,
                sdp_path=enc_sdp,
                config=config,
                dst_port=port,
                channel_order=channel_order,
                hkep=hkep_flag,
                pep=pep_flag,
            )
        except subprocess.CalledProcessError as exc:
            print(f"    ** VALIDATE FAILED ({mode.value}): {exc}")
            ok = False

    return ok


def _parse_encryption_arg(value: str) -> list[EncryptionMode]:
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
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Generate only a specific config by name",
    )
    parser.add_argument(
        "--encryption",
        type=_parse_encryption_arg,
        default=[EncryptionMode.CLEAR],
        metavar="MODE",
        help=(
            "Encryption variants to generate: "
            f"{', '.join(m.value for m in EncryptionMode)}, all "
            "(comma-separated, default: clear)"
        ),
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available configurations and exit",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove temporary files (.tmp directory) after generation",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.list:
        print(f"{'Name':<30} {'Depth':<6} {'nchan':<6} Description")
        print("-" * 90)
        for config in ALL_CONFIGS:
            print(f"{config.name:<30} L{config.bit_depth:<5} {config.nchan:<6} {config.description}")
        print(f"\n{len(ALL_CONFIGS)} configurations total")
        return 0

    configs = ALL_CONFIGS
    if args.config:
        configs = [c for c in configs if c.name == args.config]
        if not configs:
            raise SystemExit(f"Unknown config '{args.config}'. Use --list to see available configs.")

    encryption_modes: list[EncryptionMode] = args.encryption

    args.output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {args.output_dir}")
    print(f"Configs to generate: {len(configs)}")
    print(f"Encryption modes: {', '.join(m.value for m in encryption_modes)}")
    print(f"Duration per stream: {DEFAULT_DURATION_SECONDS}s")
    print()

    total = 0
    success = 0
    for index, config in enumerate(configs):
        total += 1
        print(f"[{index + 1}/{len(configs)}] {config.name}")
        print(f"  {config.description}")
        try:
            if generate_one_config(
                config,
                args.output_dir,
                DEFAULT_BASE_PORT + (index * 2),
                args.verbose,
                encryption_modes=encryption_modes,
            ):
                success += 1
        except Exception as exc:
            print(f"  ** FAILED: {exc}")
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
    print(f"Generated: {success}/{total} configs")
    if args.output_dir.exists():
        pcaps     = sorted(args.output_dir.glob("*.pcap"))
        sdps      = sorted(args.output_dir.glob("*.sdp"))
        manifests = sorted(args.output_dir.glob("*_manifest.json"))
        print(f"  pcm-streams/: {len(pcaps)} PCAPs, {len(sdps)} SDPs, {len(manifests)} manifests")
        enc_pcaps = [p for p in pcaps if any(
            f"_{m.value}.pcap" in p.name
            for m in (EncryptionMode.HKEP, EncryptionMode.PEP, EncryptionMode.HKEP_PEP)
        )]
        if enc_pcaps:
            print(f"  Encrypted variants: {len(enc_pcaps)} PCAP(s)")
    print("=" * 60)
    return 0 if success == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
