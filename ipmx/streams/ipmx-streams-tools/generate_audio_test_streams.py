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
"""Generate ST 2110-31 AM824 audio test streams (clear and encrypted variants).

Each base configuration is optionally produced in four encryption variants:
clear, HKEP, PEP, and HKEP+PEP.

Workflow per configuration:
  1. Generate synthetic audio source(s).
  2. Build AM824 RTP packets and write a clear RTP-only PCAP.
  3. Inject IPMX Sender Reports into the clear PCAP and export the SR config.
  4. For each encrypted variant: apply dummy XOR encryption (ipmx_rtp_encrypt),
     then inject SRs with the appropriate --hkep / --pep flags.
  5. Write SDP transport files for each variant.

Run:
  python3 generate_audio_test_streams.py [--output-dir DIR]
      [--family pcm|aac|mixed] [--config NAME] [--encryption MODE] [--list] [-v]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from enum import Enum
from pathlib import Path

from ipmx_am824 import (
    Aes3ChannelMode,
    Aes3SignalSource,
    AudioElementConfig,
    AudioSourceKind,
    AudioStreamConfig,
    ChannelOrderGroup,
    PtimePreset,
    build_am824_packets,
    build_channel_order,
    build_channel_order_config,
    compute_audio_sender_report_interval_packets,
    deterministic_ssrc,
    generate_am824_sdp,
    load_pcm_signal_sources,
    load_spdif_signal_source,
    resolve_nominal_packet_time_us,
    smoke_parse_am824_outputs,
    write_am824_pcap,
)


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "am824-streams"
DEFAULT_SAMPLE_RATE = 48_000
DEFAULT_DURATION_SECONDS = 6
DEFAULT_PAYLOAD_TYPE = 96
DEFAULT_BASE_PORT = 15_000
DEFAULT_BASE_SRC_PORT = 45_000
from ffmpeg_location import find_ffmpeg

_FFMPEG, _FFMPEG_ENV = find_ffmpeg()
_SR_INJECTOR = SCRIPT_DIR / "ipmx_add_sender_reports_pcap.py"
_AM824_VALIDATOR = SCRIPT_DIR / "ipmx_am824_validate_pcap.py"


# ---------------------------------------------------------------------------
# Encryption modes
# ---------------------------------------------------------------------------

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


PCM_STEREO = AudioElementConfig(
    name="pcm_stereo",
    source_kind=AudioSourceKind.PCM,
    description="Stereo PCM source",
    channels=2,
    frequencies_hz=(330, 550),
    aes3_channel_mode=Aes3ChannelMode.STEREOPHONIC,
)

PCM_51 = AudioElementConfig(
    name="pcm_51",
    source_kind=AudioSourceKind.PCM,
    description="5.1 PCM source",
    channels=6,
    frequencies_hz=(330, 440, 550, 660, 770, 880),
    aes3_channel_mode=Aes3ChannelMode.TWO_CHANNEL,
)

PCM_71 = AudioElementConfig(
    name="pcm_71",
    source_kind=AudioSourceKind.PCM,
    description="7.1 PCM source",
    channels=8,
    frequencies_hz=(330, 440, 550, 660, 770, 880, 990, 1100),
    aes3_channel_mode=Aes3ChannelMode.TWO_CHANNEL,
)

AAC_SPDIF = AudioElementConfig(
    name="aac_spdif",
    source_kind=AudioSourceKind.SPDIF,
    description="AAC wrapped in S/PDIF",
    channels=2,
    frequencies_hz=(1000, 1250),
    codec="aac",
    aes3_channel_mode=Aes3ChannelMode.UNSPECIFIED,
)


ALL_CONFIGS: list[AudioStreamConfig] = [
    AudioStreamConfig(
        name="am824_pcm_2ch_48k24_1ms",
        description="2-channel PCM as one AES3 signal over AM824",
        elements=(PCM_STEREO,),
        channel_order_groups=(ChannelOrderGroup.ST,),
        payload_type=DEFAULT_PAYLOAD_TYPE,
        sample_rate=DEFAULT_SAMPLE_RATE,
        duration_seconds=DEFAULT_DURATION_SECONDS,
    ),
    AudioStreamConfig(
        name="am824_pcm_6ch_48k24_1ms",
        description="6-channel PCM as three AES3 signals over AM824",
        elements=(PCM_51,),
        channel_order_groups=(ChannelOrderGroup.GROUP_51,),
        payload_type=DEFAULT_PAYLOAD_TYPE,
        sample_rate=DEFAULT_SAMPLE_RATE,
        duration_seconds=DEFAULT_DURATION_SECONDS,
    ),
    AudioStreamConfig(
        name="am824_pcm_8ch_48k24_125us",
        description="7.1 PCM as four AES3 signals over AM824 at 125 us packet time",
        elements=(PCM_71,),
        channel_order_groups=(ChannelOrderGroup.GROUP_71,),
        payload_type=DEFAULT_PAYLOAD_TYPE,
        sample_rate=DEFAULT_SAMPLE_RATE,
        ptime=PtimePreset.PTIME_125US,
        duration_seconds=DEFAULT_DURATION_SECONDS,
    ),
    AudioStreamConfig(
        name="am824_aac_2sf_48k_1ms",
        description="AAC carried opaquely from FFmpeg SPDIF into AM824",
        elements=(AAC_SPDIF,),
        channel_order_groups=(ChannelOrderGroup.AES3,),
        payload_type=DEFAULT_PAYLOAD_TYPE,
        sample_rate=DEFAULT_SAMPLE_RATE,
        duration_seconds=DEFAULT_DURATION_SECONDS,
    ),
    AudioStreamConfig(
        name="am824_mixed_pcm2_aac2_48k_1ms",
        description="Mixed stereo PCM and AAC AES3 sources interleaved into one AM824 stream",
        elements=(PCM_STEREO, AAC_SPDIF),
        channel_order_groups=(ChannelOrderGroup.ST, ChannelOrderGroup.AES3),
        payload_type=DEFAULT_PAYLOAD_TYPE,
        sample_rate=DEFAULT_SAMPLE_RATE,
        duration_seconds=DEFAULT_DURATION_SECONDS,
    ),
]

CHANNEL_ORDER_BY_VALUE = {
    group.value: group for group in ChannelOrderGroup
}


def config_family(config: AudioStreamConfig) -> str:
    kinds = {element.source_kind for element in config.elements}
    if kinds == {AudioSourceKind.PCM}:
        return "pcm"
    if kinds == {AudioSourceKind.SPDIF}:
        return "aac"
    return "mixed"


def parse_channel_order_groups(value: str) -> tuple[ChannelOrderGroup, ...]:
    text = value.strip()
    if text.startswith("SMPTE2110.(") and text.endswith(")"):
        text = text[len("SMPTE2110.("):-1]
    elif text.startswith("(") and text.endswith(")"):
        text = text[1:-1]
    parts = [part.strip() for part in text.split(",") if part.strip()]
    if not parts:
        raise ValueError("channel-order must contain at least one group")
    groups: list[ChannelOrderGroup] = []
    for part in parts:
        try:
            groups.append(CHANNEL_ORDER_BY_VALUE[part])
        except KeyError as exc:
            raise ValueError(f"Unsupported channel-order group '{part}'") from exc
    return tuple(groups)


def _dynamic_pcm_frequencies(channels: int, element_index: int) -> tuple[int, ...]:
    base = 330 + (element_index * 220)
    return tuple(base + (channel_index * 110) for channel_index in range(channels))


def _dynamic_element_for_group(group: ChannelOrderGroup, index: int) -> AudioElementConfig:
    if group == ChannelOrderGroup.ST:
        return AudioElementConfig(
            name=f"dynamic_pcm_st_{index}",
            source_kind=AudioSourceKind.PCM,
            description=f"Dynamic stereo PCM source {index}",
            channels=2,
            frequencies_hz=_dynamic_pcm_frequencies(2, index),
            aes3_channel_mode=Aes3ChannelMode.STEREOPHONIC,
        )
    if group == ChannelOrderGroup.GROUP_51:
        return AudioElementConfig(
            name=f"dynamic_pcm_51_{index}",
            source_kind=AudioSourceKind.PCM,
            description=f"Dynamic 5.1 PCM source {index}",
            channels=6,
            frequencies_hz=_dynamic_pcm_frequencies(6, index),
            aes3_channel_mode=Aes3ChannelMode.TWO_CHANNEL,
        )
    if group == ChannelOrderGroup.GROUP_71:
        return AudioElementConfig(
            name=f"dynamic_pcm_71_{index}",
            source_kind=AudioSourceKind.PCM,
            description=f"Dynamic 7.1 PCM source {index}",
            channels=8,
            frequencies_hz=_dynamic_pcm_frequencies(8, index),
            aes3_channel_mode=Aes3ChannelMode.TWO_CHANNEL,
        )
    if group == ChannelOrderGroup.AES3:
        freqs = _dynamic_pcm_frequencies(2, index)
        return AudioElementConfig(
            name=f"dynamic_aes3_{index}",
            source_kind=AudioSourceKind.SPDIF,
            description=f"Dynamic opaque AES3 source {index}",
            channels=2,
            frequencies_hz=freqs,
            codec="aac",
            aes3_channel_mode=Aes3ChannelMode.UNSPECIFIED,
        )
    raise ValueError(f"Unsupported channel-order group {group}")


def build_dynamic_audio_stream_config(
    *,
    name: str,
    description: str,
    channel_order: str,
    sample_rate: int,
    ptime_us: int,
    duration_seconds: float = DEFAULT_DURATION_SECONDS,
    payload_type: int = DEFAULT_PAYLOAD_TYPE,
    expected_nchan: int | None = None,
) -> AudioStreamConfig:
    groups = parse_channel_order_groups(channel_order)
    nominal_ptime_us = resolve_nominal_packet_time_us(sample_rate, ptime_us)
    if nominal_ptime_us is None:
        raise ValueError(f"Unsupported AM824 ptime {ptime_us} us at {sample_rate} Hz")
    try:
        ptime = PtimePreset(nominal_ptime_us)
    except ValueError as exc:
        raise ValueError(f"Unsupported nominal AM824 ptime {nominal_ptime_us} us") from exc

    elements = tuple(
        _dynamic_element_for_group(group, index + 1)
        for index, group in enumerate(groups)
    )
    config = AudioStreamConfig(
        name=name,
        description=description,
        elements=elements,
        channel_order_groups=groups,
        payload_type=payload_type,
        sample_rate=sample_rate,
        ptime=ptime,
        duration_seconds=duration_seconds,
    )
    if expected_nchan is not None and config.nchan != expected_nchan:
        raise ValueError(
            f"channel-order {build_channel_order(config)} implies nchan={config.nchan}, got expected_nchan={expected_nchan}"
        )
    return config


def parse_source_filter(value: str) -> set[str]:
    if value == "all":
        return {"pcm", "aac", "mixed"}
    parts = {part.strip() for part in value.split(",") if part.strip()}
    unknown = parts - {"pcm", "aac", "mixed"}
    if unknown:
        raise argparse.ArgumentTypeError(
            f"Unknown family {sorted(unknown)!r}. Valid: pcm, aac, mixed, all"
        )
    return parts


def _ensure_prerequisites() -> None:
    # ffmpeg availability is already checked by find_ffmpeg() at import time.
    try:
        import scapy  # noqa: F401
    except ImportError as exc:
        raise SystemExit("scapy is required: pip install scapy") from exc


def _ffmpeg_run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, env=_FFMPEG_ENV)


def generate_pcm_source(
    output: Path,
    element: AudioElementConfig,
    duration_seconds: int,
    sample_rate: int,
) -> Path:
    exprs = "|".join(
        f"0.35*sin(2*PI*{frequency}*t)"
        for frequency in element.frequencies_hz
    )
    cmd = [
        _FFMPEG,
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-f",
        "lavfi",
        "-i",
        f"aevalsrc={exprs}:s={sample_rate}:d={duration_seconds}",
        "-ar",
        str(sample_rate),
        "-ac",
        str(element.channels),
        "-c:a",
        "pcm_s24le",
        str(output),
    ]
    _ffmpeg_run(cmd)
    return output


def generate_aac_source(
    output: Path,
    element: AudioElementConfig,
    duration_seconds: int,
    sample_rate: int,
) -> Path:
    exprs = "|".join(
        f"0.35*sin(2*PI*{frequency}*t)"
        for frequency in element.frequencies_hz
    )
    cmd = [
        _FFMPEG,
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-f",
        "lavfi",
        "-i",
        f"aevalsrc={exprs}:s={sample_rate}:d={duration_seconds}",
        "-ar",
        str(sample_rate),
        "-ac",
        "2",
        "-c:a",
        "aac",
        "-b:a",
        "192k",
        "-f",
        "adts",
        str(output),
    ]
    _ffmpeg_run(cmd)
    return output


def generate_spdif_source(input_aac: Path, output_spdif: Path) -> Path:
    cmd = [
        _FFMPEG,
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-i",
        str(input_aac),
        "-c:a",
        "copy",
        "-f",
        "spdif",
        "-spdif_flags",
        "be",
        str(output_spdif),
    ]
    _ffmpeg_run(cmd)
    return output_spdif


def _materialize_element(
    element: AudioElementConfig,
    cache_dir: Path,
    duration_seconds: int,
    sample_rate: int,
    source_cache: dict[str, Path],
) -> Path:
    cache_key = f"{element.source_kind.value}:{element.name}:{duration_seconds}:{sample_rate}"
    if cache_key in source_cache and source_cache[cache_key].exists():
        return source_cache[cache_key]

    if element.source_kind == AudioSourceKind.PCM:
        output = cache_dir / f"{element.name}_{sample_rate}_{duration_seconds}s.wav"
        if not output.exists():
            generate_pcm_source(output, element, duration_seconds, sample_rate)
    else:
        aac_path = cache_dir / f"{element.name}_{sample_rate}_{duration_seconds}s.aac"
        if not aac_path.exists():
            generate_aac_source(aac_path, element, duration_seconds, sample_rate)
        output = cache_dir / f"{element.name}_{sample_rate}_{duration_seconds}s.spdif"
        if not output.exists():
            generate_spdif_source(aac_path, output)

    source_cache[cache_key] = output
    return output


def _load_signal_sources(config: AudioStreamConfig, element_paths: dict[str, Path]) -> list[Aes3SignalSource]:
    signal_sources: list[Aes3SignalSource] = []
    for element in config.elements:
        path = element_paths[element.name]
        if element.source_kind == AudioSourceKind.PCM:
            signal_sources.extend(load_pcm_signal_sources(path, config=config, element=element))
        else:
            signal_sources.append(load_spdif_signal_source(path, config=config, element=element))
    return signal_sources


def _write_manifest(
    manifest_path: Path,
    config: AudioStreamConfig,
    *,
    dst_port: int,
    src_port: int,
    rtcp_src_port: int,
    rtcp_dst_port: int,
    smoke_result: dict[str, object],
    sender_report_config_path: Path,
) -> None:
    channel_order_cfg = build_channel_order_config(config)
    interval_packets = compute_audio_sender_report_interval_packets(
        config.sample_rate,
        config.ptime.value,
    )
    if interval_packets is None:
        raise ValueError(
            f"Unsupported ptime {config.ptime.value} us for sample_rate={config.sample_rate}"
        )
    sender_report_count = len(range(0, config.packet_count, interval_packets))
    manifest = {
        "name": config.name,
        "description": config.description,
        "sample_rate": config.sample_rate,
        "ptime_us": config.ptime.value,
        "payload_type": config.payload_type,
        "nchan": config.nchan,
        "aes3_signal_count": config.aes3_signal_count,
        "duration_seconds": config.duration_seconds,
        "packet_count": config.packet_count,
        "payload_bytes_per_packet": config.payload_bytes_per_packet,
        "ssrc": deterministic_ssrc(config.name),
        "seq_start": 0,
        "rtp_timestamp_start": 0,
        "rtp_src_port": src_port,
        "rtp_dst_port": dst_port,
        "rtcp_src_port": rtcp_src_port,
        "rtcp_dst_port": rtcp_dst_port,
        "source_order": [element.name for element in config.elements],
        "channel_order": channel_order_cfg.value,
        "channel_order_groups": [group.value for group in channel_order_cfg.groups],
        "sample_size": 24,
        "measured_sample_rate": config.sample_rate,
        "sender_report_media_info_type": 0x0004,
        "sender_report_interval_packets": interval_packets,
        "sender_report_count": sender_report_count,
        "sender_report_config_path": str(sender_report_config_path),
        "phase1_assumptions": [
            "48 kHz only",
            "packet times limited to 125 us and 1 ms",
            "clear RTP only",
            "aes3 channel status restricted to bytes 0, 1, 2, and 23",
            "non-PCM AES3 derived opaquely from FFmpeg SPDIF",
            "audio sender reports added in phase 3",
        ],
        "smoke_parse": smoke_result,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _inject_audio_sender_reports(
    *,
    rtp_only_pcap: Path,
    final_pcap: Path,
    config: AudioStreamConfig,
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
        "--codec", "am824",
        "--port", str(dst_port),
        "--output", str(final_pcap),
        "--sample-rate", str(config.sample_rate),
        "--nchan", str(config.nchan),
        "--ptime", str(config.ptime.value / 1000),
        "--channel-order", channel_order,
        "--measured-sample-rate", str(config.sample_rate),
        "--sample-size", "24",
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
    config: AudioStreamConfig,
    dst_port: int,
    src_port: int,
    channel_order: str,
    hkep: bool = False,
    pep: bool = False,
) -> None:
    cmd = [
        sys.executable,
        str(_AM824_VALIDATOR),
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
        "--sample-size", "24",
        "--measured-sample-rate", str(config.sample_rate),
        "--expect-stream-start",
    ]
    if hkep:
        cmd.append("--hkep")
    if pep:
        cmd.append("--pep")
    subprocess.run(cmd, check=True)


def generate_one_config(
    config: AudioStreamConfig,
    output_dir: Path,
    source_cache: dict[str, Path],
    base_port: int,
    verbose: bool,
    encryption_modes: list[EncryptionMode] | None = None,
) -> bool:
    if config.payload_bytes_per_packet > 1460:
        raise ValueError(f"{config.name} exceeds MAXUDP payload budget: {config.payload_bytes_per_packet}")

    if encryption_modes is None:
        encryption_modes = [EncryptionMode.CLEAR]

    output_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = output_dir / ".tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    port = base_port
    src_port = DEFAULT_BASE_SRC_PORT + (base_port - DEFAULT_BASE_PORT)
    element_paths: dict[str, Path] = {}
    for element in config.elements:
        element_paths[element.name] = _materialize_element(
            element,
            tmp_dir,
            config.duration_seconds,
            config.sample_rate,
            source_cache,
        )

    signal_sources = _load_signal_sources(config, element_paths)
    rtp_packets = build_am824_packets(config, signal_sources)

    sr_config_path = output_dir / f"{config.name}_sr_config.json"
    rtp_only_pcap  = tmp_dir / f"{config.name}_rtp_only.pcap"
    rtcp_src_port  = src_port
    rtcp_dst_port  = port + 1
    channel_order  = build_channel_order(config)

    if verbose:
        print(f"    Writing {len(rtp_packets)} RTP packets")

    write_am824_pcap(
        rtp_only_pcap,
        rtp_packets,
        dst_port=port,
        src_port=src_port,
        capture_interval=config.ptime.value / 1_000_000.0,
    )

    # Smoke-parse using the clear SDP (encryption flags not needed here)
    clear_sdp_text = generate_am824_sdp(config, port=port, channel_order=channel_order)
    smoke_result = smoke_parse_am824_outputs(
        config=config,
        sdp_text=clear_sdp_text,
        pcap_path=rtp_only_pcap,
        dst_port=port,
    )

    ok = True

    # --- Clear variant (always needed for SR config export) ---
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
            _inject_audio_sender_reports(
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
            src_port=src_port,
            channel_order=channel_order,
        )
        manifest_path = output_dir / f"{config.name}_manifest.json"
        _write_manifest(
            manifest_path,
            config,
            dst_port=port,
            src_port=src_port,
            rtcp_src_port=rtcp_src_port,
            rtcp_dst_port=rtcp_dst_port,
            smoke_result=smoke_result,
            sender_report_config_path=sr_config_path,
        )

    # --- Encrypted variants ---
    from ipmx_rtp_encrypt import encrypt_rtp_pcap

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

            print(f"    Encrypting RTP PCAP ({mode.value}) ...")
            try:
                n = encrypt_rtp_pcap(
                    rtp_only_pcap, enc_rtp_pcap,
                    hkep=hkep_flag, pep=pep_flag,
                )
                if verbose:
                    print(f"    Encrypted {n} RTP packet(s)")
            except Exception as exc:
                print(f"    ** ENCRYPT FAILED ({mode.value}): {exc}")
                ok = False
                continue

            print(f"    Injecting SRs ({mode.value}) ...")
            try:
                _inject_audio_sender_reports(
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

        enc_sdp_text = generate_am824_sdp(
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
                src_port=src_port,
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
        "--family",
        type=parse_source_filter,
        default={"pcm", "aac", "mixed"},
        help="Generate only selected families: pcm, aac, mixed, all (default: all)",
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Generate only a specific config by name",
    )
    parser.add_argument(
        "--channel-order",
        type=str,
        help="Generate one dynamic AM824 config from a channel-order string, e.g. SMPTE2110.(ST,AES3)",
    )
    parser.add_argument(
        "--sample-rate",
        type=int,
        default=DEFAULT_SAMPLE_RATE,
        help=f"Sample rate for --channel-order mode (default: {DEFAULT_SAMPLE_RATE})",
    )
    parser.add_argument(
        "--ptime",
        type=str,
        default="1",
        help="Packet time in milliseconds for --channel-order mode (default: 1)",
    )
    parser.add_argument(
        "--duration-seconds",
        type=int,
        default=DEFAULT_DURATION_SECONDS,
        help=f"Duration for --channel-order mode (default: {DEFAULT_DURATION_SECONDS})",
    )
    parser.add_argument(
        "--name",
        type=str,
        help="Override config name for --channel-order mode",
    )
    parser.add_argument(
        "--description",
        type=str,
        help="Override description for --channel-order mode",
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
        print(f"{'Name':<34} {'Family':<8} {'nchan':<5} Description")
        print("-" * 100)
        for config in ALL_CONFIGS:
            print(f"{config.name:<34} {config_family(config):<8} {config.nchan:<5} {config.description}")
        print(f"\n{len(ALL_CONFIGS)} configurations total")
        return 0

    _ensure_prerequisites()

    if args.channel_order:
        if args.config:
            raise SystemExit("--config and --channel-order cannot be used together")
        ptime_us = int(round(float(args.ptime) * 1000))
        dynamic_name = args.name or (
            "am824_dynamic_" + "_".join(group.value.lower() for group in parse_channel_order_groups(args.channel_order))
            + f"_{args.sample_rate}_{ptime_us}us"
        )
        dynamic_description = args.description or f"Dynamic AM824 stream for {args.channel_order}"
        configs = [
            build_dynamic_audio_stream_config(
                name=dynamic_name,
                description=dynamic_description,
                channel_order=args.channel_order,
                sample_rate=args.sample_rate,
                ptime_us=ptime_us,
                duration_seconds=args.duration_seconds,
            )
        ]
    else:
        configs = ALL_CONFIGS
        configs = [config for config in configs if config_family(config) in args.family]
        if args.config:
            configs = [config for config in configs if config.name == args.config]
            if not configs:
                raise SystemExit(f"Unknown config '{args.config}'. Use --list to see available configs.")

    encryption_modes: list[EncryptionMode] = args.encryption

    args.output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {args.output_dir}")
    print(f"Configs to generate: {len(configs)}")
    print(f"Encryption modes: {', '.join(m.value for m in encryption_modes)}")
    if len(configs) == 1 and args.channel_order:
        print(f"Duration per stream: {configs[0].duration_seconds}s")
    else:
        print(f"Duration per stream: {DEFAULT_DURATION_SECONDS}s")
    print()

    total = 0
    success = 0
    source_cache: dict[str, Path] = {}
    for index, config in enumerate(configs):
        total += 1
        print(f"[{index + 1}/{len(configs)}] {config.name}")
        print(f"  {config.description}")
        try:
            if generate_one_config(
                config,
                args.output_dir,
                source_cache,
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
        print(f"  am824-streams/: {len(pcaps)} PCAPs, {len(sdps)} SDPs, {len(manifests)} manifests")
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
