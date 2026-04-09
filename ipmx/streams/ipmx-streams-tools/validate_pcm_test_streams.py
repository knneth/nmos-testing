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
"""Validate all generated ST 2110-30 PCM audio test streams.

Run:
  python3 validate_pcm_test_streams.py [--output-dir DIR]
      [--config NAME] [--verbose] [--full-report]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

from generate_pcm_test_streams import ALL_CONFIGS, DEFAULT_OUTPUT_DIR


SCRIPT_DIR = Path(__file__).resolve().parent


class Outcome(Enum):
    PASS = auto()
    FAIL = auto()
    ERROR = auto()
    SKIP = auto()


@dataclass
class ValidationResult:
    name: str
    outcome: Outcome
    shall_pass: int = 0
    shall_fail: int = 0
    shall_untestable: int = 0
    should_pass: int = 0
    should_fail: int = 0
    should_untestable: int = 0
    failures: list[str] | None = None
    error: str | None = None


def _parse_summary_line(line: str) -> tuple[int, int, int] | None:
    try:
        parts = line.strip().split(",")
        passed = int(parts[0].split("/")[0])
        failed = int(parts[1].strip().split()[0])
        cannot_test = int(parts[2].strip().split()[0]) if len(parts) >= 3 else 0
        return passed, failed, cannot_test
    except (IndexError, ValueError):
        return None


def validate_stream(
    pcap: Path,
    sdp: Path,
    manifest_path: Path,
    *,
    verbose: bool,
    full_report: bool,
) -> ValidationResult:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    name = pcap.stem
    validator = SCRIPT_DIR / "ipmx_pcm_validate_pcap.py"
    cmd: list[str] = [
        sys.executable,
        str(validator),
        str(pcap),
        "--port",
        str(manifest["rtp_dst_port"]),
        "--rtcp-port",
        str(manifest["rtcp_dst_port"]),
        "--ssrc",
        hex(int(manifest["ssrc"])),
        "--payload-type",
        str(manifest["payload_type"]),
        "--sdp",
        str(sdp),
        "--sample-rate",
        str(manifest["sample_rate"]),
        "--nchan",
        str(manifest["nchan"]),
        "--ptime",
        str(int(manifest["ptime_us"]) / 1000),
        "--channel-order",
        str(manifest["channel_order"]),
        "--sample-size",
        str(manifest["sample_size"]),
        "--measured-sample-rate",
        str(manifest["measured_sample_rate"]),
        "--bit-depth",
        str(manifest["bit_depth"]),
        "--expect-stream-start",
    ]
    if full_report:
        cmd.append("--full-report")

    hkep = "_hkep" in name
    pep = "_pep" in name
    if hkep:
        cmd.append("--hkep")
    if pep:
        cmd.append("--pep")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return ValidationResult(name=name, outcome=Outcome.ERROR, error="Validator timed out after 600s")
    except Exception as exc:
        return ValidationResult(name=name, outcome=Outcome.ERROR, error=str(exc))

    output = proc.stdout + proc.stderr
    result = ValidationResult(name=name, outcome=Outcome.PASS)
    fail_lines: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("SHALL requirements") or stripped.startswith("SHOULD requirements"):
            continue
        summary = _parse_summary_line(stripped)
        if summary is not None:
            passed, failed, cannot = summary
            if result.shall_pass == 0 and result.should_pass == 0 and result.shall_fail == 0:
                result.shall_pass = passed
                result.shall_fail = failed
                result.shall_untestable = cannot
            else:
                result.should_pass = passed
                result.should_fail = failed
                result.should_untestable = cannot
            continue
        if stripped.startswith("FAIL "):
            fail_lines.append(stripped)

    if proc.returncode != 0 or result.shall_fail > 0 or fail_lines:
        result.outcome = Outcome.FAIL if proc.returncode == 1 else Outcome.ERROR
        if result.outcome == Outcome.FAIL:
            result.failures = fail_lines
        else:
            result.error = output.strip()[-400:] or f"Validator exited with {proc.returncode}"

    if verbose and output.strip():
        for line in output.splitlines():
            print(f"    {line}")

    return result


def _encryption_suffixes() -> list[str]:
    return ["", "_hkep", "_pep", "_hkep_pep"]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"PCM streams directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument("--config", type=str, help="Validate only a specific config by name")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--full-report", action="store_true", help="Pass --full-report to the validator")
    args = parser.parse_args()

    configs = list(ALL_CONFIGS)
    if args.config:
        configs = [c for c in configs if c.name == args.config]
        if not configs:
            raise SystemExit(
                f"Unknown config '{args.config}'. "
                f"Available: {', '.join(c.name for c in ALL_CONFIGS)}"
            )

    if not args.output_dir.exists():
        raise SystemExit(f"Output directory does not exist: {args.output_dir}")

    results: list[ValidationResult] = []
    total_checks = 0
    print("=" * 70)
    print("PCM STREAMS (ST 2110-30)")
    print("=" * 70)

    for config in configs:
        for suffix in _encryption_suffixes():
            stream_name = f"{config.name}{suffix}"
            pcap = args.output_dir / f"{stream_name}.pcap"
            sdp = args.output_dir / f"{stream_name}.sdp"
            manifest = args.output_dir / f"{config.name}_manifest.json"

            if not pcap.exists():
                continue
            if not sdp.exists():
                print(f"  SKIP {stream_name} — SDP not found")
                results.append(ValidationResult(name=stream_name, outcome=Outcome.SKIP))
                continue
            if not manifest.exists():
                print(f"  SKIP {stream_name} — manifest not found")
                results.append(ValidationResult(name=stream_name, outcome=Outcome.SKIP))
                continue

            result = validate_stream(
                pcap,
                sdp,
                manifest,
                verbose=args.verbose,
                full_report=args.full_report,
            )
            results.append(result)
            total_checks += (
                result.shall_pass + result.shall_fail
                + result.should_pass + result.should_fail
            )
            if result.outcome == Outcome.PASS:
                print(
                    f"  PASS {stream_name} "
                    f"(SHALL {result.shall_pass}/{result.shall_pass + result.shall_fail}, "
                    f"SHOULD {result.should_pass}/{result.should_pass + result.should_fail})"
                )
            elif result.outcome == Outcome.FAIL:
                print(
                    f"  FAIL {stream_name} "
                    f"(SHALL {result.shall_pass}/{result.shall_pass + result.shall_fail}, "
                    f"SHOULD {result.should_pass}/{result.should_pass + result.should_fail})"
                )
                if result.failures:
                    for failure in result.failures:
                        print(f"       {failure}")
            else:
                print(f"  ERR  {stream_name} — {result.error}")

    passed = sum(1 for r in results if r.outcome == Outcome.PASS)
    failed = sum(1 for r in results if r.outcome == Outcome.FAIL)
    errors = sum(1 for r in results if r.outcome == Outcome.ERROR)
    skipped = sum(1 for r in results if r.outcome == Outcome.SKIP)

    print()
    print("=" * 70)
    print(
        f"SUMMARY: {passed} passed, {failed} failed, {errors} errors, {skipped} skipped "
        f"({len(results)} streams, {total_checks} checks)"
    )
    print("=" * 70)
    return 1 if failed or errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
