# IPMX Stream Validation Toolkit

Parse, construct, and validate RTP/RTCP streams against IPMX (VSF TR-10)
technical recommendations, NMOS BCP-006, and the underlying codec standards
(ITU-T H.265, ITU-T H.264, ISO/IEC 21122 JPEG XS).

## Supported Codecs

| Codec | RTP Parsing | Validation | HRD | Encryption | Test Streams |
|-------|-------------|------------|-----|------------|--------------|
| H.265/HEVC | Yes | TR-10-15b (64 SHALL + 9 SHOULD) | 3 tiers + sub-pic | HKEP + PEP | 52 generated |
| H.264/AVC  | Yes | TR-10-15c (57 SHALL + 11 SHOULD) | 3 tiers | HKEP + PEP | 32 generated |
| JPEG XS    | Yes | TR-10-15a (49 SHALL + 6 SHOULD) | N/A | HKEP + PEP | 3 curated |
| AM824 (ST 2110-31) | Yes | TR-10-12 (81 SHALL + 5 SHOULD) | N/A | HKEP + PEP | 5 generated |
| PCM (ST 2110-30) | Yes | ST 2110-30 (61 SHALL + 3 SHOULD) | N/A | HKEP + PEP | 4 generated |

## Quick Start

### Prerequisites

- Python 3.12+ (`/usr/local/bin/python3.12` recommended)
- `scapy` (`pip install scapy`)
- `ffmpeg` with `libx265` and `libx264` (for H.264/H.265 stream generation)

### Generate H.264/H.265 test streams

```bash
python3 generate_video_test_streams.py
```

Produces 84 PCAP/SDP pairs (21 base configurations × 4 encryption variants)
in `test-streams/`.  Streams are 6 seconds each with full HRD parameters.

### Generate AM824 audio test streams

```bash
python3 generate_audio_test_streams.py
```

Produces clear RTP/AM824 + RTCP Sender Report PCAPs, SDPs, sender-report
config JSON files, and manifest JSON files in `am824-streams/`.

```bash
# Generate one dynamic AM824 stream from channel-order
python3 generate_audio_test_streams.py \
    --channel-order 'SMPTE2110.(ST,ST)' \
    --name am824_dynamic_st_st \
    --description 'Dynamic dual stereo PCM'
```

Use `validate_audio_test_streams.py` for the curated generated corpus in
`am824-streams/`. For arbitrary dynamic AM824 outputs, validate them directly
with `ipmx_am824_validate_pcap.py`.

### Generate PCM audio test streams

```bash
python3 generate_pcm_test_streams.py
```

Produces clear RTP/PCM + RTCP Sender Report PCAPs, SDPs, and SR config
JSON files in `pcm-streams/`.

Use `validate_pcm_test_streams.py` for the generated corpus in
`pcm-streams/`. For individual captures, validate directly with
`ipmx_pcm_validate_pcap.py`.

### Validate generated video test streams

```bash
python3 validate_video_test_streams.py
```

Runs individual checks across all 87 video streams (84 generated + 3 JXSV):
- Clear streams: full validation with all 3 HRD tiers and SDP cross-validation
- Encrypted streams: encryption checks with SDP cross-validation
- JXSV streams: codestream + MIB + SDP cross-validation

```bash
# Validate only a specific codec
python3 validate_video_test_streams.py --codec jxsv
python3 validate_video_test_streams.py --codec h265

# Verbose output
python3 validate_video_test_streams.py -v --full-report
```

### Validate generated AM824 audio test streams

```bash
python3 validate_audio_test_streams.py
```

Validates RTP, AM824 payload structure, SDP cross-checks, CLI expectations,
and audio RTCP Sender Reports / AES3 MIB content.

### Validate generated PCM audio test streams

```bash
python3 validate_pcm_test_streams.py
```

Validates RTP, PCM payload structure, SDP cross-checks, CLI expectations,
and audio RTCP Sender Reports / PCM MIB content.

### Validate a single stream

```bash
# H.265 with full HRD validation
python3 ipmx_h265_validate_pcap.py capture.pcap \
    --exactframerate 60 --sdp transport.sdp --hrd-timing

# H.264 with encryption
python3 ipmx_h264_validate_pcap.py capture.pcap \
    --exactframerate 60000/1001 --sdp transport.sdp --hkep --pep

# JPEG XS
python3 ipmx_jxsv_validate_pcap.py capture.pcap \
    --exactframerate 60 --sdp transport.sdp

# ST 2110-31 / AM824
python3 ipmx_am824_validate_pcap.py capture.pcap \
    --sdp transport.sdp --sample-rate 48000 --nchan 2 --ptime 1 \
    --rtcp-port 15001 --sample-size 24 --measured-sample-rate 48000

# ST 2110-30 / PCM
python3 ipmx_pcm_validate_pcap.py capture.pcap \
    --sdp transport.sdp --sample-rate 48000 --nchan 2 --ptime 1 \
    --rtcp-port 15001 --sample-size 24 --measured-sample-rate 48000
```

### Engine JSON API examples for AM824

The engine accepts JSON on stdin and returns JSON on stdout. For AM824 audio,
the same `generate`, `validate`, and `receive` commands are available as for
video.

```bash
# Generate an AM824 stereo stream from SDP
cat <<'EOF' | python3 ipmx_engine.py
{
  "command": "generate",
  "pcap": "tmp/engine_am824_stereo.pcap",
  "sdp": "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=IPMX Test Stream\r\ni=AM824 stereo PCM\r\nt=0 0\r\na=ts-refclk:localmac=00-20-FC-32-2F-40\r\na=mediaclk:sender\r\nm=audio 15000 RTP/AVP 96\r\nc=IN IP4 127.0.0.1/0\r\na=mid:primary\r\na=rtpmap:96 AM824/48000/2\r\na=fmtp:96 channel-order=SMPTE2110.(ST); measuredsamplerate=48000; IPMX\r\na=ptime:1\r\na=rtcp:15001\r\n"
}
EOF

# Validate an AM824 capture against SDP
cat <<'EOF' | python3 ipmx_engine.py
{
  "command": "validate",
  "pcap": "tmp/engine_am824_stereo.pcap",
  "sdp": "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=IPMX Test Stream\r\ni=AM824 stereo PCM\r\nt=0 0\r\na=ts-refclk:localmac=00-20-FC-32-2F-40\r\na=mediaclk:sender\r\nm=audio 15000 RTP/AVP 96\r\nc=IN IP4 127.0.0.1/0\r\na=mid:primary\r\na=rtpmap:96 AM824/48000/2\r\na=fmtp:96 channel-order=SMPTE2110.(ST); measuredsamplerate=48000; IPMX\r\na=ptime:1\r\na=rtcp:15001\r\n"
}
EOF

# Receive-mode analysis: rebuild SDP from Sender Reports / AES3 MIBs and validate
cat <<'EOF' | python3 ipmx_engine.py
{
  "command": "receive",
  "pcap": "tmp/engine_am824_stereo.pcap",
  "sdp": "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=IPMX Test Stream\r\ni=AM824 stereo PCM\r\nt=0 0\r\na=ts-refclk:localmac=00-20-FC-32-2F-40\r\na=mediaclk:sender\r\nm=audio 15000 RTP/AVP 96\r\nc=IN IP4 127.0.0.1/0\r\na=mid:primary\r\na=rtpmap:96 AM824/48000/2\r\na=fmtp:96 channel-order=SMPTE2110.(ST); measuredsamplerate=48000; IPMX\r\na=ptime:1\r\na=rtcp:15001\r\n"
}
EOF
```

## Project Structure

### CLI Tools (20 scripts)

| Script | Description |
|--------|-------------|
| `ipmx_h265_validate_pcap.py` | Validate H.265 PCAP against VSF TR-10-15b |
| `ipmx_h264_validate_pcap.py` | Validate H.264 PCAP against VSF TR-10-15c |
| `ipmx_jxsv_validate_pcap.py` | Validate JPEG XS PCAP against VSF TR-10-15a |
| `ipmx_am824_validate_pcap.py` | Validate ST 2110-31 AM824 PCAPs and audio Sender Reports |
| `ipmx_pcm_validate_pcap.py` | Validate ST 2110-30 PCM PCAPs and audio Sender Reports |
| `ipmx_parse_rtp_pcap.py` | Parse RTP streams (H.264, H.265, JPEG XS, AM824, PCM) from PCAPs |
| `ipmx_parse_sender_report_pcap.py` | Parse RTCP Sender Reports from PCAPs |
| `ipmx_add_sender_reports_pcap.py` | Inject IPMX RTCP Sender Reports into PCAPs |
| `ipmx_capture_rtp_to_pcap.py` | Capture FFmpeg RTP output into a PCAP |
| `ipmx_sender_report.py` | Build IPMX TR-10-7 Sender Reports as binary |
| `ipmx_validate_hrd_au_offset.py` | AU-level HRD timing analysis with CSV export |
| `generate_video_test_streams.py` | Generate H.265/H.264 test PCAPs with Sender Reports and SDPs |
| `generate_audio_test_streams.py` | Generate ST 2110-31 AM824 audio test PCAPs, SDPs, manifests |
| `generate_pcm_test_streams.py` | Generate ST 2110-30 PCM audio test PCAPs, SDPs |
| `validate_video_test_streams.py` | Batch-validate video test streams (H.264, H.265, JXSV) |
| `validate_audio_test_streams.py` | Batch-validate ST 2110-31 AM824 audio test streams |
| `validate_pcm_test_streams.py` | Batch-validate ST 2110-30 PCM audio test streams |
| `ipmx_engine.py` | Central JSON command dispatcher for generation, validation, reception |
| `ipmx_pcap_carousel.py` | PCAP looping / carousel playback |
| `ipmx_rtp_encrypt.py` | Dummy HKEP/PEP XOR cipher for audio encryption |

### Library Modules (14 modules)

| Module | Description |
|--------|-------------|
| `ipmx_validate_common.py` | Shared data structures, helpers, CMAX simulation |
| `ipmx_validate_hrd.py` | H.265 HRD validation (3 tiers: self-consistency, CPB sim, PCAP timing) |
| `ipmx_validate_hrd_h264.py` | H.264 HRD validation (3 tiers) |
| `ipmx_validate_hrd_subpic.py` | H.265 sub-picture HRD validation |
| `ipmx_validate_encryption.py` | HKEP/PEP encryption validation (14 checks) |
| `ipmx_am824.py` | AM824 (ST 2110-31) data model, AES3 subframes, payload builder, SDP generator |
| `ipmx_pcm.py` | PCM (ST 2110-30) data model, payload builder, SDP generator |
| `ipmx_s337m.py` | SMPTE 337M burst scanning for non-PCM AM824 payloads |
| `ipmx_pcap_reader.py` | Low-level PCAP/pcapng reading and UDP packet iteration |
| `ipmx_sender_report.py` | IPMX TR-10-7 Sender Report data model + MIB types |
| `MatroxSdp.py` | SDP parser (ported from Go reference implementation) |
| `MatroxSdpWrite.py` | SDP encoder (ported from Go reference implementation) |
| `MatroxSdpCheck.py` | SDP validation rules (RFC 4175, RFC 9134, ST 2110-30/31) |

### Directories

| Directory | Contents |
|-----------|----------|
| `test-streams/h265/` | Generated H.265 test PCAPs + SDPs (52 pairs) |
| `test-streams/h264/` | Generated H.264 test PCAPs + SDPs (32 pairs) |
| `am824-streams/` | Generated ST 2110-31 AM824 PCAPs + SDPs + manifests (5 configs) |
| `pcm-streams/` | Generated ST 2110-30 PCM PCAPs + SDPs (4 configs) |
| `jxsv-streams/` | Curated JPEG XS reference PCAPs + SDPs (3 pairs) |
| `tmp/` | Intermediate files from parsing and injection |

## Validation Architecture

### Requirement Traceability

Every validation check is tagged with a normative requirement ID:
- `TR-10-15b-*` — H.265 rules from VSF TR-10-15 Part 2
- `TR-10-15c-*` — H.264 rules from VSF TR-10-15 Part 3
- `TR-10-15a-*` — JPEG XS rules from VSF TR-10-15 Part 1
- `TR-10-9-*` — IPMX compressed video RTP transport (common to H.264/H.265/JXSV)
- `TR-10-11-*` / `TR-10-12-10-*` — IPMX audio transport
- `TR-10-1-*` — IPMX system timing, Sender Reports, IPMX fmtp keyword
- `ST2110-30-*` / `ST2110-31-*` — ST 2110 audio encapsulation
- `HRD-*` — HRD self-consistency checks
- `HRD-TIME-*` — HRD PCAP timing cross-validation
- `ENC-01`..`ENC-14` — Encryption validation checks
- `CS-*` / `SDP-*` — Codestream / SDP cross-validation

### HRD Validation Tiers (H.264/H.265 only)

Enabled via `--hrd`, `--hrd-sim`, `--hrd-timing` (each implies the previous):

| Tier | Flag | Description |
|------|------|-------------|
| 1 | `--hrd` | HRD parameter self-consistency (VUI timing, CPB params) |
| 2 | `--hrd-sim` | CPB leaky-bucket simulation |
| 3 | `--hrd-timing` | PCAP capture timing cross-validation against HRD model |

### Encryption Validation

Enabled via `--hkep` and/or `--pep`.  Cross-validates across four sources:
1. CLI flags
2. RTP extension headers (RFC 8285 one-byte format)
3. RTCP Media Info Blocks (MIB type 0x0010 HKEP, 0x0011 PEP)
4. SDP attributes (`a=hkep`, `a=privacy`, `a=extmap` URNs)

Includes verification that full and short extension IDs are distinct within
each encryption protocol (ENC-14).

### CMAX Validation (ST 2110-21)

Enabled via `--cmax` on video validators.  Implements the Type W (wide) Network
Compatibility Model per ST 2110-21 §7.1.4:
- CMAX = MAX(16, INT(NPACKETS / (21600 × TFRAME)))
- CINST leaky-bucket simulation verifying CINST ≤ CMAX
- Reports maximum bitrate attained over a single video period

### SDP Cross-Validation

Enabled via `--sdp`.  Compares codec parameters (profile, level, sampling,
fmtp attributes) between the stream bitstream, RTCP MIBs, and the SDP
transport file.

### Profile Superset Acceptance

The `--allow-superset-profile` flag accepts higher profiles that are
backward-compatible supersets of the IPMX-mandated baseline:
- H.265: Rext (4) ⊃ Main 10 (2) ⊃ Main (1)
- H.264: High 4:4:4 Predictive (244) ⊃ High 4:2:2 (122) ⊃ High 10 (110) ⊃ High (100) ⊃ Main (77)

### Test Suite (9 test files)

| Test File | Coverage |
|-----------|----------|
| `test_ipmx_engine.py` | Engine CLI, config derivation, generate/validate integration |
| `test_hrd_validation.py` | CPB simulation, buffering period, picture timing, ffmpeg integration |
| `test_ipmx_am824_validate_pcap.py` | AM824 validator: encapsulation, SDP, SR, MIB, encryption |
| `test_ipmx_pcm_validate_pcap.py` | PCM validator: encapsulation, SDP, SR, MIB, encryption |
| `test_generate_audio_test_streams.py` | AM824 generation: configs, channel order, SDP, encryption |
| `test_generate_pcm_test_streams.py` | PCM generation: configs, SDP, encryption |
| `test_ipmx_pcap_carousel.py` | PCAP carousel looping |
| `test_initial_rtp_clock.py` | RTP clock initialization (TR-10-1 §8.6) |
| `test_audio_sender_reports.py` | Sender report parsing |

The three batch validators (`validate_video_test_streams.py`,
`validate_audio_test_streams.py`, `validate_pcm_test_streams.py`) serve as
end-to-end integration tests across all 96 generated + 3 curated streams.

## Sender Report Injection

`ipmx_add_sender_reports_pcap.py` replays the RTP timeline from a PCAP,
computes nominal frame periods, and injects RTCP Sender Reports before each
access unit.  Supports H.264, H.265, and JPEG XS codecs.

For H.264/H.265, it auto-detects codec parameters from the bitstream and
populates the appropriate Media Info Blocks.  For JPEG XS, it reads
Ppih/Plev from the codestream header (clear streams) or from the SDP
transport file (encrypted streams where the payload is inaccessible).

```bash
# H.265 injection
python3 ipmx_add_sender_reports_pcap.py input.pcap --codec h265 --output output.pcap

# JPEG XS injection (clear — reads codestream)
python3 ipmx_add_sender_reports_pcap.py input.pcap --codec jxsv \
    --sdp transport.sdp --strip-existing-rtcp --output output.pcap

# JPEG XS injection (encrypted — derives from SDP)
python3 ipmx_add_sender_reports_pcap.py encrypted.pcap --codec jxsv \
    --sdp transport.sdp --hkep --strip-existing-rtcp --output output.pcap

# Export config for reuse with encrypted streams
python3 ipmx_add_sender_reports_pcap.py input.pcap --codec h265 \
    --output output.pcap --export-sender-report-config config.json

# Apply saved config to encrypted stream
python3 ipmx_add_sender_reports_pcap.py encrypted.pcap --codec h265 \
    --output output.pcap --sender-report-config config.json --hkep
```

Key options:
- `--strip-existing-rtcp` — Remove pre-existing RTCP packets before injection
  (useful when the original capture already contains incomplete SRs)
- `--sdp` — SDP transport file for JXSV MIB enrichment (required for encrypted JXSV)
- `--export-sender-report-config` / `--sender-report-config` — Save/load MIB
  configuration for reuse across clear and encrypted variants

## RTP Parsing

`ipmx_parse_rtp_pcap.py` reconstructs elementary streams from RTP PCAPs,
handles NAL unit fragmentation (STAP-A/FU-A for H.264, AP/FU for H.265,
ISOBMFF/raw for JPEG XS), and optionally correlates with FFmpeg
`trace_headers` output.

```bash
# Extract H.265 stream with timeline
python3 ipmx_parse_rtp_pcap.py capture.pcap --codec h265 \
    --output stream.hevc --report rtp_report.json \
    --timeline header_timeline.json --frames 10

# Parse JPEG XS with CSV export
python3 ipmx_parse_rtp_pcap.py capture.pcap --codec jxsv \
    --report rtp_report.json --csv timing.csv
```

## Test Stream Configurations

### H.264/H.265 (generated)

The 21 base configurations cover representative proAV scenarios:

**H.265** (13 configs): 1080p25/30/50/59.94/60, 720p60, 2160p30/59.94/60,
4:2:0 8-bit, 4:2:0 10-bit, 4:2:2 10-bit, 4:4:4 8-bit, CBR/VBR, low-latency.

**H.264** (8 configs): 1080p30/50/59.94/60, 720p60, 2160p30,
4:2:0 8-bit, 4:2:2 10-bit, CBR/VBR, low-latency.

Each base config is produced in four encryption variants:
clear, HKEP only, PEP only, HKEP + PEP.

### JPEG XS (curated)

Three reference streams from real IPMX hardware, with injected Sender Reports:

| Stream | Resolution | Sampling | Encryption |
|--------|-----------|----------|------------|
| `jxsv_2160p60_rgb_8_clear` | 3840×2160 @ 60fps | RGB 8-bit | Clear |
| `jxsv_2160p60_444_8_hkep` | 3840×2160 @ 60fps | YCbCr-4:4:4 8-bit | HKEP |
| `jxsv_1080p5994_rgb_8_pep` | 1920×1080 @ 59.94fps | RGB 8-bit | PEP |

### AM824 (generated)

Five configurations covering stereo, multichannel, high-rate, AAC, and mixed:
- `am824_pcm_2ch_48k24_1ms` — 2-channel PCM, 48 kHz, 24-bit, 1 ms ptime
- `am824_pcm_6ch_48k24_1ms` — 6-channel PCM (5.1), 48 kHz, 24-bit, 1 ms ptime
- `am824_pcm_8ch_48k24_125us` — 8-channel PCM (7.1), 48 kHz, 24-bit, 125 µs ptime
- `am824_aac_2sf_48k_1ms` — AAC over SPDIF/AM824
- `am824_mixed_pcm2_aac2_48k_1ms` — mixed stereo PCM + AAC

### PCM (generated)

Four configurations covering different channel counts, sample rates, and bit depths:
- `pcm_2ch_48k24_1ms` — 2-channel L24, 48 kHz, 1 ms ptime
- `pcm_2ch_48k16_1ms` — 2-channel L16, 48 kHz, 1 ms ptime
- `pcm_8ch_48k24_125us` — 8-channel L24, 48 kHz, 125 µs ptime
- `pcm_2ch_96k24_1ms` — 2-channel L24, 96 kHz, 1 ms ptime

## IPMX Time Domains

The toolkit carefully distinguishes three independent time domains:

1. **Nominal RTP timestamps** — constant increments per frame in the 90 KHz
   RTP clock.  Not wall-clock times.
2. **Sender Reference Clock (SR NTP)** — PTP truncated timestamp format
   (seconds + nanoseconds), per VSF TR-10-1 §8.7.
3. **PCAP capture time** — the sniffer machine's wall clock, independent of
   the sender's clock.

## Reference Documents

- VSF TR-10-1 (IPMX System Timing and Definitions)
- VSF TR-10-5 (IPMX HDCP Key Exchange Protocol)
- VSF TR-10-7 (IPMX Sender Reports)
- VSF TR-10-9 (IPMX Compressed Video RTP Transport)
- VSF TR-10-11 (IPMX Compressed Video)
- VSF TR-10-12 (IPMX Audio)
- VSF TR-10-15a (IPMX JPEG XS Profile)
- VSF TR-10-15b (IPMX HEVC Profile)
- VSF TR-10-15c (IPMX H.264 Profile)
- SMPTE ST 2110-21 (Traffic Shaping — Network Compatibility Model)
- SMPTE ST 2110-30 (PCM Digital Audio)
- SMPTE ST 2110-31 (AES3 Transparent Transport)
- ITU-T H.265 (2021-08)
- ITU-T H.264 (2021-08)
- ISO/IEC 21122-1, -2 (JPEG XS)
- RFC 7798 (RTP Payload Format for H.265)
- RFC 6184 (RTP Payload Format for H.264)
- RFC 9134 (RTP Payload Format for JPEG XS)
- RFC 8285 (RTP Header Extension Framework)
- NMOS BCP-006

## Packaging

This project is a development workspace that will be integrated into the
official IPMX Certification test suite, which will receive proper packaging
(dependency management, CI/CD, etc.).  For now, the only external runtime
dependency is `scapy>=2.5` (`pip install scapy`).

## License

Apache License 2.0 — Copyright (C) 2026 Matrox Graphics Inc.
