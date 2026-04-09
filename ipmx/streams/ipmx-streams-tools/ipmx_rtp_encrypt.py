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
"""Dummy HKEP / PEP XOR cipher for audio RTP payload encryption.

Mirrors the two-cipher design in ffmpeg-matrox/src/libavformat/rtp_cipher.c
and the raw-audio encryption path in rtpenc.c (rtp_send_raw):

  - payload_header_size = 0   entire RTP payload is encrypted (audio has no RTP Payload Header)
  - full_ctr = 1 always       FULL RFC 8285 extension header on every packet (never SHORT)
  - input_ctr starts at 0 and increments by ceil(payload_len / 16) per packet
  - HDCP cipher applied first, PEP cipher second (decrypt order is reversed: PEP then HDCP)

The cipher logic is codec-agnostic — it encrypts any RTP payload with
payload_header_size=0.  For AM824 (ST 2110-31) test streams this module is
the primary encryption path.  For PCM (ST 2110-30) test streams ffmpeg-native
encryption via ``-hdcp_scramble`` / ``-privacy_scramble`` is preferred, but
this module remains available as a fallback.

These are NOT cryptographically secure — they exist solely to produce
properly-framed encrypted RTP streams for integration testing, identical to
what ffmpeg-matrox produces for H.264/H.265 video.
"""

from __future__ import annotations

import struct
from pathlib import Path


# ---------------------------------------------------------------------------
# Key derivation (mirrors rtp_cipher.c)
# ---------------------------------------------------------------------------

_HDCP_SALT = b"HDCP"   # 0x48, 0x44, 0x43, 0x50
_PEP_SALT  = b"PEP!"   # 0x50, 0x45, 0x50, 0x21


def derive_hdcp_key(stream_ctr: int, input_ctr: int) -> bytes:
    """Derive 16-byte HDCP XOR key (mirrors derive_hdcp_key in rtp_cipher.c).

    p[i] = (stream_ctr >> (i*8)) & 0xff     little-endian
    c[i] = (input_ctr  >> (i*8)) & 0xff     little-endian
    key[0:4]  = p ^ salt
    key[4:8]  = p ^ salt ^ 0xff
    key[8:16] = c ^ salt[i & 3]
    """
    p    = [(stream_ctr >> (i * 8)) & 0xff for i in range(4)]
    c    = [(input_ctr  >> (i * 8)) & 0xff for i in range(8)]
    salt = _HDCP_SALT
    key  = bytearray(16)
    for i in range(4):
        key[i]     = p[i] ^ salt[i]
        key[4 + i] = p[i] ^ salt[i] ^ 0xff
    for i in range(8):
        key[8 + i] = c[i] ^ salt[i & 3]
    return bytes(key)


def derive_privacy_key(stream_ctr: int, input_ctr: int) -> bytes:
    """Derive 16-byte PEP XOR key (mirrors derive_privacy_key in rtp_cipher.c).

    p[i] = (stream_ctr >> ((3-i)*8)) & 0xff   big-endian / reversed vs HDCP
    c[i] = (input_ctr  >> ((7-i)*8)) & 0xff   big-endian / reversed vs HDCP
    key[0:8]  = c ^ salt[i & 3]
    key[8:12] = p ^ salt ^ 0xa5
    key[12:16] = p ^ salt ^ 0x5a
    """
    p    = [(stream_ctr >> ((3 - i) * 8)) & 0xff for i in range(4)]
    c    = [(input_ctr  >> ((7 - i) * 8)) & 0xff for i in range(8)]
    salt = _PEP_SALT
    key  = bytearray(16)
    for i in range(8):
        key[i] = c[i] ^ salt[i & 3]
    for i in range(4):
        key[8  + i] = p[i] ^ salt[i] ^ 0xa5
        key[12 + i] = p[i] ^ salt[i] ^ 0x5a
    return bytes(key)


def _xor_apply(key: bytes, data: bytes | bytearray) -> bytes:
    """XOR data with key, cycling the 16-byte key over the full data length."""
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = b ^ key[i & 15]
    return bytes(result)


# ---------------------------------------------------------------------------
# FULL RFC 8285 one-byte extension header (mirrors rtp.h RTP_ExtHdrFull)
# ---------------------------------------------------------------------------
#
# 20-byte layout:
#   0-1:   0xBEDE        RFC 8285 one-byte header profile magic
#   2-3:   0x0004        length = 4 × 32-bit words = 16 bytes of extension data
#   4:     0x1E          id=1 (bits 7:4) | l=0xE (bits 3:0) → 15 data bytes follow
#   5-7:   0x000000      reserved (shall be zero per spec)
#   8-11:  stream_ctr    big-endian uint32 (inband_ctr: HDCP stream-ctr or PEP key_version)
#   12-19: input_ctr     big-endian uint64
#
_FULL_EXT_PROFILE = b"\xBE\xDE\x00\x04"


def build_full_ext_header(stream_ctr: int, input_ctr: int) -> bytes:
    """Build the 20-byte FULL RFC 8285 one-byte IV-counter extension header."""
    hdr = bytearray(_FULL_EXT_PROFILE)             # 0xBEDE + length = 4 words
    hdr.append(0x1E)                               # id=1 (upper nibble), l=0xE (lower nibble)
    hdr.extend(b"\x00\x00\x00")                   # reserved
    hdr.extend(struct.pack(">I", stream_ctr & 0xFFFFFFFF))           # inband_ctr
    hdr.extend(struct.pack(">Q", input_ctr  & 0xFFFFFFFFFFFFFFFF))   # input_ctr
    assert len(hdr) == 20, f"Extension header size mismatch: {len(hdr)}"
    return bytes(hdr)


# ---------------------------------------------------------------------------
# PCAP encryption entry point
# ---------------------------------------------------------------------------

def encrypt_rtp_pcap(
    input_path: Path,
    output_path: Path,
    *,
    hkep: bool,
    pep: bool,
    stream_ctr: int = 1,
) -> int:
    """Encrypt an AM824 RTP PCAP using dummy HDCP and/or PEP XOR ciphers.

    For each RTP packet:
      1. Sets the RTP X (extension) bit.
      2. Inserts a 20-byte FULL RFC 8285 IV-counter extension header.
      3. Applies HDCP cipher then PEP cipher (if both active) to the full payload
         (payload_header_size = 0: AM824 has no RTP Payload Header).
      4. Increments input_ctr by ceil(payload_len / 16).

    Non-RTP packets (RTCP etc.) are copied unchanged.
    Returns the number of RTP packets that were encrypted.
    """
    if not hkep and not pep:
        raise ValueError("encrypt_rtp_pcap: at least one of hkep or pep must be True")

    from scapy.all import PcapReader, PcapWriter, UDP, Raw  # type: ignore[import-untyped]

    input_ctr: int = 0
    count = 0

    with PcapReader(str(input_path)) as reader, \
         PcapWriter(str(output_path), sync=True) as writer:

        for pkt in reader:
            # Pass through non-UDP / non-Raw packets unchanged (e.g. RTCP)
            if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
                writer.write(pkt)
                continue

            raw_bytes: bytes = bytes(pkt[Raw].load)
            if len(raw_bytes) < 12:
                writer.write(pkt)
                continue

            # Parse the minimal RTP fixed header
            first_byte = raw_bytes[0]
            version    = (first_byte >> 6) & 0x03
            if version != 2:
                writer.write(pkt)
                continue

            has_ext   = bool((first_byte >> 4) & 0x01)
            cc        = first_byte & 0x0F
            basic_end = 12 + cc * 4          # end of fixed header + CSRC list

            if len(raw_bytes) < basic_end:
                writer.write(pkt)
                continue

            # Skip packets that already carry an extension header
            # (this function targets freshly generated clear PCAPs only)
            if has_ext:
                writer.write(pkt)
                continue

            payload = raw_bytes[basic_end:]
            if not payload:
                writer.write(pkt)
                continue

            # Rebuild the RTP fixed header with X bit set
            rtp_prefix = bytearray(raw_bytes[:basic_end])
            rtp_prefix[0] = rtp_prefix[0] | 0x10   # set X bit

            # Build the FULL extension header for this packet
            ext_hdr = build_full_ext_header(stream_ctr, input_ctr)

            # Encrypt the payload: HDCP first, then PEP (decrypt order is reversed)
            encrypted = bytearray(payload)
            if hkep:
                key = derive_hdcp_key(stream_ctr, input_ctr)
                encrypted = bytearray(_xor_apply(key, encrypted))
            if pep:
                key = derive_privacy_key(stream_ctr, input_ctr)
                encrypted = bytearray(_xor_apply(key, encrypted))

            # Advance input_ctr by ceil(payload_len / 16) matching rtpenc.c line 511
            input_ctr += (len(payload) + 15) // 16

            # Reassemble and replace the Raw payload in the packet
            new_rtp = bytes(rtp_prefix) + ext_hdr + bytes(encrypted)
            pkt[Raw].load = new_rtp

            # Invalidate auto-computed IP/UDP length and checksum fields
            if pkt.haslayer("IP"):
                del pkt["IP"].len
                del pkt["IP"].chksum
            if pkt.haslayer(UDP):
                del pkt[UDP].len
                del pkt[UDP].chksum

            writer.write(pkt)
            count += 1

    return count
