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

"""
usb_pcap_to_ipmx.py  —  Convert real USB PCAP captures to IPMX USB (TR-10-14) PCAP.

Reads USB captures in any common format using tshark for structured field
extraction and scapy for raw payload bytes, then wraps the real USB transfers
in a proper IPMX control+data channel session with authentic timing.

Supported input DLT types:
  DLT 266  macOS/Darwin  XHC USB header (XHC20-*.pcapng)
  DLT 186  Linux usbmon  usbmon_packet header
  DLT 220  Linux usbmon_mmapped  (64-byte header variant)
  DLT 249  USBPcap/Windows  (variable-length header)

Usage:
    python3 usb_pcap_to_ipmx.py input.pcap[ng] output.pcap [options]

Options:
    --busid BUSID        USB bus-ID string for IPMX  (default: auto-detected)
    --sender-ip IP       Sender (device side) IP     (default: 192.168.1.10)
    --receiver-ip IP     Receiver (host side) IP     (default: 192.168.1.20)
    --device N           Only convert device address N (default: auto, first HID)
    --list-devices       Print detected devices and exit
    --verbose            Print per-transfer details to stderr
"""

from __future__ import annotations

import argparse
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from scapy.all import PcapReader
except ImportError:
    print("Error: scapy required.  pip install scapy", file=sys.stderr)
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).parent))
import ipmx_usb_message as usb
from generate_usb_test_pcap import (
    TcpFlow, control_flow, data_flow, write_pcap,
    SENDER_CID, RECEIVER_CID, SENDER_SN, RECEIVER_SN,
    HBEAT_INDEX, RECEIVER_DATA_PORT,
    KBD_SUBSTREAMID, KBD_USBSPEED, KBD_BUSID,
)


# ---------------------------------------------------------------------------
# DLT constants
# ---------------------------------------------------------------------------

DLT_USB_LINUX          = 186   # usbmon, 48-byte header
DLT_USB_LINUX_MMAPPED  = 220   # usbmon_mmapped, 64-byte header
DLT_USBPCAP            = 249   # USBPcap/Windows, variable-length header
DLT_USB_DARWIN         = 266   # macOS XHC, 40-byte header

# Transfer types (common across formats)
XFER_ISO   = 0
XFER_INT   = 1
XFER_CTRL  = 2
XFER_BULK  = 3

# Darwin-specific transfer type codes (different numbering)
_DARWIN_XFER = {0: XFER_CTRL, 1: XFER_ISO, 2: XFER_BULK, 3: XFER_INT}
# usbmon transfer type codes (identical to common)
_USBMON_XFER = {0: XFER_ISO, 1: XFER_INT, 2: XFER_CTRL, 3: XFER_BULK}

XFER_NAMES = {XFER_ISO: 'ISO', XFER_INT: 'INT', XFER_CTRL: 'CTRL', XFER_BULK: 'BULK'}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Urb:
    """One USB request block extracted from a capture packet."""
    frame_no:      int
    ts:            float        # epoch seconds
    io_id:         int          # unique ID used to pair SUBMIT ↔ COMPLETE
    is_submit:     bool         # True = SUBMIT, False = COMPLETE
    xfer_type:     int          # XFER_* constant
    endpoint:      int          # raw endpoint address byte (direction bit in bit7)
    device_addr:   int
    io_len:        int          # requested (submit) or actual (complete) length
    io_status:     int          # 0 = success
    setup_data:    bytes        # 8-byte setup packet for CTRL SUBMIT, else b''
    payload:       bytes        # response data for COMPLETE; OUT data for CTRL SUBMIT

    @property
    def direction(self) -> int:
        """1 = IN (device→host), 0 = OUT (host→device)."""
        return 1 if (self.endpoint & 0x80) else 0

    @property
    def ep_num(self) -> int:
        return self.endpoint & 0x0F

    @property
    def xfer_name(self) -> str:
        return XFER_NAMES.get(self.xfer_type, '?')

    @property
    def rstatus(self) -> usb.StatusCode:
        if self.io_status == 0:
            return usb.StatusCode.SUCCESS
        if self.io_status in (0xC0000001, -1):  # cancelled / error
            return usb.StatusCode.CANCELED
        return usb.StatusCode.STALL


@dataclass
class UrbPair:
    """A matched SUBMIT + COMPLETE pair."""
    submit:   Urb
    complete: Urb

    @property
    def xfer_type(self) -> int:
        return self.submit.xfer_type

    @property
    def device_addr(self) -> int:
        return self.submit.device_addr


# ---------------------------------------------------------------------------
# DLT detection
# ---------------------------------------------------------------------------

def detect_dlt(path: Path) -> int:
    """Return the link-layer DLT number from a PCAP or PCAPNG file header."""
    with open(path, 'rb') as f:
        magic = struct.unpack('<I', f.read(4))[0]

    if magic in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1):
        # PCAP global header: bytes 20–23 = DLT (LE)
        with open(path, 'rb') as f:
            f.seek(20)
            return struct.unpack('<I', f.read(4))[0]

    if magic == 0x0A0D0D0A:
        # PCAPNG: find the first Interface Description Block (type 0x00000001)
        with open(path, 'rb') as f:
            f.seek(0)
            while True:
                hdr = f.read(8)
                if len(hdr) < 8:
                    break
                blk_type, blk_len = struct.unpack('<II', hdr)
                if blk_type == 0x00000001:          # IDB
                    lt = struct.unpack('<H', f.read(2))[0]
                    return lt
                if blk_len < 12:
                    break
                f.seek(blk_len - 8, 1)             # skip body + trailing length

    return -1


# ---------------------------------------------------------------------------
# tshark field extraction
# ---------------------------------------------------------------------------

# Fields requested from tshark for every DLT type
_TSHARK_FIELDS = [
    'frame.number',
    'frame.time_epoch',
    'usb.src',
    'usb.dst',
    # Darwin fields
    'usb.darwin.request_type',
    'usb.darwin.io_id',
    'usb.darwin.endpoint_address',
    'usb.darwin.endpoint_type',
    'usb.darwin.io_len',
    'usb.darwin.io_status',
    'usb.darwin.device_address',
    # usbmon / USBPcap common
    'usb.urb_id',
    'usb.urb_type',
    'usb.transfer_type',
    'usb.endpoint_address',
    'usb.device_address',
    'usb.data_len',
    # Setup packet (all formats)
    'usb.bmRequestType',
    'usb.setup.bRequest',
    'usb.setup.wValue',
    'usb.setup.wIndex',
    'usb.setup.wLength',
]

_SEP = '\x1f'   # ASCII unit separator — safe, never appears in USB field values


def run_tshark_fields(path: Path) -> dict[int, dict[str, str]]:
    """
    Run tshark -T fields on *path* and return a mapping
    frame_no → {field_name: value_string}.
    """
    args = [
        'tshark', '-r', str(path),
        '-T', 'fields',
        '-E', f'separator={_SEP}',
        '-E', 'header=y',
    ]
    for f in _TSHARK_FIELDS:
        args += ['-e', f]

    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode not in (0, 2):     # 2 = warnings only
        raise RuntimeError(f"tshark failed: {result.stderr[:200]}")

    rows: dict[int, dict[str, str]] = {}
    lines = result.stdout.splitlines()
    if not lines:
        return rows

    headers = lines[0].split(_SEP)
    for line in lines[1:]:
        cols = line.split(_SEP)
        row = dict(zip(headers, cols))
        try:
            fno = int(row.get('frame.number', '0'))
        except ValueError:
            continue
        rows[fno] = row

    return rows


# ---------------------------------------------------------------------------
# Raw payload extraction (scapy reads unknown-DLT packets as Raw)
# ---------------------------------------------------------------------------

def read_raw_packets(path: Path) -> tuple[dict[int, bytes], dict[int, float]]:
    """Return (frame_no → raw bytes, frame_no → timestamp) for every packet."""
    raw: dict[int, bytes] = {}
    timestamps: dict[int, float] = {}
    with PcapReader(str(path)) as rdr:
        for i, pkt in enumerate(rdr, start=1):
            raw[i] = bytes(pkt)
            timestamps[i] = float(getattr(pkt, 'time', 0.0))
    return raw, timestamps


# ---------------------------------------------------------------------------
# Per-DLT header parsers
# ---------------------------------------------------------------------------

def _parse_darwin(frame_no: int, ts: float, raw: bytes,
                  fields: dict[str, str]) -> Optional[Urb]:
    """Parse a DLT 266 (macOS Darwin) USB packet."""
    if len(raw) < 40:
        return None

    header_len   = raw[2]
    request_type = raw[3]             # 0 = SUBMIT, 1 = COMPLETE
    io_len       = struct.unpack_from('<I', raw, 4)[0]
    io_status    = struct.unpack_from('<I', raw, 8)[0]
    io_id        = struct.unpack_from('<Q', raw, 16)[0]
    device_addr  = raw[29]
    endpoint     = raw[30]
    darwin_xtype = raw[31]            # Darwin endpoint-type code
    xfer_type    = _DARWIN_XFER.get(darwin_xtype, XFER_CTRL)

    is_submit = (request_type == 0)
    data      = raw[header_len : header_len + io_len]

    setup_data = b''
    payload    = b''

    if xfer_type == XFER_CTRL:
        if is_submit:
            # First 8 bytes after header = USB setup packet
            setup_data = data[:8]
            payload    = data[8:]       # OUT data (rare for HID)
        else:
            payload = data              # IN data (descriptor response etc.)
    else:
        if not is_submit:
            payload = data              # INT/BULK IN data

    return Urb(
        frame_no=frame_no, ts=ts, io_id=io_id,
        is_submit=is_submit, xfer_type=xfer_type,
        endpoint=endpoint, device_addr=device_addr,
        io_len=io_len, io_status=io_status,
        setup_data=setup_data, payload=payload,
    )


def _parse_usbmon(frame_no: int, ts: float, raw: bytes, hdr_size: int,
                  fields: dict[str, str]) -> Optional[Urb]:
    """
    Parse a usbmon packet (DLT 186 = 48-byte header, DLT 220 = 64-byte header).

    usbmon_packet layout (DLT 186):
      0   u64 id
      8   u8  type  ('S'=83 submit, 'C'=67 complete)
      9   u8  transfer_type  (0=ISO 1=INT 2=CTL 3=BULK)
      10  u8  endpoint
      11  u8  devnum
      12  u16 busnum
      14  s8  flag_setup  (non-'-' means setup data present at offset 40)
      15  s8  flag_data   ('<' = data present)
      16  s64 ts_sec
      24  s32 ts_usec
      28  s32 status
      32  u32 length      (requested)
      36  u32 len_cap     (captured)
      40  u8[8] setup (or ISO desc count)
    Data: offset 48 (or 64 for mmapped), length = len_cap
    """
    if len(raw) < hdr_size:
        return None

    io_id        = struct.unpack_from('<Q', raw, 0)[0]
    urb_type     = raw[8]             # ord('S')=83, ord('C')=67
    xfer_type    = _USBMON_XFER.get(raw[9], XFER_CTRL)
    endpoint     = raw[10]
    device_addr  = raw[11]
    flag_setup   = raw[14]
    flag_data    = raw[15]
    ts_sec       = struct.unpack_from('<q', raw, 16)[0]
    ts_usec      = struct.unpack_from('<i', raw, 24)[0]
    status       = struct.unpack_from('<i', raw, 28)[0]
    length       = struct.unpack_from('<I', raw, 32)[0]
    len_cap      = struct.unpack_from('<I', raw, 36)[0]

    # Use embedded timestamp if more precise than tshark's
    ts = float(ts_sec) + ts_usec / 1_000_000

    is_submit  = (urb_type == ord('S'))
    io_status  = 0 if status == 0 else abs(status)
    setup_data = b''
    payload    = b''

    if xfer_type == XFER_CTRL and is_submit and flag_setup != ord('-'):
        setup_data = raw[40:48]
    if flag_data == ord('<') or (not is_submit and len_cap > 0):
        payload = raw[hdr_size : hdr_size + len_cap]

    return Urb(
        frame_no=frame_no, ts=ts, io_id=io_id,
        is_submit=is_submit, xfer_type=xfer_type,
        endpoint=endpoint, device_addr=device_addr,
        io_len=length, io_status=io_status,
        setup_data=setup_data, payload=payload,
    )


def _parse_usbpcap(frame_no: int, ts: float, raw: bytes,
                   fields: dict[str, str]) -> Optional[Urb]:
    """
    Parse a USBPcap packet (DLT 249).

    Minimum header (27 bytes):
      0   u16 headerLen
      2   u64 irpId
      10  u32 status
      14  u16 function
      16  u8  info      (bit0: 0=FDO→PDO OUT/submit, 1=PDO→FDO IN/complete)
      17  u16 bus
      19  u16 device
      21  u8  endpoint
      22  u8  transfer  (0=ISO 1=INT 2=CTL 3=BULK)
      23  u32 dataLength
    For CTL, 8-byte setup packet immediately precedes data (at headerLen-8).
    Data starts at offset headerLen.
    """
    if len(raw) < 27:
        return None

    header_len  = struct.unpack_from('<H', raw, 0)[0]
    io_id       = struct.unpack_from('<Q', raw, 2)[0]
    status      = struct.unpack_from('<I', raw, 10)[0]
    info        = raw[16]
    device_addr = struct.unpack_from('<H', raw, 19)[0]
    endpoint    = raw[21]
    xfer_type   = raw[22]             # already in common numbering
    data_len    = struct.unpack_from('<I', raw, 23)[0]

    if xfer_type not in (XFER_ISO, XFER_INT, XFER_CTRL, XFER_BULK):
        return None

    # USBPcap uses irpId to match pairs; direction from info bit 0
    # info bit0=0 → host→device (submit / OUT), bit0=1 → device→host (complete / IN)
    is_submit = ((info & 1) == 0)
    io_status = 0 if status == 0 else status

    setup_data = b''
    payload    = raw[header_len : header_len + data_len]

    if xfer_type == XFER_CTRL and is_submit and header_len >= 35:
        setup_data = raw[header_len - 8 : header_len]
        payload    = b''   # no extra data for CTL SUBMIT

    return Urb(
        frame_no=frame_no, ts=ts, io_id=io_id,
        is_submit=is_submit, xfer_type=xfer_type,
        endpoint=endpoint, device_addr=int(device_addr),
        io_len=data_len, io_status=io_status,
        setup_data=setup_data, payload=payload,
    )


# ---------------------------------------------------------------------------
# Load and pair URBs
# ---------------------------------------------------------------------------

def _tshark_available() -> bool:
    """Check if tshark is installed."""
    import shutil
    return shutil.which('tshark') is not None


def load_urbs(path: Path, verbose: bool = False) -> tuple[list[Urb], int]:
    """
    Read *path* with tshark (fields) + scapy (raw bytes), parse every packet
    into a Urb, and return (urb_list, dlt).

    Falls back to scapy-only parsing (with timestamps from pcap headers)
    when tshark is not available.  Darwin and usbmon DLTs need tshark for
    some fields; USBPcap parses everything from raw bytes.
    """
    dlt = detect_dlt(path)
    if dlt == -1:
        raise ValueError(f"Cannot detect DLT for {path}")

    print(f"  Input DLT: {dlt} ({_dlt_name(dlt)})", file=sys.stderr)

    tshark_rows: dict[int, dict[str, str]] = {}
    if _tshark_available():
        tshark_rows = run_tshark_fields(path)
    else:
        if dlt in (DLT_USB_DARWIN, DLT_USB_LINUX, DLT_USB_LINUX_MMAPPED):
            print("  WARNING: tshark not installed — Darwin/usbmon fields "
                  "will be incomplete", file=sys.stderr)
        else:
            print("  (tshark not available — using scapy timestamps)",
                  file=sys.stderr)

    raw_pkts, scapy_ts = read_raw_packets(path)

    urbs: list[Urb] = []
    for frame_no, raw in raw_pkts.items():
        row = tshark_rows.get(frame_no, {})
        try:
            ts = float(row.get('frame.time_epoch', '0'))
        except ValueError:
            ts = 0.0
        if ts == 0.0:
            ts = scapy_ts.get(frame_no, 0.0)

        urb = None
        if dlt == DLT_USB_DARWIN:
            urb = _parse_darwin(frame_no, ts, raw, row)
        elif dlt == DLT_USB_LINUX:
            urb = _parse_usbmon(frame_no, ts, raw, hdr_size=48, fields=row)
        elif dlt == DLT_USB_LINUX_MMAPPED:
            urb = _parse_usbmon(frame_no, ts, raw, hdr_size=64, fields=row)
        elif dlt == DLT_USBPCAP:
            urb = _parse_usbpcap(frame_no, ts, raw, row)

        if urb is not None:
            urbs.append(urb)
            if verbose:
                _print_urb(urb)

    return urbs, dlt


def pair_urbs(urbs: list[Urb]) -> list[UrbPair]:
    """
    Match SUBMIT ↔ COMPLETE by io_id (preserving capture order for submits).
    Unmatched submits/completes are silently dropped.
    """
    pending: dict[int, Urb] = {}    # io_id → SUBMIT Urb
    pairs: list[UrbPair] = []

    for urb in urbs:
        if urb.is_submit:
            pending[urb.io_id] = urb
        else:
            sub = pending.pop(urb.io_id, None)
            if sub is not None:
                pairs.append(UrbPair(submit=sub, complete=urb))

    return pairs


def list_devices(pairs: list[UrbPair]) -> dict[int, dict]:
    """
    Return a summary dict: device_addr → info  with counts of transfers
    and a guess at the device class from interface descriptors seen.
    """
    devices: dict[int, dict] = {}
    for pair in pairs:
        da = pair.device_addr
        if da not in devices:
            devices[da] = {
                'xfer_counts': {XFER_CTRL: 0, XFER_INT: 0,
                                XFER_BULK: 0, XFER_ISO: 0},
                'endpoints': set(),
                'hid_protocol': None,    # 1=keyboard, 2=mouse
                'config_desc': b'',
            }
        info = devices[da]
        if pair.xfer_type in info['xfer_counts']:
            info['xfer_counts'][pair.xfer_type] += 1
        info['endpoints'].add(pair.submit.endpoint)

        # Look for SET_PROTOCOL in CTRL SUBMITs to identify device class
        if pair.xfer_type == XFER_CTRL and len(pair.submit.setup_data) == 8:
            sd = pair.submit.setup_data
            # bmRequestType=0x21 bRequest=0x0B (SET_PROTOCOL) wValue=0 or 1
            if sd[0] == 0x21 and sd[1] == 0x0B:
                info['hid_protocol'] = sd[2]    # 0=boot, 1=?; interface protocol

        # Grab config descriptor response (bDescriptorType == 0x02)
        if (pair.xfer_type == XFER_CTRL
                and len(pair.submit.setup_data) == 8
                and pair.submit.setup_data[1] == 0x06          # GET_DESCRIPTOR
                and pair.submit.setup_data[3] == 0x02          # config
                and len(pair.complete.payload) > 18):
            if not info['config_desc']:
                info['config_desc'] = pair.complete.payload

    # Try to extract bInterfaceProtocol from config descriptor
    for da, info in devices.items():
        cd = info['config_desc']
        off = 0
        while off + 4 <= len(cd):
            blen = cd[off]
            btype = cd[off + 1] if off + 1 < len(cd) else 0
            if btype == 0x04 and off + 9 <= len(cd):   # INTERFACE descriptor
                iclass    = cd[off + 5]
                isubclass = cd[off + 6]
                iproto    = cd[off + 7]
                if iclass == 0x03:                      # HID
                    info['hid_protocol'] = iproto       # 1=kbd, 2=mouse
                    break
            if blen < 2:
                break
            off += blen

    return devices


# ---------------------------------------------------------------------------
# IPMX PCAP builder
# ---------------------------------------------------------------------------

def _set_flow_time(flow: TcpFlow, ts: float) -> None:
    """Set the flow's next packet timestamp to *ts* (absolute epoch)."""
    flow._tick = ts - flow._base_time


def build_ipmx_pcap(
    pairs:       list[UrbPair],
    device_addr: int,
    device_info: dict,
    output_path: Path,
    sender_ip:   str = "192.168.1.10",
    receiver_ip: str = "192.168.1.20",
    substreamid: int = KBD_SUBSTREAMID,
    busid:       str = KBD_BUSID,
    verbose:     bool = False,
) -> None:
    """
    Wrap *pairs* (for a single USB device) in an IPMX USB session and write
    to *output_path*.

    IPMX mapping:
      USB host   = IPMX Receiver  (server in TcpFlow)
      USB device = IPMX Sender    (client in TcpFlow)

      CTRL/INT/BULK SUBMIT → df.server_send(USB_*_SUBMIT)   Receiver→Sender
      CTRL/INT/BULK COMPLETE → df.client_send(USB_*_RETURN) Sender→Receiver
    """
    if not pairs:
        print("No URB pairs to convert.", file=sys.stderr)
        return

    base_ts = pairs[0].submit.ts
    all_pkts: list = []

    # --- Control channel (synthetic, before any USB traffic) ---
    cf = control_flow(base_ts - 0.1)
    all_pkts += cf.handshake()
    all_pkts += cf.server_send(usb.build_sender_connection_info(SENDER_CID, SENDER_SN))
    all_pkts += cf.client_send(usb.build_sender_connection_status(
        RECEIVER_CID, RECEIVER_SN, HBEAT_INDEX, RECEIVER_DATA_PORT))

    # --- Data channel ---
    usbspeed = KBD_USBSPEED   # HIGH_SPEED for all modern HID devices
    df = data_flow(base_ts - 0.05)
    df._base_time = 0           # use absolute epoch seconds for timing
    _set_flow_time(df, base_ts - 0.05)
    all_pkts += df.handshake()
    _set_flow_time(df, base_ts - 0.04)
    all_pkts += df.client_send(usb.build_usb_stream_info(substreamid, usbspeed, busid))
    _set_flow_time(df, base_ts - 0.03)
    all_pkts += df.server_send(usb.build_usb_stream_status(0))

    # --- USB transfers ---
    seqnum = 0
    ctrl_count = int_count = bulk_count = iso_count = skip_count = 0

    for pair in pairs:
        sub  = pair.submit
        cmp  = pair.complete

        # Realistic status
        rstatus = cmp.rstatus

        if pair.xfer_type == XFER_CTRL:
            if len(sub.setup_data) != 8:
                skip_count += 1
                continue
            usbdevreq = sub.setup_data
            direction = sub.direction
            # transferlength from wLength field of setup packet
            transferlength = struct.unpack_from('<H', usbdevreq, 6)[0]

            _set_flow_time(df, sub.ts)
            all_pkts += df.server_send(usb.build_usb_control_submit(
                seqnum, endpoint=sub.ep_num, direction=direction,
                binterval=0, transferlength=transferlength,
                usbdevreq=usbdevreq,
            ))
            _set_flow_time(df, cmp.ts)
            all_pkts += df.client_send(usb.build_usb_control_submit_return(
                seqnum, endpoint=sub.ep_num, direction=direction,
                actuallength=len(cmp.payload), rstatus=rstatus,
                transferdata=cmp.payload,
            ))
            ctrl_count += 1

        elif pair.xfer_type == XFER_INT:
            direction = sub.direction
            _set_flow_time(df, sub.ts)
            all_pkts += df.server_send(usb.build_usb_interrupt_submit(
                seqnum, endpoint=sub.ep_num, direction=direction,
                binterval=8, transferlength=sub.io_len or 8,
            ))
            _set_flow_time(df, cmp.ts)
            all_pkts += df.client_send(usb.build_usb_interrupt_submit_return(
                seqnum, endpoint=sub.ep_num, direction=direction,
                actuallength=len(cmp.payload), rstatus=rstatus,
                transferdata=cmp.payload,
            ))
            int_count += 1

        elif pair.xfer_type == XFER_BULK:
            direction = sub.direction
            _set_flow_time(df, sub.ts)
            all_pkts += df.server_send(usb.build_usb_bulk_submit(
                seqnum, endpoint=sub.ep_num, direction=direction,
                binterval=0, transferlength=sub.io_len,
            ))
            _set_flow_time(df, cmp.ts)
            all_pkts += df.client_send(usb.build_usb_bulk_submit_return(
                seqnum, endpoint=sub.ep_num, direction=direction,
                actuallength=len(cmp.payload), rstatus=rstatus,
                transferdata=cmp.payload,
            ))
            bulk_count += 1

        elif pair.xfer_type == XFER_ISO:
            direction = sub.direction
            payload = cmp.payload
            packet_len = len(payload) if payload else sub.io_len
            _set_flow_time(df, sub.ts)
            all_pkts += df.server_send(usb.build_usb_isochronous_submit(
                seqnum, endpoint=sub.ep_num, direction=direction,
                binterval=1, asap=1, startframe=0,
                num_packets=1, isolengths=[packet_len],
            ))
            _set_flow_time(df, cmp.ts)
            iso_status = 0 if cmp.io_status == 0 else cmp.io_status
            frame_number = int((cmp.ts - base_ts) * 1000)
            all_pkts += df.client_send(usb.build_usb_isochronous_submit_return(
                seqnum, endpoint=sub.ep_num, direction=direction,
                startframe=frame_number, errorcount=(0 if iso_status == 0 else 1),
                num_packets=1,
                iso_packets=[(len(payload), iso_status)],
                transferdata=payload,
            ))
            iso_count += 1

        else:
            skip_count += 1
            continue

        seqnum += 1
        if verbose:
            print(f"  [{seqnum:4d}] {pair.xfer_type_name if hasattr(pair,'xfer_type_name') else XFER_NAMES.get(pair.xfer_type,'?')}"
                  f"  ep={sub.ep_num:#04x}  dir={'IN' if sub.direction else 'OUT'}"
                  f"  len={len(cmp.payload)}",
                  file=sys.stderr)

    # --- Teardown ---
    last_ts = pairs[-1].complete.ts
    _set_flow_time(df, last_ts + 0.005)
    all_pkts += df.fin()
    all_pkts += cf.fin()

    write_pcap(output_path, all_pkts)
    print(f"\nSummary for device {device_addr} → {output_path}:", file=sys.stderr)
    print(f"  CTRL={ctrl_count}  INT={int_count}  BULK={bulk_count}  ISO={iso_count}"
          f"  skipped={skip_count}  SEQNUM_used={seqnum}", file=sys.stderr)
    print(f"  Total IPMX packets written: {len(all_pkts)}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dlt_name(dlt: int) -> str:
    return {
        DLT_USB_LINUX:         'usbmon/Linux (48-byte)',
        DLT_USB_LINUX_MMAPPED: 'usbmon_mmapped/Linux (64-byte)',
        DLT_USBPCAP:           'USBPcap/Windows',
        DLT_USB_DARWIN:        'XHC Darwin/macOS (40-byte)',
    }.get(dlt, f'unknown')


def _print_urb(urb: Urb) -> None:
    kind = 'SUB' if urb.is_submit else 'CMP'
    data_info = ''
    if urb.setup_data:
        data_info = f'  setup={urb.setup_data.hex()}'
    if urb.payload:
        data_info += f'  data[{len(urb.payload)}]={urb.payload[:8].hex()}'
    print(
        f"  [{urb.frame_no:4d}] {kind} {urb.xfer_name:4s}"
        f"  ep={urb.endpoint:#04x}  dev={urb.device_addr}"
        f"  io_len={urb.io_len}{data_info}",
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert real USB PCAP to IPMX USB (TR-10-14) PCAP",
    )
    parser.add_argument('input',  help="Input USB PCAP or PCAPNG file")
    parser.add_argument('output', nargs='?', help="Output IPMX PCAP file")
    parser.add_argument('--device',      type=int, default=None,
                        help="USB device address to convert (default: auto-select HID device)")
    parser.add_argument('--substreamid', type=int, default=None,
                        help="IPMX SUBSTREAMID for the data channel (default: 2)")
    parser.add_argument('--busid',       default=None,
                        help="USB Bus-ID string for IPMX (e.g. '1-1.1')")
    parser.add_argument('--sender-ip',   default="192.168.1.10",
                        help="IP address of the IPMX Sender (USB device side)")
    parser.add_argument('--receiver-ip', default="192.168.1.20",
                        help="IP address of the IPMX Receiver (USB host side)")
    parser.add_argument('--list-devices', action='store_true',
                        help="Print detected USB devices and exit")
    parser.add_argument('--verbose', '-v', action='store_true',
                        help="Print per-transfer details")
    args = parser.parse_args()

    input_path  = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found", file=sys.stderr)
        sys.exit(1)

    print(f"Loading {input_path} …", file=sys.stderr)
    urbs, dlt = load_urbs(input_path, verbose=False)
    print(f"  Parsed {len(urbs)} URBs", file=sys.stderr)

    pairs = pair_urbs(urbs)
    print(f"  Matched {len(pairs)} SUBMIT/COMPLETE pairs", file=sys.stderr)

    devices = list_devices(pairs)

    # Print device table
    print(f"\nDetected {len(devices)} USB device(s):", file=sys.stderr)
    hid_proto_name = {1: 'HID-Keyboard', 2: 'HID-Mouse'}
    for da, info in sorted(devices.items()):
        xc = info['xfer_counts']
        proto = hid_proto_name.get(info['hid_protocol'], 'unknown')
        eps   = ','.join(f"{e:#04x}" for e in sorted(info['endpoints']))
        print(
            f"  device {da:3d}  [{proto}]"
            f"  CTRL={xc[XFER_CTRL]}  INT={xc[XFER_INT]}"
            f"  BULK={xc[XFER_BULK]}  endpoints=[{eps}]",
            file=sys.stderr,
        )

    if args.list_devices:
        return

    if not args.output:
        print("Error: output file required (or use --list-devices)", file=sys.stderr)
        sys.exit(1)

    # Auto-select device: prefer HID, then first device seen
    target_device = args.device
    if target_device is None:
        for da, info in sorted(devices.items()):
            if info['hid_protocol'] in (1, 2):
                target_device = da
                break
        if target_device is None and devices:
            target_device = next(iter(sorted(devices)))

    if target_device not in devices:
        print(f"Error: device {target_device} not found. "
              f"Available: {sorted(devices.keys())}", file=sys.stderr)
        sys.exit(1)

    device_info = devices[target_device]
    dev_pairs   = [p for p in pairs if p.device_addr == target_device]

    # Derive busid from input filename if not specified
    if args.busid:
        busid = args.busid
    else:
        stem = input_path.stem.replace('.pcapng', '').replace('.pcap', '')
        busid = f"capture/{stem}/dev{target_device}"

    substreamid = args.substreamid if args.substreamid is not None else 0x02

    print(f"\nConverting device {target_device} "
          f"({len(dev_pairs)} pairs) → {args.output}", file=sys.stderr)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    build_ipmx_pcap(
        pairs       = dev_pairs,
        device_addr = target_device,
        device_info = device_info,
        output_path = output_path,
        sender_ip   = args.sender_ip,
        receiver_ip = args.receiver_ip,
        substreamid = substreamid,
        busid       = busid,
        verbose     = args.verbose,
    )


if __name__ == '__main__':
    main()
