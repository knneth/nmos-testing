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

"""USB standard-layer decoder for usbDissector.py.

IPMX (TR-10-14) tunnels raw USB inside its messages:
  * USB_*_SUBMIT carries an 8-byte SETUP packet (USBDEVREQ, USB 2.0 §9.3).
  * USB_*_SUBMIT_RETURN carries the descriptor / data bytes (TRANSFERDATA).

usbDissector.py decodes the IPMX message *envelope*; this module decodes what
rides *inside* it, so `-m --decode-usb` can expand a row such as

    usbdevreq='8006000100001200'  transferdata='1201100103...'

into human-readable form:

    GET_DESCRIPTOR Device index=0 len=18 [IN]
    -> Device: bcdUSB=1.10 class=0x00 vid=0x03F0 pid=0x0024 bcdDevice=3.00
              iMfr=1 iProduct=2 iSerial=0 numConfigs=1

Design notes
------------
* Standalone and import-safe: no sockets, no threads, no module-level side
  effects.  Safe to import from a pcap post-processor.
* The request-*builder* constants in ipmx_usb_tester.py are the mirror image of
  this module (that tool assembles outgoing requests; this one decodes captured
  ones).  The small overlap in USB constants is intentional duplication kept
  local so the live-hardware harness need not be imported here.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# USB 2.0 constants (§9.4, §9.6) and HID 1.11 (§7.1)
# ---------------------------------------------------------------------------

class UsbStandardRequest(IntEnum):
    """bRequest values for standard requests (USB 2.0 Table 9-4)."""
    GET_STATUS        = 0x00
    CLEAR_FEATURE     = 0x01
    SET_FEATURE       = 0x03
    SET_ADDRESS       = 0x05
    GET_DESCRIPTOR    = 0x06
    SET_DESCRIPTOR    = 0x07
    GET_CONFIGURATION = 0x08
    SET_CONFIGURATION = 0x09
    GET_INTERFACE     = 0x0A
    SET_INTERFACE     = 0x0B
    SYNCH_FRAME       = 0x0C


class HidClassRequest(IntEnum):
    """bRequest values for HID class requests (HID 1.11 §7.2)."""
    GET_REPORT   = 0x01
    GET_IDLE     = 0x02
    GET_PROTOCOL = 0x03
    SET_REPORT   = 0x09
    SET_IDLE     = 0x0A
    SET_PROTOCOL = 0x0B


class DescriptorType(IntEnum):
    """bDescriptorType values (USB 2.0 Table 9-5, HID 1.11 §7.1)."""
    DEVICE             = 0x01
    CONFIGURATION      = 0x02
    STRING             = 0x03
    INTERFACE          = 0x04
    ENDPOINT           = 0x05
    DEVICE_QUALIFIER   = 0x06
    OTHER_SPEED_CONFIG = 0x07
    INTERFACE_POWER    = 0x08
    BOS                = 0x0F
    HID                = 0x21
    REPORT             = 0x22
    PHYSICAL           = 0x23


class RequestType(IntEnum):
    """bmRequestType bits 6:5 — request category (USB 2.0 §9.3)."""
    STANDARD = 0
    CLASS    = 1
    VENDOR   = 2
    RESERVED = 3


class Recipient(IntEnum):
    """bmRequestType bits 4:0 — request recipient (USB 2.0 §9.3)."""
    DEVICE    = 0
    INTERFACE = 1
    ENDPOINT  = 2
    OTHER     = 3


class TransferType(IntEnum):
    """bmAttributes bits 1:0 of an endpoint descriptor (USB 2.0 Table 9-13)."""
    CONTROL     = 0
    ISOCHRONOUS = 1
    BULK        = 2
    INTERRUPT   = 3


# USB device / interface class codes we care to name (bDeviceClass / bInterfaceClass).
_USB_CLASS_NAMES = {
    0x00: "PerInterface",
    0x02: "CDC",
    0x03: "HID",
    0x08: "MassStorage",
    0x09: "Hub",
    0x0A: "CDC-Data",
    0x0B: "SmartCard",
    0x0E: "Video",
    0x0F: "HealthCare",
    0xFF: "VendorSpecific",
}

# HID boot-interface protocol (HID 1.11 §4.3) — only meaningful when subclass == 1.
_HID_BOOT_PROTOCOL_NAMES = {0: "None", 1: "Keyboard", 2: "Mouse"}


def _bcd(value: int) -> str:
    """Render a 16-bit BCD version (e.g. bcdUSB 0x0110 -> '1.10')."""
    return f"{value >> 8:X}.{value & 0xFF:02X}"


def _class_name(code: int) -> str:
    return _USB_CLASS_NAMES.get(code, f"0x{code:02X}")


# ---------------------------------------------------------------------------
# SETUP packet (USBDEVREQ) decoding
# ---------------------------------------------------------------------------

def decode_setup(raw: bytes) -> dict:
    """Decode an 8-byte USB SETUP packet (USB 2.0 §9.3).

    Returns a dict of raw fields plus a ready-to-print ``summary`` string.  For
    GET/SET_DESCRIPTOR the dict also carries ``descriptor_type`` /
    ``descriptor_index`` so a caller can decode the matching TRANSFERDATA in the
    context of what was actually requested.  Returns ``{}`` on short input.
    """
    if raw is None or len(raw) < 8:
        return {}

    bmRequestType = raw[0]
    bRequest      = raw[1]
    wValue        = int.from_bytes(raw[2:4], "little")
    wIndex        = int.from_bytes(raw[4:6], "little")
    wLength       = int.from_bytes(raw[6:8], "little")

    direction   = "IN" if (bmRequestType & 0x80) else "OUT"
    req_type    = RequestType((bmRequestType >> 5) & 0x03)
    recipient_v = bmRequestType & 0x1F
    recipient   = Recipient(recipient_v) if recipient_v in _RECIPIENT_VALUES else None

    info: dict = {
        "bmRequestType": bmRequestType,
        "bRequest": bRequest,
        "wValue": wValue,
        "wIndex": wIndex,
        "wLength": wLength,
        "direction": direction,
        "request_type": req_type,
        "recipient": recipient,
    }

    req_name = _request_name(req_type, bRequest)
    info["request_name"] = req_name

    # For descriptor requests, wValue = (descriptor_type << 8) | descriptor_index.
    if (req_type is RequestType.STANDARD
            and bRequest in (UsbStandardRequest.GET_DESCRIPTOR,
                             UsbStandardRequest.SET_DESCRIPTOR)):
        dtype = (wValue >> 8) & 0xFF
        dindex = wValue & 0xFF
        info["descriptor_type"] = dtype
        info["descriptor_index"] = dindex
        dtype_name = _descriptor_type_name(dtype)
        langid = f" langid=0x{wIndex:04X}" if wIndex else ""
        info["summary"] = (f"{req_name} {dtype_name} index={dindex}"
                           f"{langid} len={wLength} [{direction}]")
    else:
        recip = recipient.name.title() if recipient else f"recip0x{recipient_v:02X}"
        info["summary"] = (f"{req_name} {recip} "
                           f"wValue=0x{wValue:04X} wIndex=0x{wIndex:04X} "
                           f"len={wLength} [{direction}]")
    return info


_RECIPIENT_VALUES = frozenset(r.value for r in Recipient)


def _request_name(req_type: RequestType, bRequest: int) -> str:
    if req_type is RequestType.STANDARD:
        try:
            return UsbStandardRequest(bRequest).name
        except ValueError:
            return f"STD_REQ_0x{bRequest:02X}"
    if req_type is RequestType.CLASS:
        try:
            return f"HID_{HidClassRequest(bRequest).name}"
        except ValueError:
            return f"CLASS_REQ_0x{bRequest:02X}"
    if req_type is RequestType.VENDOR:
        return f"VENDOR_REQ_0x{bRequest:02X}"
    return f"REQ_0x{bRequest:02X}"


def _descriptor_type_name(dtype: int) -> str:
    try:
        return DescriptorType(dtype).name.title()
    except ValueError:
        return f"Descriptor0x{dtype:02X}"


# ---------------------------------------------------------------------------
# Descriptor (TRANSFERDATA) decoding
# ---------------------------------------------------------------------------

def describe_descriptor(data: bytes, hint_type: Optional[int] = None,
                        hint_index: Optional[int] = None) -> list[str]:
    """Decode a returned descriptor blob into human-readable lines.

    ``hint_type`` / ``hint_index`` come from the originating SETUP request
    (wValue high/low byte) and are authoritative: the device returns the
    descriptor that was asked for.  They are trusted over the blob's own header
    because some payloads cannot self-identify — a HID Report descriptor has no
    bLength/bType header at all, and its first bytes can masquerade as another
    descriptor type.  When no request was correlated (hints are None) we fall
    back to the blob's own bDescriptorType.  Returns [] when nothing useful can
    be said.
    """
    if not data:
        return []

    # A well-formed standard descriptor starts with bLength, bDescriptorType.
    self_type = (data[1] if len(data) >= 2 and 2 <= data[0] <= len(data)
                 else None)

    dtype = hint_type if hint_type is not None else self_type

    if dtype == DescriptorType.DEVICE:
        return _describe_device(data)
    if dtype == DescriptorType.CONFIGURATION:
        return _describe_configuration(data)
    if dtype == DescriptorType.STRING:
        return _describe_string(data, req_index=hint_index)
    if dtype == DescriptorType.REPORT:
        return _describe_report(data)
    if dtype == DescriptorType.BOS:
        return [f"-> BOS descriptor ({len(data)} bytes)"]
    if dtype is not None:
        return [f"-> {_descriptor_type_name(dtype)} ({len(data)} bytes)"]
    return []


def _describe_device(data: bytes) -> list[str]:
    if len(data) < 18:
        return [f"-> Device descriptor (truncated, {len(data)} bytes)"]
    bcdUSB   = int.from_bytes(data[2:4], "little")
    dclass   = data[4]
    dsub     = data[5]
    dproto   = data[6]
    maxpkt0  = data[7]
    vid      = int.from_bytes(data[8:10], "little")
    pid      = int.from_bytes(data[10:12], "little")
    bcdDev   = int.from_bytes(data[12:14], "little")
    iMfr     = data[14]
    iProduct = data[15]
    iSerial  = data[16]
    nConfigs = data[17]
    return [
        (f"-> Device: bcdUSB={_bcd(bcdUSB)} class={_class_name(dclass)} "
         f"sub=0x{dsub:02X} proto=0x{dproto:02X} maxPkt0={maxpkt0}"),
        (f"           vid=0x{vid:04X} pid=0x{pid:04X} bcdDevice={_bcd(bcdDev)} "
         f"iMfr={iMfr} iProduct={iProduct} iSerial={iSerial} numConfigs={nConfigs}"),
    ]


def _describe_configuration(data: bytes) -> list[str]:
    """Walk a (possibly full) configuration descriptor blob (USB 2.0 §9.6.3)."""
    if len(data) < 9:
        return [f"-> Configuration descriptor (truncated, {len(data)} bytes)"]
    wTotalLength = int.from_bytes(data[2:4], "little")
    nInterfaces  = data[4]
    cfgValue     = data[5]
    attrs        = data[7]
    maxPower_mA  = data[8] * 2
    lines = [
        (f"-> Configuration: value={cfgValue} numInterfaces={nInterfaces} "
         f"totalLen={wTotalLength} attrs=0x{attrs:02X} maxPower={maxPower_mA}mA"),
    ]

    # Walk the nested interface / endpoint / HID descriptors.
    i = 0
    n = len(data)
    while i + 2 <= n:
        blen = data[i]
        btype = data[i + 1]
        if blen < 2 or i + blen > n:
            break
        if btype == DescriptorType.INTERFACE and blen >= 9:
            inum   = data[i + 2]
            alt    = data[i + 3]
            nEP    = data[i + 4]
            iclass = data[i + 5]
            isub   = data[i + 6]
            iproto = data[i + 7]
            proto_note = ""
            if iclass == 0x03 and isub == 0x01:   # HID boot interface
                proto_note = f" boot={_HID_BOOT_PROTOCOL_NAMES.get(iproto, iproto)}"
            lines.append(
                f"   Interface {inum} alt={alt}: class={_class_name(iclass)} "
                f"sub=0x{isub:02X} proto=0x{iproto:02X}{proto_note} numEndpoints={nEP}")
        elif btype == DescriptorType.HID and blen >= 6:
            bcdHID = int.from_bytes(data[i + 2:i + 4], "little")
            lines.append(f"     HID: bcdHID={_bcd(bcdHID)} descriptors={data[i + 5]}")
        elif btype == DescriptorType.ENDPOINT and blen >= 7:
            addr   = data[i + 2]
            attrs2 = data[i + 3]
            maxpkt = int.from_bytes(data[i + 4:i + 6], "little") & 0x07FF
            interval = data[i + 6]
            epnum = addr & 0x0F
            epdir = "IN" if (addr & 0x80) else "OUT"
            ttype = TransferType(attrs2 & 0x03).name.title()
            lines.append(
                f"     Endpoint 0x{addr:02X} (EP{epnum} {epdir}): {ttype} "
                f"maxPkt={maxpkt} bInterval={interval}")
        i += blen
    return lines


def _describe_string(data: bytes, req_index: Optional[int] = None) -> list[str]:
    """Decode a STRING descriptor (USB 2.0 §9.6.7).

    String index 0 returns the supported-LANGID array; every other index
    returns a UTF-16LE string.  ``req_index`` is the string index from the
    originating request and is used to disambiguate.  When it is unknown we fall
    back to a content heuristic (a text string decodes to printable characters;
    a LANGID array typically does not).
    """
    if len(data) < 2:
        return [f"-> String descriptor (truncated, {len(data)} bytes)"]
    body = data[2:data[0]] if data[0] <= len(data) else data[2:]
    if not body:
        return ["-> String: (empty)"]

    def _as_langids() -> list[str]:
        langids = [int.from_bytes(body[j:j + 2], "little")
                   for j in range(0, len(body) - 1, 2)]
        return ["-> String LANGIDs: " + ", ".join(f"0x{lid:04X}" for lid in langids)]

    def _as_text() -> list[str]:
        try:
            text = body.decode("utf-16-le")
        except (UnicodeDecodeError, ValueError):
            return [f"-> String: <undecodable, {len(body)} bytes>"]
        # Escape control characters so a stray CR/NUL can't corrupt the console.
        shown = "".join(ch if 0x20 <= ord(ch) <= 0x7E else f"\\x{ord(ch):02X}"
                        for ch in text)
        return [f"-> String: '{shown}'"]

    if req_index == 0:
        return _as_langids()
    if req_index is not None:
        return _as_text()
    # No request context — guess from content.
    try:
        text = body.decode("utf-16-le")
    except (UnicodeDecodeError, ValueError):
        text = ""
    if text and all(ch == "\t" or 0x20 <= ord(ch) <= 0x7E for ch in text):
        return _as_text()
    return _as_langids()


def _describe_report(data: bytes) -> list[str]:
    """HID Report descriptor (HID 1.11 §6.2.2) — summarize; full item parse is
    out of scope here.  We surface the top-level Usage Page / Usage when present
    since that identifies the device (e.g. Generic Desktop / Keyboard)."""
    lines = [f"-> HID Report descriptor ({len(data)} bytes)"]
    usage_page = _first_short_item(data, tag=0x04)   # Usage Page (global, tag 0x0)
    usage      = _first_short_item(data, tag=0x08)   # Usage (local, tag 0x0)
    notes = []
    if usage_page is not None:
        notes.append(f"UsagePage=0x{usage_page:02X}")
    if usage is not None:
        notes.append(f"Usage=0x{usage:02X}")
    if notes:
        lines.append("   " + " ".join(notes))
    return lines


def _first_short_item(data: bytes, tag: int) -> Optional[int]:
    """Return the value of the first HID short item whose prefix == ``tag``.

    HID short items are 1 prefix byte + 0..4 data bytes; the prefix encodes
    bTag/bType in the high nibble+ and size in bits 1:0.  ``tag`` is matched
    against the prefix with the size bits masked off.
    """
    i = 0
    n = len(data)
    while i < n:
        prefix = data[i]
        size = prefix & 0x03
        nbytes = 4 if size == 3 else size
        if (prefix & 0xFC) == (tag & 0xFC) and i + 1 + nbytes <= n:
            return int.from_bytes(data[i + 1:i + 1 + nbytes], "little") if nbytes else 0
        i += 1 + nbytes
    return None
