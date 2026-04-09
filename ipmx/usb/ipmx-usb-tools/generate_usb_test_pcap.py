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
Synthetic PCAP generator for IPMX USB (TR-10-14) dissector testing.

Generates 21 scenario PCAPs covering control/data channels, USB HID
enumeration, fragmentation, out-of-order delivery, reconnections, vendor-
specific messages, realistic typing/mouse sessions, UVC webcam streaming,
UAC microphone streaming, UVC quirk handling, and fully encrypted sessions.
Derived from the USB 2.0, HID 1.11, UVC 1.1, and UAC 1.0 specifications.
No real hardware is required.

Usage:
    python3 generate_usb_test_pcap.py [--output-dir <dir>]

All PCAPs are written to ./test_pcaps/ by default.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time as time_mod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from scapy.all import Ether, IP, TCP, Raw, PcapWriter
except ImportError:
    print("Error: scapy is required.  Install with: pip install scapy")
    sys.exit(1)

import ipmx_pep as pep
import ipmx_usb_message as usb


# ---------------------------------------------------------------------------
# Shared test constants
# ---------------------------------------------------------------------------

SENDER_IP   = "192.168.1.10"
RECEIVER_IP = "192.168.1.20"
SENDER_MAC  = "02:00:00:00:00:01"
RECEIVER_MAC = "02:00:00:00:00:02"

SENDER_CID   = bytes.fromhex("0050C2")
RECEIVER_CID = bytes.fromhex("0050C2")
SENDER_SN    = "MTX-USB-001"
RECEIVER_SN  = "MTX-HOST-001"

SENDER_CTRL_PORT = 27502    # SDP port — Receiver connects to this
RECEIVER_DATA_PORT = 40000  # Receiver's listen port for data channels — from SenderConnectionStatus
HBEAT_INDEX  = 10           # Heartbeat index (period ≈ 47 s)

# USB HID keyboard device
KBD_SUBSTREAMID = 0x04
KBD_BUSID       = "1-1.1"
KBD_USBSPEED    = usb.UsbSpeed.HIGH_SPEED
KBD_ENDPOINT_IN = 0x01   # Interrupt IN endpoint number
KBD_BINTERVAL   = 8      # 8ms polling

# USB HID mouse device
MOUSE_SUBSTREAMID = 0x06
MOUSE_BUSID       = "1-1.2"
MOUSE_USBSPEED    = usb.UsbSpeed.HIGH_SPEED
MOUSE_ENDPOINT_IN = 0x01
MOUSE_BINTERVAL   = 8


# ---------------------------------------------------------------------------
# USB HID descriptor constants (real-world byte arrays)
# ---------------------------------------------------------------------------

# Standard USB Device Descriptor (18 bytes) — USB HID Keyboard
# bDeviceClass=0 (defined at interface), VID=0x045E (Microsoft), PID=0x0750
KBD_DEVICE_DESCRIPTOR = bytes([
    0x12,       # bLength
    0x01,       # bDescriptorType = DEVICE
    0x00, 0x02, # bcdUSB = 2.00
    0x00,       # bDeviceClass = 0 (defined at interface level)
    0x00,       # bDeviceSubClass
    0x00,       # bDeviceProtocol
    0x40,       # bMaxPacketSize0 = 64
    0x5E, 0x04, # idVendor = 0x045E (Microsoft)
    0x50, 0x07, # idProduct = 0x0750
    0x11, 0x01, # bcdDevice = 1.11
    0x01,       # iManufacturer = 1
    0x02,       # iProduct = 2
    0x03,       # iSerialNumber = 3
    0x01,       # bNumConfigurations = 1
])

# Configuration + Interface + HID + Endpoint descriptors (34 bytes total)
# Config(9) + Interface(9) + HID(9) + Endpoint(7) = 34 bytes
KBD_CONFIG_DESCRIPTOR = bytes([
    # Configuration Descriptor
    0x09,       # bLength
    0x02,       # bDescriptorType = CONFIGURATION
    0x22, 0x00, # wTotalLength = 34
    0x01,       # bNumInterfaces = 1
    0x01,       # bConfigurationValue = 1
    0x00,       # iConfiguration = 0
    0xA0,       # bmAttributes = bus-powered, remote wakeup
    0x32,       # bMaxPower = 100mA
    # Interface Descriptor
    0x09,       # bLength
    0x04,       # bDescriptorType = INTERFACE
    0x00,       # bInterfaceNumber = 0
    0x00,       # bAlternateSetting = 0
    0x01,       # bNumEndpoints = 1
    0x03,       # bInterfaceClass = HID
    0x01,       # bInterfaceSubClass = 1 (boot)
    0x01,       # bInterfaceProtocol = 1 (keyboard)
    0x00,       # iInterface = 0
    # HID Descriptor
    0x09,       # bLength
    0x21,       # bDescriptorType = HID
    0x11, 0x01, # bcdHID = 1.11
    0x00,       # bCountryCode = 0
    0x01,       # bNumDescriptors = 1
    0x22,       # bDescriptorType = REPORT
    0x2D, 0x00, # wDescriptorLength = 45
    # Endpoint Descriptor (Interrupt IN)
    0x07,       # bLength
    0x05,       # bDescriptorType = ENDPOINT
    0x81,       # bEndpointAddress = IN, EP1
    0x03,       # bmAttributes = Interrupt
    0x08, 0x00, # wMaxPacketSize = 8
    0x08,       # bInterval = 8ms
])

# Minimal HID Report Descriptor for boot-protocol keyboard (45 bytes)
KBD_HID_REPORT_DESCRIPTOR = bytes([
    0x05, 0x01,  # Usage Page (Generic Desktop)
    0x09, 0x06,  # Usage (Keyboard)
    0xA1, 0x01,  # Collection (Application)
    0x05, 0x07,  # Usage Page (Key Codes)
    0x19, 0xE0,  # Usage Minimum (224)
    0x29, 0xE7,  # Usage Maximum (231)
    0x15, 0x00,  # Logical Minimum (0)
    0x25, 0x01,  # Logical Maximum (1)
    0x75, 0x01,  # Report Size (1)
    0x95, 0x08,  # Report Count (8)
    0x81, 0x02,  # Input (Data, Variable, Absolute) — modifier keys
    0x95, 0x01,  # Report Count (1)
    0x75, 0x08,  # Report Size (8)
    0x81, 0x03,  # Input (Constant) — reserved byte
    0x95, 0x06,  # Report Count (6)
    0x75, 0x08,  # Report Size (8)
    0x15, 0x00,  # Logical Minimum (0)
    0x25, 0x65,  # Logical Maximum (101)
    0x05, 0x07,  # Usage Page (Key Codes)
    0x19, 0x00,  # Usage Minimum (0)
    0x29, 0x65,  # Usage Maximum (101)
    0x81, 0x00,  # Input (Data, Array) — keycode array
    0x85, 0x02,  # Report ID 2
    0x05, 0x08,  # Usage Page (LEDs)
    0x19, 0x01,  # Usage Minimum (1)
    0x29, 0x05,  # Usage Maximum (5)
    0x95, 0x05,  # Report Count (5)
    0x75, 0x01,  # Report Size (1)
    0x91, 0x02,  # Output (Data, Variable, Absolute) — LED state
    0x95, 0x01,  # Report Count (1)
    0x75, 0x03,  # Report Size (3)
    0x91, 0x03,  # Output (Constant) — padding
    0xC0,        # End Collection
])

# Mouse device descriptor (VID=0x046D Logitech, PID=0xC077)
MOUSE_DEVICE_DESCRIPTOR = bytes([
    0x12,       # bLength
    0x01,       # bDescriptorType = DEVICE
    0x00, 0x02, # bcdUSB = 2.00
    0x00,       # bDeviceClass = 0
    0x00,       # bDeviceSubClass
    0x00,       # bDeviceProtocol
    0x08,       # bMaxPacketSize0 = 8
    0x6D, 0x04, # idVendor = 0x046D (Logitech)
    0x77, 0xC0, # idProduct = 0xC077
    0x72, 0x12, # bcdDevice = 18.72
    0x01,       # iManufacturer = 1
    0x02,       # iProduct = 2
    0x00,       # iSerialNumber = 0 (no serial)
    0x01,       # bNumConfigurations = 1
])

# Mouse HID Report Descriptor (52 bytes) — boot-protocol compatible, with wheel
MOUSE_HID_REPORT_DESCRIPTOR = bytes([
    0x05, 0x01,  # Usage Page (Generic Desktop)
    0x09, 0x02,  # Usage (Mouse)
    0xA1, 0x01,  # Collection (Application)
    0x09, 0x01,  # Usage (Pointer)
    0xA1, 0x00,  # Collection (Physical)
    0x05, 0x09,  # Usage Page (Buttons)
    0x19, 0x01,  # Usage Minimum (1)
    0x29, 0x03,  # Usage Maximum (3)
    0x15, 0x00,  # Logical Minimum (0)
    0x25, 0x01,  # Logical Maximum (1)
    0x75, 0x01,  # Report Size (1)
    0x95, 0x03,  # Report Count (3)
    0x81, 0x02,  # Input (Data, Variable, Absolute) — 3 buttons
    0x75, 0x05,  # Report Size (5)
    0x95, 0x01,  # Report Count (1)
    0x81, 0x01,  # Input (Constant) — 5-bit padding
    0x05, 0x01,  # Usage Page (Generic Desktop)
    0x09, 0x30,  # Usage (X)
    0x09, 0x31,  # Usage (Y)
    0x09, 0x38,  # Usage (Wheel)
    0x15, 0x81,  # Logical Minimum (-127)
    0x25, 0x7F,  # Logical Maximum (127)
    0x75, 0x08,  # Report Size (8)
    0x95, 0x03,  # Report Count (3)
    0x81, 0x06,  # Input (Data, Variable, Relative)
    0xC0,        # End Collection (Physical)
    0xC0,        # End Collection (Application)
])

# Mouse config + interface + HID + endpoint (34 bytes)
# wDescriptorLength = len(MOUSE_HID_REPORT_DESCRIPTOR) = 52 = 0x34
MOUSE_CONFIG_DESCRIPTOR = bytes([
    # Configuration Descriptor
    0x09, 0x02, 0x22, 0x00, 0x01, 0x01, 0x00, 0xA0, 0x32,
    # Interface Descriptor (bInterfaceProtocol=2 = mouse)
    0x09, 0x04, 0x00, 0x00, 0x01, 0x03, 0x01, 0x02, 0x00,
    # HID Descriptor (wDescriptorLength=52)
    0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x34, 0x00,
    # Endpoint Descriptor (IN EP1, Interrupt, 4 bytes, 8ms)
    0x07, 0x05, 0x81, 0x03, 0x04, 0x00, 0x08,
])


# ---------------------------------------------------------------------------
# USB String Descriptors (UTF-16LE, USB 2.0 §9.6.7)
# ---------------------------------------------------------------------------

def _make_string_descriptor(s: str) -> bytes:
    """Encode *s* as a USB string descriptor (bLength, bDescriptorType=0x03, UTF-16LE)."""
    enc = s.encode('utf-16-le')
    return bytes([2 + len(enc), 0x03]) + enc

# String descriptor index 0 — supported language IDs: English US (0x0409)
KBD_LANGID_DESCRIPTOR   = bytes([0x04, 0x03, 0x09, 0x04])
MOUSE_LANGID_DESCRIPTOR = bytes([0x04, 0x03, 0x09, 0x04])

KBD_STRING_MANUFACTURER = _make_string_descriptor("Microsoft")
KBD_STRING_PRODUCT      = _make_string_descriptor("Natural Keyboard 4000")
KBD_STRING_SERIAL       = _make_string_descriptor("K4000-001")

MOUSE_STRING_MANUFACTURER = _make_string_descriptor("Logitech")
MOUSE_STRING_PRODUCT      = _make_string_descriptor("USB Optical Mouse")


# ---------------------------------------------------------------------------
# USB UVC webcam descriptors (Logitech C920 — VID:PID exercises quirk table)
# ---------------------------------------------------------------------------

CAM_SUBSTREAMID = 0x08
CAM_BUSID       = "1-1.3"
CAM_USBSPEED    = usb.UsbSpeed.HIGH_SPEED
CAM_VIDEO_EP_IN = 0x01
CAM_AUDIO_EP_IN = 0x02

CAM_DEVICE_DESCRIPTOR = bytes([
    0x12, 0x01,             # bLength, bDescriptorType = DEVICE
    0x00, 0x02,             # bcdUSB = 2.00
    0xEF,                   # bDeviceClass = Misc (IAD)
    0x02,                   # bDeviceSubClass = Common Class
    0x01,                   # bDeviceProtocol = IAD
    0x40,                   # bMaxPacketSize0 = 64
    0x6D, 0x04,             # idVendor = 0x046D (Logitech)
    0x2D, 0x08,             # idProduct = 0x082D (C920)
    0x11, 0x00,             # bcdDevice = 0.11
    0x01,                   # iManufacturer = 1
    0x02,                   # iProduct = 2
    0x03,                   # iSerialNumber = 3
    0x01,                   # bNumConfigurations = 1
])

# Configuration descriptor chain for UVC webcam + UAC 1.0 microphone.
# IAD(8) + VC Iface(9) + VC Header(13) + Input Terminal Camera(18) +
# Processing Unit(11) + Output Terminal(9) + VS Iface Alt0(9) +
# VS Input Header(13) + VS Format MJPEG(11) + VS Frame 640x480(30) +
# VS Frame 1280x720(30) + VS Color Matching(6) + VS Iface Alt1(9) +
# EP ISO IN(7) +
# IAD Audio(8) + AC Iface(9) + AC Header(9) + Input Terminal Mic(12) +
# Feature Unit(9) + Output Terminal(9) + AS Iface Alt0(9) +
# AS Iface Alt1(9) + AS General(7) + AS Format Type I(11) +
# EP ISO IN(9) + CS EP(7)
_VC_HEADER_LEN = 13
_CAM_IT_LEN = 18
_PU_LEN = 11
_OT_LEN = 9
_VC_TOTAL = _VC_HEADER_LEN + _CAM_IT_LEN + _PU_LEN + _OT_LEN  # 51

_VS_INPUT_HEADER_LEN = 14
_VS_FMT_MJPEG_LEN = 11
_VS_FRAME_LEN = 30
_VS_COLOR_LEN = 6
_VS_TOTAL = _VS_INPUT_HEADER_LEN + _VS_FMT_MJPEG_LEN + 2 * _VS_FRAME_LEN + _VS_COLOR_LEN  # 90

_AC_HEADER_LEN = 9
_AC_IT_LEN = 12
_AC_FU_LEN = 9
_AC_OT_LEN = 9
_AC_TOTAL = _AC_HEADER_LEN + _AC_IT_LEN + _AC_FU_LEN + _AC_OT_LEN  # 39

_CONFIG_TOTAL = (
    9                  # Config descriptor
    + 8 + 9 + _VC_TOTAL    # Video IAD + VC Interface + VC class-specific
    + 9 + _VS_TOTAL + 9 + 7  # VS Alt0 + VS class-specific + VS Alt1 + EP
    + 8 + 9 + _AC_TOTAL    # Audio IAD + AC Interface + AC class-specific
    + 9 + 9 + 7 + 11 + 9 + 7  # AS Alt0 + AS Alt1 + AS General + Format + EP + CS EP
)

CAM_CONFIG_DESCRIPTOR = bytes([
    # ---- Configuration Descriptor (9) ----
    0x09, 0x02,
    _CONFIG_TOTAL & 0xFF, (_CONFIG_TOTAL >> 8) & 0xFF,
    0x04,               # bNumInterfaces = 4 (VC, VS, AC, AS)
    0x01,               # bConfigurationValue = 1
    0x00, 0xA0, 0xFA,   # iConfiguration=0, bmAttributes=bus-powered+rwakeup, 500mA

    # ---- IAD for Video (8) ----
    0x08, 0x0B, 0x00, 0x02, 0x0E, 0x03, 0x00, 0x02,

    # ---- VideoControl Interface (9) ----
    0x09, 0x04, 0x00, 0x00, 0x00, 0x0E, 0x01, 0x00, 0x02,

    # ---- VC Header (13): UVC 1.1 ----
    _VC_HEADER_LEN, 0x24, 0x01,
    0x10, 0x01,           # bcdUVC = 1.1
    _VC_TOTAL & 0xFF, (_VC_TOTAL >> 8) & 0xFF,
    0x00, 0x6C, 0xDC, 0x02,  # dwClockFrequency = 48 MHz
    0x01, 0x01,           # bInCollection=1, baInterfaceNr=1

    # ---- Camera Terminal (Input Terminal) (18) ----
    _CAM_IT_LEN, 0x24, 0x02,
    0x01,                 # bTerminalID = 1
    0x01, 0x02,           # wTerminalType = ITT_CAMERA
    0x00,                 # bAssocTerminal = 0
    0x00,                 # iTerminal = 0
    0x00, 0x00,           # wObjectiveFocalLengthMin
    0x00, 0x00,           # wObjectiveFocalLengthMax
    0x00, 0x00,           # wOcularFocalLength
    0x03,                 # bControlSize = 3
    0x00, 0x02, 0x00,     # bmControls (auto-exposure)

    # ---- Processing Unit (11) ----
    _PU_LEN, 0x24, 0x05,
    0x02,                 # bUnitID = 2
    0x01,                 # bSourceID = 1 (Camera Terminal)
    0x00, 0x00,           # wMaxMultiplier
    0x02,                 # bControlSize = 2
    0x3F, 0x14,           # bmControls (brightness, contrast, etc.)
    0x00,                 # iProcessing = 0

    # ---- Output Terminal (9) ----
    _OT_LEN, 0x24, 0x03,
    0x03,                 # bTerminalID = 3
    0x01, 0x01,           # wTerminalType = TT_STREAMING
    0x00,                 # bAssocTerminal = 0
    0x02,                 # bSourceID = 2 (Processing Unit)
    0x00,                 # iTerminal = 0

    # ---- VS Interface Alt 0 (no bandwidth) (9) ----
    0x09, 0x04, 0x01, 0x00, 0x00, 0x0E, 0x02, 0x00, 0x00,

    # ---- VS Input Header (13) ----
    _VS_INPUT_HEADER_LEN, 0x24, 0x01,
    0x01,                 # bNumFormats = 1
    _VS_TOTAL & 0xFF, (_VS_TOTAL >> 8) & 0xFF,
    0x81,                 # bEndpointAddress = IN EP1
    0x00,                 # bmInfo
    0x03,                 # bTerminalLink = 3 (Output Terminal)
    0x00,                 # bStillCaptureMethod
    0x00,                 # bTriggerSupport
    0x00,                 # bTriggerUsage
    0x01, 0x00,           # bControlSize=1, bmaControls

    # ---- VS Format MJPEG (11) ----
    _VS_FMT_MJPEG_LEN, 0x24, 0x06,
    0x01,                 # bFormatIndex = 1
    0x02,                 # bNumFrameDescriptors = 2
    0x01,                 # bmFlags = FixedSizeSamples
    0x01,                 # bDefaultFrameIndex = 1
    0x00,                 # bAspectRatioX
    0x00,                 # bAspectRatioY
    0x00,                 # bmInterlaceFlags
    0x00,                 # bCopyProtect

    # ---- VS Frame 640x480 (30) ----
    _VS_FRAME_LEN, 0x24, 0x07,
    0x01,                 # bFrameIndex = 1
    0x01,                 # bmCapabilities (still image)
    0x80, 0x02,           # wWidth = 640
    0xE0, 0x01,           # wHeight = 480
    0x00, 0x00, 0x50, 0x46,  # dwMinBitRate = 1_180_000_000 (approx)
    0x00, 0x00, 0x50, 0x46,  # dwMaxBitRate
    0x00, 0x00, 0x58, 0x02,  # dwMaxVideoFrameBufferSize = 614400
    0x15, 0x16, 0x05, 0x00,  # dwDefaultFrameInterval = 333333 (30fps)
    0x01,                 # bFrameIntervalType = 1 (discrete)
    0x15, 0x16, 0x05, 0x00,  # dwFrameInterval[0] = 333333

    # ---- VS Frame 1280x720 (30) ----
    _VS_FRAME_LEN, 0x24, 0x07,
    0x02,                 # bFrameIndex = 2
    0x01,                 # bmCapabilities
    0x00, 0x05,           # wWidth = 1280
    0xD0, 0x02,           # wHeight = 720
    0x00, 0x00, 0xCA, 0x08,  # dwMinBitRate
    0x00, 0x00, 0xCA, 0x08,  # dwMaxBitRate
    0x00, 0x20, 0x1C, 0x00,  # dwMaxVideoFrameBufferSize = 1843200
    0x15, 0x16, 0x05, 0x00,  # dwDefaultFrameInterval = 333333 (30fps)
    0x01,
    0x15, 0x16, 0x05, 0x00,

    # ---- VS Color Matching (6) ----
    0x06, 0x24, 0x0D, 0x01, 0x01, 0x04,

    # ---- VS Interface Alt 1 (streaming active) (9) ----
    0x09, 0x04, 0x01, 0x01, 0x01, 0x0E, 0x02, 0x00, 0x00,

    # ---- Endpoint ISO IN EP1 (7) ----
    0x07, 0x05, 0x81, 0x05, 0x00, 0x04, 0x01,
    # bmAttributes=0x05 (isochronous, async), wMaxPacketSize=1024, bInterval=1

    # ---- IAD for Audio (8) ----
    0x08, 0x0B, 0x02, 0x02, 0x01, 0x00, 0x00, 0x00,

    # ---- AudioControl Interface (9) ----
    0x09, 0x04, 0x02, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,

    # ---- AC Header (9): UAC 1.0 ----
    _AC_HEADER_LEN, 0x24, 0x01,
    0x00, 0x01,           # bcdADC = 1.00
    _AC_TOTAL & 0xFF, (_AC_TOTAL >> 8) & 0xFF,
    0x01, 0x03,           # bInCollection=1, baInterfaceNr=3

    # ---- Input Terminal Microphone (12) ----
    _AC_IT_LEN, 0x24, 0x02,
    0x01,                 # bTerminalID = 1
    0x01, 0x02,           # wTerminalType = INPUT_UNDEFINED->Mic
    0x00,                 # bAssocTerminal
    0x02,                 # bNrChannels = 2 (stereo)
    0x03, 0x00,           # wChannelConfig (left+right)
    0x00,                 # iChannelNames
    0x00,                 # iTerminal

    # ---- Feature Unit (9) ----
    _AC_FU_LEN, 0x24, 0x06,
    0x02,                 # bUnitID = 2
    0x01,                 # bSourceID = 1
    0x01,                 # bControlSize = 1
    0x03,                 # bmaControls(0) = Mute+Volume
    0x00,                 # bmaControls(1)
    0x00,                 # iFeature

    # ---- Output Terminal USB Streaming (9) ----
    _AC_OT_LEN, 0x24, 0x03,
    0x03,                 # bTerminalID = 3
    0x01, 0x01,           # wTerminalType = USB Streaming
    0x00,                 # bAssocTerminal
    0x02,                 # bSourceID = 2 (Feature Unit)
    0x00,                 # iTerminal

    # ---- AudioStreaming Interface Alt 0 (no bandwidth) (9) ----
    0x09, 0x04, 0x03, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00,

    # ---- AudioStreaming Interface Alt 1 (active) (9) ----
    0x09, 0x04, 0x03, 0x01, 0x01, 0x01, 0x02, 0x00, 0x00,

    # ---- AS General (7) ----
    0x07, 0x24, 0x01,
    0x03,                 # bTerminalLink = 3
    0x01,                 # bDelay = 1
    0x01, 0x00,           # wFormatTag = PCM

    # ---- AS Format Type I (11) ----
    0x0B, 0x24, 0x02,
    0x01,                 # bFormatType = FORMAT_TYPE_I
    0x02,                 # bNrChannels = 2
    0x02,                 # bSubframeSize = 2
    0x10,                 # bBitResolution = 16
    0x01,                 # bSamFreqType = 1 (discrete)
    0x80, 0xBB, 0x00,     # tSamFreq[0] = 48000

    # ---- Endpoint ISO IN EP2 (9) ----
    0x09, 0x05, 0x82, 0x05, 0xC0, 0x00, 0x01, 0x00, 0x00,
    # bmAttributes=0x05 (iso, async), wMaxPacketSize=192, bInterval=1

    # ---- CS Endpoint (7) ----
    0x07, 0x25, 0x01, 0x01, 0x00, 0x00, 0x00,
])

CAM_LANGID_DESCRIPTOR = bytes([0x04, 0x03, 0x09, 0x04])
CAM_STRING_MANUFACTURER = _make_string_descriptor("Logitech")
CAM_STRING_PRODUCT      = _make_string_descriptor("HD Pro Webcam C920")
CAM_STRING_SERIAL       = _make_string_descriptor("C920-00001")


def _cam_device_descriptor_with_vid_pid(vid: int, pid: int) -> bytes:
    """Build a UVC device descriptor identical to CAM_DEVICE_DESCRIPTOR but
    with a different VID:PID (little-endian)."""
    d = bytearray(CAM_DEVICE_DESCRIPTOR)
    d[8] = vid & 0xFF
    d[9] = (vid >> 8) & 0xFF
    d[10] = pid & 0xFF
    d[11] = (pid >> 8) & 0xFF
    return bytes(d)


NOFID_DEVICE_DESCRIPTOR = _cam_device_descriptor_with_vid_pid(0x05E3, 0x0505)
NOFID_STRING_MANUFACTURER = _make_string_descriptor("Genesys Logic")
NOFID_STRING_PRODUCT      = _make_string_descriptor("USB2.0 Camera (NO_FID)")
NOFID_STRING_SERIAL       = _make_string_descriptor("GL-NOFID-001")

NOEOF_DEVICE_DESCRIPTOR = _cam_device_descriptor_with_vid_pid(0xEB1A, 0x2710)
NOEOF_STRING_MANUFACTURER = _make_string_descriptor("eMPIA Technology")
NOEOF_STRING_PRODUCT      = _make_string_descriptor("EM2710 Camera (NO_EOF)")
NOEOF_STRING_SERIAL       = _make_string_descriptor("EM-NOEOF-001")


# Standard USB device requests (bRequest codes)
USB_REQ_GET_DESCRIPTOR  = 0x06
USB_REQ_SET_ADDRESS     = 0x05
USB_REQ_SET_CONFIGURATION = 0x09
USB_REQ_SET_INTERFACE   = 0x0B
USB_REQ_SET_IDLE        = 0x0A
USB_REQ_SET_PROTOCOL    = 0x0B

USB_DT_DEVICE    = 0x01
USB_DT_CONFIG    = 0x02
USB_DT_STRING    = 0x03
USB_DT_INTERFACE_ASSOCIATION = 0x0B
USB_DT_HID       = 0x21
USB_DT_REPORT    = 0x22

# UVC class-specific request codes
UVC_SET_CUR = 0x01
UVC_GET_CUR = 0x81
UVC_GET_MIN = 0x82
UVC_GET_MAX = 0x83
UVC_GET_DEF = 0x87
UVC_VS_PROBE_CONTROL  = 0x01
UVC_VS_COMMIT_CONTROL = 0x02

def _get_descriptor_req(dtype: int, index: int, length: int, lang_id: int = 0) -> bytes:
    """Build a GET_DESCRIPTOR USBDEVREQ (8 bytes, Table 9-2 of USB 2.0).

    For string descriptors (dtype=0x03, index>0) pass lang_id=0x0409 (English US).
    """
    bmRequestType = 0x80        # Device-to-host, Standard, Device
    if dtype in (USB_DT_HID, USB_DT_REPORT):
        bmRequestType = 0x81    # Interface target
    bRequest = USB_REQ_GET_DESCRIPTOR
    wValue = (dtype << 8) | index
    wIndex = lang_id            # used as language ID for string descriptors
    wLength = length
    return struct.pack('<BBHHH', bmRequestType, bRequest, wValue, wIndex, wLength)

def _set_address_req(addr: int) -> bytes:
    """Build a SET_ADDRESS USBDEVREQ (USB 2.0 §9.4.6)."""
    return struct.pack('<BBHHH', 0x00, 0x05, addr, 0, 0)

def _set_configuration_req(config_value: int) -> bytes:
    return struct.pack('<BBHHH', 0x00, USB_REQ_SET_CONFIGURATION, config_value, 0, 0)

def _set_idle_req() -> bytes:
    return struct.pack('<BBHHH', 0x21, USB_REQ_SET_IDLE, 0x0000, 0, 0)

def _set_protocol_req(protocol: int) -> bytes:
    return struct.pack('<BBHHH', 0x21, USB_REQ_SET_PROTOCOL, protocol, 0, 0)

def _set_interface_req(interface: int, alt_setting: int) -> bytes:
    """Build a SET_INTERFACE USBDEVREQ (USB 2.0 §9.4.10)."""
    return struct.pack('<BBHHH', 0x01, USB_REQ_SET_INTERFACE, alt_setting, interface, 0)


# ---------------------------------------------------------------------------
# UVC Probe/Commit helpers
# ---------------------------------------------------------------------------

def _uvc_probe_control(format_index: int = 1, frame_index: int = 1,
                       frame_interval: int = 333333) -> bytes:
    """Build a 26-byte UVC Video Probe/Commit Control block (UVC 1.1, Table 4-75)."""
    buf = bytearray(26)
    buf[0] = 0x00           # bmHint
    buf[1] = 0x00
    buf[2] = format_index   # bFormatIndex
    buf[3] = frame_index    # bFrameIndex
    struct.pack_into('<I', buf, 4, frame_interval)  # dwFrameInterval
    return bytes(buf)


def _uvc_set_cur_req(cs: int, interface: int, length: int) -> bytes:
    """Build a SET_CUR class request targeting the VS interface."""
    return struct.pack('<BBHHH',
                       0x21,            # bmRequestType: H2D, Class, Interface
                       UVC_SET_CUR,     # bRequest
                       (cs << 8),       # wValue = CS << 8
                       interface,       # wIndex = interface
                       length)


def _uvc_get_cur_req(cs: int, interface: int, length: int) -> bytes:
    """Build a GET_CUR class request targeting the VS interface."""
    return struct.pack('<BBHHH',
                       0xA1,            # bmRequestType: D2H, Class, Interface
                       UVC_GET_CUR,     # bRequest
                       (cs << 8),       # wValue = CS << 8
                       interface,       # wIndex = interface
                       length)


def _uvc_get_def_req(cs: int, interface: int, length: int) -> bytes:
    return struct.pack('<BBHHH', 0xA1, UVC_GET_DEF, (cs << 8), interface, length)


def _uvc_get_min_req(cs: int, interface: int, length: int) -> bytes:
    return struct.pack('<BBHHH', 0xA1, UVC_GET_MIN, (cs << 8), interface, length)


def _uvc_get_max_req(cs: int, interface: int, length: int) -> bytes:
    return struct.pack('<BBHHH', 0xA1, UVC_GET_MAX, (cs << 8), interface, length)


# ---------------------------------------------------------------------------
# MJPEG frame generator
# ---------------------------------------------------------------------------

_MJPEG_MINIMAL_HEADER = bytes([
    0xFF, 0xD8,             # SOI
    0xFF, 0xE0,             # APP0 (JFIF)
    0x00, 0x10,             # length=16
    0x4A, 0x46, 0x49, 0x46, 0x00,  # "JFIF\0"
    0x01, 0x01,             # version 1.1
    0x00,                   # aspect ratio units = pixel
    0x00, 0x01, 0x00, 0x01, # X/Y density = 1
    0x00, 0x00,             # no thumbnail
])


def _generate_mjpeg_frame(width: int, height: int, frame_no: int,
                          total_frames: int = 150) -> bytes:
    """Generate a minimal valid MJPEG frame with slow colour cycling.

    Hue rotates once over total_frames so the colour change is smooth and
    pleasant at 30 fps rather than a violent per-frame flash.
    """
    import io
    import colorsys
    try:
        from PIL import Image
        hue = (frame_no / max(total_frames, 1)) % 1.0
        r, g, b = colorsys.hsv_to_rgb(hue, 0.8, 0.9)
        img = Image.new('RGB', (width, height),
                         (int(r * 255), int(g * 255), int(b * 255)))
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=30)
        return buf.getvalue()
    except ImportError:
        pass

    # Fallback: assemble a bare-minimum JPEG by hand
    buf = bytearray(_MJPEG_MINIMAL_HEADER)
    # DQT (quantisation table, all-1 for simplicity)
    buf += b'\xFF\xDB\x00\x43\x00' + bytes([1] * 64)
    # SOF0 (baseline, 8-bit, YCbCr 4:2:0 single-component for brevity)
    buf += b'\xFF\xC0\x00\x0B\x08'
    buf += struct.pack('>HH', height, width)
    buf += b'\x01\x01\x11\x00'
    # DHT (minimal Huffman table for DC)
    buf += b'\xFF\xC4\x00\x1F\x00'
    buf += bytes(16) + bytes([0, 1, 2])  # 3 symbols
    buf += bytes(13)
    # SOS
    buf += b'\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00'
    # Minimal scan data (colour-dependent byte to produce visual variation)
    colour_byte = (frame_no * 37) & 0xFF
    buf += bytes([colour_byte] * 64)
    # EOI
    buf += b'\xFF\xD9'
    return bytes(buf)


def _uvc_payload_header(fid: int, eof: bool, pts: int = 0) -> bytes:
    """Build a minimal 2-byte UVC payload header (BFH field).

    Bit 0: FID (frame ID toggle)
    Bit 1: EOF
    """
    bfh = (fid & 0x01) | ((1 if eof else 0) << 1)
    return bytes([0x02, bfh])  # bHeaderLength=2, bmHeaderInfo


def _fragment_uvc_frame(jpeg_data: bytes, fid: int,
                        max_packet: int = 1024,
                        no_fid: bool = False,
                        no_eof: bool = False) -> list[bytes]:
    """Fragment a JPEG frame into isochronous packets with UVC payload headers.

    Returns a list of raw isochronous packet payloads ready to be packed
    into IPMX USB_ISOCHRONOUS_SUBMIT_RETURN messages.
    """
    header_size = 2
    payload_per_pkt = max_packet - header_size
    packets: list[bytes] = []
    offset = 0

    while offset < len(jpeg_data):
        chunk = jpeg_data[offset:offset + payload_per_pkt]
        is_last = (offset + len(chunk) >= len(jpeg_data))

        fid_val = 0 if no_fid else fid
        eof = is_last and (not no_eof)
        hdr = _uvc_payload_header(fid_val, eof)
        packets.append(hdr + chunk)
        offset += len(chunk)

    return packets


# ---------------------------------------------------------------------------
# PCM audio generator
# ---------------------------------------------------------------------------

def _generate_pcm_chunk(sample_rate: int = 48000, channels: int = 2,
                        bits: int = 16, duration_ms: float = 1.0,
                        frequency: float = 440.0, frame_no: int = 0) -> bytes:
    """Generate one chunk of PCM audio (sine wave).

    Returns raw PCM bytes (little-endian signed 16-bit interleaved).
    """
    import math
    num_samples = int(sample_rate * duration_ms / 1000.0)
    amplitude = 16000
    data = bytearray()
    t_offset = frame_no * num_samples
    for i in range(num_samples):
        t = (t_offset + i) / sample_rate
        val = int(amplitude * math.sin(2 * math.pi * frequency * t))
        val = max(-32768, min(32767, val))
        sample = struct.pack('<h', val)
        for _ in range(channels):
            data += sample
    return bytes(data)


# ---------------------------------------------------------------------------
# HID boot-protocol reports
# ---------------------------------------------------------------------------

def kbd_report(modifiers: int = 0, *keycodes: int) -> bytes:
    """Build an 8-byte keyboard boot-protocol HID report."""
    codes = list(keycodes) + [0] * 6
    return bytes([modifiers, 0x00] + codes[:6])

def mouse_report(buttons: int = 0, dx: int = 0, dy: int = 0, wheel: int = 0) -> bytes:
    """Build a 4-byte mouse boot-protocol HID report (signed deltas, clamped to int8)."""
    def clamp8(v: int) -> int:
        return max(-128, min(127, v)) & 0xFF
    return bytes([buttons & 0xFF, clamp8(dx), clamp8(dy), clamp8(wheel)])


# ---------------------------------------------------------------------------
# TCP flow simulation
# ---------------------------------------------------------------------------

@dataclass
class TcpFlow:
    """
    Simulates a TCP connection and emits scapy packets.

    *client* connects to *server* (SYN originator is the client).
    Sequence numbers are tracked per direction.
    """
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    client_mac: str = SENDER_MAC
    server_mac: str = RECEIVER_MAC
    _client_seq: int = field(default=1000, init=False)
    _server_seq: int = field(default=2000, init=False)
    _base_time: float = field(default_factory=time_mod.time, init=False)
    _tick: float = field(default=0.0, init=False)   # seconds since flow start

    def _ts(self) -> float:
        ts = self._base_time + self._tick
        self._tick += 0.001   # 1ms default between packets
        return ts

    def _pkt(
        self,
        src_ip: str, src_port: int, dst_ip: str, dst_port: int,
        src_mac: str, dst_mac: str,
        flags: str, seq: int, ack: int, payload: bytes = b'',
    ):
        p = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port,
                  flags=flags, seq=seq, ack=ack,
                  window=65535)
        )
        if payload:
            p = p / Raw(load=payload)
        p.time = self._ts()
        return p

    # ------------------------------------------------------------------
    # Handshake / teardown
    # ------------------------------------------------------------------

    def handshake(self) -> list:
        """Emit SYN / SYN-ACK / ACK packets."""
        pkts = []
        # SYN
        pkts.append(self._pkt(
            self.client_ip, self.client_port, self.server_ip, self.server_port,
            self.client_mac, self.server_mac,
            'S', self._client_seq, 0,
        ))
        self._client_seq += 1
        # SYN-ACK
        pkts.append(self._pkt(
            self.server_ip, self.server_port, self.client_ip, self.client_port,
            self.server_mac, self.client_mac,
            'SA', self._server_seq, self._client_seq,
        ))
        self._server_seq += 1
        # ACK
        pkts.append(self._pkt(
            self.client_ip, self.client_port, self.server_ip, self.server_port,
            self.client_mac, self.server_mac,
            'A', self._client_seq, self._server_seq,
        ))
        return pkts

    def fin(self) -> list:
        """Emit FIN-ACK / FIN-ACK / ACK teardown."""
        pkts = []
        # Client FIN
        pkts.append(self._pkt(
            self.client_ip, self.client_port, self.server_ip, self.server_port,
            self.client_mac, self.server_mac,
            'FA', self._client_seq, self._server_seq,
        ))
        self._client_seq += 1
        # Server FIN-ACK
        pkts.append(self._pkt(
            self.server_ip, self.server_port, self.client_ip, self.client_port,
            self.server_mac, self.client_mac,
            'FA', self._server_seq, self._client_seq,
        ))
        self._server_seq += 1
        # Client ACK
        pkts.append(self._pkt(
            self.client_ip, self.client_port, self.server_ip, self.server_port,
            self.client_mac, self.server_mac,
            'A', self._client_seq, self._server_seq,
        ))
        return pkts

    # ------------------------------------------------------------------
    # Data packets
    # ------------------------------------------------------------------

    def client_send(self, payload: bytes) -> list:
        """Send *payload* from client to server in one TCP segment."""
        pkts = [self._pkt(
            self.client_ip, self.client_port, self.server_ip, self.server_port,
            self.client_mac, self.server_mac,
            'PA', self._client_seq, self._server_seq, payload,
        )]
        self._client_seq += len(payload)
        return pkts

    def server_send(self, payload: bytes) -> list:
        """Send *payload* from server to client in one TCP segment."""
        pkts = [self._pkt(
            self.server_ip, self.server_port, self.client_ip, self.client_port,
            self.server_mac, self.client_mac,
            'PA', self._server_seq, self._client_seq, payload,
        )]
        self._server_seq += len(payload)
        return pkts

    def client_send_fragmented(self, payload: bytes, fragment_size: int) -> list:
        """Split *payload* into segments of at most *fragment_size* bytes."""
        pkts = []
        offset = 0
        while offset < len(payload):
            chunk = payload[offset:offset + fragment_size]
            pkts.extend(self.client_send(chunk))
            offset += len(chunk)
        return pkts

    def server_send_fragmented(self, payload: bytes, fragment_size: int) -> list:
        pkts = []
        offset = 0
        while offset < len(payload):
            chunk = payload[offset:offset + fragment_size]
            pkts.extend(self.server_send(chunk))
            offset += len(chunk)
        return pkts

    def server_send_fragmented_with_retransmit(
        self, payload: bytes, fragment_sizes: list[int]
    ) -> list:
        """
        Send *payload* in fragments of sizes given by *fragment_sizes* (must
        sum to len(payload)), then retransmit the second fragment as a
        duplicate segment.
        """
        if sum(fragment_sizes) != len(payload):
            raise ValueError("fragment_sizes must sum to len(payload)")
        pkts: list = []
        offset = 0
        saved_segments: list[tuple[int, bytes]] = []  # (seq_at_send, chunk)

        for size in fragment_sizes:
            chunk = payload[offset:offset + size]
            seq_before = self._server_seq
            pkts.extend(self.server_send(chunk))
            saved_segments.append((seq_before, chunk))
            offset += size

        # Re-inject second segment as a retransmission (same seq, same data)
        if len(saved_segments) >= 2:
            retrans_seq, retrans_chunk = saved_segments[1]
            ack_at_retrans = self._client_seq
            p = self._pkt(
                self.server_ip, self.server_port, self.client_ip, self.client_port,
                self.server_mac, self.client_mac,
                'PA', retrans_seq, ack_at_retrans, retrans_chunk,
            )
            pkts.append(p)

        return pkts

    def server_send_ooo(self, payload: bytes, fragment_size: int) -> list:
        """
        Send *payload* split into two segments but in REVERSE order (segment 2
        arrives before segment 1), followed by the correct second ACK.
        """
        half = fragment_size
        seg1 = payload[:half]
        seg2 = payload[half:]

        seq1 = self._server_seq
        self._server_seq += len(seg1)
        seq2 = self._server_seq
        self._server_seq += len(seg2)

        ts1 = self._ts()
        ts2 = self._ts()

        ack = self._client_seq

        # Emit segment 2 first (OOO), then segment 1
        p2 = (
            Ether(src=self.server_mac, dst=self.client_mac)
            / IP(src=self.server_ip, dst=self.client_ip)
            / TCP(sport=self.server_port, dport=self.client_port,
                  flags='PA', seq=seq2, ack=ack, window=65535)
            / Raw(load=seg2)
        )
        p2.time = ts1

        p1 = (
            Ether(src=self.server_mac, dst=self.client_mac)
            / IP(src=self.server_ip, dst=self.client_ip)
            / TCP(sport=self.server_port, dport=self.client_port,
                  flags='PA', seq=seq1, ack=ack, window=65535)
            / Raw(load=seg1)
        )
        p1.time = ts2

        return [p2, p1]

    def advance(self, seconds: float) -> None:
        """Advance the timestamp without emitting any packets."""
        self._tick += seconds


# ---------------------------------------------------------------------------
# Control channel helpers (Receiver connects TO Sender)
# ---------------------------------------------------------------------------

def control_flow(base_time: float, client_port: int = 55000) -> TcpFlow:
    """
    Create a TcpFlow for the Control Channel.
    Receiver (client) connects to Sender (server) on SENDER_CTRL_PORT.
    """
    f = TcpFlow(
        client_ip=RECEIVER_IP, client_port=client_port,
        server_ip=SENDER_IP,   server_port=SENDER_CTRL_PORT,
        client_mac=RECEIVER_MAC, server_mac=SENDER_MAC,
    )
    f._base_time = base_time
    return f


def data_flow(base_time: float, client_port: int = 56000) -> TcpFlow:
    """
    Create a TcpFlow for a Data Channel.
    Sender (client) connects to Receiver (server) on RECEIVER_DATA_PORT.
    """
    f = TcpFlow(
        client_ip=SENDER_IP,   client_port=client_port,
        server_ip=RECEIVER_IP, server_port=RECEIVER_DATA_PORT,
        client_mac=SENDER_MAC, server_mac=RECEIVER_MAC,
    )
    f._base_time = base_time
    return f


def emit_control_handshake(cf: TcpFlow) -> list:
    """Emit the standard SenderConnectionInfo / SenderConnectionStatus exchange."""
    pkts = []
    pkts += cf.handshake()
    # Sender → Receiver: SenderConnectionInfo
    pkts += cf.server_send(usb.build_sender_connection_info(SENDER_CID, SENDER_SN))
    # Receiver → Sender: SenderConnectionStatus
    pkts += cf.client_send(usb.build_sender_connection_status(
        RECEIVER_CID, RECEIVER_SN, HBEAT_INDEX, RECEIVER_DATA_PORT))
    return pkts


def emit_data_handshake(
    df: TcpFlow, substreamid: int, usbspeed: int, busid: str
) -> list:
    """Emit the standard USBStreamInformation / USBStreamStatus exchange."""
    pkts = []
    pkts += df.handshake()
    # Sender → Receiver: USBStreamInformation
    pkts += df.client_send(usb.build_usb_stream_info(substreamid, usbspeed, busid))
    # Receiver → Sender: USBStreamStatus
    pkts += df.server_send(usb.build_usb_stream_status(0))
    return pkts


def emit_full_kbd_enumeration(df: TcpFlow, rtt_s: float = 0.0015) -> tuple[list, int]:
    """
    Emit a complete 14-step USB HID keyboard enumeration matching a real host
    sequence (USB 2.0 §9.1.2, HID 1.11 §4.4):

      1  GET_DESCRIPTOR(Device, 8)   — partial, to learn bMaxPacketSize0
      2  SET_ADDRESS(3)
      3  GET_DESCRIPTOR(Device, 18)  — full device descriptor
      4  GET_DESCRIPTOR(Config, 9)   — partial, to learn wTotalLength
      5  GET_DESCRIPTOR(Config, 34)  — full config+interface+HID+endpoint
      6  GET_DESCRIPTOR(String, 0)   — supported language IDs
      7  GET_DESCRIPTOR(String, 1, lang=0x0409)  — manufacturer
      8  GET_DESCRIPTOR(String, 2, lang=0x0409)  — product
      9  GET_DESCRIPTOR(String, 3, lang=0x0409)  — serial number
     10  SET_CONFIGURATION(1)
     11  GET_DESCRIPTOR(HID, 9)      — HID class descriptor
     12  GET_DESCRIPTOR(HID Report)  — full report descriptor
     13  SET_IDLE(0, 0)              — disable auto-repeat
     14  SET_PROTOCOL(1)             — select boot protocol

    *rtt_s*: simulated one-way network+USB latency between Submit and Return.
    """
    pkts: list = []
    seq = 0

    def ctrl_in(length: int, req: bytes, data: bytes) -> None:
        nonlocal seq
        pkts.extend(df.server_send(usb.build_usb_control_submit(
            seq, endpoint=0, direction=1, binterval=0,
            transferlength=length, usbdevreq=req,
        )))
        df.advance(rtt_s)
        pkts.extend(df.client_send(usb.build_usb_control_submit_return(
            seq, 0, 1, len(data), 0, data,
        )))
        df.advance(rtt_s)
        seq += 1

    def ctrl_out(req: bytes) -> None:
        nonlocal seq
        pkts.extend(df.server_send(usb.build_usb_control_submit(
            seq, endpoint=0, direction=0, binterval=0,
            transferlength=0, usbdevreq=req,
        )))
        df.advance(rtt_s)
        pkts.extend(df.client_send(usb.build_usb_control_submit_return(
            seq, 0, 0, 0, 0, b'',
        )))
        df.advance(rtt_s)
        seq += 1

    # 1. Partial Device Descriptor (8 bytes) — discover bMaxPacketSize0
    ctrl_in(8,  _get_descriptor_req(USB_DT_DEVICE, 0, 8),  KBD_DEVICE_DESCRIPTOR[:8])

    # 2. SET_ADDRESS(3) — host assigns address 3
    ctrl_out(_set_address_req(3))
    df.advance(0.003)   # USB spec §9.2.6.3: 2ms recovery before next request

    # 3. Full Device Descriptor at new address
    ctrl_in(18, _get_descriptor_req(USB_DT_DEVICE, 0, 18), KBD_DEVICE_DESCRIPTOR)

    # 4. Partial Configuration Descriptor (9 bytes) — discover wTotalLength
    ctrl_in(9,  _get_descriptor_req(USB_DT_CONFIG, 0, 9),  KBD_CONFIG_DESCRIPTOR[:9])

    # 5. Full Configuration Descriptor (wTotalLength = 34)
    ctrl_in(len(KBD_CONFIG_DESCRIPTOR),
            _get_descriptor_req(USB_DT_CONFIG, 0, len(KBD_CONFIG_DESCRIPTOR)),
            KBD_CONFIG_DESCRIPTOR)

    # 6. String Descriptor 0 — language IDs
    ctrl_in(255, _get_descriptor_req(USB_DT_STRING, 0, 255), KBD_LANGID_DESCRIPTOR)

    # 7–9. Manufacturer / Product / Serial strings (English US)
    ctrl_in(255, _get_descriptor_req(USB_DT_STRING, 1, 255, 0x0409), KBD_STRING_MANUFACTURER)
    ctrl_in(255, _get_descriptor_req(USB_DT_STRING, 2, 255, 0x0409), KBD_STRING_PRODUCT)
    ctrl_in(255, _get_descriptor_req(USB_DT_STRING, 3, 255, 0x0409), KBD_STRING_SERIAL)

    # 10. SET_CONFIGURATION(1)
    ctrl_out(_set_configuration_req(1))

    # 11. HID Class Descriptor (bytes 18–26 of the config blob)
    ctrl_in(9, _get_descriptor_req(USB_DT_HID, 0, 9), KBD_CONFIG_DESCRIPTOR[18:27])

    # 12. HID Report Descriptor
    ctrl_in(len(KBD_HID_REPORT_DESCRIPTOR),
            _get_descriptor_req(USB_DT_REPORT, 0, len(KBD_HID_REPORT_DESCRIPTOR)),
            KBD_HID_REPORT_DESCRIPTOR)

    # 13. SET_IDLE(0, 0) — disable auto-repeat polling
    ctrl_out(_set_idle_req())

    # 14. SET_PROTOCOL(1) — boot protocol
    ctrl_out(_set_protocol_req(1))

    return pkts, seq


def emit_full_mouse_enumeration(df: TcpFlow, rtt_s: float = 0.0015) -> tuple[list, int]:
    """
    Complete 12-step USB HID mouse enumeration:

      1  GET_DESCRIPTOR(Device, 8)   — partial
      2  SET_ADDRESS(4)
      3  GET_DESCRIPTOR(Device, 18)  — full
      4  GET_DESCRIPTOR(Config, 9)   — partial
      5  GET_DESCRIPTOR(Config, 34)  — full
      6  GET_DESCRIPTOR(String, 0)   — language IDs
      7  GET_DESCRIPTOR(String, 1, lang=0x0409)  — manufacturer
      8  GET_DESCRIPTOR(String, 2, lang=0x0409)  — product
      9  SET_CONFIGURATION(1)
     10  GET_DESCRIPTOR(HID, 9)
     11  GET_DESCRIPTOR(HID Report)
     12  SET_IDLE(0, 0)
    """
    pkts: list = []
    seq = 0

    def ctrl_in(length: int, req: bytes, data: bytes) -> None:
        nonlocal seq
        pkts.extend(df.server_send(usb.build_usb_control_submit(
            seq, endpoint=0, direction=1, binterval=0,
            transferlength=length, usbdevreq=req,
        )))
        df.advance(rtt_s)
        pkts.extend(df.client_send(usb.build_usb_control_submit_return(
            seq, 0, 1, len(data), 0, data,
        )))
        df.advance(rtt_s)
        seq += 1

    def ctrl_out(req: bytes) -> None:
        nonlocal seq
        pkts.extend(df.server_send(usb.build_usb_control_submit(
            seq, endpoint=0, direction=0, binterval=0,
            transferlength=0, usbdevreq=req,
        )))
        df.advance(rtt_s)
        pkts.extend(df.client_send(usb.build_usb_control_submit_return(
            seq, 0, 0, 0, 0, b'',
        )))
        df.advance(rtt_s)
        seq += 1

    ctrl_in(8,  _get_descriptor_req(USB_DT_DEVICE, 0, 8),  MOUSE_DEVICE_DESCRIPTOR[:8])
    ctrl_out(_set_address_req(4))
    df.advance(0.003)
    ctrl_in(18, _get_descriptor_req(USB_DT_DEVICE, 0, 18), MOUSE_DEVICE_DESCRIPTOR)
    ctrl_in(9,  _get_descriptor_req(USB_DT_CONFIG, 0, 9),  MOUSE_CONFIG_DESCRIPTOR[:9])
    ctrl_in(len(MOUSE_CONFIG_DESCRIPTOR),
            _get_descriptor_req(USB_DT_CONFIG, 0, len(MOUSE_CONFIG_DESCRIPTOR)),
            MOUSE_CONFIG_DESCRIPTOR)
    ctrl_in(255, _get_descriptor_req(USB_DT_STRING, 0, 255), MOUSE_LANGID_DESCRIPTOR)
    ctrl_in(255, _get_descriptor_req(USB_DT_STRING, 1, 255, 0x0409), MOUSE_STRING_MANUFACTURER)
    ctrl_in(255, _get_descriptor_req(USB_DT_STRING, 2, 255, 0x0409), MOUSE_STRING_PRODUCT)
    ctrl_out(_set_configuration_req(1))
    ctrl_in(9, _get_descriptor_req(USB_DT_HID, 0, 9), MOUSE_CONFIG_DESCRIPTOR[18:27])
    ctrl_in(len(MOUSE_HID_REPORT_DESCRIPTOR),
            _get_descriptor_req(USB_DT_REPORT, 0, len(MOUSE_HID_REPORT_DESCRIPTOR)),
            MOUSE_HID_REPORT_DESCRIPTOR)
    ctrl_out(_set_idle_req())

    return pkts, seq


def emit_kbd_enumeration(df: TcpFlow) -> tuple[list, int]:
    """
    Emit a full USB HID keyboard enumeration sequence via Control Submit pairs.
    Returns (packets, next_seqnum).
    """
    pkts = []
    seq = 0   # per-channel seqnum, starts at 0 per spec

    def ctrl_submit_return(seqnum: int, direction: int, xfer_data: bytes) -> bytes:
        return usb.build_usb_control_submit_return(
            seqnum, endpoint=0, direction=direction,
            actuallength=len(xfer_data), rstatus=0, transferdata=xfer_data,
        )

    # 1. GET_DESCRIPTOR(Device) — D=1 (IN)
    pkts += df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=1, binterval=0,
        transferlength=18,
        usbdevreq=_get_descriptor_req(USB_DT_DEVICE, 0, 18),
    ))
    pkts += df.client_send(ctrl_submit_return(seq, 1, KBD_DEVICE_DESCRIPTOR))
    seq += 1

    # 2. GET_DESCRIPTOR(Configuration) — D=1 (IN)
    pkts += df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=1, binterval=0,
        transferlength=len(KBD_CONFIG_DESCRIPTOR),
        usbdevreq=_get_descriptor_req(USB_DT_CONFIG, 0, len(KBD_CONFIG_DESCRIPTOR)),
    ))
    pkts += df.client_send(ctrl_submit_return(seq, 1, KBD_CONFIG_DESCRIPTOR))
    seq += 1

    # 3. SET_CONFIGURATION(1) — D=0 (OUT), no return data
    pkts += df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=0, binterval=0,
        transferlength=0,
        usbdevreq=_set_configuration_req(1),
    ))
    pkts += df.client_send(ctrl_submit_return(seq, 0, b''))
    seq += 1

    # 4. GET_DESCRIPTOR(HID Report Descriptor) — D=1 (IN)
    pkts += df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=1, binterval=0,
        transferlength=len(KBD_HID_REPORT_DESCRIPTOR),
        usbdevreq=_get_descriptor_req(USB_DT_REPORT, 0, len(KBD_HID_REPORT_DESCRIPTOR)),
    ))
    pkts += df.client_send(ctrl_submit_return(seq, 1, KBD_HID_REPORT_DESCRIPTOR))
    seq += 1

    # 5. SET_IDLE(0) — D=0 (OUT)
    pkts += df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=0, binterval=0,
        transferlength=0,
        usbdevreq=_set_idle_req(),
    ))
    pkts += df.client_send(ctrl_submit_return(seq, 0, b''))
    seq += 1

    # 6. SET_PROTOCOL(1 = boot protocol) — D=0 (OUT)
    pkts += df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=0, binterval=0,
        transferlength=0,
        usbdevreq=_set_protocol_req(1),
    ))
    pkts += df.client_send(ctrl_submit_return(seq, 0, b''))
    seq += 1

    return pkts, seq


def emit_kbd_interrupt_cycle(
    df: TcpFlow, seqnum: int, report: bytes
) -> tuple[list, int]:
    """
    Emit one USB Interrupt Submit (IN poll) + Submit Return pair.
    Returns (packets, next_seqnum).
    """
    pkts = []
    # Receiver polls (D=1)
    pkts += df.server_send(usb.build_usb_interrupt_submit(
        seqnum, endpoint=KBD_ENDPOINT_IN, direction=1,
        binterval=KBD_BINTERVAL, transferlength=8,
    ))
    # Sender returns the HID report
    pkts += df.client_send(usb.build_usb_interrupt_submit_return(
        seqnum, endpoint=KBD_ENDPOINT_IN, direction=1,
        actuallength=len(report), rstatus=0, transferdata=report,
    ))
    return pkts, seqnum + 1


def emit_mouse_interrupt_cycle(
    df: TcpFlow, seqnum: int, report: bytes
) -> tuple[list, int]:
    pkts = []
    pkts += df.server_send(usb.build_usb_interrupt_submit(
        seqnum, endpoint=MOUSE_ENDPOINT_IN, direction=1,
        binterval=MOUSE_BINTERVAL, transferlength=4,
    ))
    pkts += df.client_send(usb.build_usb_interrupt_submit_return(
        seqnum, endpoint=MOUSE_ENDPOINT_IN, direction=1,
        actuallength=len(report), rstatus=0, transferdata=report,
    ))
    return pkts, seqnum + 1


# ---------------------------------------------------------------------------
# USB HID key code table (USB HID Usage Tables, Keyboard/Keypad page 0x07)
# Each entry: char → (modifier_byte, keycode)
# modifier bit 1 (0x02) = Left Shift
# ---------------------------------------------------------------------------

_CHAR_TO_HID: dict[str, tuple[int, int]] = {
    # Lowercase a–z → keycodes 0x04–0x1D
    **{chr(ord('a') + i): (0x00, 0x04 + i) for i in range(26)},
    # Uppercase A–Z → Left Shift + same keycode
    **{chr(ord('A') + i): (0x02, 0x04 + i) for i in range(26)},
    # Digits
    '1': (0x00, 0x1E), '2': (0x00, 0x1F), '3': (0x00, 0x20),
    '4': (0x00, 0x21), '5': (0x00, 0x22), '6': (0x00, 0x23),
    '7': (0x00, 0x24), '8': (0x00, 0x25), '9': (0x00, 0x26),
    '0': (0x00, 0x27),
    # Control / whitespace
    '\n': (0x00, 0x28), '\r': (0x00, 0x28),
    '\t': (0x00, 0x2B),
    ' ':  (0x00, 0x2C),
    '\b': (0x00, 0x2A),   # Backspace
    # Punctuation — unshifted
    '-':  (0x00, 0x2D), '=':  (0x00, 0x2E),
    '[':  (0x00, 0x2F), ']':  (0x00, 0x30),
    '\\': (0x00, 0x31), ';':  (0x00, 0x33),
    "'":  (0x00, 0x34), '`':  (0x00, 0x35),
    ',':  (0x00, 0x36), '.':  (0x00, 0x37), '/': (0x00, 0x38),
    # Punctuation — shifted
    '!': (0x02, 0x1E), '@': (0x02, 0x1F), '#': (0x02, 0x20),
    '$': (0x02, 0x21), '%': (0x02, 0x22), '^': (0x02, 0x23),
    '&': (0x02, 0x24), '*': (0x02, 0x25), '(': (0x02, 0x26),
    ')': (0x02, 0x27), '_': (0x02, 0x2D), '+': (0x02, 0x2E),
    '{': (0x02, 0x2F), '}': (0x02, 0x30), '|': (0x02, 0x31),
    ':': (0x02, 0x33), '"': (0x02, 0x34), '~': (0x02, 0x35),
    '<': (0x02, 0x36), '>': (0x02, 0x37), '?': (0x02, 0x38),
}


def type_text(
    df: TcpFlow,
    seq: int,
    text: str,
    key_hold_ms: float = 80.0,
    inter_key_ms: float = 120.0,
    poll_ms: float = 8.0,
    endpoint: int = KBD_ENDPOINT_IN,
    binterval: int = KBD_BINTERVAL,
) -> tuple[list, int]:
    """
    Simulate typing *text* as USB HID Interrupt Submit/Return pairs.

    Human timing model (defaults approximate 60 WPM):
      - Key held for *key_hold_ms* (≈10 polls at 8ms = 80ms)
      - Key-up followed by *inter_key_ms* idle gap before next character
      - Unmapped characters (e.g. emoji) are silently skipped

    Returns (packets, next_seqnum).
    """
    pkts: list = []
    hold_polls  = max(1, round(key_hold_ms  / poll_ms))
    idle_polls  = max(1, round(inter_key_ms / poll_ms))

    for ch in text:
        if ch not in _CHAR_TO_HID:
            continue
        modifier, keycode = _CHAR_TO_HID[ch]

        # Key held down
        for _ in range(hold_polls):
            p, seq = emit_kbd_interrupt_cycle(
                df, seq, kbd_report(modifier, keycode),
            )
            pkts += p
            df.advance(poll_ms / 1000)

        # Key released (one idle report)
        p, seq = emit_kbd_interrupt_cycle(df, seq, kbd_report())
        pkts += p
        df.advance(poll_ms / 1000)

        # Idle gap between keystrokes
        for _ in range(idle_polls):
            p, seq = emit_kbd_interrupt_cycle(df, seq, kbd_report())
            pkts += p
            df.advance(poll_ms / 1000)

    return pkts, seq


# ---------------------------------------------------------------------------
# Mouse input helpers
# ---------------------------------------------------------------------------

def _cubic_bezier(
    p0: tuple[float, float],
    p1: tuple[float, float],
    p2: tuple[float, float],
    p3: tuple[float, float],
    t: float,
) -> tuple[float, float]:
    """Evaluate a cubic Bezier curve at parameter *t* ∈ [0, 1]."""
    u = 1.0 - t
    x = u**3*p0[0] + 3*u**2*t*p1[0] + 3*u*t**2*p2[0] + t**3*p3[0]
    y = u**3*p0[1] + 3*u**2*t*p1[1] + 3*u*t**2*p2[1] + t**3*p3[1]
    return x, y


def mouse_bezier_move(
    df: TcpFlow,
    seq: int,
    x0: float, y0: float,
    x1: float, y1: float,
    duration_ms: float = 300.0,
    poll_ms: float = 8.0,
    buttons: int = 0,
) -> tuple[list, int]:
    """
    Move mouse from (x0, y0) to (x1, y1) along a cubic Bezier curve,
    emitting one Interrupt Submit/Return pair per *poll_ms* interval.

    The control points are offset perpendicular to the straight-line path
    (15% of length) to produce a natural slightly-curved trajectory.

    *buttons* can be set to 1 (left), 2 (right), 4 (middle) for drag.

    Returns (packets, next_seqnum).
    """
    n = max(2, round(duration_ms / poll_ms))
    dx, dy = x1 - x0, y1 - y0

    # Perpendicular offset for natural arc
    perp_x, perp_y = -dy * 0.15, dx * 0.15
    p0 = (x0, y0)
    p1 = (x0 + dx * 0.3 + perp_x, y0 + dy * 0.3 + perp_y)
    p2 = (x0 + dx * 0.7 + perp_x, y0 + dy * 0.7 + perp_y)
    p3 = (x1, y1)

    pkts: list = []
    prev = p0
    for i in range(1, n + 1):
        curr = _cubic_bezier(p0, p1, p2, p3, i / n)
        rel_x = round(curr[0] - prev[0])
        rel_y = round(curr[1] - prev[1])
        p, seq = emit_mouse_interrupt_cycle(
            df, seq, mouse_report(buttons, rel_x, rel_y)
        )
        pkts += p
        df.advance(poll_ms / 1000)
        prev = curr

    return pkts, seq


def mouse_click(
    df: TcpFlow,
    seq: int,
    button: int = 1,
    hold_ms: float = 60.0,
    poll_ms: float = 8.0,
) -> tuple[list, int]:
    """
    Simulate a mouse button click: button held for *hold_ms*, then released.
    button: 1 = left, 2 = right, 4 = middle.
    Returns (packets, next_seqnum).
    """
    pkts: list = []
    hold_polls = max(1, round(hold_ms / poll_ms))

    for _ in range(hold_polls):
        p, seq = emit_mouse_interrupt_cycle(df, seq, mouse_report(button, 0, 0))
        pkts += p
        df.advance(poll_ms / 1000)

    # Button release
    p, seq = emit_mouse_interrupt_cycle(df, seq, mouse_report(0, 0, 0))
    pkts += p
    df.advance(poll_ms / 1000)

    return pkts, seq


def mouse_scroll(
    df: TcpFlow,
    seq: int,
    ticks: int,
    poll_ms: float = 8.0,
) -> tuple[list, int]:
    """
    Simulate mouse wheel scrolling.
    *ticks* > 0 = scroll up, < 0 = scroll down.
    Each tick is one HID report with wheel=-1 or +1.
    Returns (packets, next_seqnum).
    """
    pkts: list = []
    direction = 1 if ticks > 0 else -1
    for _ in range(abs(ticks)):
        p, seq = emit_mouse_interrupt_cycle(
            df, seq, mouse_report(0, 0, 0, direction)
        )
        pkts += p
        df.advance(poll_ms / 1000)
    return pkts, seq


# ---------------------------------------------------------------------------
# Encryption helper
# ---------------------------------------------------------------------------

# Default 128-bit all-zeros PSK used when --psk is not provided.
# Not secure — deterministic so PCAPs are reproducible.
_DEFAULT_PSK = b"\x00" * 16

# Deterministic PEP parameters for encrypted scenarios.
_PEP_IV          = 0x181d3f3236be89b0
_PEP_KEY_GEN     = bytes.fromhex("836b4d6eb7cbd16055c6c827237faf97")
_PEP_KEY_VERSION = bytes.fromhex("00000001")
_PEP_KEY_ID      = bytes.fromhex("0001020304050607")

# Module-level PEP state: always initialised (default or explicit PSK).
_pep_params: Optional[pep.PepParams] = None
_pep_key: Optional[bytes] = None


def _init_pep(psk_hex: Optional[str], psk_file: Optional[str]) -> None:
    """Initialise the module-level PEP state.

    Uses the explicitly provided PSK when available, otherwise falls
    back to the default all-zeros PSK so that encrypted scenarios always
    use real AES-CTR + CMAC-64-AAD per TR-10-14.
    """
    global _pep_params, _pep_key
    if psk_hex:
        psk = bytes.fromhex(psk_hex)
    elif psk_file:
        with open(psk_file, "rb") as f:
            psk = f.read()
    else:
        psk = _DEFAULT_PSK
    _pep_params = pep.PepParams(
        protocol=pep.PepProtocol.USB_KV,
        mode=pep.PepMode.AES_128_CTR_CMAC_64_AAD,
        iv=_PEP_IV,
        key_generator=_PEP_KEY_GEN,
        key_version=_PEP_KEY_VERSION,
        key_id=_PEP_KEY_ID,
        psk=psk,
    )
    _pep_key = _pep_params.derive_key()


def encrypt_message(raw: bytes, ctr: int, key_version: int = 1,
                    iv_prime: int = 0) -> bytes:
    """Encrypt one raw IPMX USB message using AES-CTR + CMAC-64-AAD."""
    if len(raw) < usb.HEADER_SIZE + usb.MAC_SIZE:
        return raw

    out = bytearray(raw)
    struct.pack_into('>Q', out, 0, ctr)
    struct.pack_into('>I', out, 8, key_version)

    assert _pep_key is not None and _pep_params is not None
    return pep.encrypt_usb_message(bytes(out), _pep_key, iv_prime, _pep_params.mode)


class EncryptingFlow:
    """
    Thin wrapper around a :class:`TcpFlow` that automatically encrypts
    every IPMX message before sending, maintaining a per-direction CTR.

    Uses real AES-CTR + CMAC-64-AAD per TR-10-14 Section 12.
    *substreamid* determines the ``iv'`` for each direction
    (even = S2R, odd = R2S).
    """

    def __init__(self, flow: TcpFlow, key_version: int = 1,
                 substreamid: int = 0):
        self._flow        = flow
        self._key_version = key_version
        self._ctr_s2r     = 0
        self._ctr_r2s     = 0
        self._client_send = flow.client_send
        self._server_send = flow.server_send

        assert _pep_params is not None
        self._iv_s2r = pep.compute_iv_prime(_pep_params.iv, substreamid)
        self._iv_r2s = pep.compute_iv_prime(_pep_params.iv, substreamid | 1)

    def _enc(self, raw: bytes, ctr: int, iv_prime: int) -> bytes:
        return encrypt_message(raw, ctr, self._key_version, iv_prime)

    def sender_send(self, msg: bytes, *, corrupt: bool = False) -> list:
        """Sender -> Receiver: encrypt then send.

        When *corrupt* is True the ciphertext is deliberately damaged
        (one byte flipped) so the receiver's CMAC verification will fail.
        """
        enc = self._enc(msg, self._ctr_s2r, self._iv_s2r)
        if corrupt:
            ba = bytearray(enc)
            ba[-1] ^= 0xFF
            enc = bytes(ba)
        pkts = self._client_send(enc)
        self._ctr_s2r += pep.usb_ctr_advance(len(enc))
        return pkts

    def receiver_send(self, msg: bytes) -> list:
        """Receiver -> Sender: encrypt then send."""
        enc = self._enc(msg, self._ctr_r2s, self._iv_r2s)
        pkts = self._server_send(enc)
        self._ctr_r2s += pep.usb_ctr_advance(len(enc))
        return pkts

    def switch_substreamid(self, new_ssid: int) -> None:
        """Switch from handshake SSID to payload SSID (preserves CTR)."""
        assert _pep_params is not None
        self._iv_s2r = pep.compute_iv_prime(_pep_params.iv, new_ssid)
        self._iv_r2s = pep.compute_iv_prime(_pep_params.iv, new_ssid | 1)

    def advance(self, seconds: float) -> None:
        self._flow.advance(seconds)

    def fin(self) -> list:
        return self._flow.fin()


# ---------------------------------------------------------------------------
# PCAP writer helper
# ---------------------------------------------------------------------------

def write_pcap(path: Path, packets: list) -> None:
    with PcapWriter(str(path), sync=True) as writer:
        for pkt in packets:
            writer.write(pkt)
    print(f"  Wrote {len(packets)} packets → {path}")


# ---------------------------------------------------------------------------
# Scenario generators
# ---------------------------------------------------------------------------

BASE_TIME = 1_700_000_000.0   # fixed epoch for reproducibility


def scenario_01(output_dir: Path) -> None:
    """Control channel only: SenderConnectionInfo → SenderConnectionStatus → heartbeats."""
    pkts: list = []
    cf = control_flow(BASE_TIME)
    pkts += emit_control_handshake(cf)

    # 3 heartbeats at simulated 47s intervals
    for _ in range(3):
        cf.advance(47.0)
        pkts += cf.server_send(usb.build_heartbeat())

    pkts += cf.fin()
    write_pcap(output_dir / "scenario_01_basic_control_channel.pcap", pkts)


def scenario_02(output_dir: Path) -> None:
    """Control + keyboard data channel: full enumeration + keystrokes."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t)
    pkts += emit_control_handshake(cf)

    # Data channel: Sender connects to Receiver
    df = data_flow(t + 0.1)
    pkts += emit_data_handshake(df, KBD_SUBSTREAMID, KBD_USBSPEED, KBD_BUSID)

    enum_pkts, seq = emit_kbd_enumeration(df)
    pkts += enum_pkts

    # Key "A" press (keycode 0x04), then release
    p, seq = emit_kbd_interrupt_cycle(df, seq, kbd_report(0, 0x04))
    pkts += p
    p, seq = emit_kbd_interrupt_cycle(df, seq, kbd_report())
    pkts += p

    # Key "B" press (0x05), then release
    p, seq = emit_kbd_interrupt_cycle(df, seq, kbd_report(0, 0x05))
    pkts += p
    p, seq = emit_kbd_interrupt_cycle(df, seq, kbd_report())
    pkts += p

    # Idle poll (no key pressed)
    p, seq = emit_kbd_interrupt_cycle(df, seq, kbd_report())
    pkts += p

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_02_keyboard_enumeration.pcap", pkts)


def scenario_03(output_dir: Path) -> None:
    """Fragmented enumeration: GET_DESCRIPTOR(Config) return split into 3 segments + retransmit."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.1)
    pkts += emit_data_handshake(df, KBD_SUBSTREAMID, KBD_USBSPEED, KBD_BUSID)

    seq = 0

    # GET_DESCRIPTOR(Device) — normal, single segment
    pkts += df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=1, binterval=0, transferlength=18,
        usbdevreq=_get_descriptor_req(USB_DT_DEVICE, 0, 18),
    ))
    reply = usb.build_usb_control_submit_return(seq, 0, 1, 18, 0, KBD_DEVICE_DESCRIPTOR)
    pkts += df.client_send(reply)
    seq += 1

    # GET_DESCRIPTOR(Config) — return fragmented into 3 segments + retransmit of segment 2
    submit = usb.build_usb_control_submit(
        seq, endpoint=0, direction=1, binterval=0,
        transferlength=len(KBD_CONFIG_DESCRIPTOR),
        usbdevreq=_get_descriptor_req(USB_DT_CONFIG, 0, len(KBD_CONFIG_DESCRIPTOR)),
    )
    pkts += df.server_send(submit)

    reply = usb.build_usb_control_submit_return(seq, 0, 1, len(KBD_CONFIG_DESCRIPTOR), 0, KBD_CONFIG_DESCRIPTOR)
    total = len(reply)
    # Fragment sizes: approx thirds of total, with retransmit of middle piece
    s1 = total // 3
    s2 = total // 3
    s3 = total - s1 - s2
    pkts += df.client_send_fragmented_with_retransmit(reply, [s1, s2, s3] if hasattr(df, 'client_send_fragmented_with_retransmit') else [s1, s2, s3])
    seq += 1

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_03_fragmented_enumeration.pcap", pkts)


def scenario_04(output_dir: Path) -> None:
    """Out-of-order: Interrupt Submit Return split into 2 segments delivered reversed."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.1)
    pkts += emit_data_handshake(df, KBD_SUBSTREAMID, KBD_USBSPEED, KBD_BUSID)

    enum_pkts, seq = emit_kbd_enumeration(df)
    pkts += enum_pkts

    # Normal poll
    p, seq = emit_kbd_interrupt_cycle(df, seq, kbd_report())
    pkts += p

    # OOO delivery: interrupt return (A key press) split across 2 segments, segment 2 arrives first
    pkts += df.server_send(usb.build_usb_interrupt_submit(
        seq, endpoint=KBD_ENDPOINT_IN, direction=1,
        binterval=KBD_BINTERVAL, transferlength=8,
    ))
    reply = usb.build_usb_interrupt_submit_return(
        seq, KBD_ENDPOINT_IN, 1, 8, 0, kbd_report(0, 0x04)
    )
    # Split at byte boundary and emit reversed
    mid = len(reply) // 2
    pkts += df.client_send_ooo(reply, mid)
    seq += 1

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_04_ooo_interrupt.pcap", pkts)


def scenario_05(output_dir: Path) -> None:
    """Reconnect: clean TCP FIN + new connection with same CID/SN."""
    pkts: list = []
    t = BASE_TIME

    # First connection
    cf1 = control_flow(t, client_port=55000)
    pkts += emit_control_handshake(cf1)
    df1 = data_flow(t + 0.1, client_port=56000)
    pkts += emit_data_handshake(df1, KBD_SUBSTREAMID, KBD_USBSPEED, KBD_BUSID)
    enum_pkts, seq = emit_kbd_enumeration(df1)
    pkts += enum_pkts
    p, seq = emit_kbd_interrupt_cycle(df1, seq, kbd_report(0, 0x04))
    pkts += p
    pkts += df1.fin()
    pkts += cf1.fin()

    # Second connection — new ephemeral ports, same Sender CID/SN
    t2 = t + 2.0
    cf2 = control_flow(t2, client_port=55001)
    pkts += emit_control_handshake(cf2)
    df2 = data_flow(t2 + 0.1, client_port=56001)
    pkts += emit_data_handshake(df2, KBD_SUBSTREAMID, KBD_USBSPEED, KBD_BUSID)
    # Only a few Interrupt polls after re-enumeration
    seq2 = 0
    p, seq2 = emit_kbd_interrupt_cycle(df2, seq2, kbd_report())
    pkts += p
    pkts += df2.fin()
    pkts += cf2.fin()

    write_pcap(output_dir / "scenario_05_reconnect.pcap", pkts)


def scenario_06(output_dir: Path) -> None:
    """Encrypted headers: non-zero CTR/KEYVERSION but MAC/DATA still zero → violation expected."""
    pkts: list = []
    t = BASE_TIME
    cf = control_flow(t)
    pkts += cf.handshake()

    ctr = 1
    # SenderConnectionInfo with non-zero CTR (violation: CTR SHALL be 0 when unencrypted)
    raw_sci = usb.build_sender_connection_info(SENDER_CID, SENDER_SN)
    # Patch CTR field (bytes 0–7) with non-zero value
    raw_sci_bad = struct.pack('>Q', ctr) + raw_sci[8:]
    pkts += cf.server_send(raw_sci_bad)
    ctr += 1

    # SenderConnectionStatus with non-zero CTR and KEYVERSION
    raw_scs = usb.build_sender_connection_status(
        RECEIVER_CID, RECEIVER_SN, HBEAT_INDEX, RECEIVER_DATA_PORT)
    raw_scs_bad = struct.pack('>Q', ctr) + struct.pack('>I', 1) + raw_scs[12:]
    pkts += cf.client_send(raw_scs_bad)
    ctr += 1

    for _ in range(2):
        cf.advance(47.0)
        raw_hb = usb.build_heartbeat()
        raw_hb_bad = struct.pack('>Q', ctr) + raw_hb[8:]
        pkts += cf.server_send(raw_hb_bad)
        ctr += 1

    pkts += cf.fin()
    write_pcap(output_dir / "scenario_06_encrypted_headers.pcap", pkts)


def scenario_07(output_dir: Path) -> None:
    """Two data channels: keyboard + mouse, interleaved traffic."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t)
    pkts += emit_control_handshake(cf)

    # Keyboard data channel
    df_kbd = data_flow(t + 0.1, client_port=56000)
    pkts += emit_data_handshake(df_kbd, KBD_SUBSTREAMID, KBD_USBSPEED, KBD_BUSID)
    kbd_enum, kbd_seq = emit_kbd_enumeration(df_kbd)
    pkts += kbd_enum

    # Mouse data channel
    df_mouse = data_flow(t + 0.2, client_port=56001)
    pkts += emit_data_handshake(df_mouse, MOUSE_SUBSTREAMID, MOUSE_USBSPEED, MOUSE_BUSID)
    # Mouse only needs GET_DESCRIPTOR(Device) + GET_DESCRIPTOR(Config) + SET_CONFIGURATION
    mouse_seq = 0
    pkts += df_mouse.server_send(usb.build_usb_control_submit(
        mouse_seq, endpoint=0, direction=1, binterval=0, transferlength=18,
        usbdevreq=_get_descriptor_req(USB_DT_DEVICE, 0, 18),
    ))
    pkts += df_mouse.client_send(usb.build_usb_control_submit_return(
        mouse_seq, 0, 1, 18, 0, MOUSE_DEVICE_DESCRIPTOR))
    mouse_seq += 1

    pkts += df_mouse.server_send(usb.build_usb_control_submit(
        mouse_seq, endpoint=0, direction=1, binterval=0,
        transferlength=len(MOUSE_CONFIG_DESCRIPTOR),
        usbdevreq=_get_descriptor_req(USB_DT_CONFIG, 0, len(MOUSE_CONFIG_DESCRIPTOR)),
    ))
    pkts += df_mouse.client_send(usb.build_usb_control_submit_return(
        mouse_seq, 0, 1, len(MOUSE_CONFIG_DESCRIPTOR), 0, MOUSE_CONFIG_DESCRIPTOR))
    mouse_seq += 1

    pkts += df_mouse.server_send(usb.build_usb_control_submit(
        mouse_seq, endpoint=0, direction=0, binterval=0, transferlength=0,
        usbdevreq=_set_configuration_req(1),
    ))
    pkts += df_mouse.client_send(usb.build_usb_control_submit_return(mouse_seq, 0, 0, 0, 0))
    mouse_seq += 1

    # Interleaved: 5 mouse movements + 3 keyboard idle polls
    mouse_moves = [
        mouse_report(0,  10,   0, 0),
        mouse_report(0,  10,   0, 0),
        mouse_report(0,  10,   0, 0),
        mouse_report(0,   0,  10, 0),
        mouse_report(0,   0,  10, 0),
    ]
    for i, mv in enumerate(mouse_moves):
        p, mouse_seq = emit_mouse_interrupt_cycle(df_mouse, mouse_seq, mv)
        pkts += p
        if i % 2 == 0:
            p, kbd_seq = emit_kbd_interrupt_cycle(df_kbd, kbd_seq, kbd_report())
            pkts += p

    pkts += df_mouse.fin()
    pkts += df_kbd.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_07_keyboard_and_mouse.pcap", pkts)


def scenario_08(output_dir: Path) -> None:
    """USB Cancel Submit + Cancel Submit Return with CANCELED status."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.1)
    pkts += emit_data_handshake(df, KBD_SUBSTREAMID, KBD_USBSPEED, KBD_BUSID)

    enum_pkts, seq = emit_kbd_enumeration(df)
    pkts += enum_pkts

    # Send a Bulk Submit (simulating an IN bulk poll)
    bulk_seq = seq
    pkts += df.server_send(usb.build_usb_bulk_submit(
        bulk_seq, endpoint=2, direction=1,
        binterval=0, transferlength=64,
    ))

    # Receiver immediately cancels it (before return arrives)
    pkts += df.server_send(usb.build_usb_cancel_submit(bulk_seq, endpoint=2, direction=1))

    # Sender returns the cancellation
    pkts += df.client_send(usb.build_usb_cancel_submit_return(
        bulk_seq, endpoint=2, direction=1,
        rstatus=usb.StatusCode.CANCELED,
    ))

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_08_cancel_submit.pcap", pkts)


def scenario_09(output_dir: Path) -> None:
    """USB Wake-up Control → USB Enter Sleep sequence."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t)
    pkts += emit_control_handshake(cf)

    # Receiver enables WoL with 6-byte magic packet password
    passwd = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    pkts += cf.client_send(usb.build_usb_wakeup_control(wakectrl=1, passwd=passwd))

    cf.advance(5.0)

    # Sender sends USB Enter Sleep (all USB ports went to sleep)
    pkts += cf.server_send(usb.build_usb_enter_sleep())

    # Per spec: Sender closes connections after Enter Sleep when WoL is enabled
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_09_wol.pcap", pkts)


def scenario_10(output_dir: Path) -> None:
    """Vendor Specific: known query (VQTYPE=0) → OK; unknown query (VQTYPE=0x42) → VQSTS=255."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t)
    pkts += emit_control_handshake(cf)

    # Sender sends a Vendor Specific Information string
    pkts += cf.server_send(usb.build_vendor_specific_info(
        SENDER_CID, vmtype=0,
        vmdata="Matrox USB Gateway v1.0".encode('utf-8'),
    ))

    # Sender asks for known query (VQTYPE=0)
    pkts += cf.server_send(usb.build_vendor_specific_query(SENDER_CID, vqtype=0))
    # Receiver responds OK with a string
    pkts += cf.client_send(usb.build_vendor_specific_query_return(
        SENDER_CID, vqtype=0, vqsts=0,
        vqdata="Matrox USB Receiver v1.0".encode('utf-8'),
    ))

    # Sender asks for unknown query (VQTYPE=0x42)
    pkts += cf.server_send(usb.build_vendor_specific_query(SENDER_CID, vqtype=0x42))
    # Receiver SHALL return VQSTS=255 with M=0 (no data)
    pkts += cf.client_send(usb.build_vendor_specific_query_return(
        SENDER_CID, vqtype=0x42, vqsts=255, vqdata=b'',
    ))

    pkts += cf.fin()
    write_pcap(output_dir / "scenario_10_vendor_specific.pcap", pkts)


# ---------------------------------------------------------------------------
# TcpFlow patch: add client_send_fragmented_with_retransmit
# ---------------------------------------------------------------------------

def _client_send_fragmented_with_retransmit(
    self: TcpFlow, payload: bytes, fragment_sizes: list[int]
) -> list:
    if sum(fragment_sizes) != len(payload):
        raise ValueError("fragment_sizes must sum to len(payload)")
    pkts: list = []
    offset = 0
    saved: list[tuple[int, bytes]] = []
    for size in fragment_sizes:
        chunk = payload[offset:offset + size]
        seq_before = self._client_seq
        pkts.extend(self.client_send(chunk))
        saved.append((seq_before, chunk))
        offset += size
    if len(saved) >= 2:
        retrans_seq, retrans_chunk = saved[1]
        ack_at = self._server_seq
        p = self._pkt(
            self.client_ip, self.client_port, self.server_ip, self.server_port,
            self.client_mac, self.server_mac,
            'PA', retrans_seq, ack_at, retrans_chunk,
        )
        pkts.append(p)
    return pkts


def _client_send_ooo(self: TcpFlow, payload: bytes, fragment_size: int) -> list:
    half = fragment_size
    seg1 = payload[:half]
    seg2 = payload[half:]
    seq1 = self._client_seq
    self._client_seq += len(seg1)
    seq2 = self._client_seq
    self._client_seq += len(seg2)
    ts1 = self._ts()
    ts2 = self._ts()
    ack = self._server_seq
    p2 = (Ether(src=self.client_mac, dst=self.server_mac)
          / IP(src=self.client_ip, dst=self.server_ip)
          / TCP(sport=self.client_port, dport=self.server_port,
                flags='PA', seq=seq2, ack=ack, window=65535)
          / Raw(load=seg2))
    p2.time = ts1
    p1 = (Ether(src=self.client_mac, dst=self.server_mac)
          / IP(src=self.client_ip, dst=self.server_ip)
          / TCP(sport=self.client_port, dport=self.server_port,
                flags='PA', seq=seq1, ack=ack, window=65535)
          / Raw(load=seg1))
    p1.time = ts2
    return [p2, p1]


# Monkey-patch TcpFlow with the methods needed by scenario_03 / scenario_04
TcpFlow.client_send_fragmented_with_retransmit = _client_send_fragmented_with_retransmit
TcpFlow.client_send_ooo = _client_send_ooo


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def scenario_11(output_dir: Path) -> None:
    """
    SHOULD / reserved-field violations:
      - VendorSpecificInfo VMTYPE=2 (reserved 1-15 SHALL NOT be used)
      - USBStreamInfo SUBSTREAMID=0x00 (channel bits 7:1=0 reserved for control)
      - USB Enter Sleep + WoL enabled, then reconnect without WoL (SHOULD NOT)
      - USBStreamStatus CSTATUS=1 (reserved value)
    """
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t)
    pkts += cf.handshake()
    pkts += cf.server_send(usb.build_sender_connection_info(SENDER_CID, SENDER_SN))
    pkts += cf.client_send(usb.build_sender_connection_status(
        RECEIVER_CID, RECEIVER_SN, HBEAT_INDEX, RECEIVER_DATA_PORT))

    # Violation: VMTYPE=2 is reserved (1-15)
    pkts += cf.server_send(usb.build_vendor_specific_info(SENDER_CID, vmtype=2, vmdata=b'\xDE\xAD'))

    # WoL enabled
    pkts += cf.client_send(usb.build_usb_wakeup_control(wakectrl=1, passwd=bytes(6)))

    # Enter Sleep — Sender should close, but instead keeps sending (violation)
    pkts += cf.server_send(usb.build_usb_enter_sleep())
    cf.advance(0.5)
    pkts += cf.server_send(usb.build_heartbeat())   # SHALL NOT send after Enter Sleep + WoL

    pkts += cf.fin()

    # Second connection shortly after — SHOULD NOT reconnect before WoL (SHOULD violation)
    t2 = t + 1.0
    cf2 = control_flow(t2, client_port=55001)
    pkts += cf2.handshake()
    pkts += cf2.server_send(usb.build_sender_connection_info(SENDER_CID, SENDER_SN))
    pkts += cf2.client_send(usb.build_sender_connection_status(
        RECEIVER_CID, RECEIVER_SN, HBEAT_INDEX, RECEIVER_DATA_PORT))
    pkts += cf2.fin()

    # Data channel with SUBSTREAMID=0x00 (reserved) and CSTATUS=1 (reserved)
    df = data_flow(t + 0.1, client_port=56000)
    pkts += df.handshake()
    pkts += df.client_send(usb.build_usb_stream_info(0x00, KBD_USBSPEED, KBD_BUSID))
    pkts += df.server_send(usb.build_usb_stream_status(cstatus=1))   # reserved CSTATUS
    pkts += df.fin()

    write_pcap(output_dir / "scenario_11_should_violations.pcap", pkts)


def scenario_12(output_dir: Path) -> None:
    """
    Realistic keyboard typing session using the full 14-step enumeration and
    human-paced key events.

    The user types "Hello, World!\n" at ≈60 WPM on a Microsoft Natural
    Keyboard 4000.  After typing, three idle polls simulate the device
    sitting quietly before the session ends.

    Key timing model:
      - 80 ms key hold  (≈ 10 × 8 ms polls while finger is down)
      - 120 ms idle gap (≈ 15 × 8 ms polls between characters)
    """
    pkts: list = []
    t = BASE_TIME

    # Control channel
    cf = control_flow(t)
    pkts += emit_control_handshake(cf)

    # Keyboard data channel — Sender connects to Receiver
    df = data_flow(t + 0.05)
    pkts += emit_data_handshake(df, KBD_SUBSTREAMID, KBD_USBSPEED, KBD_BUSID)

    # Full 14-step enumeration with realistic RTT
    enum_pkts, seq = emit_full_kbd_enumeration(df, rtt_s=0.0015)
    pkts += enum_pkts

    # Human typing: "Hello, World!\n"
    type_pkts, seq = type_text(
        df, seq, "Hello, World!\n",
        key_hold_ms=80.0, inter_key_ms=120.0, poll_ms=8.0,
    )
    pkts += type_pkts

    # Three idle polls — device quiet after typing
    for _ in range(3):
        p, seq = emit_kbd_interrupt_cycle(df, seq, kbd_report())
        pkts += p
        df.advance(0.008)

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_12_realistic_typing.pcap", pkts)


def scenario_13(output_dir: Path) -> None:
    """
    Realistic mouse session using the full 12-step enumeration, Bezier
    movement, left-click, drag, right-click, and scroll-wheel.

    Sequence (screen coords, origin top-left):
      1. Enumerate Logitech mouse (12 control steps)
      2. Move (100, 200) → (400, 300) in 300 ms — natural arc
      3. Left-click (60 ms hold)
      4. Drag (400, 300) → (600, 300) in 200 ms with button 1 held
      5. Release drag, move to (600, 400) in 100 ms
      6. Right-click (80 ms hold) — context menu
      7. Scroll wheel up 5 ticks
      8. Move back to (100, 200) in 400 ms
    """
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56001)
    pkts += emit_data_handshake(df, MOUSE_SUBSTREAMID, MOUSE_USBSPEED, MOUSE_BUSID)

    # Full 12-step mouse enumeration
    enum_pkts, seq = emit_full_mouse_enumeration(df, rtt_s=0.0015)
    pkts += enum_pkts

    # 1. Move to first target
    p, seq = mouse_bezier_move(df, seq, 100, 200, 400, 300, duration_ms=300)
    pkts += p

    # 2. Left-click
    p, seq = mouse_click(df, seq, button=1, hold_ms=60)
    pkts += p

    # Small pause before drag
    for _ in range(5):
        p, seq = emit_mouse_interrupt_cycle(df, seq, mouse_report(0, 0, 0))
        pkts += p
        df.advance(0.008)

    # 3. Drag right 200 px with left button held
    p, seq = mouse_bezier_move(df, seq, 400, 300, 600, 300,
                                duration_ms=200, buttons=1)
    pkts += p

    # 4. Release button, then move down
    p, seq = emit_mouse_interrupt_cycle(df, seq, mouse_report(0, 0, 0))
    pkts += p
    df.advance(0.008)

    p, seq = mouse_bezier_move(df, seq, 600, 300, 600, 400, duration_ms=100)
    pkts += p

    # 5. Right-click
    p, seq = mouse_click(df, seq, button=2, hold_ms=80)
    pkts += p

    # 6. Scroll wheel up 5 ticks
    p, seq = mouse_scroll(df, seq, ticks=5)
    pkts += p

    # 7. Move back to origin
    p, seq = mouse_bezier_move(df, seq, 600, 400, 100, 200, duration_ms=400)
    pkts += p

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_13_realistic_mouse.pcap", pkts)


def scenario_14(output_dir: Path) -> None:
    """
    Fully encrypted keyboard session using AES-CTR + CMAC-64-AAD per
    TR-10-14 Section 12.  Uses the supplied ``--psk`` or a default
    all-zeros 128-bit PSK when none is given.
    """
    pkts: list = []
    t = BASE_TIME

    kv_int = int.from_bytes(_PEP_KEY_VERSION, "big")

    # -----------------------------------------------------------------------
    # Control channel (substreamid=0)
    # -----------------------------------------------------------------------
    cf = control_flow(t, client_port=55014)
    ef_ctrl = EncryptingFlow(cf, key_version=kv_int, substreamid=0)
    pkts += cf.handshake()
    pkts += ef_ctrl.sender_send(usb.build_sender_connection_info(SENDER_CID, SENDER_SN))
    pkts += ef_ctrl.receiver_send(usb.build_sender_connection_status(
        RECEIVER_CID, RECEIVER_SN, HBEAT_INDEX, RECEIVER_DATA_PORT))

    # -----------------------------------------------------------------------
    # Data channel (substreamid=KBD_SUBSTREAMID)
    # -----------------------------------------------------------------------
    df = data_flow(t + 0.05, client_port=56014)
    ef_data = EncryptingFlow(df, key_version=kv_int, substreamid=2)
    pkts += df.handshake()
    pkts += ef_data.sender_send(usb.build_usb_stream_info(KBD_SUBSTREAMID, KBD_USBSPEED, KBD_BUSID))
    pkts += ef_data.receiver_send(usb.build_usb_stream_status(0))
    ef_data.switch_substreamid(KBD_SUBSTREAMID)

    # -----------------------------------------------------------------------
    # USB enumeration + typing — monkeypatch the TcpFlow so helpers
    # transparently encrypt via the EncryptingFlow.
    # -----------------------------------------------------------------------
    _orig_client_send = df.client_send
    _orig_server_send = df.server_send
    df.client_send = lambda data: ef_data.sender_send(data)
    df.server_send = lambda data: ef_data.receiver_send(data)

    enum_pkts, seq = emit_full_kbd_enumeration(df, rtt_s=0.0015)
    pkts += enum_pkts

    type_pkts, seq = type_text(
        df, seq, "Hello, World!\n",
        key_hold_ms=80.0, inter_key_ms=120.0, poll_ms=8.0,
    )
    pkts += type_pkts

    # Three idle polls
    for _ in range(3):
        p, seq = emit_kbd_interrupt_cycle(df, seq, kbd_report())
        pkts += p
        df.advance(0.008)

    # Restore original send methods before fin() (FIN/ACK are not IPMX msgs)
    df.client_send = _orig_client_send
    df.server_send = _orig_server_send

    # Heartbeat on control channel (encrypted)
    cf.advance(1.0)
    pkts += ef_ctrl.sender_send(usb.build_heartbeat())

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_14_encrypted_session.pcap", pkts)


# ---------------------------------------------------------------------------
# UVC webcam enumeration (reusable across scenarios)
# ---------------------------------------------------------------------------

def emit_cam_enumeration(df: TcpFlow, rtt_s: float = 0.0015,
                         dev_desc: bytes = CAM_DEVICE_DESCRIPTOR,
                         config_desc: Optional[bytes] = None,
                         str_mfr: bytes = CAM_STRING_MANUFACTURER,
                         str_prod: bytes = CAM_STRING_PRODUCT,
                         str_serial: bytes = CAM_STRING_SERIAL,
                         ) -> tuple[list, int]:
    """Emit full USB device enumeration (UVC webcam, UAC mic, or any device).

    Steps:
      1  GET_DESCRIPTOR(Device, 8) — partial
      2  SET_ADDRESS(5)
      3  GET_DESCRIPTOR(Device, 18) — full
      4  GET_DESCRIPTOR(Config, 9) — partial wTotalLength
      5  GET_DESCRIPTOR(Config, full)
      6  GET_DESCRIPTOR(String, 0) — language IDs
      7  GET_DESCRIPTOR(String, 1, lang) — manufacturer
      8  GET_DESCRIPTOR(String, 2, lang) — product
      9  GET_DESCRIPTOR(String, 3, lang) — serial
     10  SET_CONFIGURATION(1)
    """
    cfg = config_desc if config_desc is not None else CAM_CONFIG_DESCRIPTOR

    pkts: list = []
    seq = 0

    def ctrl_in(length: int, req: bytes, data: bytes) -> None:
        nonlocal seq
        pkts.extend(df.server_send(usb.build_usb_control_submit(
            seq, endpoint=0, direction=1, binterval=0,
            transferlength=length, usbdevreq=req,
        )))
        df.advance(rtt_s)
        pkts.extend(df.client_send(usb.build_usb_control_submit_return(
            seq, 0, 1, len(data), 0, data,
        )))
        df.advance(rtt_s)
        seq += 1

    def ctrl_out(req: bytes) -> None:
        nonlocal seq
        pkts.extend(df.server_send(usb.build_usb_control_submit(
            seq, endpoint=0, direction=0, binterval=0,
            transferlength=0, usbdevreq=req,
        )))
        df.advance(rtt_s)
        pkts.extend(df.client_send(usb.build_usb_control_submit_return(
            seq, 0, 0, 0, 0, b'',
        )))
        df.advance(rtt_s)
        seq += 1

    ctrl_in(8, _get_descriptor_req(USB_DT_DEVICE, 0, 8), dev_desc[:8])
    ctrl_out(_set_address_req(5))
    df.advance(0.003)
    ctrl_in(18, _get_descriptor_req(USB_DT_DEVICE, 0, 18), dev_desc)
    ctrl_in(9, _get_descriptor_req(USB_DT_CONFIG, 0, 9), cfg[:9])
    ctrl_in(len(cfg),
            _get_descriptor_req(USB_DT_CONFIG, 0, len(cfg)),
            cfg)
    ctrl_in(255, _get_descriptor_req(USB_DT_STRING, 0, 255), CAM_LANGID_DESCRIPTOR)
    ctrl_in(255, _get_descriptor_req(USB_DT_STRING, 1, 255, 0x0409), str_mfr)
    ctrl_in(255, _get_descriptor_req(USB_DT_STRING, 2, 255, 0x0409), str_prod)
    ctrl_in(255, _get_descriptor_req(USB_DT_STRING, 3, 255, 0x0409), str_serial)
    ctrl_out(_set_configuration_req(1))

    return pkts, seq


def emit_uvc_probe_commit(df: TcpFlow, seq: int,
                          format_index: int = 1, frame_index: int = 1,
                          frame_interval: int = 333333,
                          rtt_s: float = 0.0015) -> tuple[list, int]:
    """Emit UVC Probe/Commit negotiation: SET_CUR(PROBE), GET_CUR(PROBE), SET_CUR(COMMIT)."""
    pkts: list = []
    probe_data = _uvc_probe_control(format_index, frame_index, frame_interval)
    probe_len = len(probe_data)

    def ctrl_in(length: int, req: bytes, data: bytes) -> None:
        nonlocal seq
        pkts.extend(df.server_send(usb.build_usb_control_submit(
            seq, endpoint=0, direction=1, binterval=0,
            transferlength=length, usbdevreq=req,
        )))
        df.advance(rtt_s)
        pkts.extend(df.client_send(usb.build_usb_control_submit_return(
            seq, 0, 1, len(data), 0, data,
        )))
        df.advance(rtt_s)
        seq += 1

    def ctrl_out_data(req: bytes, data: bytes) -> None:
        nonlocal seq
        pkts.extend(df.server_send(usb.build_usb_control_submit(
            seq, endpoint=0, direction=0, binterval=0,
            transferlength=len(data), usbdevreq=req,
            transferdata=data,
        )))
        df.advance(rtt_s)
        pkts.extend(df.client_send(usb.build_usb_control_submit_return(
            seq, 0, 0, 0, 0, b'',
        )))
        df.advance(rtt_s)
        seq += 1

    def ctrl_out(req: bytes) -> None:
        nonlocal seq
        pkts.extend(df.server_send(usb.build_usb_control_submit(
            seq, endpoint=0, direction=0, binterval=0,
            transferlength=0, usbdevreq=req,
        )))
        df.advance(rtt_s)
        pkts.extend(df.client_send(usb.build_usb_control_submit_return(
            seq, 0, 0, 0, 0, b'',
        )))
        df.advance(rtt_s)
        seq += 1

    # SET_CUR(VS_PROBE_CONTROL)
    ctrl_out_data(_uvc_set_cur_req(UVC_VS_PROBE_CONTROL, 1, probe_len), probe_data)
    # GET_CUR(VS_PROBE_CONTROL) — device returns negotiated parameters
    ctrl_in(probe_len, _uvc_get_cur_req(UVC_VS_PROBE_CONTROL, 1, probe_len), probe_data)
    # SET_CUR(VS_COMMIT_CONTROL)
    ctrl_out_data(_uvc_set_cur_req(UVC_VS_COMMIT_CONTROL, 1, probe_len), probe_data)
    # SET_INTERFACE(1, alt=1) — activate streaming
    ctrl_out(_set_interface_req(1, 1))

    return pkts, seq


def emit_uac_activate(df: TcpFlow, seq: int,
                      rtt_s: float = 0.0015) -> tuple[list, int]:
    """Activate UAC streaming: SET_INTERFACE(3, alt=1)."""
    pkts: list = []
    pkts.extend(df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=0, binterval=0,
        transferlength=0, usbdevreq=_set_interface_req(3, 1),
    )))
    df.advance(rtt_s)
    pkts.extend(df.client_send(usb.build_usb_control_submit_return(
        seq, 0, 0, 0, 0, b'',
    )))
    df.advance(rtt_s)
    seq += 1
    return pkts, seq


def emit_video_stream(df: TcpFlow, seq: int,
                      width: int = 640, height: int = 480,
                      fps: float = 30.0, duration_s: float = 2.0,
                      no_fid: bool = False, no_eof: bool = False,
                      ) -> tuple[list, int]:
    """Emit isochronous video frames as MJPEG with UVC payload headers."""
    pkts: list = []
    num_frames = int(fps * duration_s)
    frame_interval_s = 1.0 / fps

    for f_idx in range(num_frames):
        jpeg = _generate_mjpeg_frame(width, height, f_idx, num_frames)
        fid = f_idx & 0x01
        iso_packets = _fragment_uvc_frame(jpeg, fid, max_packet=1024,
                                          no_fid=no_fid, no_eof=no_eof)
        transfer_data = b''.join(iso_packets)
        iso_descs: list[tuple[int, int]] = [(len(p), 0) for p in iso_packets]

        # USB frame number (1 ms ticks from stream start)
        frame_number = int(f_idx * frame_interval_s * 1000)

        # Receiver sends ISO submit (ASAP=1, STARTFRAME=0 per spec)
        isolengths = [1024] * len(iso_packets)
        pkts.extend(df.server_send(usb.build_usb_isochronous_submit(
            seq, endpoint=CAM_VIDEO_EP_IN, direction=1,
            binterval=1, asap=1, startframe=0,
            num_packets=len(iso_packets), isolengths=isolengths,
        )))
        df.advance(0.0005)
        # Sender returns data with real USB frame number
        pkts.extend(df.client_send(usb.build_usb_isochronous_submit_return(
            seq, endpoint=CAM_VIDEO_EP_IN, direction=1,
            startframe=frame_number, errorcount=0,
            num_packets=len(iso_packets),
            iso_packets=iso_descs,
            transferdata=transfer_data,
        )))
        seq += 1
        df.advance(frame_interval_s)

    return pkts, seq


def emit_audio_stream(df: TcpFlow, seq: int,
                      sample_rate: int = 48000, channels: int = 2,
                      duration_s: float = 2.0,
                      ) -> tuple[list, int]:
    """Emit isochronous audio as PCM at 1ms intervals."""
    pkts: list = []
    chunk_ms = 1.0
    num_chunks = int(duration_s * 1000 / chunk_ms)

    for c_idx in range(num_chunks):
        pcm = _generate_pcm_chunk(sample_rate, channels, 16, chunk_ms,
                                  frequency=440.0, frame_no=c_idx)

        # USB frame number (1 ms ticks, same bus clock as video)
        frame_number = c_idx

        pkts.extend(df.server_send(usb.build_usb_isochronous_submit(
            seq, endpoint=CAM_AUDIO_EP_IN, direction=1,
            binterval=1, asap=1, startframe=0,
            num_packets=1, isolengths=[len(pcm)],
        )))
        df.advance(0.0002)
        pkts.extend(df.client_send(usb.build_usb_isochronous_submit_return(
            seq, endpoint=CAM_AUDIO_EP_IN, direction=1,
            startframe=frame_number, errorcount=0,
            num_packets=1,
            iso_packets=[(len(pcm), 0)],
            transferdata=pcm,
        )))
        seq += 1
        df.advance(chunk_ms / 1000.0)

    return pkts, seq


# ---------------------------------------------------------------------------
# Scenarios 15–21: UVC webcam + UAC microphone
# ---------------------------------------------------------------------------

def scenario_15(output_dir: Path) -> None:
    """UVC webcam enumeration + probe/commit only (no streaming)."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t, client_port=55015)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56015)
    pkts += emit_data_handshake(df, CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID)

    enum_pkts, seq = emit_cam_enumeration(df)
    pkts += enum_pkts

    pc_pkts, seq = emit_uvc_probe_commit(df, seq)
    pkts += pc_pkts

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_15_webcam_enum.pcap", pkts)


def scenario_16(output_dir: Path) -> None:
    """UVC webcam streaming: 2s of MJPEG 640x480 @ 30fps."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t, client_port=55016)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56016)
    pkts += emit_data_handshake(df, CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID)

    enum_pkts, seq = emit_cam_enumeration(df)
    pkts += enum_pkts

    pc_pkts, seq = emit_uvc_probe_commit(df, seq)
    pkts += pc_pkts

    vid_pkts, seq = emit_video_stream(df, seq, 640, 480, 30.0, 2.0)
    pkts += vid_pkts

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_16_webcam_stream.pcap", pkts)


def scenario_17(output_dir: Path) -> None:
    """UAC microphone streaming: 2s of 48kHz PCM audio."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t, client_port=55017)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56017)
    pkts += emit_data_handshake(df, CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID)

    enum_pkts, seq = emit_cam_enumeration(df)
    pkts += enum_pkts

    uac_pkts, seq = emit_uac_activate(df, seq)
    pkts += uac_pkts

    aud_pkts, seq = emit_audio_stream(df, seq, duration_s=2.0)
    pkts += aud_pkts

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_17_mic_stream.pcap", pkts)


def scenario_18(output_dir: Path) -> None:
    """Composite webcam+mic: interleaved video+audio on single data channel."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t, client_port=55018)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56018)
    pkts += emit_data_handshake(df, CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID)

    enum_pkts, seq = emit_cam_enumeration(df)
    pkts += enum_pkts

    pc_pkts, seq = emit_uvc_probe_commit(df, seq)
    pkts += pc_pkts

    uac_pkts, seq = emit_uac_activate(df, seq)
    pkts += uac_pkts

    # Interleave: for each video frame, also emit ~33 audio chunks (1ms each for 33ms)
    fps = 30.0
    duration_s = 5.0
    num_frames = int(fps * duration_s)
    frame_interval_s = 1.0 / fps
    audio_chunks_per_frame = int(frame_interval_s * 1000)  # ~33

    for f_idx in range(num_frames):
        # Video frame
        jpeg = _generate_mjpeg_frame(640, 480, f_idx, num_frames)
        fid = f_idx & 0x01
        iso_packets = _fragment_uvc_frame(jpeg, fid)
        transfer_data = b''.join(iso_packets)
        iso_descs: list[tuple[int, int]] = [(len(p), 0) for p in iso_packets]

        video_frame_number = int(f_idx * frame_interval_s * 1000)
        pkts.extend(df.server_send(usb.build_usb_isochronous_submit(
            seq, endpoint=CAM_VIDEO_EP_IN, direction=1,
            binterval=1, asap=1, startframe=0,
            num_packets=len(iso_packets), isolengths=[1024] * len(iso_packets),
        )))
        df.advance(0.0005)
        pkts.extend(df.client_send(usb.build_usb_isochronous_submit_return(
            seq, endpoint=CAM_VIDEO_EP_IN, direction=1,
            startframe=video_frame_number, errorcount=0,
            num_packets=len(iso_packets),
            iso_packets=iso_descs,
            transferdata=transfer_data,
        )))
        seq += 1

        # Audio chunks interleaved between video frames
        for a_idx in range(audio_chunks_per_frame):
            audio_frame_number = f_idx * audio_chunks_per_frame + a_idx
            pcm = _generate_pcm_chunk(48000, 2, 16, 1.0, 440.0,
                                      frame_no=audio_frame_number)
            pkts.extend(df.server_send(usb.build_usb_isochronous_submit(
                seq, endpoint=CAM_AUDIO_EP_IN, direction=1,
                binterval=1, asap=1, startframe=0,
                num_packets=1, isolengths=[len(pcm)],
            )))
            df.advance(0.0002)
            pkts.extend(df.client_send(usb.build_usb_isochronous_submit_return(
                seq, endpoint=CAM_AUDIO_EP_IN, direction=1,
                startframe=audio_frame_number, errorcount=0,
                num_packets=1,
                iso_packets=[(len(pcm), 0)],
                transferdata=pcm,
            )))
            seq += 1
            df.advance(0.001)

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_18_composite.pcap", pkts)


def scenario_19(output_dir: Path) -> None:
    """Webcam with UVC_QUIRK_STREAM_NO_FID (no FID toggle in payload headers).

    Uses Genesys Logic 05E3:0505 which maps to STREAM_NO_FID (0x0002)
    in the quirk table.
    """
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t, client_port=55019)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56019)
    pkts += emit_data_handshake(df, CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID)

    enum_pkts, seq = emit_cam_enumeration(
        df, dev_desc=NOFID_DEVICE_DESCRIPTOR,
        str_mfr=NOFID_STRING_MANUFACTURER,
        str_prod=NOFID_STRING_PRODUCT,
        str_serial=NOFID_STRING_SERIAL,
    )
    pkts += enum_pkts

    pc_pkts, seq = emit_uvc_probe_commit(df, seq)
    pkts += pc_pkts

    vid_pkts, seq = emit_video_stream(df, seq, 640, 480, 30.0, 1.0, no_fid=True)
    pkts += vid_pkts

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_19_quirk_no_fid.pcap", pkts)


def scenario_20(output_dir: Path) -> None:
    """Webcam with UVC_QUIRK_MJPEG_NO_EOF (no EOF marker in payload headers).

    Uses eMPIA EM2710 EB1A:2710 which maps to STREAM_NO_FID|MJPEG_NO_EOF
    (0x0202) in the quirk table.
    """
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t, client_port=55020)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56020)
    pkts += emit_data_handshake(df, CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID)

    enum_pkts, seq = emit_cam_enumeration(
        df, dev_desc=NOEOF_DEVICE_DESCRIPTOR,
        str_mfr=NOEOF_STRING_MANUFACTURER,
        str_prod=NOEOF_STRING_PRODUCT,
        str_serial=NOEOF_STRING_SERIAL,
    )
    pkts += enum_pkts

    pc_pkts, seq = emit_uvc_probe_commit(df, seq)
    pkts += pc_pkts

    vid_pkts, seq = emit_video_stream(df, seq, 640, 480, 30.0, 1.0, no_eof=True)
    pkts += vid_pkts

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_20_quirk_no_eof.pcap", pkts)


def scenario_21(output_dir: Path) -> None:
    """Encrypted webcam+mic session (PEP AES-CTR + CMAC)."""
    pkts: list = []
    t = BASE_TIME

    kv_int = int.from_bytes(_PEP_KEY_VERSION, "big")

    cf = control_flow(t, client_port=55021)
    ef_ctrl = EncryptingFlow(cf, key_version=kv_int, substreamid=0)
    pkts += cf.handshake()
    pkts += ef_ctrl.sender_send(usb.build_sender_connection_info(SENDER_CID, SENDER_SN))
    pkts += ef_ctrl.receiver_send(usb.build_sender_connection_status(
        RECEIVER_CID, RECEIVER_SN, HBEAT_INDEX, RECEIVER_DATA_PORT))

    df = data_flow(t + 0.05, client_port=56021)
    ef_data = EncryptingFlow(df, key_version=kv_int, substreamid=2)
    pkts += df.handshake()
    pkts += ef_data.sender_send(usb.build_usb_stream_info(
        CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID))
    pkts += ef_data.receiver_send(usb.build_usb_stream_status(0))
    ef_data.switch_substreamid(CAM_SUBSTREAMID)

    _orig_client_send = df.client_send
    _orig_server_send = df.server_send
    df.client_send = lambda data: ef_data.sender_send(data)
    df.server_send = lambda data: ef_data.receiver_send(data)

    enum_pkts, seq = emit_cam_enumeration(df)
    pkts += enum_pkts

    pc_pkts, seq = emit_uvc_probe_commit(df, seq)
    pkts += pc_pkts

    uac_pkts, seq = emit_uac_activate(df, seq)
    pkts += uac_pkts

    # Short encrypted stream: 0.5s video + audio
    vid_pkts, seq = emit_video_stream(df, seq, 640, 480, 30.0, 0.5)
    pkts += vid_pkts

    aud_pkts, seq = emit_audio_stream(df, seq, duration_s=0.5)
    pkts += aud_pkts

    df.client_send = _orig_client_send
    df.server_send = _orig_server_send

    cf.advance(1.0)
    pkts += ef_ctrl.sender_send(usb.build_heartbeat())

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_21_encrypted_webcam.pcap", pkts)


# ---------------------------------------------------------------------------
# HyperX QuadCast S microphone — real descriptors from Quadcast_Plug_In_Capture.pcapng
# Standalone UAC 1.0 device (no UVC): Audio Control + 2× Audio Streaming + HID
# VID:PID 0951:171d, Interfaces: AC(0), AS-Out/monitor(1, ep0x01),
# AS-In/mic(2, ep0x82), HID(3, ep0x87)
# ---------------------------------------------------------------------------

QUADCAST_SUBSTREAMID = 0x0C
QUADCAST_BUSID       = "1-1.5"
QUADCAST_MIC_EP_IN   = 0x82

QUADCAST_DEVICE_DESCRIPTOR = bytes.fromhex(
    "120110010000001051091d17000101020301"
)

QUADCAST_CONFIG_DESCRIPTOR = bytes.fromhex(
    "0902210104010080320904000000010100000a240100016a000201020c240200"
    "01010002030000000c240202010200020300000009240306010300090009240307010100"
    "080007240508010a000d2406090f02010002000200000a24060a0201010202000a24060d"
    "0201010202000e24040f02010d02030000000000090401000001020000090401010101020"
    "000072401010101001d24020102021007401f00112b00803e00225600007d0044ac0080bb"
    "000905010dc80001000007250101000000090402000001020000090402010101020000072"
    "401070101001d24020102021007401f00112b00803e00225600007d0044ac0080bb000905"
    "8205c8000100000725010100000009040300010300000009210001000122680007058703100002"
)

QUADCAST_STRING_MANUFACTURER = _make_string_descriptor("Kingston")
QUADCAST_STRING_PRODUCT      = _make_string_descriptor("HyperX QuadCast S")
QUADCAST_STRING_SERIAL       = _make_string_descriptor("QC-S-001")

CAM2_SUBSTREAMID = 0x0A
CAM2_BUSID       = "1-1.4"
CAM2_DEVICE_DESCRIPTOR = _cam_device_descriptor_with_vid_pid(0x045E, 0x075D)
CAM2_STRING_MANUFACTURER = _make_string_descriptor("Microsoft")
CAM2_STRING_PRODUCT      = _make_string_descriptor("LifeCam HD-3000")
CAM2_STRING_SERIAL       = _make_string_descriptor("MS-CAM2-001")


def scenario_22(output_dir: Path) -> None:
    """Multi-stream: two webcam+mic devices on separate data channels."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t, client_port=55022)
    pkts += emit_control_handshake(cf)

    # Data channel 1 — Logitech C920 (substreamid 0x06)
    df1 = data_flow(t + 0.05, client_port=56022)
    pkts += emit_data_handshake(df1, CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID)

    enum1_pkts, seq1 = emit_cam_enumeration(df1)
    pkts += enum1_pkts

    pc1_pkts, seq1 = emit_uvc_probe_commit(df1, seq1)
    pkts += pc1_pkts

    uac1_pkts, seq1 = emit_uac_activate(df1, seq1)
    pkts += uac1_pkts

    # Data channel 2 — Microsoft LifeCam (substreamid 0x08)
    df2 = data_flow(t + 0.10, client_port=56023)
    pkts += emit_data_handshake(df2, CAM2_SUBSTREAMID, CAM_USBSPEED, CAM2_BUSID)

    enum2_pkts, seq2 = emit_cam_enumeration(
        df2, dev_desc=CAM2_DEVICE_DESCRIPTOR,
        str_mfr=CAM2_STRING_MANUFACTURER,
        str_prod=CAM2_STRING_PRODUCT,
        str_serial=CAM2_STRING_SERIAL,
    )
    pkts += enum2_pkts

    pc2_pkts, seq2 = emit_uvc_probe_commit(df2, seq2)
    pkts += pc2_pkts

    uac2_pkts, seq2 = emit_uac_activate(df2, seq2)
    pkts += uac2_pkts

    # Stream both devices: 30 fps video + interleaved audio, 3 seconds
    fps = 30.0
    duration_s = 3.0
    num_frames = int(fps * duration_s)
    frame_interval_s = 1.0 / fps
    audio_chunks_per_frame = int(frame_interval_s * 1000)

    for f_idx in range(num_frames):
        video_frame_number = int(f_idx * frame_interval_s * 1000)

        # Device 1 video frame
        jpeg1 = _generate_mjpeg_frame(640, 480, f_idx, num_frames)
        fid1 = f_idx & 0x01
        iso_pkt1 = _fragment_uvc_frame(jpeg1, fid1)
        td1 = b''.join(iso_pkt1)
        iso_d1: list[tuple[int, int]] = [(len(p), 0) for p in iso_pkt1]

        pkts.extend(df1.server_send(usb.build_usb_isochronous_submit(
            seq1, endpoint=CAM_VIDEO_EP_IN, direction=1,
            binterval=1, asap=1, startframe=0,
            num_packets=len(iso_pkt1), isolengths=[1024] * len(iso_pkt1),
        )))
        df1.advance(0.0005)
        pkts.extend(df1.client_send(usb.build_usb_isochronous_submit_return(
            seq1, endpoint=CAM_VIDEO_EP_IN, direction=1,
            startframe=video_frame_number, errorcount=0,
            num_packets=len(iso_pkt1), iso_packets=iso_d1,
            transferdata=td1,
        )))
        seq1 += 1

        # Device 2 video frame (offset hue by 120 degrees)
        jpeg2 = _generate_mjpeg_frame(640, 480,
                                      (f_idx + num_frames // 3) % num_frames,
                                      num_frames)
        fid2 = f_idx & 0x01
        iso_pkt2 = _fragment_uvc_frame(jpeg2, fid2)
        td2 = b''.join(iso_pkt2)
        iso_d2: list[tuple[int, int]] = [(len(p), 0) for p in iso_pkt2]

        pkts.extend(df2.server_send(usb.build_usb_isochronous_submit(
            seq2, endpoint=CAM_VIDEO_EP_IN, direction=1,
            binterval=1, asap=1, startframe=0,
            num_packets=len(iso_pkt2), isolengths=[1024] * len(iso_pkt2),
        )))
        df2.advance(0.0005)
        pkts.extend(df2.client_send(usb.build_usb_isochronous_submit_return(
            seq2, endpoint=CAM_VIDEO_EP_IN, direction=1,
            startframe=video_frame_number, errorcount=0,
            num_packets=len(iso_pkt2), iso_packets=iso_d2,
            transferdata=td2,
        )))
        seq2 += 1

        # Audio for both devices
        for a_idx in range(audio_chunks_per_frame):
            audio_frame_number = f_idx * audio_chunks_per_frame + a_idx

            pcm1 = _generate_pcm_chunk(48000, 2, 16, 1.0, 440.0,
                                       frame_no=audio_frame_number)
            pkts.extend(df1.server_send(usb.build_usb_isochronous_submit(
                seq1, endpoint=CAM_AUDIO_EP_IN, direction=1,
                binterval=1, asap=1, startframe=0,
                num_packets=1, isolengths=[len(pcm1)],
            )))
            df1.advance(0.0002)
            pkts.extend(df1.client_send(usb.build_usb_isochronous_submit_return(
                seq1, endpoint=CAM_AUDIO_EP_IN, direction=1,
                startframe=audio_frame_number, errorcount=0,
                num_packets=1, iso_packets=[(len(pcm1), 0)],
                transferdata=pcm1,
            )))
            seq1 += 1

            pcm2 = _generate_pcm_chunk(48000, 2, 16, 1.0, 880.0,
                                       frame_no=audio_frame_number)
            pkts.extend(df2.server_send(usb.build_usb_isochronous_submit(
                seq2, endpoint=CAM_AUDIO_EP_IN, direction=1,
                binterval=1, asap=1, startframe=0,
                num_packets=1, isolengths=[len(pcm2)],
            )))
            df2.advance(0.0002)
            pkts.extend(df2.client_send(usb.build_usb_isochronous_submit_return(
                seq2, endpoint=CAM_AUDIO_EP_IN, direction=1,
                startframe=audio_frame_number, errorcount=0,
                num_packets=1, iso_packets=[(len(pcm2), 0)],
                transferdata=pcm2,
            )))
            seq2 += 1
            df1.advance(0.001)
            df2.advance(0.001)

    pkts += df1.fin()
    pkts += df2.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_22_multi_device.pcap", pkts)


def scenario_23(output_dir: Path) -> None:
    """Standalone USB microphone (HyperX QuadCast S) — real descriptors, synthetic audio."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t, client_port=55023)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56023)
    pkts += emit_data_handshake(df, QUADCAST_SUBSTREAMID,
                                CAM_USBSPEED, QUADCAST_BUSID)

    enum_pkts, seq = emit_cam_enumeration(
        df,
        dev_desc=QUADCAST_DEVICE_DESCRIPTOR,
        config_desc=QUADCAST_CONFIG_DESCRIPTOR,
        str_mfr=QUADCAST_STRING_MANUFACTURER,
        str_prod=QUADCAST_STRING_PRODUCT,
        str_serial=QUADCAST_STRING_SERIAL,
    )
    pkts += enum_pkts

    # SET_INTERFACE(2, alt=1) — activate microphone streaming (interface 2)
    set_iface_req = bytes([0x01, USB_REQ_SET_INTERFACE, 0x01, 0x00,
                           0x02, 0x00, 0x00, 0x00])
    pkts.extend(df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=0, binterval=0,
        transferlength=0, usbdevreq=set_iface_req,
    )))
    df.advance(0.0015)
    pkts.extend(df.client_send(usb.build_usb_control_submit_return(
        seq, 0, 0, 0, 0, b'',
    )))
    seq += 1
    df.advance(0.001)

    # Stream 3 seconds of 48 kHz stereo 16-bit audio via ISO on EP 0x82
    sample_rate = 48000
    channels = 2
    duration_s = 3.0
    chunk_ms = 1.0
    num_chunks = int(duration_s * 1000 / chunk_ms)

    for c_idx in range(num_chunks):
        pcm = _generate_pcm_chunk(sample_rate, channels, 16, chunk_ms,
                                  frequency=440.0, frame_no=c_idx)

        pkts.extend(df.server_send(usb.build_usb_isochronous_submit(
            seq, endpoint=QUADCAST_MIC_EP_IN, direction=1,
            binterval=1, asap=1, startframe=0,
            num_packets=1, isolengths=[len(pcm)],
        )))
        df.advance(0.0002)
        pkts.extend(df.client_send(usb.build_usb_isochronous_submit_return(
            seq, endpoint=QUADCAST_MIC_EP_IN, direction=1,
            startframe=c_idx, errorcount=0,
            num_packets=1,
            iso_packets=[(len(pcm), 0)],
            transferdata=pcm,
        )))
        seq += 1
        df.advance(chunk_ms / 1000.0)

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_23_quadcast_mic.pcap", pkts)


# ---------------------------------------------------------------------------
# Scenario 24: H.264 webcam (Frame-Based format) — synthetic NAL units
# ---------------------------------------------------------------------------

# H.264 GUID: {34363248-0000-0010-8000-00AA00389B71}
_H264_GUID = bytes([
    0x48, 0x32, 0x36, 0x34, 0x00, 0x00, 0x10, 0x00,
    0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
])

# HEVC GUID: {35363248-0000-0010-8000-00AA00389B71}
_HEVC_GUID = bytes([
    0x48, 0x32, 0x36, 0x35, 0x00, 0x00, 0x10, 0x00,
    0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
])

H264_SUBSTREAMID = 0x0E
H264_BUSID       = "1-1.5"
H264_VIDEO_EP_IN = 0x01

# Device descriptor — Logitech BRIO (046d:085e)
H264_DEVICE_DESCRIPTOR = bytes([
    0x12, 0x01,             # bLength, bDescriptorType = DEVICE
    0x00, 0x02,             # bcdUSB = 2.00
    0xEF,                   # bDeviceClass = Misc (IAD)
    0x02,                   # bDeviceSubClass
    0x01,                   # bDeviceProtocol = IAD
    0x40,                   # bMaxPacketSize0 = 64
    0x6D, 0x04,             # idVendor = 0x046D (Logitech)
    0x5E, 0x08,             # idProduct = 0x085E (BRIO)
    0x12, 0x00,             # bcdDevice = 0.12
    0x01,                   # iManufacturer = 1
    0x02,                   # iProduct = 2
    0x03,                   # iSerialNumber = 3
    0x01,                   # bNumConfigurations = 1
])

H264_STRING_MANUFACTURER = _make_string_descriptor("Logitech")
H264_STRING_PRODUCT      = _make_string_descriptor("Logitech BRIO")
H264_STRING_SERIAL       = _make_string_descriptor("BRIO-H264-001")

# Frame-based format: VS_FORMAT_FRAME_BASED (0x10) + VS_FRAME_FRAME_BASED (0x11)
_VS_FMT_FRAME_BASED_LEN = 28
_VS_FRAME_FRAME_BASED_LEN = 30

_H264_VC_TOTAL = 51  # Same VC block as standard cam

# Frame-based layout (UVC 1.5):
#  VS_FORMAT_FRAME_BASED: 5 header + 16 GUID + 6 fields + 1 bVariableSize = 28
#  VS_FRAME_FRAME_BASED:  offset 17 = dwDefaultFrameInterval (no dwMaxVideoFrameBufferSize)
#    base = 22, + 4 dwBytesPerLine = 26, + 4*N intervals.  For 1 discrete: 30.
_H264_VS_TOTAL = (
    14  # VS Input Header
    + _VS_FMT_FRAME_BASED_LEN   # 28
    + _VS_FRAME_FRAME_BASED_LEN # 30
    + 6  # VS Color Matching
)

_H264_CONFIG_TOTAL = (
    9                          # Config descriptor
    + 8 + 9 + _H264_VC_TOTAL  # Video IAD + VC Interface + VC class-specific
    + 9 + _H264_VS_TOTAL + 9 + 7  # VS Alt0 + VS class-specific + VS Alt1 + EP
)

H264_CONFIG_DESCRIPTOR = bytes([
    # ---- Configuration Descriptor (9) ----
    0x09, 0x02,
    _H264_CONFIG_TOTAL & 0xFF, (_H264_CONFIG_TOTAL >> 8) & 0xFF,
    0x02,               # bNumInterfaces = 2 (VC, VS)
    0x01,               # bConfigurationValue = 1
    0x00, 0xA0, 0xFA,   # iConfiguration=0, bmAttributes=bus-powered+rwakeup, 500mA

    # ---- IAD for Video (8) ----
    0x08, 0x0B, 0x00, 0x02, 0x0E, 0x03, 0x00, 0x02,

    # ---- VideoControl Interface (9) ----
    0x09, 0x04, 0x00, 0x00, 0x00, 0x0E, 0x01, 0x00, 0x02,

    # ---- VC Header (13): UVC 1.5 ----
    0x0D, 0x24, 0x01,
    0x50, 0x01,           # bcdUVC = 1.5
    _H264_VC_TOTAL & 0xFF, (_H264_VC_TOTAL >> 8) & 0xFF,
    0x00, 0x6C, 0xDC, 0x02,
    0x01, 0x01,

    # ---- Camera Terminal (18) ----
    0x12, 0x24, 0x02,
    0x01, 0x01, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x02, 0x00,

    # ---- Processing Unit (11) ----
    0x0B, 0x24, 0x05,
    0x02, 0x01, 0x00, 0x00, 0x02, 0x3F, 0x14, 0x00,

    # ---- Output Terminal (9) ----
    0x09, 0x24, 0x03,
    0x03, 0x01, 0x01, 0x00, 0x02, 0x00,

    # ---- VS Interface Alt 0 (9) ----
    0x09, 0x04, 0x01, 0x00, 0x00, 0x0E, 0x02, 0x00, 0x00,

    # ---- VS Input Header (14) ----
    0x0E, 0x24, 0x01,
    0x01,                 # bNumFormats = 1
    _H264_VS_TOTAL & 0xFF, (_H264_VS_TOTAL >> 8) & 0xFF,
    0x81,                 # bEndpointAddress = IN EP1
    0x00, 0x03, 0x00, 0x00,
    0x01, 0x00, 0x00,     # bControlSize=1, bmaControls pad

    # ---- VS Format Frame-Based (28 = 0x1C) ----
    _VS_FMT_FRAME_BASED_LEN, 0x24, 0x10,
    0x01,                 # bFormatIndex = 1
    0x01,                 # bNumFrameDescriptors = 1
]) + _H264_GUID + bytes([
    0x00,                 # bBitsPerPixel = 0 (compressed)
    0x01,                 # bDefaultFrameIndex = 1
    0x00,                 # bAspectRatioX
    0x00,                 # bAspectRatioY
    0x00,                 # bmInterlaceFlags
    0x00,                 # bCopyProtect
    0x00,                 # bVariableSize = 0 (fixed-size frames)

    # ---- VS Frame Frame-Based 1920x1080@30fps (30 = 0x1E) ----
    # Layout: [0]bLength [1]bDescType [2]bDescSubtype [3]bFrameIndex
    # [4]bmCap [5-6]wWidth [7-8]wHeight [9-12]dwMinBitRate [13-16]dwMaxBitRate
    # [17-20]dwDefaultFrameInterval [21]bFrameIntervalType [22-25]dwBytesPerLine
    # [26-29]dwFrameInterval[0]
    _VS_FRAME_FRAME_BASED_LEN, 0x24, 0x11,
    0x01,                 # bFrameIndex = 1
    0x01,                 # bmCapabilities
    0x80, 0x07,           # wWidth = 1920
    0x38, 0x04,           # wHeight = 1080
    0x00, 0x00, 0x94, 0x11,  # dwMinBitRate
    0x00, 0x00, 0x94, 0x11,  # dwMaxBitRate
    0x15, 0x16, 0x05, 0x00,  # dwDefaultFrameInterval = 333333 (30fps)
    0x01,                 # bFrameIntervalType = 1 (discrete)
    0x00, 0x00, 0x00, 0x00,  # dwBytesPerLine = 0
    0x15, 0x16, 0x05, 0x00,  # dwFrameInterval[0] = 333333

    # ---- VS Color Matching (6) ----
    0x06, 0x24, 0x0D, 0x01, 0x01, 0x04,

    # ---- VS Interface Alt 1 (9) ----
    0x09, 0x04, 0x01, 0x01, 0x01, 0x0E, 0x02, 0x00, 0x00,

    # ---- Endpoint ISO IN EP1 (7) ----
    0x07, 0x05, 0x81, 0x05, 0x00, 0x0C, 0x01,
    # wMaxPacketSize=3072, bInterval=1
])


_H264_SPS_1080P = bytes.fromhex(
    '000000016742c028dc0780227e5c0440000003004000000f03c60ce0'
)
_H264_PPS_1080P = bytes.fromhex('0000000168ce0f2c80')


def _generate_synthetic_h264_frame(frame_no: int, width: int = 1920,
                                   height: int = 1080) -> bytes:
    """Generate a minimal synthetic H.264 access unit (SPS + PPS + IDR slice).

    Uses valid SPS/PPS from libx264 Baseline L4.0 for 1920x1080 so the
    FFmpeg H.264 probe can determine stream parameters.  The IDR slice body
    is filler; the frame is not visually meaningful but structurally valid.
    """
    idr_header = bytes([
        0x00, 0x00, 0x00, 0x01,
        0x65,
        0x88, 0x84, 0x04, 0xBC, 0x46, 0x28,
    ])
    fill_byte = ((frame_no * 73) + 0x42) & 0xFF
    slice_data = bytes([fill_byte] * 2048)

    return _H264_SPS_1080P + _H264_PPS_1080P + idr_header + slice_data


def scenario_24(output_dir: Path) -> None:
    """H.264 webcam (Frame-Based format) — 1s of synthetic H.264 at 1920x1080@30fps."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t, client_port=55024)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56024)
    pkts += emit_data_handshake(df, H264_SUBSTREAMID, CAM_USBSPEED, H264_BUSID)

    enum_pkts, seq = emit_cam_enumeration(
        df,
        dev_desc=H264_DEVICE_DESCRIPTOR,
        config_desc=H264_CONFIG_DESCRIPTOR,
        str_mfr=H264_STRING_MANUFACTURER,
        str_prod=H264_STRING_PRODUCT,
        str_serial=H264_STRING_SERIAL,
    )
    pkts += enum_pkts

    # UVC Probe/Commit for frame-based format
    pc_pkts, seq = emit_uvc_probe_commit(df, seq, format_index=1,
                                         frame_index=1, frame_interval=333333)
    pkts += pc_pkts

    # Stream 1 second of synthetic H.264 frames at 30fps
    fps = 30.0
    duration_s = 1.0
    num_frames = int(fps * duration_s)
    frame_interval_s = 1.0 / fps

    for f_idx in range(num_frames):
        h264_data = _generate_synthetic_h264_frame(f_idx)
        fid = f_idx & 0x01
        iso_packets = _fragment_uvc_frame(h264_data, fid, max_packet=3072)
        transfer_data = b''.join(iso_packets)
        iso_descs: list[tuple[int, int]] = [(len(p), 0) for p in iso_packets]

        frame_number = int(f_idx * frame_interval_s * 1000)
        isolengths = [3072] * len(iso_packets)
        pkts.extend(df.server_send(usb.build_usb_isochronous_submit(
            seq, endpoint=H264_VIDEO_EP_IN, direction=1,
            binterval=1, asap=1, startframe=0,
            num_packets=len(iso_packets), isolengths=isolengths,
        )))
        df.advance(0.0005)
        pkts.extend(df.client_send(usb.build_usb_isochronous_submit_return(
            seq, endpoint=H264_VIDEO_EP_IN, direction=1,
            startframe=frame_number, errorcount=0,
            num_packets=len(iso_packets),
            iso_packets=iso_descs,
            transferdata=transfer_data,
        )))
        seq += 1
        df.advance(frame_interval_s)

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_24_h264_webcam.pcap", pkts)


def scenario_25(output_dir: Path) -> None:
    """Encrypted multi-channel session: webcam (ch0) + mic (ch1) on separate
    data channels.  Both use handshake SSID 2/3, then switch to their
    respective payload SSIDs.  Validates the two-phase SSID model with
    multiple channels sharing the same handshake SSID."""
    pkts: list = []
    t = BASE_TIME
    kv_int = int.from_bytes(_PEP_KEY_VERSION, "big")

    cf = control_flow(t, client_port=55025)
    ef_ctrl = EncryptingFlow(cf, key_version=kv_int, substreamid=0)
    pkts += cf.handshake()
    pkts += ef_ctrl.sender_send(usb.build_sender_connection_info(SENDER_CID, SENDER_SN))
    pkts += ef_ctrl.receiver_send(usb.build_sender_connection_status(
        RECEIVER_CID, RECEIVER_SN, HBEAT_INDEX, RECEIVER_DATA_PORT))

    # Data channel 0 — webcam (payload SSID = CAM_SUBSTREAMID)
    df1 = data_flow(t + 0.05, client_port=56025)
    ef_data1 = EncryptingFlow(df1, key_version=kv_int, substreamid=2)
    pkts += df1.handshake()
    pkts += ef_data1.sender_send(usb.build_usb_stream_info(
        CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID))
    pkts += ef_data1.receiver_send(usb.build_usb_stream_status(0))
    ef_data1.switch_substreamid(CAM_SUBSTREAMID)

    _orig1_cs = df1.client_send
    _orig1_ss = df1.server_send
    df1.client_send = lambda data: ef_data1.sender_send(data)
    df1.server_send = lambda data: ef_data1.receiver_send(data)

    enum_pkts, seq1 = emit_cam_enumeration(df1)
    pkts += enum_pkts
    pc_pkts, seq1 = emit_uvc_probe_commit(df1, seq1)
    pkts += pc_pkts

    # Data channel 1 — QuadCast mic (payload SSID = QUADCAST_SUBSTREAMID)
    df2 = data_flow(t + 0.10, client_port=56026)
    ef_data2 = EncryptingFlow(df2, key_version=kv_int, substreamid=2)
    pkts += df2.handshake()
    pkts += ef_data2.sender_send(usb.build_usb_stream_info(
        QUADCAST_SUBSTREAMID, usb.UsbSpeed.HIGH_SPEED, QUADCAST_BUSID))
    pkts += ef_data2.receiver_send(usb.build_usb_stream_status(0))
    ef_data2.switch_substreamid(QUADCAST_SUBSTREAMID)

    _orig2_cs = df2.client_send
    _orig2_ss = df2.server_send
    df2.client_send = lambda data: ef_data2.sender_send(data)
    df2.server_send = lambda data: ef_data2.receiver_send(data)

    # Enumerate mic on ch1
    enum_pkts2, seq2 = emit_cam_enumeration(
        df2,
        dev_desc=QUADCAST_DEVICE_DESCRIPTOR,
        config_desc=QUADCAST_CONFIG_DESCRIPTOR,
        str_mfr=QUADCAST_STRING_MANUFACTURER,
        str_prod=QUADCAST_STRING_PRODUCT,
        str_serial=QUADCAST_STRING_SERIAL,
    )
    pkts += enum_pkts2

    # Short video stream on ch0
    vid_pkts, seq1 = emit_video_stream(df1, seq1, 640, 480, 30.0, 0.3)
    pkts += vid_pkts

    # Restore and close
    df1.client_send = _orig1_cs
    df1.server_send = _orig1_ss
    df2.client_send = _orig2_cs
    df2.server_send = _orig2_ss

    cf.advance(1.0)
    pkts += ef_ctrl.sender_send(usb.build_heartbeat())

    pkts += df1.fin()
    pkts += df2.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_25_encrypted_multichannel.pcap", pkts)


def scenario_26(output_dir: Path) -> None:
    """Encrypted keyboard session with deliberately corrupted messages.

    Identical to scenario_14 except that 3 mid-stream S2R INTERRUPT_SUBMIT
    messages have their ciphertext flipped so CMAC verification fails.
    Tests that the receiver/dissector correctly detects MAC failures.
    """
    pkts: list = []
    t = BASE_TIME
    kv_int = int.from_bytes(_PEP_KEY_VERSION, "big")

    cf = control_flow(t, client_port=55026)
    ef_ctrl = EncryptingFlow(cf, key_version=kv_int, substreamid=0)
    pkts += cf.handshake()
    pkts += ef_ctrl.sender_send(usb.build_sender_connection_info(SENDER_CID, SENDER_SN))
    pkts += ef_ctrl.receiver_send(usb.build_sender_connection_status(
        RECEIVER_CID, RECEIVER_SN, HBEAT_INDEX, RECEIVER_DATA_PORT))

    df = data_flow(t + 0.05, client_port=56026)
    ef_data = EncryptingFlow(df, key_version=kv_int, substreamid=2)
    pkts += df.handshake()
    pkts += ef_data.sender_send(usb.build_usb_stream_info(KBD_SUBSTREAMID, KBD_USBSPEED, KBD_BUSID))
    pkts += ef_data.receiver_send(usb.build_usb_stream_status(0))
    ef_data.switch_substreamid(KBD_SUBSTREAMID)

    _orig_client_send = df.client_send
    _orig_server_send = df.server_send
    df.client_send = lambda data: ef_data.sender_send(data)
    df.server_send = lambda data: ef_data.receiver_send(data)

    enum_pkts, seq = emit_full_kbd_enumeration(df, rtt_s=0.0015)
    pkts += enum_pkts

    # Type a few keys. Corrupt 3 S2R (Sender→Receiver) INTERRUPT_SUBMIT_RETURN
    # messages so the receiver sees MAC failures mid-stream.
    reports = [kbd_report(0, 0x04), kbd_report(),
               kbd_report(0, 0x05), kbd_report(),
               kbd_report(0, 0x06), kbd_report()]
    corrupt_at = {1, 3, 5}
    for i, report in enumerate(reports):
        # R2S: Receiver polls (interrupt submit)
        pkts += ef_data.receiver_send(usb.build_usb_interrupt_submit(
            seq, endpoint=KBD_ENDPOINT_IN, direction=1,
            binterval=KBD_BINTERVAL, transferlength=8))
        # S2R: Sender returns the HID report — corrupt selected ones
        pkts += ef_data.sender_send(
            usb.build_usb_interrupt_submit_return(
                seq, endpoint=KBD_ENDPOINT_IN, direction=1,
                actuallength=len(report), rstatus=0, transferdata=report),
            corrupt=(i in corrupt_at))
        seq += 1
        df.advance(0.008)

    # Three clean idle polls to prove the stream continues after MAC failures
    for _ in range(3):
        p, seq = emit_kbd_interrupt_cycle(df, seq, kbd_report())
        pkts += p
        df.advance(0.008)

    df.client_send = _orig_client_send
    df.server_send = _orig_server_send

    cf.advance(1.0)
    pkts += ef_ctrl.sender_send(usb.build_heartbeat())

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_26_encrypted_mac_failure.pcap", pkts)


# ---------------------------------------------------------------------------
# Scenario 27: HEVC webcam (Frame-Based format) — synthetic NAL units
# ---------------------------------------------------------------------------

HEVC_SUBSTREAMID = 0x10
HEVC_BUSID       = "1-1.7"
HEVC_VIDEO_EP_IN = 0x01

HEVC_DEVICE_DESCRIPTOR = bytes([
    0x12, 0x01,             # bLength, bDescriptorType = DEVICE
    0x00, 0x02,             # bcdUSB = 2.00
    0xEF,                   # bDeviceClass = Misc (IAD)
    0x02,                   # bDeviceSubClass
    0x01,                   # bDeviceProtocol = IAD
    0x40,                   # bMaxPacketSize0 = 64
    0x6D, 0x04,             # idVendor = 0x046D (Logitech)
    0x5F, 0x08,             # idProduct = 0x085F (HEVC variant)
    0x12, 0x00,             # bcdDevice = 0.12
    0x01,                   # iManufacturer = 1
    0x02,                   # iProduct = 2
    0x03,                   # iSerialNumber = 3
    0x01,                   # bNumConfigurations = 1
])

HEVC_STRING_MANUFACTURER = _make_string_descriptor("Logitech")
HEVC_STRING_PRODUCT      = _make_string_descriptor("Logitech BRIO HEVC")
HEVC_STRING_SERIAL       = _make_string_descriptor("BRIO-HEVC-001")

# HEVC config descriptor — identical to H264 but with HEVC GUID
_hevc_guid_offset = H264_CONFIG_DESCRIPTOR.index(_H264_GUID)
HEVC_CONFIG_DESCRIPTOR = (
    H264_CONFIG_DESCRIPTOR[:_hevc_guid_offset]
    + _HEVC_GUID
    + H264_CONFIG_DESCRIPTOR[_hevc_guid_offset + 16:]
)


def _generate_synthetic_hevc_frame(frame_no: int) -> bytes:
    """Generate minimal HEVC access unit: VPS + SPS + PPS + IDR."""
    vps = bytes([0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0c, 0x01,
                 0xff, 0xff, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00,
                 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03,
                 0x00, 0x7b, 0xac, 0x09])
    sps = bytes([0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x01, 0x01,
                 0x60, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00,
                 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x7b, 0xa0,
                 0x03, 0xc0, 0x80, 0x10, 0xe5, 0x96, 0x56, 0x69,
                 0x24, 0xca, 0xf0, 0x10, 0x00, 0x00, 0x03, 0x00,
                 0x10, 0x00, 0x00, 0x03, 0x01, 0xe0, 0x80])
    pps = bytes([0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0xc1, 0x72,
                 0xb4, 0x62, 0x40])
    idr_header = bytes([0x00, 0x00, 0x00, 0x01, 0x26, 0x01, 0xaf,
                        0x08, 0x42])
    fill_byte = ((frame_no * 73) + 0x42) & 0xFF
    slice_data = bytes([fill_byte] * 2048)
    return vps + sps + pps + idr_header + slice_data


def scenario_27(output_dir: Path) -> None:
    """HEVC webcam (Frame-Based format) — 1s of synthetic HEVC at 1920x1080@30fps."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t, client_port=55027)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56027)
    pkts += emit_data_handshake(df, HEVC_SUBSTREAMID, CAM_USBSPEED, HEVC_BUSID)

    enum_pkts, seq = emit_cam_enumeration(
        df,
        dev_desc=HEVC_DEVICE_DESCRIPTOR,
        config_desc=HEVC_CONFIG_DESCRIPTOR,
        str_mfr=HEVC_STRING_MANUFACTURER,
        str_prod=HEVC_STRING_PRODUCT,
        str_serial=HEVC_STRING_SERIAL,
    )
    pkts += enum_pkts

    pc_pkts, seq = emit_uvc_probe_commit(df, seq, format_index=1,
                                         frame_index=1, frame_interval=333333)
    pkts += pc_pkts

    fps = 30.0
    duration_s = 1.0
    num_frames = int(fps * duration_s)
    frame_interval_s = 1.0 / fps

    for f_idx in range(num_frames):
        hevc_data = _generate_synthetic_hevc_frame(f_idx)
        fid = f_idx & 0x01
        iso_packets = _fragment_uvc_frame(hevc_data, fid, max_packet=3072)
        transfer_data = b''.join(iso_packets)
        iso_descs: list[tuple[int, int]] = [(len(p), 0) for p in iso_packets]

        frame_number = int(f_idx * frame_interval_s * 1000)
        isolengths = [3072] * len(iso_packets)
        pkts.extend(df.server_send(usb.build_usb_isochronous_submit(
            seq, endpoint=HEVC_VIDEO_EP_IN, direction=1,
            binterval=1, asap=1, startframe=0,
            num_packets=len(iso_packets), isolengths=isolengths,
        )))
        df.advance(0.0005)
        pkts.extend(df.client_send(usb.build_usb_isochronous_submit_return(
            seq, endpoint=HEVC_VIDEO_EP_IN, direction=1,
            startframe=frame_number, errorcount=0,
            num_packets=len(iso_packets),
            iso_packets=iso_descs,
            transferdata=transfer_data,
        )))
        seq += 1
        df.advance(frame_interval_s)

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_27_hevc_webcam.pcap", pkts)


# ---------------------------------------------------------------------------
# Scenario 28: UAC 2.0 microphone — 48 kHz / 24-bit / stereo
# ---------------------------------------------------------------------------

UAC2_MIC_SUBSTREAMID = 0x12
UAC2_MIC_BUSID       = "1-1.8"
UAC2_MIC_AUDIO_EP_IN = 0x02

UAC2_MIC_DEVICE_DESCRIPTOR = bytes([
    0x12, 0x01,             # bLength, bDescriptorType = DEVICE
    0x00, 0x02,             # bcdUSB = 2.00
    0xEF,                   # bDeviceClass = Misc (IAD)
    0x02,                   # bDeviceSubClass
    0x01,                   # bDeviceProtocol = IAD
    0x40,                   # bMaxPacketSize0 = 64
    0x56, 0x12,             # idVendor = 0x1256
    0x01, 0x30,             # idProduct = 0x3001
    0x00, 0x01,             # bcdDevice = 1.00
    0x01,                   # iManufacturer = 1
    0x02,                   # iProduct = 2
    0x03,                   # iSerialNumber = 3
    0x01,                   # bNumConfigurations = 1
])

UAC2_MIC_STRING_MANUFACTURER = _make_string_descriptor("Generic")
UAC2_MIC_STRING_PRODUCT      = _make_string_descriptor("UAC2 Studio Mic")
UAC2_MIC_STRING_SERIAL       = _make_string_descriptor("UAC2-MIC-001")

_UAC2_AC_HEADER_LEN   = 9
_UAC2_CLOCK_SRC_LEN   = 8
_UAC2_INPUT_TERM_LEN  = 17
_UAC2_FEATURE_UNIT_LEN = 14
_UAC2_OUTPUT_TERM_LEN = 12
_UAC2_AC_TOTAL = (
    _UAC2_AC_HEADER_LEN + _UAC2_CLOCK_SRC_LEN + _UAC2_INPUT_TERM_LEN
    + _UAC2_FEATURE_UNIT_LEN + _UAC2_OUTPUT_TERM_LEN
)

_UAC2_AS_GENERAL_LEN  = 16
_UAC2_AS_FORMAT_LEN   = 6
_UAC2_EP_DESC_LEN     = 7
_UAC2_CS_EP_LEN       = 8

_UAC2_CONFIG_TOTAL = (
    9                                    # Configuration descriptor
    + 8 + 9 + _UAC2_AC_TOTAL            # IAD + AC Interface + AC class-specific
    + 9                                  # AS Interface Alt 0 (zero-bandwidth)
    + 9 + _UAC2_AS_GENERAL_LEN + _UAC2_AS_FORMAT_LEN  # AS Interface Alt 1 + descriptors
    + _UAC2_EP_DESC_LEN + _UAC2_CS_EP_LEN             # ISO Endpoint + CS Audio EP
)

UAC2_MIC_CONFIG_DESCRIPTOR = bytes([
    # ---- Configuration Descriptor (9) ----
    0x09, 0x02,
    _UAC2_CONFIG_TOTAL & 0xFF, (_UAC2_CONFIG_TOTAL >> 8) & 0xFF,
    0x02,               # bNumInterfaces = 2 (AC, AS)
    0x01,               # bConfigurationValue = 1
    0x00, 0x80, 0xFA,   # iConfiguration=0, bmAttributes=bus-powered, 500mA

    # ---- IAD for Audio (8) ----
    0x08, 0x0B,
    0x00,               # bFirstInterface = 0
    0x02,               # bInterfaceCount = 2
    0x01,               # bFunctionClass = Audio
    0x00,               # bFunctionSubClass
    0x20,               # bFunctionProtocol = AF 2.0
    0x02,               # iFunction = 2

    # ---- AudioControl Interface (9) ----
    0x09, 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x20, 0x00,

    # ---- AC Header (9) — UAC 2.0 ----
    _UAC2_AC_HEADER_LEN, 0x24, 0x01,
    0x00, 0x02,         # bcdADC = 2.00
    0x01,               # bCategory = MICROPHONE
    _UAC2_AC_TOTAL & 0xFF, (_UAC2_AC_TOTAL >> 8) & 0xFF,
    0x00,               # bmControls

    # ---- Clock Source (8) — bClockID = 0x09 ----
    _UAC2_CLOCK_SRC_LEN, 0x24, 0x0A,
    0x09,               # bClockID = 9
    0x01,               # bmAttributes = internal fixed
    0x07,               # bmControls = freq r/w, validity r
    0x00,               # bAssocTerminal
    0x00,               # iClockSource

    # ---- Input Terminal Microphone (17) — UAC 2.0 ----
    _UAC2_INPUT_TERM_LEN, 0x24, 0x02,
    0x01,               # bTerminalID = 1
    0x01, 0x02,         # wTerminalType = 0x0201 (Microphone)
    0x00,               # bAssocTerminal
    0x09,               # bCSourceID = 9 (Clock Source)
    0x02,               # bNrChannels = 2 (stereo)
    0x03, 0x00, 0x00, 0x00,  # bmChannelConfig = FL + FR
    0x00,               # iChannelNames
    0x00, 0x00,         # bmControls
    0x00,               # iTerminal

    # ---- Feature Unit (14) — UAC 2.0 ----
    _UAC2_FEATURE_UNIT_LEN, 0x24, 0x06,
    0x02,               # bUnitID = 2
    0x01,               # bSourceID = 1 (Input Terminal)
    0x0F, 0x00, 0x00, 0x00,  # bmaControls(0) = Mute + Volume + Bass + Mid
    0x0F, 0x00, 0x00, 0x00,  # bmaControls(1)
    0x00,               # iFeature

    # ---- Output Terminal (12) — UAC 2.0 ----
    _UAC2_OUTPUT_TERM_LEN, 0x24, 0x03,
    0x03,               # bTerminalID = 3
    0x01, 0x01,         # wTerminalType = 0x0101 (USB Streaming)
    0x00,               # bAssocTerminal
    0x02,               # bSourceID = 2 (Feature Unit)
    0x09,               # bCSourceID = 9 (Clock Source)
    0x00, 0x00,         # bmControls
    0x00,               # iTerminal

    # ---- AS Interface Alt 0 — zero-bandwidth (9) ----
    0x09, 0x04, 0x01, 0x00, 0x00, 0x01, 0x02, 0x20, 0x00,

    # ---- AS Interface Alt 1 — active (9) ----
    0x09, 0x04, 0x01, 0x01, 0x01, 0x01, 0x02, 0x20, 0x00,

    # ---- AS General (16) — UAC 2.0 ----
    _UAC2_AS_GENERAL_LEN, 0x24, 0x01,
    0x03,               # bTerminalLink = 3 (Output Terminal)
    0x00,               # bmControls
    0x01,               # bFormatType = FORMAT_TYPE_I
    0x01, 0x00, 0x00, 0x00,  # bmFormats = PCM
    0x02,               # bNrChannels = 2
    0x03, 0x00, 0x00, 0x00,  # bmChannelConfig = FL + FR
    0x00,               # iChannelNames

    # ---- AS Format Type I (6) — UAC 2.0 ----
    _UAC2_AS_FORMAT_LEN, 0x24, 0x02,
    0x01,               # bFormatType = FORMAT_TYPE_I
    0x03,               # bSubslotSize = 3 (24-bit)
    0x18,               # bBitResolution = 24

    # ---- ISO Endpoint IN EP2 (7) ----
    0x07, 0x05,
    0x82,               # bEndpointAddress = IN EP2
    0x05,               # bmAttributes = Isochronous, Async
    0x20, 0x01,         # wMaxPacketSize = 288 (48*3*2 = 288 bytes/ms)
    0x01,               # bInterval = 1

    # ---- CS Audio Endpoint (8) — UAC 2.0 ----
    _UAC2_CS_EP_LEN, 0x25, 0x01,
    0x00,               # bmAttributes
    0x00,               # bmControls
    0x00,               # bLockDelayUnits
    0x00, 0x00,         # wLockDelay
])


def _generate_pcm24_chunk(sample_rate: int = 48000, channels: int = 2,
                          duration_ms: float = 1.0, frequency: float = 440.0,
                          frame_no: int = 0) -> bytes:
    """Generate one chunk of 24-bit PCM audio (sine wave).

    Returns raw PCM bytes (little-endian signed 24-bit interleaved).
    """
    import math
    num_samples = int(sample_rate * duration_ms / 1000.0)
    amplitude = 4_000_000
    data = bytearray()
    t_offset = frame_no * num_samples
    for i in range(num_samples):
        t = (t_offset + i) / sample_rate
        val = int(amplitude * math.sin(2 * math.pi * frequency * t))
        val = max(-8_388_608, min(8_388_607, val))
        sample_le = struct.pack('<i', val)[:3]
        for _ in range(channels):
            data += sample_le
    return bytes(data)


def scenario_28(output_dir: Path) -> None:
    """UAC 2.0 microphone — 2s of synthetic 48 kHz / 24-bit / stereo PCM audio."""
    pkts: list = []
    t = BASE_TIME

    cf = control_flow(t, client_port=55028)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56028)
    pkts += emit_data_handshake(df, UAC2_MIC_SUBSTREAMID,
                                usb.UsbSpeed.HIGH_SPEED, UAC2_MIC_BUSID)

    enum_pkts, seq = emit_cam_enumeration(
        df,
        dev_desc=UAC2_MIC_DEVICE_DESCRIPTOR,
        config_desc=UAC2_MIC_CONFIG_DESCRIPTOR,
        str_mfr=UAC2_MIC_STRING_MANUFACTURER,
        str_prod=UAC2_MIC_STRING_PRODUCT,
        str_serial=UAC2_MIC_STRING_SERIAL,
    )
    pkts += enum_pkts

    # Clock Source GET_RANGE: request supported sample rates
    # bmRequestType=0xA1 (class, interface, device-to-host), bRequest=0x02 (RANGE)
    # wValue=0x0100 (SAM_FREQ_CONTROL << 8 | CN=0)
    # wIndex = entityID(9) | (AC_interface(0) << 8) = 0x0009
    clock_range_req = bytes([0xA1, 0x02, 0x00, 0x01, 0x09, 0x00, 0x0E, 0x00])
    clock_range_data = struct.pack('<H', 1) + struct.pack('<III', 48000, 48000, 0)
    pkts.extend(df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=1, binterval=0,
        transferlength=len(clock_range_data), usbdevreq=clock_range_req,
    )))
    df.advance(0.0015)
    pkts.extend(df.client_send(usb.build_usb_control_submit_return(
        seq, 0, 1, len(clock_range_data), 0, clock_range_data,
    )))
    seq += 1
    df.advance(0.001)

    # Clock Source SET_CUR: set sample rate to 48000
    # bmRequestType=0x21 (class, interface, host-to-device), bRequest=0x01 (CUR)
    # wValue=0x0100 (SAM_FREQ_CONTROL << 8 | CN=0)
    # wIndex = entityID(9) | (AC_interface(0) << 8) = 0x0009
    clock_set_req = bytes([0x21, 0x01, 0x00, 0x01, 0x09, 0x00, 0x04, 0x00])
    clock_set_data = struct.pack('<I', 48000)
    pkts.extend(df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=0, binterval=0,
        transferlength=len(clock_set_data), usbdevreq=clock_set_req,
        transferdata=clock_set_data,
    )))
    df.advance(0.0015)
    pkts.extend(df.client_send(usb.build_usb_control_submit_return(
        seq, 0, 0, 0, 0, b'',
    )))
    seq += 1
    df.advance(0.001)

    # SET_INTERFACE(1, alt=1) — activate audio streaming
    set_iface_req = bytes([0x01, USB_REQ_SET_INTERFACE, 0x01, 0x00,
                           0x01, 0x00, 0x00, 0x00])
    pkts.extend(df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=0, binterval=0,
        transferlength=0, usbdevreq=set_iface_req,
    )))
    df.advance(0.0015)
    pkts.extend(df.client_send(usb.build_usb_control_submit_return(
        seq, 0, 0, 0, 0, b'',
    )))
    seq += 1
    df.advance(0.001)

    # Stream 2 seconds of 48 kHz stereo 24-bit audio via ISO on EP 0x82
    sample_rate = 48000
    channels = 2
    duration_s = 2.0
    chunk_ms = 1.0
    num_chunks = int(duration_s * 1000 / chunk_ms)

    for c_idx in range(num_chunks):
        pcm = _generate_pcm24_chunk(sample_rate, channels, chunk_ms,
                                    frequency=440.0, frame_no=c_idx)

        pkts.extend(df.server_send(usb.build_usb_isochronous_submit(
            seq, endpoint=UAC2_MIC_AUDIO_EP_IN, direction=1,
            binterval=1, asap=1, startframe=0,
            num_packets=1, isolengths=[len(pcm)],
        )))
        df.advance(0.0002)
        pkts.extend(df.client_send(usb.build_usb_isochronous_submit_return(
            seq, endpoint=UAC2_MIC_AUDIO_EP_IN, direction=1,
            startframe=c_idx, errorcount=0,
            num_packets=1,
            iso_packets=[(len(pcm), 0)],
            transferdata=pcm,
        )))
        seq += 1
        df.advance(chunk_ms / 1000.0)

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_28_uac2_mic.pcap", pkts)


# ---------------------------------------------------------------------------
# Quirk-exercising scenarios 29–32
# ---------------------------------------------------------------------------

def _device_descriptor_with_vid_pid(desc: bytes, vid: int, pid: int) -> bytes:
    """Return a copy of device descriptor with idVendor (offset 8) and idProduct (offset 10) replaced."""
    arr = bytearray(desc)
    if len(arr) >= 12:
        arr[8], arr[9] = vid & 0xFF, (vid >> 8) & 0xFF
        arr[10], arr[11] = pid & 0xFF, (pid >> 8) & 0xFF
    return bytes(arr)


def emit_uvc_probe_commit_with_minmax(
    df: TcpFlow, seq: int,
    format_index: int = 1, frame_index: int = 1,
    frame_interval: int = 333333,
    min_format: int = 1, min_frame: int = 1, min_interval: int = 333333,
    max_format: int = 1, max_frame: int = 1, max_interval: int = 333333,
    include_get_def: bool = False,
    rtt_s: float = 0.0015,
) -> tuple[list, int]:
    """Emit UVC Probe/Commit with GET_DEF/GET_MIN/GET_MAX responses for quirk-exercising PCAPs."""
    pkts: list = []
    probe_data = _uvc_probe_control(format_index, frame_index, frame_interval)
    min_data = _uvc_probe_control(min_format, min_frame, min_interval)
    max_data = _uvc_probe_control(max_format, max_frame, max_interval)
    probe_len = len(probe_data)

    def ctrl_in(length: int, req: bytes, data: bytes) -> None:
        nonlocal seq
        pkts.extend(df.server_send(usb.build_usb_control_submit(
            seq, endpoint=0, direction=1, binterval=0,
            transferlength=length, usbdevreq=req,
        )))
        df.advance(rtt_s)
        pkts.extend(df.client_send(usb.build_usb_control_submit_return(
            seq, 0, 1, len(data), 0, data,
        )))
        df.advance(rtt_s)
        seq += 1

    def ctrl_out_data(req: bytes, data: bytes) -> None:
        nonlocal seq
        pkts.extend(df.server_send(usb.build_usb_control_submit(
            seq, endpoint=0, direction=0, binterval=0,
            transferlength=len(data), usbdevreq=req, transferdata=data,
        )))
        df.advance(rtt_s)
        pkts.extend(df.client_send(usb.build_usb_control_submit_return(
            seq, 0, 0, 0, 0, b'',
        )))
        df.advance(rtt_s)
        seq += 1

    def ctrl_out(req: bytes) -> None:
        nonlocal seq
        pkts.extend(df.server_send(usb.build_usb_control_submit(
            seq, endpoint=0, direction=0, binterval=0,
            transferlength=0, usbdevreq=req,
        )))
        df.advance(rtt_s)
        pkts.extend(df.client_send(usb.build_usb_control_submit_return(
            seq, 0, 0, 0, 0, b'',
        )))
        df.advance(rtt_s)
        seq += 1

    if include_get_def:
        ctrl_in(probe_len, _uvc_get_def_req(UVC_VS_PROBE_CONTROL, 1, probe_len), probe_data)
    ctrl_in(probe_len, _uvc_get_min_req(UVC_VS_PROBE_CONTROL, 1, probe_len), min_data)
    ctrl_in(probe_len, _uvc_get_max_req(UVC_VS_PROBE_CONTROL, 1, probe_len), max_data)
    ctrl_out_data(_uvc_set_cur_req(UVC_VS_PROBE_CONTROL, 1, probe_len), probe_data)
    ctrl_in(probe_len, _uvc_get_cur_req(UVC_VS_PROBE_CONTROL, 1, probe_len), probe_data)
    ctrl_out_data(_uvc_set_cur_req(UVC_VS_COMMIT_CONTROL, 1, probe_len), probe_data)
    ctrl_out(_set_interface_req(1, 1))

    return pkts, seq


def scenario_29(output_dir: Path) -> None:
    """RESTRICT_FRAME_RATE quirk (04F2:B071 Chicony CNF7129, UVC 0x0040).
    The receiver should override active_interval to the frame's default_interval."""
    pkts: list = []
    t = BASE_TIME

    dev = _device_descriptor_with_vid_pid(CAM_DEVICE_DESCRIPTOR, 0x04F2, 0xB071)

    cf = control_flow(t, client_port=55029)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56029)
    pkts += emit_data_handshake(df, CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID)

    enum_pkts, seq = emit_cam_enumeration(df, dev_desc=dev,
        str_prod=_make_string_descriptor("Chicony CNF7129"))
    pkts += enum_pkts

    pc_pkts, seq = emit_uvc_probe_commit(df, seq)
    pkts += pc_pkts

    vid_pkts, seq = emit_video_stream(df, seq, 640, 480, 30.0, 1.0)
    pkts += vid_pkts

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_29_quirk_restrict_fps.pcap", pkts)


def scenario_30(output_dir: Path) -> None:
    """PROBE_DEF + PROBE_MINMAX quirk (05AC:8501 Apple iSight, UVC 0x0030).
    PCAP includes GET_DEF, GET_MIN, GET_MAX responses so the sim has them queued
    and the receiver's clamping/default paths are exercised."""
    pkts: list = []
    t = BASE_TIME

    dev = _device_descriptor_with_vid_pid(CAM_DEVICE_DESCRIPTOR, 0x05AC, 0x8501)

    cf = control_flow(t, client_port=55030)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56030)
    pkts += emit_data_handshake(df, CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID)

    enum_pkts, seq = emit_cam_enumeration(df, dev_desc=dev,
        str_prod=_make_string_descriptor("Apple iSight"))
    pkts += enum_pkts

    pc_pkts, seq = emit_uvc_probe_commit_with_minmax(
        df, seq,
        format_index=1, frame_index=1, frame_interval=333333,
        min_format=1, min_frame=1, min_interval=333333,
        max_format=1, max_frame=1, max_interval=2000000,
        include_get_def=True,
    )
    pkts += pc_pkts

    vid_pkts, seq = emit_video_stream(df, seq, 640, 480, 30.0, 1.0)
    pkts += vid_pkts

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_30_quirk_probe_def_minmax.pcap", pkts)


def _cam_config_2rates() -> bytes:
    """Config descriptor identical to CAM_CONFIG_DESCRIPTOR but with 2 UAC sample rates
    (48000 + 44100) so the receiver's SET_CUR(Sampling Frequency) path is taken."""
    arr = bytearray(CAM_CONFIG_DESCRIPTOR)
    # Find AS Format Type I: bSamFreqType at offset within the descriptor.
    # The descriptor has bytes 0x0B, 0x24, 0x02 (AS Format Type I header).
    # bSamFreqType is at +7, tSamFreq starts at +8.
    # We need to change bSamFreqType from 1 to 2, insert 3 extra bytes for 44100.
    for i in range(len(arr) - 3):
        if arr[i] == 0x0B and arr[i+1] == 0x24 and arr[i+2] == 0x02:
            # AS Format Type I descriptor at offset i, bLength=0x0B (11)
            freq_type_off = i + 7
            freq_data_off = i + 8
            if arr[freq_type_off] == 0x01:  # bSamFreqType == 1
                arr[freq_type_off] = 0x02
                arr[i] = 0x0E  # bLength: 11 + 3 = 14
                rate_44100 = struct.pack('<I', 44100)[:3]
                arr = arr[:freq_data_off + 3] + bytearray(rate_44100) + arr[freq_data_off + 3:]
                # Update wTotalLength in config descriptor (bytes 2-3)
                new_total = len(arr)
                arr[2] = new_total & 0xFF
                arr[3] = (new_total >> 8) & 0xFF
                break
    return bytes(arr)


def scenario_31(output_dir: Path) -> None:
    """IGNORE_CTL_ERROR quirk (046D:0A0E Logitech Headset, UAC 0x0004).
    Config has 2 sample rates so receiver sends SET_CUR(Sampling Frequency)
    which returns error rstatus.  With the quirk, this is non-fatal."""
    pkts: list = []
    t = BASE_TIME
    rtt_s = 0.0015

    dev = _device_descriptor_with_vid_pid(CAM_DEVICE_DESCRIPTOR, 0x046D, 0x0A0E)
    cfg_2rates = _cam_config_2rates()

    cf = control_flow(t, client_port=55031)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56031)
    pkts += emit_data_handshake(df, CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID)

    enum_pkts, seq = emit_cam_enumeration(df, dev_desc=dev,
        config_desc=cfg_2rates,
        str_prod=_make_string_descriptor("Logitech H340"))
    pkts += enum_pkts

    pc_pkts, seq = emit_uvc_probe_commit(df, seq)
    pkts += pc_pkts

    # UAC activation: SET_INTERFACE(3, alt=1) — succeeds
    pkts.extend(df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=0, binterval=0,
        transferlength=0, usbdevreq=_set_interface_req(3, 1),
    )))
    df.advance(rtt_s)
    pkts.extend(df.client_send(usb.build_usb_control_submit_return(
        seq, 0, 0, 0, 0, b'',
    )))
    df.advance(rtt_s)
    seq += 1

    # SET_CUR(Sampling Frequency) — class request (0x22) returning error rstatus.
    # This is the request the receiver sends on UAC 1.0 when num_sample_rates > 1.
    rate_data = struct.pack('<I', 48000)[:3]
    set_freq_req = struct.pack('<BBHHH', 0x22, 0x01, 0x0100, 0x0082, 0x0003)
    pkts.extend(df.server_send(usb.build_usb_control_submit(
        seq, endpoint=0, direction=0, binterval=0,
        transferlength=3, usbdevreq=set_freq_req, transferdata=rate_data,
    )))
    df.advance(rtt_s)
    pkts.extend(df.client_send(usb.build_usb_control_submit_return(
        seq, 0, 0, 0, 0x80000500, b'',
    )))
    df.advance(rtt_s)
    seq += 1

    vid_pkts, seq = emit_video_stream(df, seq, 640, 480, 30.0, 1.0)
    pkts += vid_pkts

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_31_quirk_ignore_ctl_error.pcap", pkts)


def scenario_32(output_dir: Path) -> None:
    """ALIGN_TRANSFER quirk (0D8C:0102 C-Media CM106, UAC 0x0002).
    Mic audio flow with a quirked VID:PID that triggers alignment logic
    in ipmx_uac_extract_audio."""
    pkts: list = []
    t = BASE_TIME

    dev = _device_descriptor_with_vid_pid(CAM_DEVICE_DESCRIPTOR, 0x0D8C, 0x0102)

    cf = control_flow(t, client_port=55032)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56032)
    pkts += emit_data_handshake(df, CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID)

    enum_pkts, seq = emit_cam_enumeration(df, dev_desc=dev,
        str_prod=_make_string_descriptor("C-Media CM106"))
    pkts += enum_pkts

    uac_pkts, seq = emit_uac_activate(df, seq)
    pkts += uac_pkts

    aud_pkts, seq = emit_audio_stream(df, seq, duration_s=1.0)
    pkts += aud_pkts

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_32_quirk_align_transfer.pcap", pkts)


def _cam_config_no_rates() -> bytes:
    """Config descriptor with bSamFreqType=0 (continuous range, no discrete rates).
    The UAC parser will leave num_sample_rates=0, so active_sample_rate stays 0
    and the RATE_FIX quirk forces it to 48000."""
    arr = bytearray(CAM_CONFIG_DESCRIPTOR)
    for i in range(len(arr) - 3):
        if arr[i] == 0x0B and arr[i + 1] == 0x24 and arr[i + 2] == 0x02:
            freq_type_off = i + 7
            if arr[freq_type_off] == 0x01:
                arr[freq_type_off] = 0x00  # bSamFreqType = 0 (continuous)
                # Replace the 3-byte discrete rate with tLowerSamFreq + tUpperSamFreq (6 bytes)
                # bLength goes from 11 to 14
                freq_data_off = i + 8
                arr[i] = 0x0E  # bLength = 14
                lower = struct.pack('<I', 8000)[:3]
                upper = struct.pack('<I', 96000)[:3]
                arr = arr[:freq_data_off] + bytearray(lower + upper) + arr[freq_data_off + 3:]
                new_total = len(arr)
                arr[2] = new_total & 0xFF
                arr[3] = (new_total >> 8) & 0xFF
                break
    return bytes(arr)


def scenario_33(output_dir: Path) -> None:
    """RATE_FIX quirk (046D:0A45 Logitech H390, UAC 0x0001).
    Config has bSamFreqType=0 (continuous range), so active_sample_rate stays 0
    after parsing. The RATE_FIX quirk forces it to 48000."""
    pkts: list = []
    t = BASE_TIME

    dev = _device_descriptor_with_vid_pid(CAM_DEVICE_DESCRIPTOR, 0x046D, 0x0A45)
    cfg = _cam_config_no_rates()

    cf = control_flow(t, client_port=55033)
    pkts += emit_control_handshake(cf)

    df = data_flow(t + 0.05, client_port=56033)
    pkts += emit_data_handshake(df, CAM_SUBSTREAMID, CAM_USBSPEED, CAM_BUSID)

    enum_pkts, seq = emit_cam_enumeration(df, dev_desc=dev,
        config_desc=cfg,
        str_prod=_make_string_descriptor("Logitech H390"))
    pkts += enum_pkts

    uac_pkts, seq = emit_uac_activate(df, seq)
    pkts += uac_pkts

    aud_pkts, seq = emit_audio_stream(df, seq, duration_s=1.0)
    pkts += aud_pkts

    pkts += df.fin()
    pkts += cf.fin()
    write_pcap(output_dir / "scenario_33_quirk_rate_fix.pcap", pkts)


SCENARIOS = [
    scenario_01, scenario_02, scenario_03, scenario_04, scenario_05,
    scenario_06, scenario_07, scenario_08, scenario_09, scenario_10,
    scenario_11, scenario_12, scenario_13, scenario_14,
    scenario_15, scenario_16, scenario_17, scenario_18, scenario_19,
    scenario_20, scenario_21, scenario_22, scenario_23, scenario_24,
    scenario_25, scenario_26, scenario_27, scenario_28, scenario_29,
    scenario_30, scenario_31, scenario_32, scenario_33,
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate IPMX USB test PCAPs")
    parser.add_argument(
        '--output-dir', '--out', default='test_pcaps',
        dest='output_dir',
        help="Directory to write PCAP files (default: test_pcaps/)",
    )
    parser.add_argument(
        '--scenario', type=int, default=0,
        help="Run only scenario N (1–33); 0 = all (default)",
    )
    parser.add_argument(
        '--psk', type=str, default=None,
        help="Pre-Shared Key as hex string — enables real PEP encryption",
    )
    parser.add_argument(
        '--psk-file', type=str, default=None,
        help="Pre-Shared Key from binary file",
    )
    parser.add_argument(
        '--sdp', type=str, default=None,
        help="Write SDP transport file with privacy parameters",
    )
    args = parser.parse_args()

    _init_pep(args.psk, args.psk_file)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    scenarios = SCENARIOS if args.scenario == 0 else [SCENARIOS[args.scenario - 1]]

    custom_psk = bool(args.psk or args.psk_file)
    print(f"PEP encryption: mode={_pep_params.mode.value}  "  # type: ignore[union-attr]
          f"key={_pep_key.hex()}"                              # type: ignore[union-attr]
          f"{'  (default PSK)' if not custom_psk else ''}")

    print(f"Generating {len(scenarios)} PCAP(s) in {output_dir}/")
    for fn in scenarios:
        fn(output_dir)

    if args.sdp:
        _pep_params.write_sdp(  # type: ignore[union-attr]
            args.sdp, sender_ip=SENDER_IP, sender_port=SENDER_CTRL_PORT)
        print(f"  Wrote SDP transport file -> {args.sdp}")

    print("Done.")


if __name__ == '__main__':
    main()
