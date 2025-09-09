#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025, Matrox Graphics Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions, and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions, and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""SDP to CCF Capabilities Converter

This module provides functionality to convert SDP (Session Description Protocol)
files into CCF (Constraint-Capability Framework) capabilities using the MatroxSdp
parser and MatroxCCF framework.
"""

from typing import Optional, List, Set, Dict, Any
from fractions import Fraction
from .MatroxSdp import MatroxSdp, MediaDescriptor, TargetSpecification
from .MatroxCCF import (
    Caps, CapSet, Capability, RangeValue, RangeType,
    FormatVideo, FormatAudio, FormatData, FormatMux,
    CapFormatMediaType, CapFormatGrainRate, CapFormatFrameWidth, CapFormatFrameHeight,
    CapFormatInterlaceMode, CapFormatColorspace, CapFormatTransferCharacteristic,
    CapFormatColorSampling, CapFormatComponentDepth, CapFormatChannelCount,
    CapFormatSampleRate, CapFormatSampleDepth, CapFormatBitRate, CapFormatProfile,
    CapFormatLevel, CapFormatSublevel, CapFormatConstantBitRate, CapFormatVideoLayers,
    CapFormatAudioLayers, CapFormatDataLayers, CapTransportBitRate,
    CapTransportPacketTime, CapTransportMaxPacketTime, CapTransport_ST2110_21_SenderType,
    CapTransportPacketTransmissionMode, CapTransportParameterSetsFlowMode,
    CapTransportParameterSetsTransportMode, CapTransportChannelOrder,
    CapTransportHkep, CapTransportPrivacy, CapTransportClockRefType,
    CapTransportInfoBlock, CapTransportSynchronousMedia, CapMetaLabel,
    CapMetaPreference, CapMetaFormat, CapMetaLayer, CapMetaLayerCompatibilityGroups
)

class SdpToCapabilitiesConverter:
    """Converts SDP files to CCF Capabilities"""
    
    def __init__(self):
        self.sdp = MatroxSdp()
        
    def convert_file(self, sdp_file_path: str) -> Caps:
        """
        Convert an SDP file to CCF Capabilities
        
        Args:
            sdp_file_path: Path to the SDP file
            
        Returns:
            Caps: CCF Capabilities structure
        """
        with open(sdp_file_path, 'r') as f:
            sdp_content = f.read()
            
        return self.convert_string(sdp_content)
        
    def convert_string(self, sdp_content: str) -> Caps:
        """
        Convert SDP content string to CCF Capabilities
        
        Args:
            sdp_content: SDP content as string
            
        Returns:
            Caps: CCF Capabilities structure
        """
        # Parse SDP
        error = self.sdp.decode(sdp_content)
        if error:
            raise ValueError(f"SDP parsing error: {error}")
            
        # Convert to capabilities
        return self._convert_sdp_to_caps()
        
    def _convert_sdp_to_caps(self) -> Caps:
        """
        Convert parsed SDP to CCF Capabilities
        
        Returns:
            Caps: CCF Capabilities structure
        """
        capsets: List[CapSet] = []
        
        # Handle primary media
        if self.sdp.primary_media:
            primary_capset = self._convert_media_to_capset(
                self.sdp.primary_media, 
                "Primary", 
                preference=100
            )
            
            # Handle secondary media (redundancy) - verify it's identical to primary
            if (self.sdp.secondary_media and 
                self.sdp.has_group_attribute and 
                self.sdp.secondary_media != self.sdp.primary_media):
                
                secondary_capset = self._convert_media_to_capset(
                    self.sdp.secondary_media, 
                    "Secondary_Verification", 
                    preference=90
                )
                
                # Verify capabilities are identical
                if not self._verify_capabilities_identical(primary_capset, secondary_capset):
                    raise ValueError(
                        "Secondary media capabilities must be identical to primary media for redundancy. "
                        "Found differences between primary and secondary streams."
                    )
                
                # Add redundancy metadata to primary capset
                primary_capset.label = "Primary (with redundancy)"
                # Could add redundancy capability here if needed
            
            capsets.append(primary_capset)
            
        return Caps(capsets=capsets)
        
    def _verify_capabilities_identical(self, primary_capset: CapSet, secondary_capset: CapSet) -> bool:
        """
        Verify that two CapSets have identical capabilities (for redundancy verification)
        
        Args:
            primary_capset: Primary media CapSet
            secondary_capset: Secondary media CapSet
            
        Returns:
            bool: True if capabilities are identical, False otherwise
        """
        # Check if they have the same capability parameter names
        primary_params = set(primary_capset.caps.keys())
        secondary_params = set(secondary_capset.caps.keys())
        
        if primary_params != secondary_params:
            return False
            
        # Check if each capability has the same value
        for param_name in primary_params:
            primary_cap = primary_capset.caps[param_name]
            secondary_cap = secondary_capset.caps[param_name]
            
            # Compare capability values
            if (primary_cap.value.infinite != secondary_cap.value.infinite or
                primary_cap.value.empty != secondary_cap.value.empty or
                primary_cap.value.type != secondary_cap.value.type or
                primary_cap.value.min != secondary_cap.value.min or
                primary_cap.value.max != secondary_cap.value.max or
                primary_cap.value.enumerated != secondary_cap.value.enumerated):
                return False
                
        return True
        
    def _convert_media_to_capset(self, media: MediaDescriptor, label: str, preference: int = 100) -> CapSet:
        """
        Convert a MediaDescriptor to a CapSet
        
        Args:
            media: MediaDescriptor from SDP
            label: Label for the CapSet
            preference: Preference value for the CapSet
            
        Returns:
            CapSet: Converted capability set
        """
        capabilities: Dict[str, Capability] = {}
        format_type = self._determine_format_type(media)
        
        # Media type capability
        if format_type:
            media_type = self._get_media_type_from_format(format_type, media)
            if media_type:
                capabilities[CapFormatMediaType] = Capability(
                    CapFormatMediaType,
                    RangeValue(values=(media_type,), type=RangeType.STRING)
                )
        
        # Format-specific capabilities
        if format_type == FormatVideo:
            self._add_video_capabilities(media, capabilities)
        elif format_type == FormatAudio:
            self._add_audio_capabilities(media, capabilities)
        elif format_type == FormatData:
            self._add_data_capabilities(media, capabilities)
            
        # Transport capabilities
        self._add_transport_capabilities(media, capabilities)
        
        # IPMX-specific capabilities
        if media.ipmx:
            self._add_ipmx_capabilities(media, capabilities)
            
        return CapSet(
            caps=capabilities,
            label=label,
            preference=preference,
            format=format_type if not self.sdp.has_group_attribute else None,
            layer=None  # Will be set for hierarchical structures
        )
        
    def _determine_format_type(self, media: MediaDescriptor) -> Optional[str]:
        """Determine the NMOS format type from media descriptor"""
        if media.type is None:
            return None
            
        type_name = media.type.name if hasattr(media.type, 'name') else str(media.type)
        
        if type_name.lower() == 'video':
            # Check if this is actually data (ST 2110-40)
            if media.encoding_name and hasattr(media.encoding_name, 'name'):
                encoding = media.encoding_name.name.lower()
                if encoding == 'smpte291':
                    return FormatData
            return FormatVideo
        elif type_name.lower() == 'audio':
            return FormatAudio
        elif type_name.lower() == 'application':
            return FormatData
        else:
            return None
            
    def _get_media_type_from_format(self, format_type: str, media: MediaDescriptor) -> Optional[str]:
        """Get the media type string for capabilities"""
        if not media.encoding_name:
            return None
            
        encoding = media.encoding_name.name if hasattr(media.encoding_name, 'name') else str(media.encoding_name)
        
        if format_type == FormatVideo:
            if encoding.lower() == 'raw':
                return "video/raw"
            elif encoding.lower().startswith('jxsv'):
                return "video/jxsv"
            elif encoding.lower().startswith('h264'):
                return "video/H264"
            elif encoding.lower().startswith('h265'):
                return "video/H265"
        elif format_type == FormatAudio:
            if encoding.lower().startswith('l'):
                return f"audio/{encoding}"
            elif encoding.lower() == 'mpeg4-generic':
                return "audio/mpeg4-generic"
        elif format_type == FormatData:
            return "video/smpte291"
            
        return None
        
    def _add_video_capabilities(self, media: MediaDescriptor, capabilities: Dict[str, Capability]):
        """Add video-specific capabilities"""
        # Frame rate
        if media.exact_frame_rate_numerator > 0:
            denominator = media.exact_frame_rate_denominator if media.exact_frame_rate_denominator > 0 else 1
            frame_rate = Fraction(media.exact_frame_rate_numerator, denominator)
            capabilities[CapFormatGrainRate] = Capability(
                CapFormatGrainRate,
                RangeValue(values=(frame_rate,), type=RangeType.RATIONAL)
            )
            
        # Frame dimensions
        if media.width > 0:
            capabilities[CapFormatFrameWidth] = Capability(
                CapFormatFrameWidth,
                RangeValue(values=(media.width,), type=RangeType.INT)
            )
            
        if media.height > 0:
            capabilities[CapFormatFrameHeight] = Capability(
                CapFormatFrameHeight,
                RangeValue(values=(media.height,), type=RangeType.INT)
            )
            
        # Interlace mode
        interlace_mode = "progressive"
        if media.interlaced:
            interlace_mode = "interlaced_tff" if media.top_field_first else "interlaced_bff"
        elif media.segmented:
            interlace_mode = "interlaced_psf"
            
        capabilities[CapFormatInterlaceMode] = Capability(
            CapFormatInterlaceMode,
            RangeValue(values=(interlace_mode,), type=RangeType.STRING)
        )
        
        # Colorimetry
        if media.colorimetry:
            colorspace = media.colorimetry.name if hasattr(media.colorimetry, 'name') else str(media.colorimetry)
            capabilities[CapFormatColorspace] = Capability(
                CapFormatColorspace,
                RangeValue(values=(colorspace,), type=RangeType.STRING)
            )
            
        # Transfer characteristic
        if media.transfer_characteristic:
            transfer_char = media.transfer_characteristic.name if hasattr(media.transfer_characteristic, 'name') else str(media.transfer_characteristic)
            capabilities[CapFormatTransferCharacteristic] = Capability(
                CapFormatTransferCharacteristic,
                RangeValue(values=(transfer_char,), type=RangeType.STRING)
            )
            
        # Color sampling
        if media.sampling:
            sampling = media.sampling.name if hasattr(media.sampling, 'name') else str(media.sampling)
            capabilities[CapFormatColorSampling] = Capability(
                CapFormatColorSampling,
                RangeValue(values=(sampling,), type=RangeType.STRING)
            )
            
        # Component depth
        if media.depth > 0:
            capabilities[CapFormatComponentDepth] = Capability(
                CapFormatComponentDepth,
                RangeValue(values=(media.depth,), type=RangeType.INT)
            )
            
        # Profile/Level for coded formats
        if media.profile:
            profile = media.profile.name if hasattr(media.profile, 'name') else str(media.profile)
            capabilities[CapFormatProfile] = Capability(
                CapFormatProfile,
                RangeValue(values=(profile,), type=RangeType.STRING)
            )
            
        if media.level:
            level = media.level.name if hasattr(media.level, 'name') else str(media.level)
            capabilities[CapFormatLevel] = Capability(
                CapFormatLevel,
                RangeValue(values=(level,), type=RangeType.STRING)
            )
            
        if media.sub_level:
            sublevel = media.sub_level.name if hasattr(media.sub_level, 'name') else str(media.sub_level)
            capabilities[CapFormatSublevel] = Capability(
                CapFormatSublevel,
                RangeValue(values=(sublevel,), type=RangeType.STRING)
            )
            
    def _add_audio_capabilities(self, media: MediaDescriptor, capabilities: Dict[str, Capability]):
        """Add audio-specific capabilities"""
        # Channel count
        if media.channels > 0:
            capabilities[CapFormatChannelCount] = Capability(
                CapFormatChannelCount,
                RangeValue(values=(media.channels,), type=RangeType.INT)
            )
            
        # Sample rate
        if media.sample_rate > 0:
            # Convert to rational for precise representation
            sample_rate = Fraction(media.sample_rate, 1)
            capabilities[CapFormatSampleRate] = Capability(
                CapFormatSampleRate,
                RangeValue(values=(sample_rate,), type=RangeType.RATIONAL)
            )
            
        # Sample depth (infer from format)
        if media.encoding_name:
            encoding = media.encoding_name.name if hasattr(media.encoding_name, 'name') else str(media.encoding_name)
            if encoding.startswith('L'):
                try:
                    # Extract bit depth from encoding name like "L24", "L16"
                    depth = int(encoding[1:])
                    capabilities[CapFormatSampleDepth] = Capability(
                        CapFormatSampleDepth,
                        RangeValue(values=(depth,), type=RangeType.INT)
                    )
                except ValueError:
                    pass
                    
        # Packet time
        if media.p_time_us > 0:
            packet_time_ms = media.p_time_us / 1000.0  # Convert microseconds to milliseconds
            capabilities[CapTransportPacketTime] = Capability(
                CapTransportPacketTime,
                RangeValue(values=(packet_time_ms,), type=RangeType.FLOAT)
            )
            
        if media.max_p_time_us > 0:
            max_packet_time_ms = media.max_p_time_us / 1000.0
            capabilities[CapTransportMaxPacketTime] = Capability(
                CapTransportMaxPacketTime,
                RangeValue(values=(max_packet_time_ms,), type=RangeType.FLOAT)
            )
            
    def _add_data_capabilities(self, media: MediaDescriptor, capabilities: Dict[str, Capability]):
        """Add data-specific capabilities"""
        # For ST 2110-40 ancillary data
        if media.did_sdid:
            # This would typically map to event_type for data streams
            pass
            
    def _add_transport_capabilities(self, media: MediaDescriptor, capabilities: Dict[str, Capability]):
        """Add transport-specific capabilities"""
        # Bit rate
        if media.bitrate_kbits > 0:
            bitrate_bps = media.bitrate_kbits * 1000  # Convert kbps to bps
            capabilities[CapTransportBitRate] = Capability(
                CapTransportBitRate,
                RangeValue(values=(bitrate_bps,), type=RangeType.INT)
            )
            
        # ST 2110-21 sender type
        if media.sender_type:
            sender_type = media.sender_type.name if hasattr(media.sender_type, 'name') else str(media.sender_type)
            capabilities[CapTransport_ST2110_21_SenderType] = Capability(
                CapTransport_ST2110_21_SenderType,
                RangeValue(values=(sender_type,), type=RangeType.STRING)
            )
            
        # Packet transmission mode
        if media.packing_mode:
            packing_mode = media.packing_mode.name if hasattr(media.packing_mode, 'name') else str(media.packing_mode)
            capabilities[CapTransportPacketTransmissionMode] = Capability(
                CapTransportPacketTransmissionMode,
                RangeValue(values=(packing_mode,), type=RangeType.STRING)
            )
            
        # HKEP
        if media.hkep:
            capabilities[CapTransportHkep] = Capability(
                CapTransportHkep,
                RangeValue(values=(True,), type=RangeType.BOOL)
            )
            
        # Privacy
        if media.privacy:
            capabilities[CapTransportPrivacy] = Capability(
                CapTransportPrivacy,
                RangeValue(values=(True,), type=RangeType.BOOL)
            )
            
        # Channel order for audio
        if media.channel_order:
            capabilities[CapTransportChannelOrder] = Capability(
                CapTransportChannelOrder,
                RangeValue(values=(media.channel_order,), type=RangeType.STRING)
            )
            
    def _add_ipmx_capabilities(self, media: MediaDescriptor, capabilities: Dict[str, Capability]):
        """Add IPMX-specific capabilities"""
        # Add Matrox-specific capabilities for IPMX streams
        # This could include additional transport parameters, etc.
        pass
        


def convert_sdp_file_to_capabilities(sdp_file_path: str) -> Caps:
    """
    Convenience function to convert an SDP file to CCF Capabilities
    
    Args:
        sdp_file_path: Path to the SDP file
        
    Returns:
        Caps: CCF Capabilities structure
    """
    converter = SdpToCapabilitiesConverter()
    return converter.convert_file(sdp_file_path)


def convert_sdp_string_to_capabilities(sdp_content: str) -> Caps:
    """
    Convenience function to convert SDP content to CCF Capabilities
    
    Args:
        sdp_content: SDP content as string
        
    Returns:
        Caps: CCF Capabilities structure
    """
    converter = SdpToCapabilitiesConverter()
    return converter.convert_string(sdp_content)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python SdpToCapabilities.py <sdp_file_path>")
        sys.exit(1)
        
    sdp_file = sys.argv[1]
    
    try:
        caps = convert_sdp_file_to_capabilities(sdp_file)
        print("Converted SDP to CCF Capabilities:")
        print(caps)
        
        # Example of using the capabilities
        print("\nTrunk capabilities:")
        trunk_caps = caps.get(format=FormatMux)
        print(trunk_caps)
        
        print("\nVideo layer capabilities:")
        video_caps = caps.get(format=FormatVideo)
        print(video_caps)
        
        print("\nAudio layer capabilities:")
        audio_caps = caps.get(format=FormatAudio)
        print(audio_caps)
        
    except Exception as e:
        print(f"Error converting SDP: {e}")
        sys.exit(1)

