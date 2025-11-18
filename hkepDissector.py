#!/usr/bin/env python3
"""
HKEP (HDCP Key Exchange Protocol) Dissector for PCAP files
Converted from Lua Wireshark dissector by Ryosuke Yamamoto

Copyright (c) 2024, Matrox Graphics Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import struct
import sys
from typing import Dict, List, Tuple, Optional

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    from scapy.packet import Packet
    from scapy.utils import PcapReader
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)


class HKEPExchange:
    """Represents a single HKEP protocol exchange (TCP connection)"""

    def __init__(self, stream_key: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        self.stream_key = stream_key
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.messages = []
        self.start_time = None
        self.end_time = None
        self.connection_state = 'unknown'
        self.disconnection_reason = None

    def add_message(self, message: Dict):
        """Add a message to this exchange"""
        self.messages.append(message)

        # Update timing
        msg_time = message.get('timestamp', 0)
        if self.start_time is None or msg_time < self.start_time:
            self.start_time = msg_time
        if self.end_time is None or msg_time > self.end_time:
            self.end_time = msg_time

    def get_messages(self) -> List[Dict]:
        """Get all messages in chronological order"""
        return sorted(self.messages, key=lambda x: x.get('timestamp', 0))

    def get_messages_by_type(self, msg_type: str) -> List[Dict]:
        """Get all messages of a specific type"""
        return [msg for msg in self.messages if msg.get('hkep', {}).get('message_type') == msg_type]

    def get_message_count(self) -> int:
        """Get total number of messages"""
        return len(self.messages)

    def get_duration(self) -> float:
        """Get duration of the exchange in seconds"""
        if self.start_time is None or self.end_time is None:
            return 0.0
        return self.end_time - self.start_time

    def get_encoder_messages(self) -> List[Dict]:
        """Get messages sent from encoder to decoder"""
        return [msg for msg in self.messages if msg.get('hkep', {}).get('direction') == 'Encoder->Decoder']

    def get_decoder_messages(self) -> List[Dict]:
        """Get messages sent from decoder to encoder"""
        return [msg for msg in self.messages if msg.get('hkep', {}).get('direction') == 'Decoder->Encoder']

    def is_successful(self) -> bool:
        """Check if the exchange completed successfully"""
        return self.disconnection_reason is None or self.disconnection_reason == 'FIN'

    def __str__(self):
        return f"HKEPExchange({self.stream_key}, {self.get_message_count()} messages, {self.get_duration():.3f}s)"


class HKEPAnalysisResult:
    """Container for HKEP analysis results"""

    def __init__(self):
        self.exchanges = []
        self.total_packets = 0
        self.total_messages = 0

    def add_exchange(self, exchange: HKEPExchange):
        """Add an exchange to the results"""
        self.exchanges.append(exchange)
        self.total_messages += exchange.get_message_count()

    def get_all_exchanges(self) -> List[HKEPExchange]:
        """Get all exchanges"""
        return self.exchanges

    def get_successful_exchanges(self) -> List[HKEPExchange]:
        """Get exchanges that completed successfully"""
        return [ex for ex in self.exchanges if ex.is_successful()]

    def get_failed_exchanges(self) -> List[HKEPExchange]:
        """Get exchanges that failed or were aborted"""
        return [ex for ex in self.exchanges if not ex.is_successful()]

    def get_exchange_by_stream_key(self, stream_key: str) -> Optional[HKEPExchange]:
        """Get exchange by stream key"""
        for ex in self.exchanges:
            if ex.stream_key == stream_key:
                return ex
        return None

    def get_exchange_count(self) -> int:
        """Get total number of exchanges"""
        return len(self.exchanges)

    def __str__(self):
        return f"HKEPAnalysisResult({self.get_exchange_count()} exchanges, {self.total_messages} messages)"


class HKEPDissector:
    """HKEP Protocol Dissector"""
    
    # HKEP Message Types
    MSG_TYPES = {
        1: "Null message",
        2: "AKE_Init",
        3: "AKE_Send_Cert",
        4: "AKE_No_Stored_km",
        5: "AKE_Stored_km",
        6: "AKE_Send_rrx",
        7: "AKE_Send_H_prime",
        8: "AKE_Send_Pairing_Info",
        9: "LC_Init",
        10: "LC_Send_L_prime",
        11: "SKE_Send_Eks",
        12: "RepeaterAuth_Send_ReceiverID_List",
        13: "RTT_Ready",
        14: "RTT_Challenge",
        15: "RepeaterAuth_Send_Ack",
        16: "RepeaterAuth_Stream_Manage",
        17: "RepeaterAuth_Stream_Ready",
        18: "Receiver_AuthStatus",
        19: "AKE_Transmitter_Info",
        20: "AKE_Receiver_Info",
        32: "AKE_PreInit",
        33: "AKE_PreInitStatus"
    }
    
    def __init__(self, target_port: Optional[int] = None):
        """
        Initialize the HKEP dissector
        
        Args:
            target_port: TCP port to filter for HKEP traffic (None = auto-detect)
        """
        self.target_port = target_port
        self.tcp_streams = {}  # Track TCP streams for reassembly
        self.seen_packets = set()  # Track packet hashes to detect retransmissions
        
    def bytes_to_hex(self, data: bytes) -> str:
        """Convert bytes to hex string representation"""
        return data.hex()
    
    def dissect_null_message(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 1: Null message"""
        return {
            "message_type": "Null message",
            "msg_size": msg_size,
            "msg_id": 1
        }
    
    def dissect_ake_init(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 2: AKE_Init (Encoder->Decoder)"""
        r_tx = data[3:11]
        return {
            "message_type": "AKE_Init",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 2,
            "r_tx[63:0]": self.bytes_to_hex(r_tx)
        }
    
    def dissect_ake_send_cert(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 3: AKE_Send_Cert (Decoder->Encoder)"""
        # AKE_Send_Cert should be 526 bytes total (2 header + 524 data)
        # But msg_size includes msg_id, so msg_size should be 524
        # Total = 2 + 524 = 526
        
        if len(data) < 4:
            raise ValueError(f"AKE_Send_Cert requires at least 4 bytes, got {len(data)}")
        
        repeater = data[3] == 1 if len(data) > 3 else False
        
        # Extract fields with bounds checking
        cert_rx = data[4:min(526, len(data))] if len(data) > 4 else b''
        receiver_id = data[4:9] if len(data) >= 9 else data[4:] if len(data) > 4 else b''
        receiver_pubkey = data[9:140] if len(data) >= 140 else data[9:] if len(data) > 9 else b''
        
        # Parse protocol descriptor
        if len(data) >= 142:
            protocol_descriptor_bytes = data[140:142]
            protocol_descriptor = struct.unpack('>H', protocol_descriptor_bytes)[0]
            sertrx_reserved = protocol_descriptor % 4096
            protocol_descriptor = (protocol_descriptor - sertrx_reserved) // 4096
        else:
            protocol_descriptor = 0
            sertrx_reserved = 0
        
        dcp_signature = data[142:526] if len(data) >= 526 else data[142:] if len(data) > 142 else b''
        
        return {
            "message_type": "AKE_Send_Cert",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 3,
            "REPEATER": repeater,
            "cert_rx[4175:0]": self.bytes_to_hex(cert_rx),
            "Receiver_ID": self.bytes_to_hex(receiver_id),
            "Receiver_Public_Key": self.bytes_to_hex(receiver_pubkey),
            "Protocol_Descriptor": protocol_descriptor,
            "Reserved": sertrx_reserved,
            "DCP_LLC_Signature": self.bytes_to_hex(dcp_signature)
        }
    
    def dissect_ake_no_stored_km(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 4: AKE_No_Stored_km (Encoder->Decoder)"""
        ekpub_km = data[3:131]
        return {
            "message_type": "AKE_No_Stored_km",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 4,
            "Ekpub_km[1023:0]": self.bytes_to_hex(ekpub_km)
        }
    
    def dissect_ake_stored_km(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 5: AKE_Stored_km (Encoder->Decoder)"""
        ekh_km = data[3:19]
        m = data[19:35]
        return {
            "message_type": "AKE_Stored_km",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 5,
            "Ekh_km[127:0]": self.bytes_to_hex(ekh_km),
            "m[127:0]": self.bytes_to_hex(m)
        }
    
    def dissect_ake_send_rrx(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 6: AKE_Send_rrx (Decoder->Encoder)"""
        r_rx = data[3:11]
        return {
            "message_type": "AKE_Send_rrx",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 6,
            "r_rx[63:0]": self.bytes_to_hex(r_rx)
        }
    
    def dissect_ake_send_h_prime(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 7: AKE_Send_H_prime (Decoder->Encoder)"""
        h_prime = data[3:35]
        return {
            "message_type": "AKE_Send_H_prime",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 7,
            "H'[255:0]": self.bytes_to_hex(h_prime)
        }
    
    def dissect_ake_send_pairing_info(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 8: AKE_Send_Pairing_Info (Decoder->Encoder)"""
        ekh_km = data[3:19]
        return {
            "message_type": "AKE_Send_Pairing_Info",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 8,
            "Ekh_km[127:0]": self.bytes_to_hex(ekh_km)
        }
    
    def dissect_lc_init(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 9: LC_Init (Encoder->Decoder)"""
        r_n = data[3:11]
        return {
            "message_type": "LC_Init",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 9,
            "r_n[63:0]": self.bytes_to_hex(r_n)
        }
    
    def dissect_lc_send_l_prime(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 10: LC_Send_L_prime (Decoder->Encoder)"""
        result = {
            "message_type": "LC_Send_L_prime",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 10
        }
        
        if msg_size == 35:
            result["L'[255:0]"] = self.bytes_to_hex(data[3:35])
        else:
            result["L'[255:128]"] = self.bytes_to_hex(data[3:19])
            
        return result
    
    def dissect_ske_send_eks(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 11: SKE_Send_Eks (Encoder->Decoder)"""
        edkey_ks = data[3:19]
        r_iv = data[19:27]
        
        result = {
            "message_type": "SKE_Send_Eks",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 11,
            "Edkey_Ks[127:0]": self.bytes_to_hex(edkey_ks),
            "r_iv[63:0]": self.bytes_to_hex(r_iv)
        }
        
        if msg_size == 59:
            result["HMAC(r_iv)[255:0]"] = self.bytes_to_hex(data[27:59])
            result["note"] = "The receiver complies with HDCP2.3 or higher."
        else:
            result["note"] = "The receiver is not compliant with HDCP2.3 or above."
            
        return result
    
    def dissect_repeaterauth_send_receiverid_list(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 12: RepeaterAuth_Send_ReceiverID_List (Decoder->Encoder)"""
        max_devs_exceeded = data[3] == 1
        max_cascade_exceeded = data[4] == 1
        repeaterauth_type = (msg_size - 39) % 5
        
        result = {
            "message_type": "RepeaterAuth_Send_ReceiverID_List",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 12,
            "HDCP_2.0_compliant": repeaterauth_type == 0,
            "MAX_DEVS_EXCEEDED": max_devs_exceeded,
            "MAX_CASCADE_EXCEEDED": max_cascade_exceeded
        }
        
        if not max_devs_exceeded and not max_cascade_exceeded:
            device_count = data[5]
            depth = data[6]
            result["DEVICE_COUNT"] = device_count
            result["DEPTH"] = depth
            
            if repeaterauth_type == 0:
                result["V'[255:0]"] = self.bytes_to_hex(data[7:39])
                j_max = (msg_size - 39) // 5
                receiver_ids = []
                for j in range(j_max):
                    offset = 39 + (j * 5)
                    receiver_ids.append(self.bytes_to_hex(data[offset:offset+5]))
                result["Receiver_IDs"] = receiver_ids
            else:
                result["HDCP2_LEGACY_DEVICE_DOWNSTREAM"] = data[7] == 1
                result["HDCP1_DEVICE_DOWNSTREAM"] = data[8] == 1
                result["seq_num_V"] = struct.unpack('>I', b'\x00' + data[9:12])[0]
                result["V'[255:128]"] = self.bytes_to_hex(data[12:28])
                j_max = (msg_size - 28) // 5
                receiver_ids = []
                for j in range(j_max):
                    offset = 28 + (j * 5)
                    receiver_ids.append(self.bytes_to_hex(data[offset:offset+5]))
                result["Receiver_IDs"] = receiver_ids
                
        return result
    
    def dissect_rtt_ready(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 13: RTT_Ready (Decoder->Encoder)"""
        return {
            "message_type": "RTT_Ready",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 13
        }
    
    def dissect_rtt_challenge(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 14: RTT_Challenge (Encoder->Decoder)"""
        l_value = data[3:19]
        return {
            "message_type": "RTT_Challenge",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 14,
            "L[127:0]": self.bytes_to_hex(l_value)
        }
    
    def dissect_repeaterauth_send_ack(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 15: RepeaterAuth_Send_Ack (Encoder->Decoder)"""
        v_value = data[3:19]
        return {
            "message_type": "RepeaterAuth_Send_Ack",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 15,
            "V[127:0]": self.bytes_to_hex(v_value)
        }
    
    def dissect_repeaterauth_stream_manage(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 16: RepeaterAuth_Stream_Manage (Encoder->Decoder)"""
        seq_num_m = struct.unpack('>I', b'\x00' + data[3:6])[0]
        k_value = struct.unpack('>H', data[6:8])[0]
        
        result = {
            "message_type": "RepeaterAuth_Stream_Manage",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 16,
            "seq_num_M": seq_num_m,
            "k": k_value,
            "streams": []
        }
        
        for j in range(k_value):
            offset = 8 + (j * 12)
            stream_ctr = self.bytes_to_hex(data[offset:offset+4])
            content_stream_id = data[offset+4:offset+11]
            
            # Parse IP address (can be IPv4 or IPv6)
            ip_bytes = data[offset+4:offset+8]
            ipv4 = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
            ipv6 = f"::{self.bytes_to_hex(data[offset+4:offset+6])}:{self.bytes_to_hex(data[offset+6:offset+8])}"
            
            udp_port = struct.unpack('>H', data[offset+8:offset+10])[0]
            payload_type = data[offset+10]
            stream_type = data[offset+11]
            
            stream_info = {
                "stream_number": j + 1,
                "streamCtr": stream_ctr,
                "ContentStreamID": self.bytes_to_hex(content_stream_id),
                "Destination_IPv4": ipv4,
                "Destination_IPv6": ipv6,
                "Destination_UDP_Port": udp_port,
                "Payload_Type": payload_type,
                "Type": stream_type
            }
            result["streams"].append(stream_info)
            
        return result
    
    def dissect_repeaterauth_stream_ready(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 17: RepeaterAuth_Stream_Ready (Decoder->Encoder)"""
        m_prime = data[3:35]
        return {
            "message_type": "RepeaterAuth_Stream_Ready",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 17,
            "M'[255:0]": self.bytes_to_hex(m_prime)
        }
    
    def dissect_receiver_authstatus(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 18: Receiver_AuthStatus (Decoder->Encoder)"""
        length = struct.unpack('>H', data[3:5])[0]
        reauth_req = data[4] == 1
        return {
            "message_type": "Receiver_AuthStatus",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 18,
            "LENGTH": length,
            "REAUTH_REQ": reauth_req
        }
    
    def dissect_ake_transmitter_info(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 19: AKE_Transmitter_Info (Encoder->Decoder)"""
        length = struct.unpack('>H', data[3:5])[0]
        version = data[5]
        transinfo_tmp = struct.unpack('>H', data[6:8])[0]
        
        transinfo_cap_msk = transinfo_tmp % 4
        transinfo_reserved = (transinfo_tmp - transinfo_cap_msk) // 4
        transinfo_locality_precompute = transinfo_cap_msk % 2
        transinfo_ccont_category = (transinfo_cap_msk - transinfo_locality_precompute) // 2
        
        return {
            "message_type": "AKE_Transmitter_Info",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 19,
            "LENGTH": length,
            "VERSION": version,
            "TRANSMITTER_CAPABILITY_MASK": hex(transinfo_tmp),
            "Reserved": hex(transinfo_reserved),
            "TRANSMITTER_CONTENT_CATEGORY_SUPPORT": transinfo_ccont_category == 1,
            "TRANSMITTER_LOCALITY_PRECOMPUTE_SUPPORT": transinfo_locality_precompute == 1
        }
    
    def dissect_ake_receiver_info(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 20: AKE_Receiver_Info (Decoder->Encoder)"""
        length = struct.unpack('>H', data[3:5])[0]
        version = data[5]
        receiverinfo_tmp = struct.unpack('>H', data[6:8])[0]
        
        receiverinfo_cap_msk = receiverinfo_tmp % 2
        receiverinfo_reserved = (receiverinfo_tmp - receiverinfo_cap_msk) // 2
        receiverinfo_locality_precompute = receiverinfo_cap_msk
        
        return {
            "message_type": "AKE_Receiver_Info",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 20,
            "LENGTH": length,
            "VERSION": version,
            "RECEIVER_CAPABILITY_MASK": hex(receiverinfo_tmp),
            "Reserved": hex(receiverinfo_reserved),
            "RECEIVER_LOCALITY_PRECOMPUTE_SUPPORT": receiverinfo_locality_precompute == 1
        }
    
    def dissect_ake_preinit(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 32: AKE_PreInit (Decoder->Encoder)"""
        version_byte = data[3]
        minor_ver = version_byte % 16
        major_ver = (version_byte - minor_ver) // 16
        
        pairing = data[4] == 1
        restart_reauth = data[5] == 1
        receiver = data[6] == 1
        
        return {
            "message_type": "AKE_PreInit",
            "direction": "Decoder->Encoder",
            "msg_size": msg_size,
            "msg_id": 32,
            "Version": hex(version_byte),
            "MajorVersion": major_ver,
            "MinorVersion": minor_ver,
            "pairing": pairing,
            "restart/REAUTH_REQ": restart_reauth,
            "receiver": receiver,
            "receiverId": self.bytes_to_hex(data[7:12]),
            "portId": self.bytes_to_hex(data[12:17]),
            "nodeId": self.bytes_to_hex(data[17:33]),
            "vendorExtension": self.bytes_to_hex(data[33:49])
        }
    
    def dissect_ake_preinitstatus(self, data: bytes, msg_size: int) -> Dict:
        """Dissect msg_id 33: AKE_PreInitStatus (Encoder->Decoder)"""
        version_byte = data[3]
        minor_ver = version_byte % 16
        major_ver = (version_byte - minor_ver) // 16
        
        preinit_status = data[4]
        status_map = {
            0: "Ok",
            1: "statusInvalidParameters",
            2: "statusPairingExpired",
            3: "statusSessionExpired"
        }
        status_text = status_map.get(preinit_status, "Reserved")
        
        pairing_slots = struct.unpack('>H', data[5:7])[0]
        session_slots = struct.unpack('>H', data[7:9])[0]
        
        return {
            "message_type": "AKE_PreInitStatus",
            "direction": "Encoder->Decoder",
            "msg_size": msg_size,
            "msg_id": 33,
            "Version": hex(version_byte),
            "MajorVersion": major_ver,
            "MinorVersion": minor_ver,
            "status": preinit_status,
            "status_text": status_text,
            "pairingSlots": pairing_slots,
            "sessionSlots": session_slots,
            "vendorExtension": self.bytes_to_hex(data[9:25])
        }
    
    def dissect_hkep_message(self, data: bytes) -> Optional[Dict]:
        """
        Dissect a single HKEP message
        
        Args:
            data: Raw bytes containing HKEP message
            
        Returns:
            Dictionary with parsed message data or None if invalid
        """
        if len(data) < 3:
            return None
            
        msg_size = struct.unpack('>H', data[0:2])[0]
        msg_id = data[2]
        
        if msg_id not in self.MSG_TYPES:
            return {
                "message_type": f"Unknown (ID: {msg_id})",
                "msg_size": msg_size,
                "msg_id": msg_id,
                "raw_data": self.bytes_to_hex(data[:min(len(data), msg_size + 2)])
            }
        
        # Dispatch to appropriate dissector based on msg_id
        dissectors = {
            1: self.dissect_null_message,
            2: self.dissect_ake_init,
            3: self.dissect_ake_send_cert,
            4: self.dissect_ake_no_stored_km,
            5: self.dissect_ake_stored_km,
            6: self.dissect_ake_send_rrx,
            7: self.dissect_ake_send_h_prime,
            8: self.dissect_ake_send_pairing_info,
            9: self.dissect_lc_init,
            10: self.dissect_lc_send_l_prime,
            11: self.dissect_ske_send_eks,
            12: self.dissect_repeaterauth_send_receiverid_list,
            13: self.dissect_rtt_ready,
            14: self.dissect_rtt_challenge,
            15: self.dissect_repeaterauth_send_ack,
            16: self.dissect_repeaterauth_stream_manage,
            17: self.dissect_repeaterauth_stream_ready,
            18: self.dissect_receiver_authstatus,
            19: self.dissect_ake_transmitter_info,
            20: self.dissect_ake_receiver_info,
            32: self.dissect_ake_preinit,
            33: self.dissect_ake_preinitstatus
        }
        
        dissector_func = dissectors.get(msg_id)
        if dissector_func:
            try:
                return dissector_func(data, msg_size)
            except Exception as e:
                return {
                    "message_type": f"Parse Error ({self.MSG_TYPES[msg_id]})",
                    "msg_size": msg_size,
                    "msg_id": msg_id,
                    "error": str(e),
                    "raw_data": self.bytes_to_hex(data[:min(len(data), 50)])
                }
        
        return None
    
    def get_stream_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
        """Generate a unique key for TCP stream identification"""
        # Normalize the stream key (bidirectional)
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
    
    def get_packet_hash(self, packet: Packet) -> str:
        """Generate hash of packet to detect retransmissions"""
        if not packet.haslayer(TCP):
            return ""
        tcp_layer = packet[TCP]
        # Use SEQ number, payload, and IPs to identify unique packets
        src_ip = packet[IP].src if packet.haslayer(IP) else "0"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "0"
        payload = bytes(tcp_layer.payload) if tcp_layer.payload else b""
        return f"{src_ip}:{dst_ip}:{tcp_layer.seq}:{len(payload)}:{payload[:20].hex()}"
    
    def is_complete_hkep_message(self, data: bytes) -> Tuple[bool, int]:
        """
        Check if data contains a complete HKEP message

        Returns:
            (is_complete, expected_length)

        HKEP message format: [2 bytes msg_size] [1 byte msg_id] [msg_size-1 bytes data]
        The msg_size includes the msg_id byte.
        """
        if len(data) < 3:  # Need at least msg_size (2) + msg_id (1)
            return False, 3

        msg_size = struct.unpack('>H', data[0:2])[0]
        msg_id = data[2]

        # msg_size includes the msg_id byte, so payload should be exactly msg_size bytes
        expected_length = msg_size

        if len(data) >= expected_length:
            # Additional validation: check that msg_id is valid
            if msg_id in self.MSG_TYPES:
                return True, expected_length
            else:
                return False, expected_length
        else:
            return False, expected_length
    
    def detect_hkep_ports(self, pcap_file: str) -> Dict[int, int]:
        """
        Scan all TCP ports to detect which ones contain HKEP traffic
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Dictionary mapping port numbers to count of HKEP messages
        """
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            return {}
        
        port_hkep_counts = {}
        
        for packet in packets:
            if not packet.haslayer(TCP):
                continue
                
            tcp_layer = packet[TCP]
            
            if not tcp_layer.payload:
                continue
                
            payload = bytes(tcp_layer.payload)
            if len(payload) < 3:
                continue
            
            # Try to parse as HKEP
            try:
                msg_size = struct.unpack('>H', payload[0:2])[0]
                msg_id = payload[2]
                
                # Check if msg_id is a valid HKEP message type
                if msg_id in self.MSG_TYPES:
                    # Check if message size is reasonable (HKEP messages are typically < 1000 bytes)
                    if 1 <= msg_size <= 1000:
                        # Valid HKEP message detected
                        sport = tcp_layer.sport
                        dport = tcp_layer.dport
                        
                        port_hkep_counts[sport] = port_hkep_counts.get(sport, 0) + 1
                        port_hkep_counts[dport] = port_hkep_counts.get(dport, 0) + 1
            except:
                continue
        
        return port_hkep_counts
    
    def reassemble_tcp_stream(self, packets: List, target_port: int) -> Dict[str, bytes]:
        """
        Reassemble TCP streams by collecting all packets for each stream
        Returns dict mapping stream_key -> reassembled data
        """
        streams = {}
        
        for packet in packets:
            if not packet.haslayer(TCP):
                continue
            
            tcp = packet[TCP]
            if tcp.sport != target_port and tcp.dport != target_port:
                continue
            
            if not tcp.payload:
                continue
            
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
            
            # Create bidirectional stream key
            if (src_ip, tcp.sport) < (dst_ip, tcp.dport):
                stream_key = f"{src_ip}:{tcp.sport}-{dst_ip}:{tcp.dport}"
                direction = "forward"
            else:
                stream_key = f"{dst_ip}:{tcp.dport}-{src_ip}:{tcp.sport}"
                direction = "reverse"
            
            if stream_key not in streams:
                streams[stream_key] = {'forward': [], 'reverse': []}
            
            payload = bytes(tcp.payload)
            seq = tcp.seq
            
            # Store packet with sequence number
            if direction == "forward":
                streams[stream_key]['forward'].append((seq, payload, packet))
            else:
                streams[stream_key]['reverse'].append((seq, payload, packet))
        
        # Reassemble each stream
        reassembled = {}
        for stream_key, directions in streams.items():
            # Reassemble forward direction
            forward_data = self._reassemble_direction(directions['forward'])
            # Reassemble reverse direction  
            reverse_data = self._reassemble_direction(directions['reverse'])
            
            reassembled[f"{stream_key}_forward"] = forward_data
            reassembled[f"{stream_key}_reverse"] = reverse_data
        
        return reassembled
    
    def _reassemble_direction(self, packets: List[Tuple[int, bytes, Packet]]) -> bytes:
        """Reassemble packets in one direction by sequence number"""
        if not packets:
            return b''
        
        # Sort by sequence number
        packets.sort(key=lambda x: x[0])
        
        # Simple reassembly - just concatenate in order
        # (assuming no gaps or overlaps for now)
        result = b''
        expected_seq = None
        
        for seq, payload, packet in packets:
            if expected_seq is None:
                expected_seq = seq
                result = payload
            elif seq == expected_seq:
                # In order - append
                result += payload
                expected_seq += len(payload)
            elif seq < expected_seq:
                # Retransmission or duplicate - skip
                continue
            else:
                # Gap - append anyway (might be out of order)
                result += payload
                expected_seq = seq + len(payload)
        
        return result
    
    def reassemble_tcp_stream_properly(self, packets: List[Tuple[int, int, bytes]]) -> Tuple[bytes, List[Dict]]:
        """
        Properly reassemble TCP stream from packets with (seq, length, payload)
        Handles gaps, overlaps, and out-of-order packets

        Returns:
            (reassembled_data, discontinuity_info)

        discontinuity_info contains info about gaps/discontinuities found
        """
        if not packets:
            return b'', []

        # Sort by sequence number
        packets.sort(key=lambda x: x[0])

        result = bytearray()
        last_end = None
        discontinuities = []

        for seq, length, payload in packets:
            if len(payload) == 0:
                continue

            if last_end is None:
                # First packet
                result.extend(payload)
                last_end = seq + len(payload)
            elif seq == last_end:
                # Perfect continuation - no gap, no overlap
                result.extend(payload)
                last_end = seq + len(payload)
            elif seq < last_end:
                # Overlap - skip overlapping bytes
                overlap = last_end - seq
                if overlap < len(payload):
                    # Partial overlap - append non-overlapping part
                    result.extend(payload[overlap:])
                    last_end = seq + len(payload)
                # else: completely overlapped, skip
            else:
                # Gap - record the discontinuity and stop reassembly
                gap = seq - last_end
                discontinuities.append({
                    'gap_start': last_end,
                    'gap_end': seq,
                    'gap_size': gap,
                    'description': f'Gap of {gap} bytes between SEQ {last_end} and {seq}'
                })

                # Stop reassembly at gaps to avoid misalignment
                break

        return bytes(result), discontinuities

    def _find_contiguous_blocks(self, packets: List[Tuple[int, int, bytes, int, Packet]]) -> List[Tuple[bytes, List[Tuple[int, int, bytes, int, Packet]]]]:
        """
        Find contiguous blocks of packets (no gaps in sequence numbers)

        Returns list of (block_data, block_packets) tuples
        """
        if not packets:
            return []

        # Sort by sequence number
        packets.sort(key=lambda x: x[0])

        blocks = []
        current_block = []
        current_data = bytearray()
        expected_seq = None

        for seq, length, payload, pkt_num, packet in packets:
            if len(payload) == 0:
                continue

            if expected_seq is None:
                # Start new block
                current_block = [(seq, length, payload, pkt_num, packet)]
                current_data = bytearray(payload)
                expected_seq = seq + len(payload)
            elif seq == expected_seq:
                # Continuation of current block
                current_block.append((seq, length, payload, pkt_num, packet))
                current_data.extend(payload)
                expected_seq = seq + len(payload)
            else:
                # Gap detected - save current block and start new one
                if current_block:
                    blocks.append((bytes(current_data), current_block))

                # Start new block
                current_block = [(seq, length, payload, pkt_num, packet)]
                current_data = bytearray(payload)
                expected_seq = seq + len(payload)

        # Add final block
        if current_block:
            blocks.append((bytes(current_data), current_block))

        return blocks

    def _extract_messages_from_block(self, block_data: bytes, block_packets: List, stream_key: str, direction_name: str, hkep_message_count: int) -> List[Dict]:
        """
        Extract HKEP messages from a contiguous block of data

        Returns list of message results
        """
        messages = []
        offset = 0
        max_offset = len(block_data) - 2
        last_valid_offset = -1

        while offset <= max_offset:
            # Check if we have enough bytes for msg_size
            if offset + 2 > len(block_data):
                break

            msg_size = struct.unpack('>H', block_data[offset:offset+2])[0]
            total_len = 2 + msg_size

            # Validate msg_size (HKEP messages are typically 3-1000 bytes)
            if msg_size > 1000 or msg_size < 1:
                offset += 1
                continue

            # Check if we have a complete message
            if offset + total_len <= len(block_data):
                # Complete message
                msg_data = block_data[offset:offset+total_len]

                # Validate msg_id is a known HKEP message type
                if len(msg_data) >= 3:
                    msg_id = msg_data[2]
                    if msg_id not in self.MSG_TYPES:
                        offset += 1
                        continue

                    # Try to dissect
                    try:
                        hkep_data = self.dissect_hkep_message(msg_data)

                        if hkep_data and hkep_data.get('msg_id') in self.MSG_TYPES:
                            last_valid_offset = offset

                            # Find which packet contains this message
                            actual_pkt_num = block_packets[0][3]  # Default to first packet
                            actual_timestamp = float(block_packets[0][4].time) if hasattr(block_packets[0][4], 'time') else 0

                            # Track offset to find the right packet
                            current_offset = 0
                            for seq, length, payload, pkt_num, pkt in block_packets:
                                if current_offset <= offset < current_offset + len(payload):
                                    actual_pkt_num = pkt_num
                                    actual_timestamp = float(pkt.time) if hasattr(pkt, 'time') else actual_timestamp
                                    break
                                current_offset += len(payload)

                            messages.append({
                                "packet_number": actual_pkt_num,
                                "timestamp": actual_timestamp,
                                "hkep": hkep_data
                            })

                            offset += total_len
                            continue
                    except (ValueError, IndexError, struct.error) as e:
                        # Parse error - skip this offset
                        pass

            # If we haven't found a valid message, try next byte
            # But if we've moved too far from last valid message, try harder to find next
            if offset - last_valid_offset > 100:
                # Look ahead for next valid message start
                found = False
                for search in range(offset + 1, min(offset + 200, len(block_data) - 2)):
                    test_size = struct.unpack('>H', block_data[search:search+2])[0]
                    if 1 <= test_size <= 1000 and search + 2 < len(block_data):
                        test_id = block_data[search + 2]
                        if test_id in self.MSG_TYPES and search + 2 + test_size <= len(block_data):
                            offset = search
                            found = True
                            break
                if not found:
                    offset += 1
            else:
                offset += 1

        return messages

    def analyze_pcap(self, pcap_file: str, verbose: bool = True, handle_reassembly: bool = True, show_tcp_issues: bool = False) -> HKEPAnalysisResult:
        """
        Analyze PCAP file for HKEP messages

        Args:
            pcap_file: Path to PCAP file
            verbose: Print results to console
            handle_reassembly: Enable TCP stream reassembly (recommended)
            show_tcp_issues: Show warnings for TCP reassembly issues (default: False)

        Returns:
            HKEPAnalysisResult containing grouped HKEP exchanges and messages
        """
        # Auto-detect HKEP ports if target_port not specified
        if self.target_port is None:
            if verbose:
                print("No port specified. Scanning for HKEP traffic...")
            port_counts = self.detect_hkep_ports(pcap_file)
            
            if not port_counts:
                if verbose:
                    print("No HKEP traffic detected on any port.")
                return HKEPAnalysisResult()
            
            # Find the port(s) with HKEP traffic
            # Use the port with most HKEP messages
            detected_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)
            
            if verbose:
                print(f"\nDetected HKEP traffic on the following ports:")
                for port, count in detected_ports:
                    print(f"  Port {port}: {count} potential HKEP messages")
                print()
            
            # Use the port with most traffic
            self.target_port = detected_ports[0][0]
            
            if verbose:
                print(f"Using port {self.target_port} for analysis (highest HKEP message count)")
                print()
        
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            return HKEPAnalysisResult()
        
        # Use proper TCP stream reassembly
        if handle_reassembly:
            return self._analyze_with_proper_reassembly(packets, verbose, show_tcp_issues)
        
        # Fallback to packet-by-packet (original method)
        results = []
        hkep_packet_count = 0
        retransmission_count = 0
        incomplete_count = 0
        tcp_issue_count = 0
        tcp_connections = {}  # Track connection states
        
        for pkt_num, packet in enumerate(packets, 1):
            if not packet.haslayer(TCP):
                continue
                
            tcp_layer = packet[TCP]
            
            # Filter for target port
            if tcp_layer.dport != self.target_port and tcp_layer.sport != self.target_port:
                continue
            
            # Extract packet metadata
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            
            # Track TCP connection state changes
            conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            conn_key_rev = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            
            # Detect TCP connection events (SYN, FIN, RST)
            if tcp_layer.flags.S and not tcp_layer.flags.A:
                # SYN - new connection
                tcp_connections[conn_key] = 'SYN'
                if verbose:
                    print(f"\n{'='*80}")
                    print(f"[TCP CONNECTION START] Packet #{pkt_num}")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  SYN: SEQ={tcp_layer.seq}")
                    print(f"{'='*80}")
            elif tcp_layer.flags.S and tcp_layer.flags.A:
                # SYN-ACK - connection acknowledgment
                tcp_connections[conn_key_rev] = 'ESTABLISHED'
                if verbose:
                    print(f"\n{'='*80}")
                    print(f"[TCP CONNECTION ESTABLISHED] Packet #{pkt_num}")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  SYN-ACK: SEQ={tcp_layer.seq}, ACK={tcp_layer.ack}")
                    print(f"{'='*80}")
            elif tcp_layer.flags.F:
                # FIN - graceful disconnect
                if verbose:
                    print(f"\n{'='*80}")
                    print(f"[TCP DISCONNECT - FIN] Packet #{pkt_num}")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  FIN: SEQ={tcp_layer.seq}, ACK={tcp_layer.ack if tcp_layer.flags.A else 'N/A'}")
                    print(f"{'='*80}")
                    print(f"\n{'#'*80} << END OF HKEP EXCHANGE\n")
                # Mark connection as closing
                if conn_key in tcp_connections:
                    tcp_connections[conn_key] = 'CLOSING'
                if conn_key_rev in tcp_connections:
                    tcp_connections[conn_key_rev] = 'CLOSING'
            elif tcp_layer.flags.R:
                # RST - abrupt disconnect
                if verbose:
                    print(f"\n{'='*80}")
                    print(f"[TCP DISCONNECT - RST] Packet #{pkt_num}")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  RST: SEQ={tcp_layer.seq}")
                    print(f"{'='*80}")
                    print(f"\n{'#'*80} << END OF HKEP EXCHANGE (ABORTED)\n")
                # Remove connection from tracking
                tcp_connections.pop(conn_key, None)
                tcp_connections.pop(conn_key_rev, None)
            
            # Get TCP payload - use TCP payload directly (Raw layer may be incomplete)
            if not tcp_layer.payload:
                continue
            
            payload = bytes(tcp_layer.payload)
            if len(payload) < 3:
                continue
            
            # Track seen packets for retransmission detection (but don't skip yet - might be needed for reassembly)
            pkt_hash = self.get_packet_hash(packet)
            is_retransmission = pkt_hash in self.seen_packets
            if is_retransmission:
                retransmission_count += 1
                if show_tcp_issues and verbose:
                    print(f"\n[WARNING] Packet #{pkt_num}: TCP Retransmission detected")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}, SEQ={tcp_layer.seq}")
                # Don't skip retransmissions - they might be needed for reassembly
                # We'll skip them later if they're truly duplicates
            if not is_retransmission:
                self.seen_packets.add(pkt_hash)
            
            # Check for complete HKEP message
            is_complete, expected_length = self.is_complete_hkep_message(payload)
            
            tcp_flags = []
            if tcp_layer.flags.P:
                tcp_flags.append("PSH")
            if tcp_layer.flags.A:
                tcp_flags.append("ACK")
            if tcp_layer.flags.S:
                tcp_flags.append("SYN")
            if tcp_layer.flags.F:
                tcp_flags.append("FIN")
            if tcp_layer.flags.R:
                tcp_flags.append("RST")
            
            if not is_complete:
                incomplete_count += 1
                tcp_issue_count += 1
                if show_tcp_issues and verbose:
                    print(f"\n[WARNING] Packet #{pkt_num}: Incomplete HKEP message")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  TCP Flags: {','.join(tcp_flags) if tcp_flags else 'None'}")
                    print(f"  Payload length: {len(payload)} bytes, Expected: {expected_length} bytes")
                    print(f"  SEQ: {tcp_layer.seq}, ACK: {tcp_layer.ack if tcp_layer.flags.A else 'N/A'}")
                
                if handle_reassembly:
                    # Store for potential reassembly
                    # Use directional stream key (src->dst)
                    stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    
                    if stream_key not in self.tcp_streams:
                        self.tcp_streams[stream_key] = {
                            'buffer': b'',
                            'expected_seq': None,  # Will be set from first packet
                            'packets': []
                        }
                    
                    stream = self.tcp_streams[stream_key]
                    
                    # Initialize expected_seq from first packet with data
                    if stream['expected_seq'] is None:
                        stream['expected_seq'] = tcp_layer.seq
                    
                    # Check if this is the expected sequence number
                    if tcp_layer.seq == stream['expected_seq']:
                        # In-order packet - add to buffer
                        stream['buffer'] += payload
                        stream['expected_seq'] = tcp_layer.seq + len(payload)
                        stream['packets'].append(pkt_num)
                    elif tcp_layer.seq < stream['expected_seq']:
                        # Old/duplicate packet - skip
                        if show_tcp_issues and verbose:
                            print(f"  [INFO] Skipping old/duplicate packet with SEQ={tcp_layer.seq}")
                        continue
                    else:
                        # Out-of-order packet - this shouldn't happen often
                        if show_tcp_issues and verbose:
                            print(f"  [WARNING] Out-of-order packet detected!")
                        continue
                    
                    # Extract all complete messages from buffer
                    messages_extracted = False
                    while len(stream['buffer']) >= 2:
                        is_complete_now, expected_length_now = self.is_complete_hkep_message(stream['buffer'])
                        if is_complete_now:
                            if show_tcp_issues and verbose and len(stream['packets']) > 1:
                                print(f"  [INFO] Reassembled complete message from packets: {stream['packets']}")
                            payload = stream['buffer'][:expected_length_now]
                            # Remove processed message from buffer
                            stream['buffer'] = stream['buffer'][expected_length_now:]
                            stream['packets'] = [pkt_num]  # Reset for next message
                            messages_extracted = True
                            break  # Process this message, then come back for more
                        else:
                            # Not enough data for a complete message yet
                            break
                    
                    if not messages_extracted:
                        # No complete message yet - wait for more packets
                        continue
                else:
                    continue  # Skip incomplete messages if reassembly disabled
            
            # Check for spurious data (payload longer than expected)
            # This might actually be multiple messages in one packet!
            if len(payload) > expected_length:
                tcp_issue_count += 1
                if show_tcp_issues and verbose:
                    print(f"\n[WARNING] Packet #{pkt_num}: Payload longer than expected message")
                    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  Payload length: {len(payload)} bytes, Expected: {expected_length} bytes")
                    print(f"  This might contain multiple messages - processing first message")
                # Process first message, then check if there's more
                first_message = payload[:expected_length]
                remaining_data = payload[expected_length:]
                
                # Process first message
                payload = first_message
                
                # If there's remaining data, try to process it as additional messages
                # But for now, just process the first one to avoid complexity
            
            hkep_packet_count += 1
            
            # Dissect HKEP message
            hkep_data = self.dissect_hkep_message(payload)
            
            if hkep_data:
                result = {
                    "packet_number": pkt_num,
                    "hkep_packet_number": hkep_packet_count,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "timestamp": float(packet.time) if hasattr(packet, 'time') else 0,
                    "tcp_seq": tcp_layer.seq,
                    "tcp_ack": tcp_layer.ack if tcp_layer.flags.A else None,
                    "tcp_flags": ','.join(tcp_flags) if tcp_flags else None,
                    "hkep": hkep_data
                }
                results.append(result)
                
                if verbose:
                    self.print_hkep_message(result)
        
        if verbose:
            # Count TCP connection events
            active_connections = sum(1 for state in tcp_connections.values() if state == 'ESTABLISHED')
            closing_connections = sum(1 for state in tcp_connections.values() if state == 'CLOSING')
            
            print(f"\n{'='*80}")
            print(f"Summary:")
            print(f"  Total packets: {len(packets)}")
            print(f"  Valid HKEP messages: {hkep_packet_count}")
            print(f"  Active TCP connections: {active_connections}")
            print(f"  Closing TCP connections: {closing_connections}")
            if show_tcp_issues:
                print(f"  TCP retransmissions detected: {retransmission_count}")
                print(f"  Incomplete/fragmented messages: {incomplete_count}")
                print(f"  Total TCP issues: {tcp_issue_count}")
            print(f"{'='*80}")
        
        return results
    
    def _analyze_with_proper_reassembly(self, packets: List, verbose: bool, show_tcp_issues: bool) -> HKEPAnalysisResult:
        """Analyze using proper TCP stream reassembly - gets ALL messages"""
        analysis_result = HKEPAnalysisResult()
        analysis_result.total_packets = len(packets)

        exchanges = {}  # stream_key -> HKEPExchange
        tcp_connections = {}
        stream_data = {}  # stream_key -> {'forward': [(seq, len, payload, pkt_num, packet)], 'reverse': [...]}
        timeline_events = []  # List of events in chronological order: (pkt_num, timestamp, event_type, event_data)
        
        # First pass: collect all packets, track connections, and record TCP events
        for pkt_num, packet in enumerate(packets, 1):
            if not packet.haslayer(TCP):
                continue
            
            tcp_layer = packet[TCP]
            if tcp_layer.dport != self.target_port and tcp_layer.sport != self.target_port:
                continue
            
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            timestamp = float(packet.time) if hasattr(packet, 'time') else 0
            
            # Track TCP connection events and add to timeline
            conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            conn_key_rev = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            
            if tcp_layer.flags.S and not tcp_layer.flags.A:
                tcp_connections[conn_key] = 'SYN'
                timeline_events.append({
                    'pkt_num': pkt_num,
                    'timestamp': timestamp,
                    'type': 'tcp_syn',
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'seq': tcp_layer.seq
                })
            elif tcp_layer.flags.S and tcp_layer.flags.A:
                tcp_connections[conn_key_rev] = 'ESTABLISHED'
                timeline_events.append({
                    'pkt_num': pkt_num,
                    'timestamp': timestamp,
                    'type': 'tcp_syn_ack',
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'seq': tcp_layer.seq,
                    'ack': tcp_layer.ack
                })
            elif tcp_layer.flags.F:
                timeline_events.append({
                    'pkt_num': pkt_num,
                    'timestamp': timestamp,
                    'type': 'tcp_fin',
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'seq': tcp_layer.seq,
                    'ack': tcp_layer.ack if tcp_layer.flags.A else None
                })
            elif tcp_layer.flags.R:
                timeline_events.append({
                    'pkt_num': pkt_num,
                    'timestamp': timestamp,
                    'type': 'tcp_rst',
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'seq': tcp_layer.seq
                })
            
            # Collect payload for reassembly
            if tcp_layer.payload:
                payload = bytes(tcp_layer.payload)
                if len(payload) > 0:
                    # Create bidirectional stream key
                    if (src_ip, src_port) < (dst_ip, dst_port):
                        stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    else:
                        stream_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
                    
                    # Determine direction
                    if src_port == self.target_port:
                        direction = 'forward'
                    else:
                        direction = 'reverse'
                    
                    if stream_key not in stream_data:
                        stream_data[stream_key] = {'forward': [], 'reverse': []}
                    
                    seq = tcp_layer.seq
                    stream_data[stream_key][direction].append((seq, len(payload), payload, pkt_num, packet))
        
        # Second pass: reassemble streams and extract HKEP messages
        hkep_message_count = 0
        
        if verbose:
            print(f"\nReassembling {len(stream_data)} TCP streams...")
        
        # Collect HKEP messages with their packet info for timeline
        hkep_messages = []  # List of (pkt_num, timestamp, hkep_data, stream_info)
        
        for stream_key, directions in stream_data.items():
            # Create exchange object for this stream if it doesn't exist
            if stream_key not in exchanges:
                # Get metadata from first packet in either direction
                first_direction = 'forward' if directions['forward'] else 'reverse'
                first_packet = directions[first_direction][0][4] if directions[first_direction] else None
                if first_packet:
                    tcp_layer = first_packet[TCP]
                    src_ip = first_packet[IP].src if first_packet.haslayer(IP) else "unknown"
                    dst_ip = first_packet[IP].dst if first_packet.haslayer(IP) else "unknown"
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    exchanges[stream_key] = HKEPExchange(stream_key, src_ip, src_port, dst_ip, dst_port)

            # Process each direction - collect ALL packets and try multiple approaches
            for direction_name in ['forward', 'reverse']:
                direction_packets = directions[direction_name]

                if not direction_packets:
                    continue

                # Get metadata from first packet
                first_pkt_num, first_packet = direction_packets[0][3], direction_packets[0][4]
                tcp_layer = first_packet[TCP]
                src_ip = first_packet[IP].src if first_packet.haslayer(IP) else "unknown"
                dst_ip = first_packet[IP].dst if first_packet.haslayer(IP) else "unknown"

                if verbose:
                    print(f"  Stream {stream_key} {direction_name}: {len(direction_packets)} packets")

                # Approach 1: Process each packet individually (like Wireshark does)
                # This catches all packets that contain complete HKEP messages
                for seq, length, payload, pkt_num, packet in direction_packets:
                    if len(payload) < 3:
                        continue

                    # Check if this packet contains a complete HKEP message
                    is_complete, expected_length = self.is_complete_hkep_message(payload)
                    if is_complete and len(payload) >= expected_length:
                        # Try to parse this individual packet
                        hkep_data = self.dissect_hkep_message(payload[:expected_length])
                        if hkep_data and hkep_data.get('msg_id') in self.MSG_TYPES:
                            # Check if we already processed this message from a block
                            exchange = exchanges[stream_key]
                            already_processed = any(
                                msg['packet_number'] == pkt_num for msg in exchange.messages
                            )

                            if not already_processed:
                                hkep_message_count += 1
                                timestamp = float(packet.time) if hasattr(packet, 'time') else 0

                                message = {
                                    "packet_number": pkt_num,
                                    "hkep_packet_number": hkep_message_count,
                                    "src_ip": src_ip,
                                    "src_port": tcp_layer.sport,
                                    "dst_ip": dst_ip,
                                    "dst_port": tcp_layer.dport,
                                    "timestamp": timestamp,
                                    "stream": stream_key,
                                    "direction": direction_name,
                                    "hkep": hkep_data
                                }
                                exchange.add_message(message)

                                # Add to timeline
                                timeline_events.append({
                                    'pkt_num': pkt_num,
                                    'timestamp': timestamp,
                                    'type': 'hkep_message',
                                    'result': message
                                })

                                if verbose:
                                    print(f"    Packet #{pkt_num}: extracted HKEP message")

                # Approach 2: Try to reassemble contiguous blocks for messages that span packets
                contiguous_blocks = self._find_contiguous_blocks(direction_packets)

                for block_idx, (block_data, block_packets) in enumerate(contiguous_blocks):
                    if len(block_data) < 3:
                        continue

                    if verbose and len(contiguous_blocks) > 1:
                        print(f"    Block {block_idx + 1}: {len(block_data)} bytes from {len(block_packets)} packets")

                    # Try to extract messages from this contiguous block
                    messages_from_block = self._extract_messages_from_block(
                        block_data, block_packets, stream_key, direction_name, hkep_message_count
                    )

                    for msg_result in messages_from_block:
                        # Check if we already processed this message from individual packet processing
                        exchange = exchanges[stream_key]
                        already_processed = any(
                            msg['packet_number'] == msg_result["packet_number"] for msg in exchange.messages
                        )

                        if not already_processed:
                            hkep_message_count += 1
                            message = {
                                "packet_number": msg_result["packet_number"],
                                "hkep_packet_number": hkep_message_count,
                                "src_ip": src_ip,
                                "src_port": tcp_layer.sport,
                                "dst_ip": dst_ip,
                                "dst_port": tcp_layer.dport,
                                "timestamp": msg_result["timestamp"],
                                "stream": stream_key,
                                "direction": direction_name,
                                "hkep": msg_result["hkep"]
                            }
                            exchange.add_message(message)

                            # Add to timeline
                            timeline_events.append({
                                'pkt_num': msg_result["packet_number"],
                                'timestamp': msg_result["timestamp"],
                                'type': 'hkep_message',
                                'result': message
                            })

        
        # Sort timeline events by packet number (chronological order)
        timeline_events.sort(key=lambda x: (x['pkt_num'], x.get('timestamp', 0)))
        
        # Print events in chronological order
        if verbose:
            for event in timeline_events:
                if event['type'] == 'tcp_syn':
                    print(f"\n{'='*80}")
                    print(f"[TCP CONNECTION START] Packet #{event['pkt_num']}")
                    print(f"  {event['src_ip']}:{event['src_port']} -> {event['dst_ip']}:{event['dst_port']}")
                    print(f"  SYN: SEQ={event['seq']}")
                    print(f"{'='*80}")
                elif event['type'] == 'tcp_syn_ack':
                    print(f"\n{'='*80}")
                    print(f"[TCP CONNECTION ESTABLISHED] Packet #{event['pkt_num']}")
                    print(f"  {event['src_ip']}:{event['src_port']} -> {event['dst_ip']}:{event['dst_port']}")
                    print(f"  SYN-ACK: SEQ={event['seq']}, ACK={event['ack']}")
                    print(f"{'='*80}")
                elif event['type'] == 'tcp_fin':
                    print(f"\n{'='*80}")
                    print(f"[TCP DISCONNECT - FIN] Packet #{event['pkt_num']}")
                    print(f"  {event['src_ip']}:{event['src_port']} -> {event['dst_ip']}:{event['dst_port']}")
                    print(f"  FIN: SEQ={event['seq']}, ACK={event.get('ack', 'N/A')}")
                    print(f"{'='*80}")
                    print(f"\n{'#'*80} << END OF HKEP EXCHANGE\n")
                elif event['type'] == 'tcp_rst':
                    print(f"\n{'='*80}")
                    print(f"[TCP DISCONNECT - RST] Packet #{event['pkt_num']}")
                    print(f"  {event['src_ip']}:{event['src_port']} -> {event['dst_ip']}:{event['dst_port']}")
                    print(f"  RST: SEQ={event['seq']}")
                    print(f"{'='*80}")
                    print(f"\n{'#'*80} << END OF HKEP EXCHANGE (ABORTED)\n")
                elif event['type'] == 'hkep_message':
                    self.print_hkep_message(event['result'])
        
        # Add all exchanges to the analysis result
        for exchange in exchanges.values():
            analysis_result.add_exchange(exchange)

        if verbose:
            print(f"\n{'='*80}")
            print(f"Summary:")
            print(f"  Total packets: {analysis_result.total_packets}")
            print(f"  Valid HKEP messages: {analysis_result.total_messages}")
            print(f"  HKEP exchanges: {analysis_result.get_exchange_count()}")
            print(f"{'='*80}")

        return analysis_result
    
    def print_hkep_message(self, result: Dict):
        """Pretty print a single HKEP message"""
        print(f"\n{'='*80}")
        print(f"Packet #{result['packet_number']} (HKEP #{result['hkep_packet_number']})")
        print(f"{result['src_ip']}:{result['src_port']} -> {result['dst_ip']}:{result['dst_port']}")
        if result.get('tcp_flags'):
            print(f"TCP: SEQ={result['tcp_seq']}, ACK={result.get('tcp_ack', 'N/A')}, Flags=[{result['tcp_flags']}]")
        print(f"{'='*80}")
        
        hkep = result['hkep']
        print(f"HKEP Protocol: {hkep.get('message_type', 'Unknown')}")
        
        for key, value in hkep.items():
            if key in ['message_type']:
                continue
            elif key == 'streams':
                print(f"  Streams ({len(value)}):")
                for stream in value:
                    print(f"    Stream {stream['stream_number']}:")
                    for sk, sv in stream.items():
                        if sk != 'stream_number':
                            print(f"      {sk}: {sv}")
            elif key == 'Receiver_IDs':
                print(f"  Receiver ID List ({len(value)} devices):")
                for i, rid in enumerate(value):
                    print(f"    Receiver_ID{i}[39:0]: {rid}")
            elif isinstance(value, bool):
                print(f"  {key}: {'true' if value else 'false'}")
            else:
                print(f"  {key}: {value}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='HKEP Protocol Dissector for PCAP files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s capture.pcap
  %(prog)s capture.pcap --port 48879
  %(prog)s capture.pcap --quiet
  %(prog)s capture.pcap --output results.txt
        """
    )
    
    parser.add_argument('pcap_file', help='PCAP file to analyze')
    parser.add_argument('--port', type=int, default=None, 
                        help='TCP port to filter for HKEP traffic (default: auto-detect)')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress console output')
    parser.add_argument('--output', '-o', help='Write results to JSON file')
    parser.add_argument('--no-reassembly', action='store_true',
                        help='Disable TCP stream reassembly (not recommended)')
    parser.add_argument('--show-tcp-issues', action='store_true',
                        help='Show warnings for TCP retransmissions, fragmentation, etc.')
    
    args = parser.parse_args()
    
    # Create dissector
    dissector = HKEPDissector(target_port=args.port)
    
    # Analyze PCAP
    results = dissector.analyze_pcap(
        args.pcap_file, 
        verbose=not args.quiet,
        handle_reassembly=not args.no_reassembly,
        show_tcp_issues=args.show_tcp_issues
    )
    
    # Write to JSON if requested
    if args.output:
        import json
        try:
            # Convert analysis result to serializable format
            output_data = {
                'total_packets': results.total_packets,
                'total_messages': results.total_messages,
                'exchange_count': results.get_exchange_count(),
                'exchanges': []
            }

            for exchange in results.get_all_exchanges():
                exchange_data = {
                    'stream_key': exchange.stream_key,
                    'src_ip': exchange.src_ip,
                    'src_port': exchange.src_port,
                    'dst_ip': exchange.dst_ip,
                    'dst_port': exchange.dst_port,
                    'message_count': exchange.get_message_count(),
                    'duration': exchange.get_duration(),
                    'start_time': exchange.start_time,
                    'end_time': exchange.end_time,
                    'successful': exchange.is_successful(),
                    'disconnection_reason': exchange.disconnection_reason,
                    'messages': exchange.get_messages()
                }
                output_data['exchanges'].append(exchange_data)

            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"\nResults written to {args.output}")
        except Exception as e:
            print(f"Error writing output file: {e}")


def example_programmatic_usage():
    """
    Example of how to programmatically analyze HKEP exchanges
    """
    dissector = HKEPDissector()

    # Analyze a PCAP file
    results = dissector.analyze_pcap("example.pcap", verbose=False)

    print(f"Found {results.get_exchange_count()} HKEP exchanges")
    print(f"Total messages: {results.total_messages}")

    # Analyze each exchange
    for exchange in results.get_all_exchanges():
        print(f"\nExchange: {exchange.stream_key}")
        print(f"  Duration: {exchange.get_duration():.3f} seconds")
        print(f"  Messages: {exchange.get_message_count()}")
        print(f"  Successful: {exchange.is_successful()}")

        # Get messages by type
        ake_init_messages = exchange.get_messages_by_type("AKE_Init")
        print(f"  AKE_Init messages: {len(ake_init_messages)}")

        # Get messages by direction
        encoder_messages = exchange.get_encoder_messages()
        decoder_messages = exchange.get_decoder_messages()
        print(f"  Encoder->Decoder: {len(encoder_messages)}")
        print(f"  Decoder->Encoder: {len(decoder_messages)}")

        # Access individual messages
        for msg in exchange.get_messages():
            hkep_data = msg['hkep']
            print(f"    Packet {msg['packet_number']}: {hkep_data['message_type']}")

    # Get only successful exchanges
    successful = results.get_successful_exchanges()
    print(f"\nSuccessful exchanges: {len(successful)}")

    # Get specific exchange by stream key
    specific_exchange = results.get_exchange_by_stream_key("10.20.10.168:49160-10.20.10.189:2000")
    if specific_exchange:
        print(f"Specific exchange has {specific_exchange.get_message_count()} messages")


if __name__ == "__main__":
    main()

