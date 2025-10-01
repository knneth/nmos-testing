# Copyright (C) 2025 Matrox Graphics Inc.
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

import socket
import struct
import time
import ipaddress
import platform
import subprocess
import re
from typing import Optional, Tuple, List
from . import Config as CONFIG


class MulticastJoinError(Exception):
    """Exception raised when multicast join operations fail"""
    pass


class MulticastUtils:
    """Utility class for multicast operations including IGMP v3 joins with source filtering"""
    
    @staticmethod
    def is_multicast_address(ip: str) -> bool:
        """Check if the given IP address is a valid multicast address"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                return ip_obj.is_multicast
            elif ip_obj.version == 6:
                return ip_obj.is_multicast
            return False
        except ValueError:
            return False
    
    @staticmethod
    def get_interface_ip() -> str:
        """Get the default interface IP address for multicast operations"""
        try:
            # Create a socket to determine the default interface
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # Connect to a non-routable address to determine local interface
                s.connect(("192.0.2.1", 80))
                return s.getsockname()[0]
        except Exception:
            return "0.0.0.0"
    
    @staticmethod
    def get_configured_interface() -> Optional[str]:
        """Get the configured multicast interface from Config.py"""
        return getattr(CONFIG, 'MULTICAST_INTERFACE', None)
    
    @staticmethod
    def get_windows_interface_ip(interface_name: str) -> Optional[str]:
        """
        Get IP address for a Windows interface name using ipconfig
        
        Args:
            interface_name: Windows interface name like "NIC2", "Ethernet", "Wi-Fi", etc.
            
        Returns:
            str: IP address of the interface, or None if not found
        """
        try:
            # Run ipconfig /all to get detailed interface information
            result = subprocess.run(['ipconfig', '/all'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return None
                
            output = result.stdout
            
            # Look for the interface by name
            interface_section = None
            lines = output.split('\n')
            
            for i, line in enumerate(lines):
                # Look for adapter lines that contain our interface name
                if 'adapter' in line.lower() and interface_name.lower() in line.lower():
                    interface_section = i
                    break
                # Also try exact name match
                elif line.strip().startswith(interface_name):
                    interface_section = i
                    break
            
            if interface_section is None:
                return None
            
            # Search for IPv4 address in the interface section
            for i in range(interface_section, min(interface_section + 20, len(lines))):
                line = lines[i].strip()
                if 'IPv4 Address' in line:
                    # Extract IP address using regex
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        return ip_match.group(1)
                # Stop if we hit another adapter section
                elif 'adapter' in line.lower() and i > interface_section:
                    break
                    
        except Exception as e:
            print(f"Warning: Failed to query Windows interface {interface_name}: {e}")
            
        return None
    
    @staticmethod
    def get_best_interface_for_destination(dest_ip: str) -> str:
        """
        Try to determine the best interface to reach a specific destination
        
        Args:
            dest_ip: The destination IP address (e.g., sender source_ip)
            
        Returns:
            str: IP address of the interface that can reach the destination
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((dest_ip, 80))
                return s.getsockname()[0]
        except Exception:
            # Fallback to default interface detection
            return MulticastUtils.get_interface_ip()
    
    @staticmethod
    def interface_name_to_ip(interface_name: str) -> str:
        """
        Convert network interface name to IP address
        
        Args:
            interface_name: Interface name like 'eth0', 'lo', 'wlan0', 'NIC2', etc.
            
        Returns:
            str: IP address of the interface
            
        Raises:
            MulticastJoinError: If interface not found or has no IP
        """
        # On Windows, try to query the actual interface first
        if platform.system() == "Windows":
            windows_ip = MulticastUtils.get_windows_interface_ip(interface_name)
            if windows_ip:
                return windows_ip
        
        # Hardcoded mapping for common interfaces
        interface_map = {
            'lo': '127.0.0.1',
            'localhost': '127.0.0.1',
            'loopback': '127.0.0.1',
        }
        
        # On Windows, add some common interface aliases
        if platform.system() == "Windows":
            interface_map.update({
                'eth0': '0.0.0.0',     # Let Windows choose
                'wlan0': '0.0.0.0',    # Let Windows choose  
                'any': '0.0.0.0',      # Bind to any interface
                'ethernet': '0.0.0.0', # Common Windows name
                'wi-fi': '0.0.0.0',    # Common Windows name
            })
        else:
            # On Linux/Unix, be more specific
            interface_map.update({
                'eth0': '0.0.0.0',     # Let system choose
                'wlan0': '0.0.0.0',    # Let system choose
                'any': '0.0.0.0'       # Bind to any interface
            })
        
        if interface_name in interface_map:
            return interface_map[interface_name]
        else:
            # If we get here and it's Windows, the interface wasn't found
            if platform.system() == "Windows":
                raise MulticastJoinError(f"Windows interface '{interface_name}' not found. "
                                       f"Use 'ipconfig /all' to see available interfaces, "
                                       f"or try: {list(interface_map.keys())}")
            else:
                raise MulticastJoinError(f"Interface {interface_name} not supported. "
                                       f"Supported interfaces: {list(interface_map.keys())}")
    
    @staticmethod
    def resolve_interface_param(interface_param: Optional[str], source_ip: Optional[str] = None) -> str:
        """
        Resolve interface parameter to IP address with intelligent selection
        
        Args:
            interface_param: Can be None (auto-detect), IP address, or interface name
            source_ip: Optional source IP from the sender to help with interface selection
            
        Returns:
            str: IP address to use for multicast operations
        """
        # Priority 1: Use explicitly provided interface parameter
        if interface_param is not None:
            # Check if it's already an IP address
            try:
                ipaddress.ip_address(interface_param)
                return interface_param  # It's already a valid IP
            except ValueError:
                # It's not an IP, treat as interface name
                return MulticastUtils.interface_name_to_ip(interface_param)
        
        # Priority 2: Use configured interface from Config.py
        configured_interface = MulticastUtils.get_configured_interface()
        if configured_interface is not None:
            try:
                ipaddress.ip_address(configured_interface)
                return configured_interface  # It's an IP address
            except ValueError:
                # It's an interface name
                return MulticastUtils.interface_name_to_ip(configured_interface)
        
        # Priority 3: Try to find best interface for the source IP (if provided)
        if source_ip is not None:
            try:
                best_interface = MulticastUtils.get_best_interface_for_destination(source_ip)
                if best_interface != "0.0.0.0":
                    return best_interface
            except Exception:
                pass
        
        # Priority 4: Fall back to default interface detection
        return MulticastUtils.get_interface_ip()
    
    @staticmethod
    def join_multicast_group_igmpv3(
        multicast_ip: str, 
        source_ip: str, 
        port: int,
        interface_name: Optional[str] = None,
        timeout: int = 10
    ) -> socket.socket:
        """
        Join a multicast group using IGMP v3 with source filtering
        
        Args:
            multicast_ip: The multicast group IP address
            source_ip: The source IP address to filter on
            port: The port number to bind to
            interface_name: The local interface name or IP (optional, auto-detected if None)
            timeout: Socket timeout in seconds
            
        Returns:
            socket.socket: The bound socket ready to receive multicast traffic
            
        Raises:
            MulticastJoinError: If the join operation fails
        """
        if not MulticastUtils.is_multicast_address(multicast_ip):
            raise MulticastJoinError(f"Invalid multicast address: {multicast_ip}")
        
        interface_ip = MulticastUtils.resolve_interface_param(interface_name, source_ip)
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Set socket timeout
            sock.settimeout(timeout)
            
            # Windows-specific multicast handling
            if platform.system() == "Windows":
                # On Windows, bind to INADDR_ANY for multicast
                try:
                    sock.bind(('', port))  # Bind to any address, specific port
                except Exception:
                    # Fallback: bind to multicast address
                    sock.bind((multicast_ip, port))
            else:
                # On Linux/Unix, bind to the multicast address
                sock.bind((multicast_ip, port))
            
            # Join the multicast group
            if interface_ip == "0.0.0.0":
                # Use INADDR_ANY for interface selection
                mreq = struct.pack("4s4s", 
                                 socket.inet_aton(multicast_ip), 
                                 struct.pack("!I", socket.INADDR_ANY))
            else:
                # Use specific interface IP
                mreq = struct.pack("4s4s", 
                                 socket.inet_aton(multicast_ip), 
                                 socket.inet_aton(interface_ip))
            
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            # For IGMP v3 source filtering, we need to set up source-specific multicast
            # This is a simplified approach - full IGMP v3 implementation would require
            # more complex packet construction
            try:
                # Set socket option for source filtering (if supported by OS)
                # Note: This is OS-dependent and may not work on all systems
                source_filter = struct.pack("4s4s", 
                                          socket.inet_aton(source_ip), 
                                          socket.inet_aton(multicast_ip))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_SOURCE_MEMBERSHIP, source_filter)
            except (OSError, AttributeError):
                # Fallback: If source filtering is not supported, log a warning
                # but continue with regular multicast join
                print(f"Warning: Source filtering not supported on this system. "
                      f"Joining multicast group {multicast_ip} without source filtering.")
            
            return sock
            
        except Exception as e:
            if 'sock' in locals():
                sock.close()
            raise MulticastJoinError(f"Failed to join multicast group {multicast_ip}: {e}")
    
    @staticmethod
    def join_multicast_group_simple(
        multicast_ip: str, 
        port: int,
        interface_name: Optional[str] = None,
        timeout: int = 10
    ) -> socket.socket:
        """
        Join a multicast group using simple IGMP (fallback method)
        
        Args:
            multicast_ip: The multicast group IP address
            port: The port number to bind to
            interface_name: The local interface name or IP (optional, auto-detected if None)
            timeout: Socket timeout in seconds
            
        Returns:
            socket.socket: The bound socket ready to receive multicast traffic
        """
        if not MulticastUtils.is_multicast_address(multicast_ip):
            raise MulticastJoinError(f"Invalid multicast address: {multicast_ip}")
        
        interface_ip = MulticastUtils.resolve_interface_param(interface_name)
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Set socket timeout
            sock.settimeout(timeout)
            
            # Windows-specific multicast handling
            if platform.system() == "Windows":
                # On Windows, bind to INADDR_ANY for multicast
                try:
                    sock.bind(('', port))  # Bind to any address, specific port
                except Exception:
                    # Fallback: bind to multicast address
                    sock.bind((multicast_ip, port))
            else:
                # On Linux/Unix, bind to the multicast address
                sock.bind((multicast_ip, port))
            
            # Join the multicast group
            if interface_ip == "0.0.0.0":
                # Use INADDR_ANY for interface selection
                mreq = struct.pack("4s4s", 
                                 socket.inet_aton(multicast_ip), 
                                 struct.pack("!I", socket.INADDR_ANY))
            else:
                # Use specific interface IP
                mreq = struct.pack("4s4s", 
                                 socket.inet_aton(multicast_ip), 
                                 socket.inet_aton(interface_ip))
            
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            return sock
            
        except Exception as e:
            if 'sock' in locals():
                sock.close()
            raise MulticastJoinError(f"Failed to join multicast group {multicast_ip}: {e}")
    
    @staticmethod
    def leave_multicast_group(sock: socket.socket, multicast_ip: str, interface_name: Optional[str] = None):
        """
        Leave a multicast group
        
        Args:
            sock: The socket that was used to join the group
            multicast_ip: The multicast group IP address
            interface_name: The local interface name or IP (optional, auto-detected if None)
        """
        try:
            interface_ip = MulticastUtils.resolve_interface_param(interface_name)
            
            # Windows-specific handling for leaving multicast
            if interface_ip == "0.0.0.0" or platform.system() == "Windows":
                # Use INADDR_ANY for interface selection (Windows-friendly)
                mreq = struct.pack("4s4s", 
                                 socket.inet_aton(multicast_ip), 
                                 struct.pack("!I", socket.INADDR_ANY))
            else:
                # Use specific interface IP
                mreq = struct.pack("4s4s", 
                                 socket.inet_aton(multicast_ip), 
                                 socket.inet_aton(interface_ip))
            
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
        except Exception as e:
            # Try multiple fallback strategies
            fallback_attempts = []
            
            # Fallback 1: Try with INADDR_ANY
            if not (interface_ip == "0.0.0.0" or platform.system() == "Windows"):
                fallback_attempts.append(("INADDR_ANY", lambda: struct.pack("4s4s", 
                                                                           socket.inet_aton(multicast_ip), 
                                                                           struct.pack("!I", socket.INADDR_ANY))))
            
            # Fallback 2: Try with auto-detected interface if we used a specific one
            if interface_name is not None:
                try:
                    auto_interface_ip = MulticastUtils.get_interface_ip()
                    if auto_interface_ip != interface_ip:
                        fallback_attempts.append(("auto-detected", lambda: struct.pack("4s4s", 
                                                                                      socket.inet_aton(multicast_ip), 
                                                                                      socket.inet_aton(auto_interface_ip))))
                except Exception:
                    pass
            
            # Try fallback attempts
            for attempt_name, mreq_func in fallback_attempts:
                try:
                    mreq = mreq_func()
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                    return  # Success with fallback
                except Exception:
                    continue
            
            # If all attempts fail, just print a warning but don't crash
            print(f"Warning: Failed to leave multicast group {multicast_ip}: {e}")
            # Note: This is often not critical as the socket will be closed anyway
    
    @staticmethod
    def receive_multicast_data(sock: socket.socket, buffer_size: int = 4096) -> Tuple[bytes, str]:
        """
        Receive data from a multicast socket
        
        Args:
            sock: The multicast socket
            buffer_size: Maximum buffer size for received data
            
        Returns:
            Tuple of (data, source_address)
        """
        try:
            data, addr = sock.recvfrom(buffer_size)
            return data, addr[0]
        except socket.timeout:
            return b"", ""
        except Exception as e:
            raise MulticastJoinError(f"Failed to receive multicast data: {e}")
    
    @staticmethod
    def test_multicast_connectivity(
        multicast_ip: str, 
        source_ip: str, 
        port: int,
        duration: int = 5,
        interface_name: Optional[str] = None
    ) -> bool:
        """
        Test multicast connectivity by joining the group and listening for data
        
        Args:
            multicast_ip: The multicast group IP address
            source_ip: The source IP address to filter on
            port: The port number
            duration: How long to listen for data (seconds)
            interface_name: The local interface name or IP (optional, auto-detected if None)
            
        Returns:
            bool: True if data was received, False otherwise
        """
        sock = None
        try:
            # Try IGMP v3 with source filtering first
            try:
                sock = MulticastUtils.join_multicast_group_igmpv3(
                    multicast_ip, source_ip, port, interface_name=interface_name
                )
                print(f"Successfully joined multicast group {multicast_ip} with source filtering for {source_ip}")
            except MulticastJoinError:
                # Fallback to simple multicast join
                sock = MulticastUtils.join_multicast_group_simple(
                    multicast_ip, port, interface_name=interface_name
                )
                print(f"Successfully joined multicast group {multicast_ip} (without source filtering)")
            
            # Listen for data
            start_time = time.time()
            data_received = False
            
            while time.time() - start_time < duration:
                data, source = MulticastUtils.receive_multicast_data(sock, 1024)
                if data:
                    print(f"Received {len(data)} bytes from {source}")
                    data_received = True
                    break
            
            return data_received
            
        except Exception as e:
            print(f"Multicast connectivity test failed: {e}")
            return False
        finally:
            if sock:
                MulticastUtils.leave_multicast_group(sock, multicast_ip)
                sock.close()
