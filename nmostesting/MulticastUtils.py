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
from typing import Optional, Tuple
from . import Config as CONFIG


class MulticastJoinError(Exception):
    """Exception raised when multicast join operations fail"""
    pass


class MulticastUtils:
    """Utility class for multicast operations including IGMP v3 joins with source filtering"""

    # -----------------------------
    # Helpers
    # -----------------------------

    @staticmethod
    def _set_multicast_if(sock: socket.socket, interface_ip: str) -> None:
        """Set the outgoing/interface for multicast membership ops (best-effort)."""
        try:
            if interface_ip and interface_ip != "0.0.0.0":
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface_ip))
        except OSError:
            # Not fatal; some stacks don't require it
            pass

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
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
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
        """
        try:
            result = subprocess.run(['ipconfig', '/all'],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return None

            output = result.stdout
            interface_section = None
            lines = output.split('\n')

            for i, line in enumerate(lines):
                if 'adapter' in line.lower() and interface_name.lower() in line.lower():
                    interface_section = i
                    break
                elif line.strip().startswith(interface_name):
                    interface_section = i
                    break

            if interface_section is None:
                return None

            for i in range(interface_section, min(interface_section + 20, len(lines))):
                line = lines[i].strip()
                if 'IPv4 Address' in line:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        return ip_match.group(1)
                elif 'adapter' in line.lower() and i > interface_section:
                    break

        except Exception as e:
            print(f"Warning: Failed to query Windows interface {interface_name}: {e}")

        return None

    @staticmethod
    def get_best_interface_for_destination(dest_ip: str) -> str:
        """Determine the best local interface to reach dest_ip"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((dest_ip, 80))
                return s.getsockname()[0]
        except Exception:
            return MulticastUtils.get_interface_ip()

    @staticmethod
    def interface_name_to_ip(interface_name: str) -> str:
        """Convert network interface name to IP address"""
        if platform.system() == "Windows":
            windows_ip = MulticastUtils.get_windows_interface_ip(interface_name)
            if windows_ip:
                return windows_ip

        interface_map = {
            'lo': '127.0.0.1',
            'localhost': '127.0.0.1',
            'loopback': '127.0.0.1',
        }

        if platform.system() == "Windows":
            interface_map.update({
                'eth0': '0.0.0.0',
                'wlan0': '0.0.0.0',
                'any': '0.0.0.0',
                'ethernet': '0.0.0.0',
                'wi-fi': '0.0.0.0',
            })
        else:
            interface_map.update({
                'eth0': '0.0.0.0',
                'wlan0': '0.0.0.0',
                'any': '0.0.0.0',
            })

        if interface_name in interface_map:
            return interface_map[interface_name]
        else:
            if platform.system() == "Windows":
                raise MulticastJoinError(
                    f"Windows interface '{interface_name}' not found. "
                    f"Use 'ipconfig /all' to see available interfaces, "
                    f"or try: {list(interface_map.keys())}"
                )
            else:
                raise MulticastJoinError(
                    f"Interface {interface_name} not supported. "
                    f"Supported interfaces: {list(interface_map.keys())}"
                )

    @staticmethod
    def resolve_interface_param(interface_param: Optional[str], source_ip: Optional[str] = None) -> str:
        """Resolve interface parameter to IP address with intelligent selection"""
        if interface_param is not None:
            try:
                ipaddress.ip_address(interface_param)
                return interface_param
            except ValueError:
                return MulticastUtils.interface_name_to_ip(interface_param)

        configured_interface = MulticastUtils.get_configured_interface()
        if configured_interface is not None:
            try:
                ipaddress.ip_address(configured_interface)
                return configured_interface
            except ValueError:
                return MulticastUtils.interface_name_to_ip(configured_interface)

        if source_ip is not None:
            try:
                best_interface = MulticastUtils.get_best_interface_for_destination(source_ip)
                if best_interface != "0.0.0.0":
                    return best_interface
            except Exception:
                pass

        return MulticastUtils.get_interface_ip()

    # -----------------------------
    # Join (IGMPv3 SSM)
    # -----------------------------

    @staticmethod
    def join_multicast_group_igmpv3(
        multicast_ip: str,
        source_ip: str,
        port: int,
        interface_name: Optional[str] = None,
        timeout: int = 10
    ) -> Tuple[socket.socket, str]:
        """Join a multicast group using IGMP v3 with source filtering

        Returns:
            Tuple[socket.socket, str]: The socket and the resolved interface IP used for joining
        """
        if not MulticastUtils.is_multicast_address(multicast_ip):
            raise MulticastJoinError(f"Invalid multicast address: {multicast_ip}")

        interface_ip = MulticastUtils.resolve_interface_param(interface_name, source_ip)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)

            if platform.system() == "Windows":
                try:
                    sock.bind(('', port))
                except Exception:
                    sock.bind((multicast_ip, port))
            else:
                sock.bind(('', port))

            MulticastUtils._set_multicast_if(sock, interface_ip)

            # ASM membership
            if interface_ip == "0.0.0.0":
                mreq = struct.pack("4s4s",
                                   socket.inet_aton(multicast_ip),
                                   struct.pack("!I", socket.INADDR_ANY))
            else:
                mreq = struct.pack("4s4s",
                                   socket.inet_aton(multicast_ip),
                                   socket.inet_aton(interface_ip))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            # SSM membership (ip_mreq_source: group, source, iface)
            try:
                source_mreq = struct.pack(
                    "4s4s4s",
                    socket.inet_aton(multicast_ip),
                    socket.inet_aton(source_ip),
                    socket.inet_aton(interface_ip) if interface_ip != "0.0.0.0"
                    else struct.pack("!I", socket.INADDR_ANY),
                )
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_SOURCE_MEMBERSHIP, source_mreq)
            except (OSError, AttributeError):
                print(f"Warning: Source filtering not supported on this system. "
                      f"Joining multicast group {multicast_ip} without source filtering.")

            return sock, interface_ip

        except Exception as e:
            if 'sock' in locals():
                try:
                    sock.close()
                except Exception:
                    pass
            raise MulticastJoinError(f"Failed to join multicast group {multicast_ip}: {e}")

    # -----------------------------
    # Join (ASM simple)
    # -----------------------------

    @staticmethod
    def join_multicast_group_simple(
        multicast_ip: str,
        port: int,
        interface_name: Optional[str] = None,
        timeout: int = 10
    ) -> Tuple[socket.socket, str]:
        """Join a multicast group using simple IGMP (ASM)

        Returns:
            Tuple[socket.socket, str]: The socket and the resolved interface IP used for joining
        """
        if not MulticastUtils.is_multicast_address(multicast_ip):
            raise MulticastJoinError(f"Invalid multicast address: {multicast_ip}")

        interface_ip = MulticastUtils.resolve_interface_param(interface_name)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)

            if platform.system() == "Windows":
                try:
                    sock.bind(('', port))
                except Exception:
                    sock.bind((multicast_ip, port))
            else:
                sock.bind(('', port))

            MulticastUtils._set_multicast_if(sock, interface_ip)

            if interface_ip == "0.0.0.0":
                mreq = struct.pack("4s4s",
                                   socket.inet_aton(multicast_ip),
                                   struct.pack("!I", socket.INADDR_ANY))
            else:
                mreq = struct.pack("4s4s",
                                   socket.inet_aton(multicast_ip),
                                   socket.inet_aton(interface_ip))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            return sock, interface_ip

        except Exception as e:
            if 'sock' in locals():
                try:
                    sock.close()
                except Exception:
                    pass
            raise MulticastJoinError(f"Failed to join multicast group {multicast_ip}: {e}")

    # -----------------------------
    # Leave
    # -----------------------------

    @staticmethod
    def leave_multicast_group(sock: socket.socket, multicast_ip: str, interface_ip: str):
        """
        Leave a multicast group using the exact interface IP that was used for joining.

        Args:
            sock: The socket to leave from
            multicast_ip: The multicast group IP
            interface_ip: The resolved interface IP that was used for joining (returned by join methods)
        """
        try:
            # Use the exact same interface IP that was used for joining
            if interface_ip == "0.0.0.0":
                mreq = struct.pack(
                    "4s4s",
                    socket.inet_aton(multicast_ip),
                    struct.pack("!I", socket.INADDR_ANY),
                )
            else:
                mreq = struct.pack(
                    "4s4s",
                    socket.inet_aton(multicast_ip),
                    socket.inet_aton(interface_ip),
                )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)

            # Optional best-effort: attempt to drop any SSM memberships too
            try:
                drop_src_any = struct.pack(
                    "4s4s4s",
                    socket.inet_aton(multicast_ip),
                    struct.pack("!I", socket.INADDR_ANY),  # ANY source
                    struct.pack("!I", socket.INADDR_ANY),  # ANY interface
                )
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_SOURCE_MEMBERSHIP, drop_src_any)
            except (OSError, AttributeError):
                # Either unsupported or requires exact source; safe to ignore.
                pass

        except Exception as e:
            print(f"Warning: Failed to leave multicast group {multicast_ip}: {e}")

    # -----------------------------
    # Misc
    # -----------------------------

    @staticmethod
    def is_local_ip(ip: str) -> bool:
        """Check if the provided IP is assigned to a local interface."""
        try:
            hostname = socket.gethostname()
            local_ips = socket.gethostbyname_ex(hostname)[2]
            return ip in local_ips or ip == "127.0.0.1"
        except Exception:
            return False

    @staticmethod
    def receive_multicast_data(sock: socket.socket, buffer_size: int = 4096) -> Tuple[bytes, str]:
        """Receive data from a multicast socket"""
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
        """Test multicast connectivity by joining the group and listening for data"""
        sock = None
        interface_ip = None
        try:
            # Try IGMP v3 with source filtering first
            try:
                sock, interface_ip = MulticastUtils.join_multicast_group_igmpv3(
                    multicast_ip, source_ip, port, interface_name=interface_name
                )
                print(f"Successfully joined multicast group {multicast_ip} with source filtering for {source_ip}")
            except MulticastJoinError:
                # Fallback to simple multicast join
                sock, interface_ip = MulticastUtils.join_multicast_group_simple(
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
            if sock and interface_ip is not None:
                MulticastUtils.leave_multicast_group(sock, multicast_ip, interface_ip)
                sock.close()
