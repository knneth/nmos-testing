"""
TP10-1Sec12.1.py
----------------
A Python utility to listen for IEEE 1588 PTPv2 Announce and Delay messages.

Features:
 - Listens on UDP ports 319 (Delay_Req/Delay_Resp) and 320 (Announce)
 - Joins the standard multicast group 224.0.1.129
 - Displays domain and grandmaster information
 - Tracks Delay_Req / Delay_Resp pairs by clock identity and port number
 - Threaded operation for simultaneous listening

Usage:
    sudo python3 TP10-1Sec12.1.py <interface_ip>

Example:
    sudo python3 TP10-1Sec12.1.py 192.168.1.10
"""
import socket
import struct
import argparse
import time
import threading

PTP_MULTICAST_ADDR = '224.0.1.129'
PTP_EVENT_PORT = 319   # Delay_Req / Delay_Resp
PTP_GENERAL_PORT = 320 # Announce

PTP_ANNOUNCE = 0x0B
DELAY_REQ = 1
DELAY_RESP = 9

def parse_ptp_announce(data):
    if len(data) < 34:
        return None

    message_type = data[0] & 0x0F
    domain_number = data[4]

    if message_type != PTP_ANNOUNCE:
        return None

    gm_identity = data[20:28].hex(':').upper()

    return {
        'domain': domain_number,
        'grandmaster_identity': gm_identity
    }

def get_message_type(data):
    return data[0] & 0x0F

def get_clock_identity(data):
    return data[8:16]

def get_port_number(data):
    return struct.unpack('!H', data[16:18])[0]

def clock_id_to_str(clock_id):
    return ':'.join(f'{b:02X}' for b in clock_id)

def get_requesting_port_identity(data, msg_type):
    if msg_type == DELAY_RESP:
        clock_id = data[34:42]
        port_num = struct.unpack('!H', data[42:44])[0]
    elif msg_type == DELAY_REQ:
        clock_id = get_clock_identity(data)
        port_num = get_port_number(data)
    else:
        return None
    return (clock_id, port_num)

class DelayReqTracker:
    def __init__(self):
        self.requests = {}
        self.lock = threading.Lock()

    def add_request(self, follower_ip, port, clock_id, port_num):
        key = (clock_id, port_num)
        with self.lock:
            self.requests[key] = {'time': time.time(), 'ip': follower_ip, 'port': port, 'matched': False}

    def match_response(self, clock_id, port_num):
        key = (clock_id, port_num)
        with self.lock:
            if key in self.requests:
                self.requests[key]['matched'] = True
                return True
        return False

    def cleanup(self, max_age_sec=60):
        now = time.time()
        with self.lock:
            to_del = [k for k,v in self.requests.items() if now - v['time'] > max_age_sec]
            for k in to_del:
                del self.requests[k]

def listen_announces(interface_ip, stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', PTP_GENERAL_PORT))

    mreq = struct.pack("4s4s", socket.inet_aton(PTP_MULTICAST_ADDR), socket.inet_aton(interface_ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print(f"Listening for PTPv2 Announce messages on {PTP_MULTICAST_ADDR}:{PTP_GENERAL_PORT} via {interface_ip}")
    print("Press Ctrl+C to stop.\n")

    try:
        while not stop_event.is_set():
            sock.settimeout(1)
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            result = parse_ptp_announce(data)
            if result:
                print(f"\n📡 Announce message from {addr}")
                print(f"   Domain: {result['domain']}")
                print(f"   Grandmaster ID: {result['grandmaster_identity']}")
    finally:
        print("Closing Socket")
        sock.close()

def listen_delay(interface_ip, tracker, stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', PTP_EVENT_PORT))

    mreq = struct.pack("4s4s", socket.inet_aton(PTP_MULTICAST_ADDR), socket.inet_aton(interface_ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print(f"Listening for PTPv2 Delay_Req/Delay_Resp on {PTP_MULTICAST_ADDR}:{PTP_EVENT_PORT} via {interface_ip}")

    try:
        while not stop_event.is_set():
            sock.settimeout(1)
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue

            if len(data) < 44:
                continue

            msg_type = get_message_type(data)

            if msg_type == DELAY_REQ:
                clock_id = get_clock_identity(data)
                port_num = get_port_number(data)
                follower_ip, follower_port = addr
                tracker.add_request(follower_ip, follower_port, clock_id, port_num)
                print(f"\n⏳ Delay_Req from {follower_ip}:{follower_port} - ClockID: {clock_id_to_str(clock_id)}, Port: {port_num}")
            elif msg_type == DELAY_RESP:
                clock_id = data[34:42]
                port_num = struct.unpack('!H', data[42:44])[0]
                matched = tracker.match_response(clock_id, port_num)
                status = "✅ Matched Delay_Resp" if matched else "⚠️ Unmatched Delay_Resp"
                print(f"\n{status} - ClockID: {clock_id_to_str(clock_id)}, Port: {port_num}")

            tracker.cleanup()
    finally:
        sock.close()

def main():
    parser = argparse.ArgumentParser(
        prog='TP10-1Sec12.1.py',
        description="Listen for PTPv2 Announce and Delay messages on a specified network interface."
    )
    parser.add_argument(
        'interface_ip',
        help="IP address of the local network interface to use (e.g. 192.168.1.10)"
    )
    args = parser.parse_args()

    stop_event = threading.Event()
    tracker = DelayReqTracker()

    announce_thread = threading.Thread(target=listen_announces, args=(args.interface_ip, stop_event))
    delay_thread = threading.Thread(target=listen_delay, args=(args.interface_ip, tracker, stop_event))

    announce_thread.start()
    delay_thread.start()

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping...")
        stop_event.set()

    announce_thread.join()
    delay_thread.join()
    print("Exited cleanly.")

if __name__ == "__main__":
    main()
