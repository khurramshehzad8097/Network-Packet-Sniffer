#!/usr/bin/env python3

import ipaddress
import socket
import struct
import sys
import argparse

parser = argparse.ArgumentParser(description='Network packet sniffer')
parser.add_argument('--ip', help='IP address to sniff on', required=True)
parser.add_argument('--proto', help='Protocol to sniff (TCP/ICMP)', required=True)
parser.add_argument('--data', help='Display data', action='store_true')
opts = parser.parse_args()

class Packet:
    def __init__(self, data):
        self.packet = data
        header = struct.unpack('<BBHHHBBH4s4s', self.packet[0:20])
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.off = header[4]
        self.ttl = header[5]
        self.pro = header[6]
        self.num = header[7]
        self.src = header[8]
        self.dst = header[9]
        
        self.src_addr = ipaddress.ip_address(self.src)
        self.dst_addr = ipaddress.ip_address(self.dst)
        
        self.protocol_map = {1: "ICMP", 6: "TCP"}  # Added TCP
        
        try:
            self.protocol = self.protocol_map.get(self.pro, str(self.pro))
        except Exception as e:
            print(f';{e} No protocol for {self.pro}')
            self.protocol = str(self.pro)
        
    def print_header_short(self):  # Fixed indentation
        print(f'Protocol: {self.protocol} {self.src_addr} -> {self.dst_addr}')
         
    def print_data(self):  # Fixed indentation
        data = self.packet[20:]
        print('*'*10 + 'ASCII START' + '*'*10)
        for b in data:
            if b < 128:
                print(chr(b), end='')
            else:
                print('.', end='')
        print('\n' + '*'*10 + 'ASCII END' + '*'*10)
            

def sniff(host):
    # Convert protocol string to proper case
    proto_upper = opts.proto.upper()
    
    if proto_upper == 'TCP':
        socket_protocol = socket.IPPROTO_TCP
    elif proto_upper == 'ICMP':
        socket_protocol = socket.IPPROTO_ICMP
    else:
        print(f"Unsupported protocol: {opts.proto}")
        sys.exit(1)
    
    # Create raw socket
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        # Bind to the specified IP address
        sniffer.bind((host, 0))
        # Include IP headers
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        print(f"Sniffing on {host} for {proto_upper} packets...")
        
        try:
            while True:
                raw_data, addr = sniffer.recvfrom(65535)  # Use recvfrom to get address info
                packet = Packet(raw_data)
                packet.print_header_short()
                if opts.data:
                    packet.print_data()
        except KeyboardInterrupt:
            print("\nSniffing stopped.")
            sys.exit(0)
            
    except PermissionError:
        print("Error: This script requires root privileges to create raw sockets.")
        sys.exit(1)
    except OSError as e:
        print(f"Socket error: {e}")
        print(f"Make sure {host} is a valid local IP address assigned to this machine.")
        sys.exit(1)

if __name__ == '__main__':
    # Pass the IP address from command line to the sniff function
    sniff(opts.ip)