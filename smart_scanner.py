#!/usr/bin/env python3
"""
Smart Network scanner
"""

import socket

def scan_port(host, port):
    # check if a port is open
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

# ports to check
common_ports = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3389: "RDP"}

host = "scanme.nmap.org"
print(f"Scanning {host}...\n")

for port, name in common_ports.items():
    if scan_port(host, port):
        print(f"Port {port} ({name}) is OPEN")
    else:
        print(f"Port {port} ({name}) is CLOSED")
