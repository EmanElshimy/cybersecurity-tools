#!/usr/bin/env python3
"""
Smart Network scanner
"""

import socket
from datetime import datetime

class SmartScanner:
    def __init__(self, target):
        self.target = target
        # common ports and their services
        self.ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            80: 'HTTP', 443: 'HTTPS', 3389: 'RDP', 3306: 'MySQL',
            5900: 'VNC', 8080: 'HTTP-Alt'
        }
        # dangerous services to flag
        self.dangerous = {21: 'FTP', 23: 'Telnet', 3389: 'RDP', 5900: 'VNC'}
    
    def scan_port(self, port):
        """Check if a single port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0  # true if open
        except:
            return False
    
    def run_scan(self):
        """Scan all common ports"""
        print(f"Scanning {self.target} at {datetime.now()}")
        
        open_ports = []
        for port, service in self.ports.items():
            if self.scan_port(port):
                open_ports.append((port, service))
                print(f"  Port {port}: {service} - OPEN")
        
        # risk assessment
        risks = [port for port, _ in open_ports if port in self.dangerous]
        
        print(f"\nFound {len(open_ports)} open ports")
        if risks:
            print(f"WARNING: Dangerous services on ports: {risks}")
            if 23 in risks:
                print("  - Telnet is unencrypted. Use SSH instead.")
            if 3389 in risks:
                print("  - RDP is a common brute force target. Restrict access.")
        else:
            print("No dangerous services found.")
        
        return open_ports

# usage
scanner = SmartScanner("127.0.0.1")
results = scanner.run_scan()
