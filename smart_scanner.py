#!/usr/bin/env python3
"""
Smart Network scanner with service detection
Author: Eman Elshimy
Use case: Asset discovery, vulnerability scanning prep, network hygiene
"""

import socket
import threading
import sys
from datetime import datetime
from typing import List, Dict, Tuple

class SmartScanner:
    def __init__(self, target: str, timeout: float = 1.0):
        self.target = target
        self.timeout = timeout
        self.open_ports = []
        self.service_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        self.vulnerable_services = {
            21: 'FTP - Weak authentication, data sent in clear text',
            23: 'Telnet - All traffic unencrypted, severe security risk',
            3389: 'RDP - Brute force target, BlueKeep vulnerability',
            5900: 'VNC - Weak passwords common, no encryption by default'
        }
        
    def scan_port(self, port: int) -> Tuple[int, bool, str]:
        """Scan a single port and identify service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                service = self.service_map.get(port, 'Unknown')
                return port, True, service
            return port, False, ''
        except:
            return port, False, ''
    
    def run_scan(self, ports: List[int] = None) -> Dict:
        """Main scanning function with threading"""
        if ports is None:
            ports = list(self.service_map.keys())
        
        print(f"Scanning {self.target} at {datetime.now()}")
        print(f"Testing {len(ports)} ports...\n")
        
        threads = []
        results = []
        
        # Threaded scanning for speed
        def worker(port):
            results.append(self.scan_port(port))
        
        for port in ports:
            thread = threading.Thread(target=worker, args=(port,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Process results
        open_ports = [(port, service) for port, is_open, service in results if is_open]
        
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'open_ports': open_ports,
            'total_open': len(open_ports),
            'risk_assessment': self._assess_risk(open_ports)
        }
        
        return report
    
    def _assess_risk(self, open_ports: List[Tuple[int, str]]) -> Dict:
        """Generate risk assessment based on open services"""
        risks = []
        severity = 'low'
        
        for port, service in open_ports:
            if port in self.vulnerable_services:
                risks.append({
                    'port': port,
                    'service': service,
                    'risk': self.vulnerable_services[port]
                })
                severity = 'high' if port in [23, 3389] else 'medium'
        
        return {
            'severity': severity,
            'risks': risks,
            'recommendation': self._generate_recommendation(risks)
        }
    
    def _generate_recommendation(self, risks: List[Dict]) -> str:
        """Generate actionable remediation steps"""
        if not risks:
            return "No high-risk services detected. Follow least privilege principle."
        
        recs = []
        for risk in risks:
            if risk['port'] == 23:
                recs.append("Disable Telnet immediately, use SSH instead")
            elif risk['port'] == 21:
                recs.append("Migrate FTP to SFTP or FTPS with strong encryption")
            elif risk['port'] == 3389:
                recs.append("Restrict RDP with VPN, enable Network Level Authentication")
            elif risk['port'] == 5900:
                recs.append("Use VNC over SSH tunnel or switch to secure alternative")
        
        return "; ".join(recs)
    
    def banner_grab(self, port: int) -> str:
        """Attempt to grab service banner (for version detection)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            
            # Send generic probe
            if port == 80:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
            elif port == 22:
                sock.send(b"SSH-2.0-Client\r\n")
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner[:200]  # Truncate long banners
        except:
            return "Banner grab failed"

# ============= USAGE EXAMPLE =============
if __name__ == "__main__":
    # Scan localhost or a test target
    target = input("Enter target IP or hostname (default: 127.0.0.1): ").strip()
    if not target:
        target = "127.0.0.1"
    
    scanner = SmartScanner(target, timeout=0.5)
    
    # Scan common ports
    report = scanner.run_scan()
    
    # Display results
    print("\n" + "="*60)
    print(f"SCAN REPORT FOR {report['target']}")
    print("="*60)
    
    if report['open_ports']:
        print(f"\nFound {report['total_open']} open ports:\n")
        for port, service in report['open_ports']:
            banner = scanner.banner_grab(port)
            print(f"  Port {port}: {service}")
            if banner:
                print(f"    Banner: {banner[:80]}")
        
        # Risk assessment
        print(f"\nRISK ASSESSMENT: {report['risk_assessment']['severity'].upper()}")
        for risk in report['risk_assessment']['risks']:
            print(f"  • Port {risk['port']} ({risk['service']}): {risk['risk']}")
        
        print(f"\nRECOMMENDATION: {report['risk_assessment']['recommendation']}")
    else:
        print("\nNo common ports open. Good security posture!")
    
    print(f"\nScan completed: {report['timestamp']}")

"""
EXPECTED OUTPUT (if SSH and HTTP open):
============================================================
SCAN REPORT FOR 192.168.1.10
============================================================

Found 2 open ports:

  Port 22: SSH
    Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
  Port 80: HTTP
    Banner: HTTP/1.1 200 OK

RISK ASSESSMENT: LOW

RECOMMENDATION: No high-risk services detected. Follow least privilege principle.

Scan completed: 2026-04-03T12:30:45

EXPECTED OUTPUT (if dangerous ports open):
============================================================
Found 3 open ports:

  Port 23: Telnet
    Banner: Telnet server ready
  Port 3389: RDP
  Port 5900: VNC

RISK ASSESSMENT: HIGH
  • Port 23 (Telnet): All traffic unencrypted, severe security risk
  • Port 3389 (RDP): Brute force target, BlueKeep vulnerability
  • Port 5900 (VNC): Weak passwords common, no encryption by default

RECOMMENDATION: Disable Telnet immediately, use SSH instead; 
Restrict RDP with VPN, enable Network Level Authentication; 
Use VNC over SSH tunnel or switch to secure alternative

WHAT THIS CODE DOES:
1. Multi-threaded port scanning (faster than sequential)
2. Service identification from common port mapping
3. Vulnerability mapping for dangerous services (Telnet, RDP, FTP)
4. Banner grabbing for version detection
5. Generates business-friendly risk assessment and remediation steps
"""