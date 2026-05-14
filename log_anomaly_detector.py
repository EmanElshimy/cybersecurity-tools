#!/usr/bin/env python3
"""
Log anomaly detector for security events
Use case: Detect brute force, scanning, and unusual patterns in real-time
"""
import re
from collections import defaultdict
from datetime import datetime, timedelta

class LogAnomalyDetector:
    def __init__(self):
        # track failed logins per IP with timestamps
        self.failed_logins = defaultdict(list)
    
    def detect_brute_force(self, log_file):
        """Read auth.log and detect brute force attempts"""
        
        with open(log_file, 'r') as f:
            for line in f:
                # look for failed SSH attempts
                match = re.search(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    self.failed_logins[ip].append(datetime.now())
        
        # check for brute force
        alerts = []
        now = datetime.now()
        
        for ip, timestamps in self.failed_logins.items():
            # count failures in last 5 minutes
            recent = [ts for ts in timestamps if now - ts <= timedelta(minutes=5)]
            
            if len(recent) >= 10:
                alerts.append(f"BRUTE FORCE from {ip}: {len(recent)} attempts in 5 minutes")
            elif len(recent) >= 5:
                alerts.append(f"SUSPICIOUS from {ip}: {len(recent)} failed attempts")
        
        return alerts

# usage
detector = LogAnomalyDetector()
alerts = detector.detect_brute_force("auth.log")
for alert in alerts:
    print(alert)
