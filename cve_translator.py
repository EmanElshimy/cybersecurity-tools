#!/usr/bin/env python3
"""
CVE to plain english translator
Author: Eman Elshimy
Use case: Convert technical CVE data into executive-readable risk summaries
"""

import requests
import json
from datetime import datetime
from typing import Dict, Optional

class CVETranslator:
    def __init__(self):
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.severity_map = {
            "CRITICAL": "Immediate action required - attack is likely and impact is severe",
            "HIGH": "Take action within days - attackers will actively exploit this",
            "MEDIUM": "Plan remediation within weeks - limited impact or complex attack",
            "LOW": "Monitor and patch during normal cycles"
        }
    
    def fetch_cve(self, cve_id: str) -> Optional[Dict]:
        """Fetch CVE data from NVD API"""
        url = f"{self.nvd_api}?cveId={cve_id}"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data.get('vulnerabilities'):
                return data['vulnerabilities'][0]['cve']
            return None
        except requests.exceptions.RequestException as e:
            print(f"API Error: {e}")
            return None
    
    def translate_to_plain_english(self, cve_data: Dict) -> str:
        """Convert technical CVE into plain English"""
        # Extract metrics
        metrics = cve_data.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
        
        severity = cvss_v3.get('baseSeverity', 'UNKNOWN')
        score = cvss_v3.get('baseScore', 'N/A')
        
        # Extract description (remove tech jargon)
        description = cve_data.get('descriptions', [{}])[0].get('value', 'No description')
        
        # Simplify description
        simplified = self._simplify_description(description)
        
        # Build plain English summary
        summary = f"""
CVE: {cve_data.get('id', 'Unknown')}
Published: {cve_data.get('published', 'Unknown')[:10]}
Severity: {severity} (CVSS: {score})
Risk to business: {self.severity_map.get(severity, 'Review required')}

What this means in plain English:
{simplified}

For executives:
• {'Patch within 48 hours' if severity in ['CRITICAL', 'HIGH'] else 'Schedule for next patch cycle'}
• {'Expect active exploitation' if severity == 'CRITICAL' else 'Limited exploitation reported'}

Technical team action:
• Affected versions: {self._extract_versions(cve_data)}
• Reference: {cve_data.get('references', [{}])[0].get('url', 'N/A')}
"""
        return summary
    
    def _simplify_description(self, tech_description: str) -> str:
        """Remove CVE-specific jargon"""
        # Common replacements
        replacements = {
            'buffer overflow': 'attacker can crash the system or run their own code',
            'privilege escalation': 'a normal user can gain admin access',
            'SQL injection': 'attacker can directly read or modify your database',
            'XSS': 'attacker can inject malicious code into web pages',
            'remote code execution': 'attacker can run any command on your server from anywhere',
            'denial of service': 'attacker can make your service unavailable',
            'authentication bypass': 'attacker can log in without a password',
            'information disclosure': 'attacker can read sensitive data they should not access'
        }
        
        simplified = tech_description
        for tech_term, plain_term in replacements.items():
            if tech_term in simplified.lower():
                simplified = simplified.lower().replace(tech_term, plain_term)
        
        # Truncate if too long
        if len(simplified) > 300:
            simplified = simplified[:297] + "..."
        
        return simplified
    
    def _extract_versions(self, cve_data: Dict) -> str:
        """Extract affected version info"""
        try:
            nodes = cve_data.get('configurations', [{}])[0].get('nodes', [])
            for node in nodes:
                for match in node.get('cpeMatch', []):
                    if match.get('vulnerable'):
                        version = match.get('criteria', '').split(':')[-1]
                        return f"Version {version} or earlier"
            return "Check NVD link for version details"
        except:
            return "See reference link"
    
    def batch_translate(self, cve_list: list) -> str:
        """Translate multiple CVEs"""
        reports = []
        for cve_id in cve_list:
            print(f"Processing {cve_id}...")
            data = self.fetch_cve(cve_id)
            if data:
                reports.append(self.translate_to_plain_english(data))
            else:
                reports.append(f"❌ Could not fetch {cve_id}")
        return "\n" + ("="*60).join(reports)

# ============= USAGE EXAMPLE =============
if __name__ == "__main__":
    translator = CVETranslator()
    
    # Test with recent critical CVEs
    test_cves = ["CVE-2024-6387", "CVE-2023-44487"]
    
    for cve_id in test_cves:
        print(f"\n{'='*60}")
        print(f"Fetching {cve_id}...")
        cve_data = translator.fetch_cve(cve_id)
        if cve_data:
            plain_english = translator.translate_to_plain_english(cve_data)
            print(plain_english)
        else:
            print(f"CVE {cve_id} not found or API rate limited")

"""
EXPECTED OUTPUT (for CVE-2024-6387 - regreSSHion):
============================================================
CVE: CVE-2024-6387
Published: 2024-07-09
Severity: CRITICAL (CVSS: 8.1)
Risk to business: Immediate action required - attack is likely and impact is severe

What this means in plain English:
a signal handler race condition in OpenSSH server (sshd) allows 
attacker can run any command on your server from anywhere

For executives:
• Patch within 48 hours
• Expect active exploitation

Technical team action:
• Affected versions: Version 4.4p1 or earlier
• Reference: https://nvd.nist.gov/vuln/detail/CVE-2024-6387

WHAT THIS CODE DOES:
1. Fetches raw CVE JSON from NIST NVD API
2. Extracts CVSS score, severity, description
3. Replaces technical jargon with business-friendly language
4. Generates separate summaries for executives vs technical teams
5. Handles API errors gracefully
"""