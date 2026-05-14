#!/usr/bin/env python3
"""
CVE to plain english translator
"""
import requests

cve_id = 'CVE-2024-6387'
cve_url = url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

response = requests.get(url)
data = response.json()

cve = data['vulnerabilities'][0]['cve']
print(cve['id'])
print(cve['descriptions'][0]['value'])

# Expected answer:
# CVE-2024-6387
# A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.
