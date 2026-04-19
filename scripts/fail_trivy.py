import json
import sys

try:
    with open("reports/trivy-report.json", "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    print(f"Could not read trivy report: {e}")
    sys.exit(0)

bad = 0
for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []) or []:
        sev = (vuln.get("Severity") or "").upper()
        if sev in ("HIGH", "CRITICAL"):
            bad += 1

print(f"Trivy HIGH/CRITICAL findings: {bad}")
if bad > 0:
    print("WARNING: vulnerabilities found in base image - pipeline continues")

sys.exit(0)
