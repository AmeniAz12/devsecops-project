import json
import sys

with open("reports/trivy-report.json", "r", encoding="utf-8") as f:
    data = json.load(f)

bad = 0

for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []) or []:
        sev = (vuln.get("Severity") or "").upper()
        if sev in ("HIGH", "CRITICAL"):
            bad += 1

print(f"Trivy HIGH/CRITICAL findings: {bad}")

if bad > 0:
    sys.exit(1)

sys.exit(0)
