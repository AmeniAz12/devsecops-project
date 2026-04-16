import json
import sys
from pathlib import Path

report = Path("reports/zap-report.json")

if not report.exists():
    print("ZAP report not found")
    sys.exit(1)

with open(report, "r", encoding="utf-8") as f:
    data = json.load(f)

bad = 0
medium = 0
low = 0

sites = data.get("site", [])

for site in sites:
    for alert in site.get("alerts", []):
        risk = str(alert.get("riskcode", ""))

        if risk == "3":
            bad += 1
        elif risk == "2":
            medium += 1
        elif risk == "1":
            low += 1

print(f"ZAP High alerts: {bad}")
print(f"ZAP Medium alerts: {medium}")
print(f"ZAP Low alerts: {low}")

# Politique actuelle:
# - bloquer si au moins 1 alerte High
if bad > 0:
    sys.exit(1)

sys.exit(0)
