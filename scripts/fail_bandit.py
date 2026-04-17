import json
import sys

with open("reports/bandit-report.json", "r", encoding="utf-8") as f:
    data = json.load(f)

results = data.get("results", [])
bad = []

for item in results:
    sev = item.get("issue_severity", "").upper()
    if sev in ("MEDIUM", "HIGH"):
        bad.append(item)

print(f"Bandit findings MEDIUM/HIGH: {len(bad)}")

if bad:
    for i, item in enumerate(bad[:10], 1):
        print(f"[{i}] {item.get('filename')}:{item.get('line_number')} - {item.get('test_name')} - {item.get('issue_text')}")
    sys.exit(1)

sys.exit(0)
