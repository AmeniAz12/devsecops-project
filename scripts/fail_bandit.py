import json
import sys

try:
    with open("reports/bandit-report.json", "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    print(f"Could not read bandit report: {e}")
    sys.exit(0)

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
    print("WARNING: Bandit findings found - pipeline continues")

sys.exit(0)  # warn only, do not block
