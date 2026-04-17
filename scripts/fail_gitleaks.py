import json
import sys
from pathlib import Path

report = Path("reports/gitleaks-report.json")

if not report.exists():
    print("Gitleaks report not found")
    sys.exit(1)

with open(report, "r", encoding="utf-8") as f:
    data = json.load(f)

count = len(data) if isinstance(data, list) else 0
print(f"Gitleaks findings: {count}")

if count > 0:
    for i, item in enumerate(data[:10], 1):
        print(f"[{i}] Rule={item.get('RuleID')} File={item.get('File')} Line={item.get('StartLine')}")
    sys.exit(1)

sys.exit(0)
