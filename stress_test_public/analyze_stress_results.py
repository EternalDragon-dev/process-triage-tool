import json
from collections import Counter
from pathlib import Path
from statistics import mean

BASE = Path(__file__).resolve().parent
REPORT = BASE / "public_correction_report.json"
AUDIT = BASE / "public_correction_audit_log.jsonl"

with REPORT.open(encoding="utf-8") as f:
    report = json.load(f)

with AUDIT.open(encoding="utf-8") as f:
    audit = [json.loads(line) for line in f if line.strip()]

corr = report.get("corrected_findings", [])
changes = [round(c["revised_confidence"] - c["original_confidence"], 3) for c in corr]
rule_counts = Counter(c["rule_id"] for c in corr)
ctype_counts = Counter(c["correction_type"] for c in corr)

up = sum(1 for d in changes if d > 0)
down = sum(1 for d in changes if d < 0)
flat = sum(1 for d in changes if d == 0)

print("report_type", report.get("report_type"))
print("integrity_sha256", report.get("integrity", {}).get("report_sha256"))
print("triage_summary", report.get("triage_summary"))
print("correction_summary", report.get("correction_summary"))
print("confidence_factor", report.get("confidence_factor"))
print("confidence_shift_counts", {"up": up, "down": down, "flat": flat})
print("avg_shift", round(mean(changes), 3) if changes else 0)
print("max_increase", max(changes) if changes else 0)
print("max_decrease", min(changes) if changes else 0)
print("top_rules", rule_counts.most_common())
print("correction_types", dict(ctype_counts))

audit_types = Counter(e["event_type"] for e in audit)
print("audit_total_events", len(audit))
print("audit_event_types", dict(audit_types))
started = audit_types.get("audit_tool_invocation_started", 0)
completed = audit_types.get("audit_tool_invocation_completed", 0)
print(
    "audit_tool_invocation_balance",
    {"started": started, "completed": completed, "balanced": started == completed},
)