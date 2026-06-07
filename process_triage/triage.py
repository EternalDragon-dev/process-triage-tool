from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256

from process_triage.audit import AuditLogger, audit_tool
from process_triage.models import ProcessRecord
from process_triage.rules import evaluate_process


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_report(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(canonical).hexdigest()


@audit_tool(
    tool_name="run_triage",
    reasoning="Evaluate process artifacts using deterministic rules and produce structured findings.",
)
def run_triage(
    processes: list[ProcessRecord],
    source: str,
    audit_logger: AuditLogger | None = None,
    include_audit_events: bool = True,
) -> dict:
    logger = audit_logger or AuditLogger(enabled=False)
    logger.log("triage_started", source=source, total_processes=len(processes))

    findings = []
    for process in processes:
        process_findings = evaluate_process(process, audit_logger=logger)
        findings.extend(process_findings)
        logger.log(
            "process_evaluated",
            pid=process.pid,
            ppid=process.ppid,
            process_name=process.name,
            findings_generated=len(process_findings),
        )

    by_severity = Counter(f.severity for f in findings)
    report: dict = {
        "report_type": "sentinel_loop.process_triage.v1",
        "generated_at_utc": _utc_now_iso(),
        "input": {"source": source, "total_processes": len(processes)},
        "summary": {
            "total_findings": len(findings),
            "high": by_severity.get("HIGH", 0),
            "medium": by_severity.get("MEDIUM", 0),
            "low": by_severity.get("LOW", 0),
        },
        "findings": [f.to_dict() for f in findings],
    }

    integrity_seed = dict(report)
    integrity_seed["integrity"] = {"hash_algorithm": "sha256", "report_sha256": "PENDING"}
    report_hash = _hash_report(integrity_seed)
    report["integrity"] = {"hash_algorithm": "sha256", "report_sha256": report_hash}

    logger.log(
        "triage_completed",
        total_findings=len(findings),
        high=by_severity.get("HIGH", 0),
        medium=by_severity.get("MEDIUM", 0),
        low=by_severity.get("LOW", 0),
        report_sha256=report_hash,
    )

    if include_audit_events:
        report["audit_events"] = logger.events

    return report
