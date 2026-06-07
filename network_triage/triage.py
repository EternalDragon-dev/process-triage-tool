from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256

from network_triage.models import NetworkConnection, NetworkFinding
from network_triage.rules import evaluate_connection
from process_triage.audit import AuditLogger, audit_tool


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_report(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(canonical).hexdigest()


def _calculate_confidence_factor(findings: list[NetworkFinding]) -> float:
    if not findings:
        return 0.2
    total = sum(f.confidence_factor for f in findings)
    return round(total / len(findings), 3)


@audit_tool(
    tool_name="run_network_triage",
    reasoning="Evaluate network connection artifacts and generate deterministic network findings.",
)
def run_network_triage(
    connections: list[NetworkConnection],
    source: str,
    audit_logger: AuditLogger | None = None,
    include_audit_events: bool = True,
) -> dict:
    logger = audit_logger or AuditLogger(enabled=False)
    logger.log("network_triage_started", source=source, total_connections=len(connections))

    findings: list[NetworkFinding] = []
    for connection in connections:
        connection_findings = evaluate_connection(connection, audit_logger=logger)
        findings.extend(connection_findings)
        logger.log(
            "network_connection_evaluated",
            pid=connection.pid,
            process_name=connection.process_name,
            findings_generated=len(connection_findings),
        )

    by_severity = Counter(f.severity for f in findings)
    confidence_factor = _calculate_confidence_factor(findings)

    report: dict = {
        "report_type": "sentinel_loop.network_triage.v1",
        "generated_at_utc": _utc_now_iso(),
        "input": {"source": source, "total_connections": len(connections)},
        "summary": {
            "total_findings": len(findings),
            "high": by_severity.get("HIGH", 0),
            "medium": by_severity.get("MEDIUM", 0),
            "low": by_severity.get("LOW", 0),
        },
        "confidence_factor": confidence_factor,
        "findings": [f.to_dict() for f in findings],
    }

    integrity_seed = dict(report)
    integrity_seed["integrity"] = {"hash_algorithm": "sha256", "report_sha256": "PENDING"}
    report_hash = _hash_report(integrity_seed)
    report["integrity"] = {"hash_algorithm": "sha256", "report_sha256": report_hash}

    logger.log(
        "network_triage_completed",
        total_findings=len(findings),
        high=by_severity.get("HIGH", 0),
        medium=by_severity.get("MEDIUM", 0),
        low=by_severity.get("LOW", 0),
        confidence_factor=confidence_factor,
        report_sha256=report_hash,
    )

    if include_audit_events:
        report["audit_events"] = logger.events

    return report
