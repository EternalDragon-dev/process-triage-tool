from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256

from persistence_triage.models import PersistenceArtifact, PersistenceFinding
from persistence_triage.rules import evaluate_artifact
from process_triage.audit import AuditLogger, audit_tool


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_report(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(canonical).hexdigest()


def _calculate_confidence_factor(findings: list[PersistenceFinding]) -> float:
    if not findings:
        return 0.2
    total = sum(f.confidence_factor for f in findings)
    return round(total / len(findings), 3)


@audit_tool(
    tool_name="run_persistence_triage",
    reasoning="Evaluate persistence artifacts and generate deterministic persistence findings.",
)
def run_persistence_triage(
    artifacts: list[PersistenceArtifact],
    source: str,
    audit_logger: AuditLogger | None = None,
    include_audit_events: bool = True,
) -> dict:
    logger = audit_logger or AuditLogger(enabled=False)
    logger.log("persistence_triage_started", source=source, total_artifacts=len(artifacts))

    findings: list[PersistenceFinding] = []
    for artifact in artifacts:
        artifact_findings = evaluate_artifact(artifact, audit_logger=logger)
        findings.extend(artifact_findings)
        logger.log(
            "persistence_artifact_evaluated",
            artifact_type=artifact.artifact_type,
            artifact_name=artifact.name,
            findings_generated=len(artifact_findings),
        )

    by_severity = Counter(f.severity for f in findings)
    confidence_factor = _calculate_confidence_factor(findings)

    report: dict = {
        "report_type": "sentinel_loop.persistence_triage.v1",
        "generated_at_utc": _utc_now_iso(),
        "input": {"source": source, "total_artifacts": len(artifacts)},
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
        "persistence_triage_completed",
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
