from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from correction_engine.correlator import run_correlations
from correction_engine.models import (
    CONFIRMED_UPWARD,
    DOWNGRADED,
    ESCALATED,
    UNCONFIRMED,
    CorrectedFinding,
)
from network_triage.loader import load_connections_csv
from network_triage.triage import run_network_triage
from persistence_triage.loader import load_persistence_csv
from persistence_triage.triage import run_persistence_triage
from process_triage.audit import AuditLogger, audit_tool
from process_triage.loader import load_processes_csv
from process_triage.triage import run_triage


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_report(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(canonical).hexdigest()


def _avg_confidence(findings: list[CorrectedFinding]) -> float:
    if not findings:
        return 0.0
    return round(sum(f.revised_confidence for f in findings) / len(findings), 3)


@audit_tool(
    tool_name="run_correction_loop",
    reasoning="Cross-reference process, network, and persistence findings to revise confidence based on corroborating evidence.",
)
def run_correction_loop(
    processes_csv: str,
    network_csv: str,
    persistence_csv: str,
    include_audit_events: bool = True,
    audit_log_path: str | None = None,
    audit_logger: AuditLogger | None = None,
) -> dict[str, Any]:
    """
    Full Hypothesis-Verification-Correction loop:

    1. Run all three deterministic triage tools independently.
    2. Feed their findings into the correlator.
    3. Emit a unified CorrectionReport with per-finding revised confidence and
       a complete audit trail of every hypothesis correction.
    """
    logger = audit_logger or AuditLogger(enabled=True)
    logger.log(
        "correction_loop_started",
        processes_csv=processes_csv,
        network_csv=network_csv,
        persistence_csv=persistence_csv,
    )

    processes = load_processes_csv(processes_csv, audit_logger=logger)
    process_report = run_triage(
        processes=processes,
        source=processes_csv,
        audit_logger=logger,
        include_audit_events=False,
    )

    connections = load_connections_csv(network_csv, audit_logger=logger)
    network_report = run_network_triage(
        connections=connections,
        source=network_csv,
        audit_logger=logger,
        include_audit_events=False,
    )

    artifacts = load_persistence_csv(persistence_csv, audit_logger=logger)
    persistence_report = run_persistence_triage(
        artifacts=artifacts,
        source=persistence_csv,
        audit_logger=logger,
        include_audit_events=False,
    )

    logger.log(
        "triage_phase_complete",
        process_findings=process_report["summary"]["total_findings"],
        network_findings=network_report["summary"]["total_findings"],
        persistence_findings=persistence_report["summary"]["total_findings"],
    )

    corrected_findings, correction_events = run_correlations(
        process_findings=process_report.get("findings", []),
        network_findings=network_report.get("findings", []),
        persistence_findings=persistence_report.get("findings", []),
    )

    for evt in correction_events:
        logger.log("correction_event", **evt.to_dict())

    by_type = Counter(cf.correction_type for cf in corrected_findings)
    avg_cf = _avg_confidence(corrected_findings)

    report: dict[str, Any] = {
        "report_type": "sentinel_loop.correction_engine.v1",
        "generated_at_utc": _utc_now_iso(),
        "input": {
            "processes_csv": processes_csv,
            "network_csv": network_csv,
            "persistence_csv": persistence_csv,
        },
        "triage_summary": {
            "process": process_report["summary"],
            "network": network_report["summary"],
            "persistence": persistence_report["summary"],
        },
        "correction_summary": {
            "total_corrected_findings": len(corrected_findings),
            ESCALATED: by_type.get(ESCALATED, 0),
            CONFIRMED_UPWARD: by_type.get(CONFIRMED_UPWARD, 0),
            DOWNGRADED: by_type.get(DOWNGRADED, 0),
            UNCONFIRMED: by_type.get(UNCONFIRMED, 0),
        },
        "confidence_factor": avg_cf,
        "correction_events": [e.to_dict() for e in correction_events],
        "corrected_findings": [cf.to_dict() for cf in corrected_findings],
    }

    integrity_seed = dict(report)
    integrity_seed["integrity"] = {"hash_algorithm": "sha256", "report_sha256": "PENDING"}
    report_hash = _hash_report(integrity_seed)
    report["integrity"] = {"hash_algorithm": "sha256", "report_sha256": report_hash}

    logger.log(
        "correction_loop_complete",
        total_corrected_findings=len(corrected_findings),
        escalated=by_type.get(ESCALATED, 0),
        confirmed_upward=by_type.get(CONFIRMED_UPWARD, 0),
        downgraded=by_type.get(DOWNGRADED, 0),
        unconfirmed=by_type.get(UNCONFIRMED, 0),
        confidence_factor=avg_cf,
        report_sha256=report_hash,
    )

    if audit_log_path:
        logger.write_jsonl(audit_log_path)

    if include_audit_events:
        report["audit_events"] = logger.events

    return report
