from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from correction_engine.engine import run_correction_loop
from network_triage.loader import load_connections_csv
from network_triage.triage import run_network_triage
from persistence_triage.loader import load_persistence_csv
from persistence_triage.triage import run_persistence_triage
from process_triage.audit import AuditLogger
from process_triage.loader import load_processes_csv
from process_triage.triage import run_triage
from validation import InputValidationError

PROJECT_ROOT = Path(__file__).resolve().parent
mcp = FastMCP("sentinel-loop-dfir")


def _resolve_input_path(input_path: str) -> str:
    candidate = Path(input_path).expanduser()
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    return str(candidate.resolve())


def _error_response(tool: str, exc: Exception) -> dict[str, Any]:
    if isinstance(exc, InputValidationError):
        return {
            "ok": False,
            "tool": tool,
            "report_type": "sentinel_loop.error.v1",
            "error": exc.to_dict(),
        }
    if isinstance(exc, FileNotFoundError):
        return {
            "ok": False,
            "tool": tool,
            "report_type": "sentinel_loop.error.v1",
            "error": {
                "code": "INPUT_FILE_NOT_FOUND",
                "domain": "mcp",
                "message": "Input file was not found.",
                "details": {"path": str(exc.filename) if getattr(exc, "filename", None) else "unknown"},
            },
        }
    return {
        "ok": False,
        "tool": tool,
        "report_type": "sentinel_loop.error.v1",
        "error": {
            "code": "UNHANDLED_TOOL_ERROR",
            "domain": "mcp",
            "message": str(exc),
        },
    }


@mcp.tool()
def triage_processes(
    input_path: str = "processes.csv",
    include_audit_events: bool = True,
    audit_log_path: str | None = None,
) -> dict[str, Any]:
    """
    Analyze process artifacts and return deterministic suspicious-process findings.
    """
    try:
        resolved_input = _resolve_input_path(input_path)
        audit_logger = AuditLogger(enabled=True)
        processes = load_processes_csv(resolved_input, audit_logger=audit_logger)
        report = run_triage(
            processes=processes,
            source=resolved_input,
            audit_logger=audit_logger,
            include_audit_events=include_audit_events,
        )
        if audit_log_path:
            audit_logger.write_jsonl(_resolve_input_path(audit_log_path))
        return report
    except Exception as exc:
        return _error_response("triage_processes", exc)


@mcp.tool()
def triage_network(
    input_path: str = "network_connections.csv",
    include_audit_events: bool = True,
    audit_log_path: str | None = None,
) -> dict[str, Any]:
    """
    Analyze network connection artifacts and return deterministic network findings.
    """
    try:
        resolved_input = _resolve_input_path(input_path)
        audit_logger = AuditLogger(enabled=True)
        connections = load_connections_csv(resolved_input, audit_logger=audit_logger)
        report = run_network_triage(
            connections=connections,
            source=resolved_input,
            audit_logger=audit_logger,
            include_audit_events=include_audit_events,
        )
        if audit_log_path:
            audit_logger.write_jsonl(_resolve_input_path(audit_log_path))
        return report
    except Exception as exc:
        return _error_response("triage_network", exc)


@mcp.tool()
def triage_persistence(
    input_path: str = "persistence_artifacts.csv",
    include_audit_events: bool = True,
    audit_log_path: str | None = None,
) -> dict[str, Any]:
    """
    Analyze persistence artifacts (cron/systemd/launchd) and return deterministic findings.
    """
    try:
        resolved_input = _resolve_input_path(input_path)
        audit_logger = AuditLogger(enabled=True)
        artifacts = load_persistence_csv(resolved_input, audit_logger=audit_logger)
        report = run_persistence_triage(
            artifacts=artifacts,
            source=resolved_input,
            audit_logger=audit_logger,
            include_audit_events=include_audit_events,
        )
        if audit_log_path:
            audit_logger.write_jsonl(_resolve_input_path(audit_log_path))
        return report
    except Exception as exc:
        return _error_response("triage_persistence", exc)


@mcp.tool()
def triage_all(
    processes_csv: str = "processes.csv",
    network_csv: str = "network_connections.csv",
    persistence_csv: str = "persistence_artifacts.csv",
    include_audit_events: bool = True,
    audit_log_path: str | None = None,
) -> dict[str, Any]:
    """
    Run the full Hypothesis-Verification-Correction loop across all three triage
    domains (process, network, persistence) and return a unified CorrectionReport
    with cross-referenced confidence scores and a complete forensic audit trail.
    """
    try:
        audit_logger = AuditLogger(enabled=True)
        return run_correction_loop(
            processes_csv=_resolve_input_path(processes_csv),
            network_csv=_resolve_input_path(network_csv),
            persistence_csv=_resolve_input_path(persistence_csv),
            include_audit_events=include_audit_events,
            audit_log_path=_resolve_input_path(audit_log_path) if audit_log_path else None,
            audit_logger=audit_logger,
        )
    except Exception as exc:
        return _error_response("triage_all", exc)


if __name__ == "__main__":
    mcp.run(transport="stdio")
