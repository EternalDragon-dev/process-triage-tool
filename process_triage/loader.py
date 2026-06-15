from __future__ import annotations

import csv

from process_triage.audit import AuditLogger
from process_triage.models import ProcessRecord
from validation import InputValidationError

_REQUIRED_COLUMNS = {"pid", "name", "path", "command_line"}


def _safe_int(raw: str | None) -> int | None:
    if raw is None:
        return None
    raw = str(raw).strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _extract_user(row: dict[str, str]) -> str:
    for candidate in ("user", "username", "owner", "account"):
        value = row.get(candidate, "").strip()
        if value:
            return value
    return "UNKNOWN"


def _extract_ppid(row: dict[str, str]) -> int | None:
    for candidate in ("ppid", "parent", "parent_pid"):
        parsed = _safe_int(row.get(candidate))
        if parsed is not None:
            return parsed
    return None

def _normalize_headers(fieldnames: list[str] | None) -> set[str]:
    if not fieldnames:
        raise InputValidationError(
            domain="process",
            message="CSV header is missing or unreadable.",
            details={"required_columns": sorted(_REQUIRED_COLUMNS)},
        )
    return {str(name).strip().lower() for name in fieldnames if str(name).strip()}


def _validate_headers(fieldnames: list[str] | None) -> None:
    normalized = _normalize_headers(fieldnames)
    missing = sorted(_REQUIRED_COLUMNS - normalized)
    if missing:
        raise InputValidationError(
            domain="process",
            message="Process CSV is missing required columns.",
            details={"missing_columns": missing, "required_columns": sorted(_REQUIRED_COLUMNS)},
        )


def load_processes_csv(file_path: str, audit_logger: AuditLogger | None = None) -> list[ProcessRecord]:
    processes: list[ProcessRecord] = []
    with open(file_path, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        _validate_headers(reader.fieldnames)
        for row_num, row in enumerate(reader, start=1):
            pid_value = _safe_int(row.get("pid"))
            if pid_value is None:
                raise InputValidationError(
                    domain="process",
                    message="Invalid or missing process pid value.",
                    details={"row_number": row_num, "column": "pid", "value": row.get("pid")},
                )
            process_name = row.get("name", "").strip()
            if not process_name:
                raise InputValidationError(
                    domain="process",
                    message="Process name cannot be empty.",
                    details={"row_number": row_num, "column": "name"},
                )
            process_path = row.get("path", "").strip()
            if not process_path:
                raise InputValidationError(
                    domain="process",
                    message="Process path cannot be empty.",
                    details={"row_number": row_num, "column": "path"},
                )
            command_line = row.get("command_line", "").strip()
            if not command_line:
                raise InputValidationError(
                    domain="process",
                    message="Process command_line cannot be empty.",
                    details={"row_number": row_num, "column": "command_line"},
                )
            process = ProcessRecord(
                pid=pid_value,
                ppid=_extract_ppid(row),
                name=process_name,
                path=process_path,
                command_line=command_line,
                user=_extract_user(row),
            )
            processes.append(process)
            if audit_logger:
                audit_logger.log(
                    "process_row_loaded",
                    row_number=row_num,
                    pid=process.pid,
                    ppid=process.ppid,
                    process_name=process.name,
                )

    if audit_logger:
        audit_logger.log("input_loaded", source=file_path, total_rows=len(processes))
    return processes
