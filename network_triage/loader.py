from __future__ import annotations

import csv

from network_triage.models import NetworkConnection
from process_triage.audit import AuditLogger
from validation import InputValidationError

_REQUIRED_COLUMNS = {
    "pid",
    "protocol",
    "state",
    "local_address",
    "local_port",
    "remote_address",
    "remote_port",
}
_PROCESS_NAME_COLUMNS = {"process_name", "name"}


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


def _clean_str(value: str | None) -> str:
    if value is None:
        return ""
    return value.strip()


def _normalize_headers(fieldnames: list[str] | None) -> set[str]:
    if not fieldnames:
        raise InputValidationError(
            domain="network",
            message="CSV header is missing or unreadable.",
            details={"required_columns": sorted(_REQUIRED_COLUMNS)},
        )
    return {str(name).strip().lower() for name in fieldnames if str(name).strip()}


def _validate_headers(fieldnames: list[str] | None) -> None:
    normalized = _normalize_headers(fieldnames)
    missing = sorted(_REQUIRED_COLUMNS - normalized)
    if missing:
        raise InputValidationError(
            domain="network",
            message="Network CSV is missing required columns.",
            details={"missing_columns": missing, "required_columns": sorted(_REQUIRED_COLUMNS)},
        )
    if not (_PROCESS_NAME_COLUMNS & normalized):
        raise InputValidationError(
            domain="network",
            message="Network CSV must provide either process_name or name column.",
            details={"required_any_of": sorted(_PROCESS_NAME_COLUMNS)},
        )


def load_connections_csv(
    file_path: str,
    audit_logger: AuditLogger | None = None,
) -> list[NetworkConnection]:
    connections: list[NetworkConnection] = []
    with open(file_path, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        _validate_headers(reader.fieldnames)
        for row_num, row in enumerate(reader, start=1):
            pid_value = _safe_int(row.get("pid"))
            if pid_value is None:
                raise InputValidationError(
                    domain="network",
                    message="Invalid or missing network pid value.",
                    details={"row_number": row_num, "column": "pid", "value": row.get("pid")},
                )
            process_name = _clean_str(row.get("process_name")) or _clean_str(row.get("name"))
            if not process_name:
                raise InputValidationError(
                    domain="network",
                    message="Network process name cannot be empty.",
                    details={"row_number": row_num, "columns": ["process_name", "name"]},
                )
            connection = NetworkConnection(
                pid=pid_value,
                process_name=process_name,
                protocol=_clean_str(row.get("protocol")).upper() or "UNKNOWN",
                state=_clean_str(row.get("state")).upper() or "UNKNOWN",
                local_address=_clean_str(row.get("local_address")),
                local_port=_safe_int(row.get("local_port")),
                remote_address=_clean_str(row.get("remote_address")),
                remote_port=_safe_int(row.get("remote_port")),
                user=_clean_str(row.get("user")) or "UNKNOWN",
                executable_path=_clean_str(row.get("executable_path")) or _clean_str(row.get("path")),
            )
            connections.append(connection)
            if audit_logger:
                audit_logger.log(
                    "network_row_loaded",
                    row_number=row_num,
                    pid=connection.pid,
                    process_name=connection.process_name,
                    remote_address=connection.remote_address,
                    remote_port=connection.remote_port,
                )

    if audit_logger:
        audit_logger.log("network_input_loaded", source=file_path, total_rows=len(connections))
    return connections
