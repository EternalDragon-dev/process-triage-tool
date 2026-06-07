from __future__ import annotations

import csv

from process_triage.audit import AuditLogger
from process_triage.models import ProcessRecord


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


def load_processes_csv(file_path: str, audit_logger: AuditLogger | None = None) -> list[ProcessRecord]:
    processes: list[ProcessRecord] = []
    with open(file_path, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        for row_num, row in enumerate(reader, start=1):
            process = ProcessRecord(
                pid=_safe_int(row.get("pid")) or -1,
                ppid=_extract_ppid(row),
                name=row.get("name", "").strip(),
                path=row.get("path", "").strip(),
                command_line=row.get("command_line", "").strip(),
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
