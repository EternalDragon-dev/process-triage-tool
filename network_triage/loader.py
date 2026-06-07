from __future__ import annotations

import csv

from network_triage.models import NetworkConnection
from process_triage.audit import AuditLogger


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


def load_connections_csv(
    file_path: str,
    audit_logger: AuditLogger | None = None,
) -> list[NetworkConnection]:
    connections: list[NetworkConnection] = []
    with open(file_path, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        for row_num, row in enumerate(reader, start=1):
            connection = NetworkConnection(
                pid=_safe_int(row.get("pid")) or -1,
                process_name=_clean_str(row.get("process_name")) or _clean_str(row.get("name")),
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
