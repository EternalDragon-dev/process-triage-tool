from __future__ import annotations

import csv

from persistence_triage.models import PersistenceArtifact
from process_triage.audit import AuditLogger


def _clean_str(value: str | None) -> str:
    if value is None:
        return ""
    return value.strip()


def _to_bool(value: str | None) -> bool:
    normalized = _clean_str(value).lower()
    return normalized in {"1", "true", "yes", "y", "enabled"}


def load_persistence_csv(
    file_path: str,
    audit_logger: AuditLogger | None = None,
) -> list[PersistenceArtifact]:
    artifacts: list[PersistenceArtifact] = []
    with open(file_path, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        for row_num, row in enumerate(reader, start=1):
            artifact = PersistenceArtifact(
                artifact_type=_clean_str(row.get("artifact_type")).lower() or "unknown",
                name=_clean_str(row.get("name")),
                path=_clean_str(row.get("path")),
                command=_clean_str(row.get("command")),
                user=_clean_str(row.get("user")) or "UNKNOWN",
                schedule=_clean_str(row.get("schedule")),
                enabled=_to_bool(row.get("enabled")),
            )
            artifacts.append(artifact)
            if audit_logger:
                audit_logger.log(
                    "persistence_row_loaded",
                    row_number=row_num,
                    artifact_type=artifact.artifact_type,
                    artifact_name=artifact.name,
                    user=artifact.user,
                    enabled=artifact.enabled,
                )

    if audit_logger:
        audit_logger.log("persistence_input_loaded", source=file_path, total_rows=len(artifacts))
    return artifacts
