from __future__ import annotations

import csv

from persistence_triage.models import PersistenceArtifact
from process_triage.audit import AuditLogger
from validation import InputValidationError

_REQUIRED_COLUMNS = {"artifact_type", "name", "path", "command", "enabled"}


def _clean_str(value: str | None) -> str:
    if value is None:
        return ""
    return value.strip()


def _to_bool(value: str | None) -> bool:
    normalized = _clean_str(value).lower()
    return normalized in {"1", "true", "yes", "y", "enabled"}


def _normalize_headers(fieldnames: list[str] | None) -> set[str]:
    if not fieldnames:
        raise InputValidationError(
            domain="persistence",
            message="CSV header is missing or unreadable.",
            details={"required_columns": sorted(_REQUIRED_COLUMNS)},
        )
    return {str(name).strip().lower() for name in fieldnames if str(name).strip()}


def _validate_headers(fieldnames: list[str] | None) -> None:
    normalized = _normalize_headers(fieldnames)
    missing = sorted(_REQUIRED_COLUMNS - normalized)
    if missing:
        raise InputValidationError(
            domain="persistence",
            message="Persistence CSV is missing required columns.",
            details={"missing_columns": missing, "required_columns": sorted(_REQUIRED_COLUMNS)},
        )


def load_persistence_csv(
    file_path: str,
    audit_logger: AuditLogger | None = None,
) -> list[PersistenceArtifact]:
    artifacts: list[PersistenceArtifact] = []
    with open(file_path, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        _validate_headers(reader.fieldnames)
        for row_num, row in enumerate(reader, start=1):
            artifact_type = _clean_str(row.get("artifact_type")).lower()
            artifact_name = _clean_str(row.get("name"))
            artifact_path = _clean_str(row.get("path"))
            artifact_command = _clean_str(row.get("command"))
            if not artifact_type:
                raise InputValidationError(
                    domain="persistence",
                    message="Persistence artifact_type cannot be empty.",
                    details={"row_number": row_num, "column": "artifact_type"},
                )
            if not artifact_name:
                raise InputValidationError(
                    domain="persistence",
                    message="Persistence artifact name cannot be empty.",
                    details={"row_number": row_num, "column": "name"},
                )
            if not artifact_path:
                raise InputValidationError(
                    domain="persistence",
                    message="Persistence artifact path cannot be empty.",
                    details={"row_number": row_num, "column": "path"},
                )
            if not artifact_command:
                raise InputValidationError(
                    domain="persistence",
                    message="Persistence artifact command cannot be empty.",
                    details={"row_number": row_num, "column": "command"},
                )
            artifact = PersistenceArtifact(
                artifact_type=artifact_type,
                name=artifact_name,
                path=artifact_path,
                command=artifact_command,
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
