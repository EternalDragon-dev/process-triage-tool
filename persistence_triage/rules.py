from __future__ import annotations

from persistence_triage.models import PersistenceArtifact, PersistenceFinding
from process_triage.audit import AuditLogger


def _log_rule_eval(
    audit_logger: AuditLogger | None,
    rule_id: str,
    artifact: PersistenceArtifact,
    matched: bool,
) -> None:
    if not audit_logger:
        return
    audit_logger.log(
        "persistence_rule_evaluated",
        rule_id=rule_id,
        artifact_type=artifact.artifact_type,
        artifact_name=artifact.name,
        path=artifact.path,
        user=artifact.user,
        matched=matched,
    )


def evaluate_artifact(
    artifact: PersistenceArtifact,
    audit_logger: AuditLogger | None = None,
) -> list[PersistenceFinding]:
    findings: list[PersistenceFinding] = []
    path_lower = artifact.path.lower()
    command_lower = artifact.command.lower()
    schedule = artifact.schedule.strip()

    suspicious_exec_path_match = (
        artifact.enabled
        and ("\\temp\\" in path_lower or "/tmp/" in path_lower or "\\appdata\\" in path_lower or "/dev/shm/" in path_lower)
    ) or (
        artifact.enabled
        and ("\\temp\\" in command_lower or "/tmp/" in command_lower or "\\appdata\\" in command_lower or "/dev/shm/" in command_lower)
    )
    _log_rule_eval(audit_logger, "P001_SUSPICIOUS_PERSISTENCE_PATH", artifact, suspicious_exec_path_match)
    if suspicious_exec_path_match:
        findings.append(
            PersistenceFinding(
                rule_id="P001_SUSPICIOUS_PERSISTENCE_PATH",
                severity="HIGH",
                message="Persistence entry executes from suspicious temporary path.",
                confidence_factor=0.9,
                artifact_type=artifact.artifact_type,
                artifact_name=artifact.name,
                path=artifact.path,
                user=artifact.user,
                evidence={"command": artifact.command, "path": artifact.path},
            )
        )

    downloader_cron_match = (
        artifact.enabled
        and artifact.artifact_type == "cron"
        and any(token in command_lower for token in ("curl ", "wget ", "invoke-webrequest "))
        and any(token in command_lower for token in ("| sh", "|bash", "bash -c", "python -c"))
    )
    _log_rule_eval(audit_logger, "P002_DOWNLOADER_EXEC_CHAIN", artifact, downloader_cron_match)
    if downloader_cron_match:
        findings.append(
            PersistenceFinding(
                rule_id="P002_DOWNLOADER_EXEC_CHAIN",
                severity="HIGH",
                message="Cron entry downloads remote content and executes it.",
                confidence_factor=0.94,
                artifact_type=artifact.artifact_type,
                artifact_name=artifact.name,
                path=artifact.path,
                user=artifact.user,
                evidence={"command": artifact.command, "schedule": artifact.schedule},
            )
        )

    high_frequency_cron_match = (
        artifact.enabled
        and artifact.artifact_type == "cron"
        and schedule in {"* * * * *", "*/1 * * * *"}
    )
    _log_rule_eval(audit_logger, "P003_HIGH_FREQUENCY_CRON", artifact, high_frequency_cron_match)
    if high_frequency_cron_match:
        findings.append(
            PersistenceFinding(
                rule_id="P003_HIGH_FREQUENCY_CRON",
                severity="MEDIUM",
                message="Cron persistence executes every minute.",
                confidence_factor=0.72,
                artifact_type=artifact.artifact_type,
                artifact_name=artifact.name,
                path=artifact.path,
                user=artifact.user,
                evidence={"schedule": artifact.schedule, "command": artifact.command},
            )
        )

    hidden_user_agent_match = (
        artifact.enabled
        and artifact.artifact_type in {"launchd", "systemd"}
        and ("/.hidden/" in command_lower or "/.cache/" in command_lower)
    )
    _log_rule_eval(audit_logger, "P004_HIDDEN_USERSPACE_AGENT", artifact, hidden_user_agent_match)
    if hidden_user_agent_match:
        findings.append(
            PersistenceFinding(
                rule_id="P004_HIDDEN_USERSPACE_AGENT",
                severity="MEDIUM",
                message="Persistence agent appears to run from hidden userspace directory.",
                confidence_factor=0.78,
                artifact_type=artifact.artifact_type,
                artifact_name=artifact.name,
                path=artifact.path,
                user=artifact.user,
                evidence={"command": artifact.command},
            )
        )

    return findings
