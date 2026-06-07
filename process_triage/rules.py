from __future__ import annotations

from process_triage.audit import AuditLogger
from process_triage.models import Finding, ProcessRecord


def _log_rule_eval(
    audit_logger: AuditLogger | None,
    rule_id: str,
    process: ProcessRecord,
    matched: bool,
) -> None:
    if not audit_logger:
        return
    audit_logger.log(
        "rule_evaluated",
        rule_id=rule_id,
        pid=process.pid,
        ppid=process.ppid,
        process_name=process.name,
        matched=matched,
    )


def evaluate_process(process: ProcessRecord, audit_logger: AuditLogger | None = None) -> list[Finding]:
    findings: list[Finding] = []
    name = process.name.lower()
    path = process.path.lower()
    cmd = process.command_line.lower()

    encoded_tokens = [" -enc ", " -encodedcommand ", " -e "]
    encoded_match = "powershell" in name and (
        any(token in f" {cmd} " for token in encoded_tokens) or "-enc" in cmd
    )
    _log_rule_eval(audit_logger, "R001_ENCODED_POWERSHELL", process, encoded_match)
    if encoded_match:
        findings.append(
            Finding(
                rule_id="R001_ENCODED_POWERSHELL",
                severity="HIGH",
                message=f"Encoded PowerShell detected (PID {process.pid})",
                pid=process.pid,
                ppid=process.ppid,
                process_name=process.name,
                path=process.path,
                user=process.user,
                evidence={"command_line": process.command_line},
            )
        )

    suspicious_path_markers = ["\\appdata\\", "\\temp\\", "/tmp/"]
    suspicious_path_match = any(marker in path for marker in suspicious_path_markers)
    _log_rule_eval(audit_logger, "R002_SUSPICIOUS_EXEC_PATH", process, suspicious_path_match)
    if suspicious_path_match:
        findings.append(
            Finding(
                rule_id="R002_SUSPICIOUS_EXEC_PATH",
                severity="MEDIUM",
                message=f"Execution from suspicious path detected (PID {process.pid})",
                pid=process.pid,
                ppid=process.ppid,
                process_name=process.name,
                path=process.path,
                user=process.user,
                evidence={"path": process.path},
            )
        )

    valid_svchost_markers = ["windows\\system32\\svchost.exe", "/windows/system32/svchost.exe"]
    fake_svchost_match = process.name.lower() == "svchost.exe" and not any(
        marker in path for marker in valid_svchost_markers
    )
    _log_rule_eval(audit_logger, "R003_FAKE_SVCHOST_LOCATION", process, fake_svchost_match)
    if fake_svchost_match:
        findings.append(
            Finding(
                rule_id="R003_FAKE_SVCHOST_LOCATION",
                severity="HIGH",
                message=f"Potential fake svchost location detected (PID {process.pid})",
                pid=process.pid,
                ppid=process.ppid,
                process_name=process.name,
                path=process.path,
                user=process.user,
                evidence={"path": process.path, "expected": "Windows\\System32\\svchost.exe"},
            )
        )

    return findings
