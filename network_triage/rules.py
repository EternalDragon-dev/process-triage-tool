from __future__ import annotations
import ipaddress

from network_triage.models import NetworkConnection, NetworkFinding
from process_triage.audit import AuditLogger


def _is_external_ipv4(address: str) -> bool:
    addr = address.strip()
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_global


def _log_rule_eval(
    audit_logger: AuditLogger | None,
    rule_id: str,
    connection: NetworkConnection,
    matched: bool,
) -> None:
    if not audit_logger:
        return
    audit_logger.log(
        "network_rule_evaluated",
        rule_id=rule_id,
        pid=connection.pid,
        process_name=connection.process_name,
        remote_address=connection.remote_address,
        remote_port=connection.remote_port,
        matched=matched,
    )


def evaluate_connection(
    connection: NetworkConnection,
    audit_logger: AuditLogger | None = None,
) -> list[NetworkFinding]:
    findings: list[NetworkFinding] = []
    process_name = connection.process_name.lower()
    exec_path = connection.executable_path.lower()

    high_risk_c2_ports = {4444, 1337, 6667, 9001}
    c2_port_match = (
        connection.state == "ESTABLISHED"
        and connection.remote_port in high_risk_c2_ports
        and _is_external_ipv4(connection.remote_address)
    )
    _log_rule_eval(audit_logger, "N001_EXTERNAL_HIGH_RISK_PORT", connection, c2_port_match)
    if c2_port_match:
        findings.append(
            NetworkFinding(
                rule_id="N001_EXTERNAL_HIGH_RISK_PORT",
                severity="HIGH",
                message="Established outbound connection to external high-risk port.",
                confidence_factor=0.93,
                pid=connection.pid,
                process_name=connection.process_name,
                protocol=connection.protocol,
                state=connection.state,
                remote_address=connection.remote_address,
                remote_port=connection.remote_port,
                user=connection.user,
                evidence={
                    "remote_address": connection.remote_address,
                    "remote_port": connection.remote_port,
                    "state": connection.state,
                },
            )
        )

    lolbin_external_match = (
        process_name in {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"}
        and connection.state == "ESTABLISHED"
        and _is_external_ipv4(connection.remote_address)
    )
    _log_rule_eval(audit_logger, "N002_LOLBIN_EXTERNAL_BEACONING", connection, lolbin_external_match)
    if lolbin_external_match:
        findings.append(
            NetworkFinding(
                rule_id="N002_LOLBIN_EXTERNAL_BEACONING",
                severity="HIGH",
                message="LOLBin process established an external network connection.",
                confidence_factor=0.9,
                pid=connection.pid,
                process_name=connection.process_name,
                protocol=connection.protocol,
                state=connection.state,
                remote_address=connection.remote_address,
                remote_port=connection.remote_port,
                user=connection.user,
                evidence={"process_name": connection.process_name, "remote_address": connection.remote_address},
            )
        )

    temp_path_network_match = (
        ("\\temp\\" in exec_path or "\\appdata\\" in exec_path or "/tmp/" in exec_path)
        and connection.state in {"ESTABLISHED", "LISTEN"}
    )
    _log_rule_eval(audit_logger, "N003_TEMP_PATH_NETWORK_ACTIVITY", connection, temp_path_network_match)
    if temp_path_network_match:
        findings.append(
            NetworkFinding(
                rule_id="N003_TEMP_PATH_NETWORK_ACTIVITY",
                severity="MEDIUM",
                message="Process running from suspicious path has network activity.",
                confidence_factor=0.76,
                pid=connection.pid,
                process_name=connection.process_name,
                protocol=connection.protocol,
                state=connection.state,
                remote_address=connection.remote_address,
                remote_port=connection.remote_port,
                user=connection.user,
                evidence={"executable_path": connection.executable_path, "state": connection.state},
            )
        )

    exposed_rdp_listener_match = (
        connection.state == "LISTEN"
        and connection.local_port == 3389
        and connection.local_address in {"0.0.0.0", "::"}
    )
    _log_rule_eval(audit_logger, "N004_PUBLIC_RDP_LISTENER", connection, exposed_rdp_listener_match)
    if exposed_rdp_listener_match:
        findings.append(
            NetworkFinding(
                rule_id="N004_PUBLIC_RDP_LISTENER",
                severity="MEDIUM",
                message="RDP listener exposed on all interfaces.",
                confidence_factor=0.78,
                pid=connection.pid,
                process_name=connection.process_name,
                protocol=connection.protocol,
                state=connection.state,
                remote_address=connection.remote_address,
                remote_port=connection.remote_port,
                user=connection.user,
                evidence={"local_address": connection.local_address, "local_port": connection.local_port},
            )
        )

    return findings
