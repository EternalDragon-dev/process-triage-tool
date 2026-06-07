from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class NetworkConnection:
    pid: int
    process_name: str
    protocol: str
    state: str
    local_address: str
    local_port: int | None
    remote_address: str
    remote_port: int | None
    user: str = "UNKNOWN"
    executable_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "protocol": self.protocol,
            "state": self.state,
            "local_address": self.local_address,
            "local_port": self.local_port,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "user": self.user,
            "executable_path": self.executable_path,
        }


@dataclass(slots=True)
class NetworkFinding:
    rule_id: str
    severity: str
    message: str
    confidence_factor: float
    pid: int
    process_name: str
    protocol: str
    state: str
    remote_address: str
    remote_port: int | None
    user: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "confidence_factor": self.confidence_factor,
            "pid": self.pid,
            "process_name": self.process_name,
            "protocol": self.protocol,
            "state": self.state,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "user": self.user,
            "evidence": self.evidence,
        }
