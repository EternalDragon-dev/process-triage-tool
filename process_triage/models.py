from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ProcessRecord:
    pid: int
    ppid: int | None
    name: str
    path: str
    command_line: str
    user: str = "UNKNOWN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "path": self.path,
            "command_line": self.command_line,
            "user": self.user,
        }


@dataclass(slots=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    pid: int
    ppid: int | None
    process_name: str
    path: str
    user: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "pid": self.pid,
            "ppid": self.ppid,
            "process_name": self.process_name,
            "path": self.path,
            "user": self.user,
            "evidence": self.evidence,
        }
