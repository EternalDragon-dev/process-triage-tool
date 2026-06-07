from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PersistenceArtifact:
    artifact_type: str
    name: str
    path: str
    command: str
    user: str
    schedule: str
    enabled: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_type": self.artifact_type,
            "name": self.name,
            "path": self.path,
            "command": self.command,
            "user": self.user,
            "schedule": self.schedule,
            "enabled": self.enabled,
        }


@dataclass(slots=True)
class PersistenceFinding:
    rule_id: str
    severity: str
    message: str
    confidence_factor: float
    artifact_type: str
    artifact_name: str
    path: str
    user: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "confidence_factor": self.confidence_factor,
            "artifact_type": self.artifact_type,
            "artifact_name": self.artifact_name,
            "path": self.path,
            "user": self.user,
            "evidence": self.evidence,
        }
