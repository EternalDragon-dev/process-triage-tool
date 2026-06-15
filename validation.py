from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class InputValidationError(Exception):
    domain: str
    message: str
    code: str = "INPUT_VALIDATION_ERROR"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "domain": self.domain,
            "message": self.message,
        }
        if self.details:
            payload["details"] = self.details
        return payload
