from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ── Correction type labels ──────────────────────────────────────────────────
CONFIRMED_UPWARD = "CONFIRMED_UPWARD"   # extra evidence supports the finding
ESCALATED = "ESCALATED"                 # multi-domain evidence (worst case)
DOWNGRADED = "DOWNGRADED"               # counter-evidence reduces likelihood
UNCONFIRMED = "UNCONFIRMED"             # no corroboration found

# Baseline confidence assigned to process findings (they lack a numeric score)
_SEVERITY_BASELINE: dict[str, float] = {
    "HIGH": 0.85,
    "MEDIUM": 0.65,
    "LOW": 0.40,
}

# Confidence delta per correction type
_DELTA: dict[str, float] = {
    CONFIRMED_UPWARD: +0.10,
    ESCALATED: +0.15,
    DOWNGRADED: -0.15,
    UNCONFIRMED: -0.05,
}


def baseline_confidence(severity: str) -> float:
    return _SEVERITY_BASELINE.get(severity.upper(), 0.50)


def apply_correction(original: float, correction_type: str) -> float:
    delta = _DELTA.get(correction_type, 0.0)
    return round(min(max(original + delta, 0.05), 0.99), 3)


@dataclass(slots=True)
class CorrectionEvent:
    """A single hypothesis-correction step recorded in the audit trail."""

    finding_domain: str          # "process" | "network" | "persistence"
    finding_rule_id: str
    correction_type: str
    original_confidence: float
    revised_confidence: float
    reasoning: str
    corroborating_evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_domain": self.finding_domain,
            "finding_rule_id": self.finding_rule_id,
            "correction_type": self.correction_type,
            "original_confidence": self.original_confidence,
            "revised_confidence": self.revised_confidence,
            "reasoning": self.reasoning,
            "corroborating_evidence": self.corroborating_evidence,
        }


@dataclass(slots=True)
class CorrectedFinding:
    """A triage finding after the correction loop has been applied."""

    source_domain: str           # "process" | "network" | "persistence"
    rule_id: str
    severity: str
    message: str
    original_confidence: float
    revised_confidence: float
    correction_type: str
    correction_reason: str
    original_finding: dict[str, Any] = field(default_factory=dict)
    corroborating_evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "original_confidence": self.original_confidence,
            "revised_confidence": self.revised_confidence,
            "correction_type": self.correction_type,
            "correction_reason": self.correction_reason,
            "original_finding": self.original_finding,
            "corroborating_evidence": self.corroborating_evidence,
        }
