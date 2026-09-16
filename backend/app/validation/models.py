"""Validation domain types (spec §7).

A candidate Finding becomes a ValidatedFinding with a status, a confidence,
and - when we could prove it safely - a proof-of-exploit string. Only
CONFIRMED / LIKELY findings should reach the client report; FALSE_POSITIVE
is dropped, UNCONFIRMED is kept for manual follow-up.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


class ValidationStatus(str, enum.Enum):
    CONFIRMED = "confirmed"          # safe PoC reproduced the issue
    LIKELY = "likely"                # strong signal, not independently reproduced
    UNCONFIRMED = "unconfirmed"      # could not reproduce; needs a human
    FALSE_POSITIVE = "false_positive"  # actively disproven


# Confidence floors per status (validators may set higher within their band).
STATUS_CONFIDENCE = {
    ValidationStatus.CONFIRMED: 0.95,
    ValidationStatus.LIKELY: 0.6,
    ValidationStatus.UNCONFIRMED: 0.3,
    ValidationStatus.FALSE_POSITIVE: 0.0,
}


@dataclass
class ValidationResult:
    status: ValidationStatus
    confidence: float
    method: str                      # how we decided (validator name / "tool-confirmed" / "llm")
    poc: str = ""                    # reproducible proof-of-exploit (curl, payload, evidence)
    detail: str = ""

    @classmethod
    def confirmed(cls, method: str, poc: str, *, confidence: float = 0.95, detail: str = "") -> "ValidationResult":
        return cls(ValidationStatus.CONFIRMED, max(confidence, 0.9), method, poc, detail)

    @classmethod
    def likely(cls, method: str, *, confidence: float = 0.6, detail: str = "", poc: str = "") -> "ValidationResult":
        return cls(ValidationStatus.LIKELY, confidence, method, poc, detail)

    @classmethod
    def unconfirmed(cls, method: str, *, detail: str = "") -> "ValidationResult":
        return cls(ValidationStatus.UNCONFIRMED, 0.3, method, "", detail)

    @classmethod
    def false_positive(cls, method: str, *, detail: str = "") -> "ValidationResult":
        return cls(ValidationStatus.FALSE_POSITIVE, 0.0, method, "", detail)


@dataclass
class ValidatedFinding:
    id: str
    engagement_id: str
    source_job_id: Optional[str]
    tool: str
    vuln_class: str
    severity: str
    title: str
    target: str
    status: str
    confidence: float
    method: str
    poc: str
    evidence: str
    created_at: float
    chain_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_public(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "source_job_id": self.source_job_id,
            "tool": self.tool,
            "vuln_class": self.vuln_class,
            "severity": self.severity,
            "title": self.title,
            "target": self.target,
            "status": self.status,
            "confidence": self.confidence,
            "method": self.method,
            "poc": self.poc,
            "evidence": self.evidence,
            "chain_id": self.chain_id,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }
