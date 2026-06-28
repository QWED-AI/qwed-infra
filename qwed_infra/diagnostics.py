"""
QWED-Infra Structured Verification Diagnostics.

Implements the same 3-layer model as QWED-Tax TaxDiagnosticResult
but as an independent package with infrastructure-specific fields.

    Layer 1 — Agent-Safe Diagnostics
        agent_message: str
    Layer 2 — Developer Diagnostics
        developer_fields: dict
    Layer 3 — Proof Diagnostics
        proof_ref: Optional[str]

This module does NOT depend on qwed-tax. The model follows the same
3-layer pattern using infra-specific developer_fields.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class InfraDiagnosticStatus(str, Enum):
    """Infrastructure verification diagnostic status (3 states only)."""
    VERIFIED = "VERIFIED"
    UNVERIFIABLE = "UNVERIFIABLE"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class InfraAdvisoryCheck:
    """A non-proof-bearing analysis result attached as advisory metadata."""
    name: str
    advisory_only: bool = True
    constraint_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.advisory_only is not True:
            raise ValueError(
                "InfraAdvisoryCheck.advisory_only must be True — "
                "advisory checks must never influence the verification verdict."
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "advisory_only": self.advisory_only,
            "constraint_id": self.constraint_id,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InfraAdvisoryCheck":
        raw_advisory_only = data.get("advisory_only", True)
        if isinstance(raw_advisory_only, bool):
            advisory_only = raw_advisory_only
        elif isinstance(raw_advisory_only, int) and raw_advisory_only in (0, 1):
            advisory_only = bool(raw_advisory_only)
        else:
            raise ValueError(
                "InfraAdvisoryCheck.advisory_only must be a bool or integer 0/1"
            )
        return cls(
            name=data.get("name", ""),
            advisory_only=advisory_only,
            constraint_id=data.get("constraint_id"),
            details=data.get("details", {}),
        )


def compute_proof_ref(evidence: Dict[str, Any]) -> str:
    """Compute a deterministic proof reference hash from retained evidence."""
    try:
        payload = json.dumps(evidence, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Proof evidence must be JSON-serializable for proof_ref hashing: {exc}"
        ) from exc
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


@dataclass(frozen=True)
class InfraDiagnosticResult:
    """Unified 3-layer infra verification diagnostic result.

    Authority contract:
        proof_ref is not None → authoritative, admissible for control flow
        proof_ref is None     → non-authoritative, NOT admissible for control flow
    """

    status: InfraDiagnosticStatus
    agent_message: str
    developer_fields: Dict[str, Any] = field(default_factory=dict)
    proof_ref: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, InfraDiagnosticStatus):
            valid = ", ".join(s.value for s in InfraDiagnosticStatus)
            raise ValueError(f"status must be an InfraDiagnosticStatus ({valid})")

        if not isinstance(self.agent_message, str) or not self.agent_message.strip():
            raise ValueError(
                "agent_message must be a non-empty string — "
                "Layer 1 diagnostics are mandatory"
            )

        if not isinstance(self.developer_fields, dict):
            raise ValueError("developer_fields must be a dict")

        if self.status is InfraDiagnosticStatus.VERIFIED and not self.proof_ref:
            raise ValueError(
                "VERIFIED status requires proof_ref is not None and non-empty — "
                "a claim cannot be marked proven without a proof artifact hash. "
                "Use UNVERIFIABLE if no proof was established."
            )

        if self.status is not InfraDiagnosticStatus.VERIFIED and self.proof_ref is not None:
            raise ValueError(
                f"{self.status.value} status requires proof_ref is None — "
                "non-VERIFIED states are non-authoritative by construction."
            )

    @property
    def is_verified(self) -> bool:
        return self.status is InfraDiagnosticStatus.VERIFIED

    @property
    def is_authoritative(self) -> bool:
        return self.proof_ref is not None

    @property
    def is_fail_closed(self) -> bool:
        return self.status in (InfraDiagnosticStatus.UNVERIFIABLE, InfraDiagnosticStatus.BLOCKED)

    @property
    def constraint_id(self) -> Optional[str]:
        return self.developer_fields.get("constraint_id")

    @property
    def audit_trace(self) -> Optional[Dict[str, Any]]:
        return self.developer_fields.get("audit_trace")

    @property
    def advisory_checks(self) -> List[InfraAdvisoryCheck]:
        raw = self.developer_fields.get("advisory_checks", [])
        if not isinstance(raw, list):
            return []
        result = []
        for item in raw:
            if isinstance(item, dict):
                try:
                    result.append(InfraAdvisoryCheck.from_dict(item))
                except ValueError:
                    continue
            elif isinstance(item, InfraAdvisoryCheck):
                result.append(item)
        return result

    def to_dict(self) -> Dict[str, Any]:
        fields = dict(self.developer_fields)
        checks = fields.get("advisory_checks")
        if isinstance(checks, list):
            fields["advisory_checks"] = [
                item.to_dict() if isinstance(item, InfraAdvisoryCheck) else item
                for item in checks
            ]
        return {
            "status": self.status.value,
            "agent_message": self.agent_message,
            "developer_fields": fields,
            "proof_ref": self.proof_ref,
            "is_authoritative": self.is_authoritative,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InfraDiagnosticResult":
        status = data.get("status", "UNVERIFIABLE")
        if isinstance(status, str):
            try:
                status = InfraDiagnosticStatus(status)
            except ValueError:
                valid = ", ".join(s.value for s in InfraDiagnosticStatus)
                raise ValueError(
                    f"from_dict: invalid status {status!r} — "
                    f"must be one of: {valid}."
                ) from None
        elif not isinstance(status, InfraDiagnosticStatus):
            valid = ", ".join(s.value for s in InfraDiagnosticStatus)
            raise ValueError(
                f"from_dict: invalid status type {type(status).__name__} — "
                f"must be one of: {valid}."
            )

        agent_message = data.get("agent_message")
        if not isinstance(agent_message, str) or not agent_message.strip():
            raise ValueError(
                "from_dict: 'agent_message' is missing or empty — "
                "Layer 1 diagnostics are mandatory."
            )

        developer_fields = data.get("developer_fields", {})
        if not isinstance(developer_fields, dict):
            raise ValueError("from_dict: 'developer_fields' must be a dict.")

        return cls(
            status=status,
            agent_message=agent_message,
            developer_fields=developer_fields,
            proof_ref=data.get("proof_ref"),
        )

    @classmethod
    def verified(
        cls,
        agent_message: str,
        developer_fields: Dict[str, Any],
        evidence: Dict[str, Any],
    ) -> "InfraDiagnosticResult":
        return cls(
            status=InfraDiagnosticStatus.VERIFIED,
            agent_message=agent_message,
            developer_fields=developer_fields,
            proof_ref=compute_proof_ref(evidence),
        )

    @classmethod
    def unverifiable(
        cls,
        agent_message: str,
        developer_fields: Optional[Dict[str, Any]] = None,
    ) -> "InfraDiagnosticResult":
        return cls(
            status=InfraDiagnosticStatus.UNVERIFIABLE,
            agent_message=agent_message,
            developer_fields=developer_fields or {},
            proof_ref=None,
        )

    @classmethod
    def blocked(
        cls,
        agent_message: str,
        developer_fields: Optional[Dict[str, Any]] = None,
    ) -> "InfraDiagnosticResult":
        return cls(
            status=InfraDiagnosticStatus.BLOCKED,
            agent_message=agent_message,
            developer_fields=developer_fields or {},
            proof_ref=None,
        )


__all__ = [
    "InfraDiagnosticStatus",
    "InfraDiagnosticResult",
    "InfraAdvisoryCheck",
    "compute_proof_ref",
]
