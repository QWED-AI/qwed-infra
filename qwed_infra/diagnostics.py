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
from dataclasses import dataclass, field, replace
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
        payload = json.dumps(evidence, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Proof evidence must be JSON-serializable for proof_ref hashing: {exc}"
        ) from exc
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _parse_status(raw_status: Any) -> InfraDiagnosticStatus:
    """Parse and validate a serialized diagnostic status (fail-closed)."""
    if raw_status is None:
        raise ValueError("from_dict: 'status' is required — no default.")
    if isinstance(raw_status, InfraDiagnosticStatus):
        return raw_status
    if isinstance(raw_status, str):
        try:
            return InfraDiagnosticStatus(raw_status)
        except ValueError:
            pass
    valid = ", ".join(s.value for s in InfraDiagnosticStatus)
    raise ValueError(
        f"from_dict: invalid status {raw_status!r} — must be one of: {valid}."
    )


def _validated_proof_pair(proof_ref: Any, proof_data: Any) -> Optional[str]:
    """Validate a serialized (proof_ref, proof_data) pair; return proof_data.

    Fail-closed integrity check: whenever both are present, proof_data must
    commit to proof_ref — including the empty-string case, which would
    otherwise skip validation and allow a tampered pair through.
    """
    if proof_data is not None and not isinstance(proof_data, str):
        raise ValueError("'proof_data' must be a string or None.")
    if proof_ref is not None and proof_data is not None:
        expected = f"sha256:{hashlib.sha256(proof_data.encode('utf-8')).hexdigest()}"
        if expected != proof_ref:
            raise ValueError(
                "'proof_data' does not commit to 'proof_ref' — "
                "the diagnostic's evidence commitment is inconsistent."
            )
    return proof_data


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
    # Canonical evidence string whose sha256 == proof_ref (VERIFIED only).
    # Retained so attestations can bind qwed.proof_hash to this exact
    # evidence commitment (issue #47), mirroring qwed-verification's
    # proof_data=str(evidence) issuance flow.
    proof_data: Optional[str] = None

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

        if self.status is InfraDiagnosticStatus.VERIFIED:
            if not self.proof_ref:
                raise ValueError(
                    "VERIFIED status requires proof_ref is not None and non-empty — "
                    "a claim cannot be marked proven without a proof artifact hash. "
                    "Use UNVERIFIABLE if no proof was established."
                )
            if "audit_trace" not in self.developer_fields:
                raise ValueError(
                    "VERIFIED status requires 'audit_trace' in developer_fields — "
                    "a proved claim must reference its audit trace."
                )
            # #47 proof commitment: proof_data must be present and hash to
            # proof_ref on EVERY construction path (factory, from_dict, direct),
            # so serialized evidence can never diverge from the attested
            # commitment. The dataclass is frozen, which prevents later mutation.
            _validated_proof_pair(self.proof_ref, self.proof_data)
            if not isinstance(self.proof_data, str) or not self.proof_data:
                raise ValueError(
                    "VERIFIED status requires non-empty proof_data — the canonical "
                    "evidence string that commits to proof_ref. Attestations bind "
                    "qwed.proof_hash to it (#47)."
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
            "proof_data": self.proof_data,
            "is_authoritative": self.is_authoritative,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InfraDiagnosticResult":
        status = _parse_status(data.get("status"))
        agent_message = data.get("agent_message")
        if not isinstance(agent_message, str) or not agent_message.strip():
            raise ValueError(
                "from_dict: 'agent_message' is missing or empty — "
                "Layer 1 diagnostics are mandatory."
            )

        developer_fields = data.get("developer_fields", {})
        if not isinstance(developer_fields, dict):
            raise ValueError("from_dict: 'developer_fields' must be a dict.")

        proof_ref = data.get("proof_ref")
        proof_data = _validated_proof_pair(proof_ref, data.get("proof_data"))

        return cls(
            status=status,
            agent_message=agent_message,
            developer_fields=developer_fields,
            proof_ref=proof_ref,
            proof_data=proof_data,
        )

    @classmethod
    def verified(
        cls,
        agent_message: str,
        developer_fields: Dict[str, Any],
        evidence: Dict[str, Any],
    ) -> "InfraDiagnosticResult":
        try:
            payload = json.dumps(evidence, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Proof evidence must be JSON-serializable for proof_ref hashing: {exc}"
            ) from exc
        return cls(
            status=InfraDiagnosticStatus.VERIFIED,
            agent_message=agent_message,
            developer_fields=developer_fields,
            proof_ref=f"sha256:{hashlib.sha256(payload.encode('utf-8')).hexdigest()}",
            proof_data=payload,
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
    "enforce_trust_decision",
]


# ---------------------------------------------------------------------------
# Trust boundary enforcement — consumption-side attestation validation (#47).
# Mirrors qwed-verification's enforce_trust_decision: no trust-boundary path
# can return/consume effective VERIFIED without a required attestation artifact.
# ---------------------------------------------------------------------------

def _compute_query_hash(query: str) -> str:
    """Compute a query hash in the same format as AttestationService._hash_content."""
    return f"sha256:{hashlib.sha256(query.encode('utf-8')).hexdigest()}"


def _verify_attestation_token(
    attestation_token: str,
    trusted_issuers: Optional[List[str]],
    result: "InfraDiagnosticResult",
    policy: str,
) -> "InfraDiagnosticResult | tuple[bool, Dict[str, Any], Optional[str]]":
    """Verify the attestation token. Returns (is_valid, claims, error) or a blocked result."""
    try:
        from .attestation import get_attestation_service

        service = get_attestation_service()
        is_valid, token_claims, error = service.verify_attestation(
            attestation_token,
            trusted_issuers=trusted_issuers,
        )
    except Exception as exc:
        # Record the exception type only — never args/message — so no internal
        # detail (paths, keys, stack context) leaks into developer_fields.
        return InfraDiagnosticResult.blocked(
            agent_message="Verification blocked — proof artifact verification failed",
            developer_fields={
                "constraint_id": "trust_gate.attestation_verification_error",
                "error_type": type(exc).__name__,
                "policy": policy,
                "verdict_status": result.status.value,
                "verdict_proof_ref": result.proof_ref,
            },
        )

    if not is_valid:
        return InfraDiagnosticResult.blocked(
            agent_message="Verification blocked — proof artifact invalid",
            developer_fields={
                "constraint_id": "trust_gate.invalid_attestation_token",
                "validation_error": error,
                "policy": policy,
                "verdict_status": result.status.value,
                "verdict_proof_ref": result.proof_ref,
            },
        )

    return is_valid, token_claims, error


def _validate_attestation_claims(
    result: "InfraDiagnosticResult",
    token_claims: Dict[str, Any],
    query: Optional[str],
    policy: str,
) -> Optional["InfraDiagnosticResult"]:
    """Validate token claims against result. Returns a blocked result or None.

    Binding checks (all must hold for VERIFIED to survive enforcement):
    - qwed.result.status == result.status          (attested outcome matches)
    - qwed.query_hash   == sha256(formal_statement) (attested claim matches the
      formal statement — closes the statement-overclaim vector)
    - qwed.proof_hash   == result.proof_ref         (attested evidence hash matches
      the diagnostic's evidence commitment)
    """
    raw_qwed = (token_claims or {}).get("qwed")
    qwed_claims = raw_qwed if isinstance(raw_qwed, dict) else None
    raw_result_claims = qwed_claims.get("result") if qwed_claims else None
    result_claims = raw_result_claims if isinstance(raw_result_claims, dict) else None
    if result_claims is None:
        return InfraDiagnosticResult.blocked(
            agent_message="Verification blocked — attestation claims missing or malformed",
            developer_fields={
                "constraint_id": "trust_gate.claims_missing",
                "policy": policy,
            },
        )

    token_status = result_claims.get("status")
    if token_status != result.status.value:
        return InfraDiagnosticResult.blocked(
            agent_message="Verification blocked — attestation claims do not match result status",
            developer_fields={
                "constraint_id": "trust_gate.claims_status_mismatch",
                "token_status": token_status,
                "result_status": result.status.value,
                "policy": policy,
            },
        )

    if query is not None:
        expected_query_hash = _compute_query_hash(query)
        token_query_hash = qwed_claims.get("query_hash")
        if token_query_hash != expected_query_hash:
            return InfraDiagnosticResult.blocked(
                agent_message="Verification blocked — attestation query hash does not match",
                developer_fields={
                    "constraint_id": "trust_gate.claims_query_mismatch",
                    "expected_query_hash": expected_query_hash,
                    "token_query_hash": token_query_hash,
                    "policy": policy,
                },
            )

    token_proof_hash = qwed_claims.get("proof_hash")
    if token_proof_hash is None:
        return InfraDiagnosticResult.blocked(
            agent_message="Verification blocked — attestation carries no proof hash",
            developer_fields={
                "constraint_id": "trust_gate.claims_proof_missing",
                "result_proof_ref": result.proof_ref,
                "policy": policy,
            },
        )
    if token_proof_hash != result.proof_ref:
        return InfraDiagnosticResult.blocked(
            agent_message="Verification blocked — attestation proof hash does not match result",
            developer_fields={
                "constraint_id": "trust_gate.claims_proof_mismatch",
                "token_proof_hash": token_proof_hash,
                "result_proof_ref": result.proof_ref,
                "policy": policy,
            },
        )

    return None


def enforce_trust_decision(
    result: InfraDiagnosticResult,
    *,
    attestation_token: Optional[str] = None,
    require_attestation: bool = True,
    trusted_issuers: Optional[List[str]] = None,
    query: Optional[str] = None,
) -> InfraDiagnosticResult:
    """Enforce trust-boundary gate: VERIFIED without required attestation → BLOCKED.

    Single enforcement point for consumption-side attestation validation
    (mirrors qwed-verification). Every admission decision MUST route VERIFIED
    results through this function before admitting.

    Args:
        result: The verification InfraDiagnosticResult from the guard.
        attestation_token: JWT attestation token from
            attestation.create_verification_attestation. May be None.
        require_attestation: If True (default), VERIFIED without a valid
            attestation token fails closed (caller maps it per policy).
        trusted_issuers: Optional list of trusted issuer DIDs.
        query: Formal statement for query_hash binding validation. When given,
            the token's qwed.query_hash must equal sha256(query) — binding the
            attestation to the exact claim, so overclaiming statements fail.

    Returns:
        The original InfraDiagnosticResult if all checks pass, or a BLOCKED
        InfraDiagnosticResult on any failure (missing/invalid token, mismatched
        claims). Fail-closed statuses pass through unchanged.
    """
    import logging

    logger = logging.getLogger(__name__)
    policy = "mandatory" if require_attestation else "optional"

    # Deep-copy detach: the caller keeps a mutable dict; validation and any
    # returned result must not alias caller-mutable state.
    try:
        import copy as _copy

        result = replace(result, developer_fields=_copy.deepcopy(result.developer_fields))
    except Exception as exc:
        logger.warning(
            "trust_gate.blocked reason=diagnostic_snapshot_failed policy=%s error_type=%s",
            policy,
            type(exc).__name__,
        )
        return InfraDiagnosticResult.blocked(
            agent_message="Verification blocked — diagnostic snapshot failed",
            developer_fields={
                "constraint_id": "trust_gate.diagnostic_snapshot_failed",
                "policy": policy,
            },
        )

    if result.is_fail_closed:
        return result

    if not attestation_token:
        if not require_attestation:
            return result
        return InfraDiagnosticResult.blocked(
            agent_message="Verification blocked — proof artifact missing",
            developer_fields={
                "constraint_id": "trust_gate.mandatory_attestation_missing",
                "missing": "attestation_token",
                "policy": policy,
                "verdict_status": result.status.value,
                "verdict_proof_ref": result.proof_ref,
            },
        )

    verification = _verify_attestation_token(attestation_token, trusted_issuers, result, policy)
    if isinstance(verification, InfraDiagnosticResult):
        return verification
    _is_valid, token_claims, _error = verification

    validation = _validate_attestation_claims(result, token_claims, query, policy)
    if validation is not None:
        return validation

    return result
