"""
QWED-Infra Verification Context Bridge.

Converts InfraDiagnosticResult to Verification Context v1.0 document.
Mirrors qwed-verification/src/qwed_new/core/verification_context_bridge.py.
"""

from __future__ import annotations

import copy
from importlib.metadata import PackageNotFoundError, version
from typing import Optional

from .diagnostics import InfraDiagnosticResult, InfraDiagnosticStatus
from .verification_context import (
    Admission,
    Decision,
    Evidence,
    Formalization,
    Interpretation,
    Proof,
    Verdict,
    VerificationContext,
    VerificationContextDocument,
    VerificationContextValidationError,
)


def _resolved_verifier_version(verifier_version: Optional[str]) -> str:
    if verifier_version is not None:
        if not verifier_version.strip():
            raise VerificationContextValidationError(
                "verifier_version must be non-empty"
            )
        return verifier_version
    try:
        return version("qwed-infra")
    except PackageNotFoundError:
        from qwed_infra import __version__ as qwed_infra_version

        return qwed_infra_version


def verification_context_from_diagnostic_result(
    result: InfraDiagnosticResult,
    *,
    formal_statement: str,
    verifier: str,
    verifier_version: Optional[str] = None,
    attestation_token: Optional[str] = None,
) -> VerificationContextDocument:
    if not isinstance(formal_statement, str) or not formal_statement.strip():
        raise VerificationContextValidationError(
            "formal_statement must be a non-empty string"
        )
    if not isinstance(verifier, str) or not verifier.strip():
        raise VerificationContextValidationError(
            "verifier must be a non-empty string"
        )
    if not isinstance(result, InfraDiagnosticResult):
        raise VerificationContextValidationError(
            f"result must be an InfraDiagnosticResult, got {type(result).__name__}"
        )

    if not isinstance(result.developer_fields, dict):
        result = InfraDiagnosticResult.blocked(
            agent_message="Diagnostic result is malformed",
            developer_fields={
                "constraint_id": "verification_context.malformed_developer_fields",
            },
        )

    if result.status is InfraDiagnosticStatus.VERIFIED and attestation_token is None:
        # Fail-closed: VERIFIED requires attestation to maintain authority;
        # without it, demote to UNVERIFIABLE (consistent with core contract).
        result = InfraDiagnosticResult.unverifiable(
            agent_message=result.agent_message,
            developer_fields=result.developer_fields,
        )

    interpretation = Interpretation(theory=f"{verifier} verification")
    proof = Proof(
        verifier=verifier,
        verifier_version=_resolved_verifier_version(verifier_version),
        configuration={},
        theory_scope=f"{verifier} deterministic verification",
        trusted_dependencies=("qwed-infra",),
        outcome_treatment="unknown/timeout/error resolve to UNVERIFIABLE or BLOCKED",
    )
    formalization = Formalization(
        source_query=formal_statement,
        translator=verifier,
    )

    evidence_payload = copy.deepcopy(result.to_dict())
    # Exclude proof_ref from bound payload (it commits to itself)
    evidence_payload.pop("proof_ref", None)

    if result.status is InfraDiagnosticStatus.VERIFIED:
        decision = Decision(admission=Admission.ADMIT)
        proof_ref = result.proof_ref
    else:
        decision = Decision(admission=Admission.DENY)
        proof_ref = None

    context = VerificationContext(
        interpretation=interpretation,
        proof=proof,
        evidence=Evidence(payload=evidence_payload, proof_ref=proof_ref),
        decision=decision,
    )

    verdict_map = {
        InfraDiagnosticStatus.VERIFIED: Verdict.VERIFIED,
        InfraDiagnosticStatus.UNVERIFIABLE: Verdict.UNVERIFIABLE,
        InfraDiagnosticStatus.BLOCKED: Verdict.BLOCKED,
    }

    return VerificationContextDocument(
        spec_version="1.0",
        object={"formal_statement": formal_statement},
        context=context,
        verdict=verdict_map[result.status],
        formalization=formalization,
    )