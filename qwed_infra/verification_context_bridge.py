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
    SPEC_VERSION,
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

    if attestation_token is not None and (
        not isinstance(attestation_token, str) or not attestation_token.strip()
    ):
        raise VerificationContextValidationError(
            "attestation_token must be a non-empty string or None"
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
        configuration={} if attestation_token is None else {"attestation": "present"},
        theory_scope=f"{verifier} deterministic verification",
        trusted_dependencies=("qwed-infra",),
        outcome_treatment="unknown/timeout/error resolve to UNVERIFIABLE or BLOCKED",
    )
    formalization = Formalization(
        source_query=formal_statement,
        translator=verifier,
    )

    # Build evidence payload: preserve diagnostic fields, keep diagnostic proof_ref
    # under a NESTED key (diagnostic_proof_ref) to avoid conflict with document proof_ref.
    evidence_payload = copy.deepcopy(result.to_dict())
    diagnostic_proof_ref = evidence_payload.pop("proof_ref", None)
    if diagnostic_proof_ref is not None:
        evidence_payload["diagnostic_proof_ref"] = diagnostic_proof_ref

    if result.status is InfraDiagnosticStatus.VERIFIED:
        decision = Decision(admission=Admission.ADMIT)
        # Assemble context WITHOUT proof_ref to compute document-level hash,
        # then set proof_ref from the assembled document.
        from .verification_context import compute_document_proof_ref
        doc_for_hash = {
            "spec_version": SPEC_VERSION,
            "object": {"formal_statement": formal_statement},
            "context": {
                "interpretation": interpretation.to_dict(),
                "proof": proof.to_dict(),
                "evidence": {"payload": evidence_payload, "proof_ref": None},
                "decision": decision.to_dict(),
            },
            "verdict": Verdict.VERIFIED.value,
        }
        proof_ref = compute_document_proof_ref(doc_for_hash)
    else:
        decision = Decision(admission=Admission.DENY)
        proof_ref = None

    context = VerificationContext(
        interpretation=interpretation,
        proof=proof,
        evidence=Evidence(payload=evidence_payload, proof_ref=proof_ref),
        decision=decision,
    )

    return VerificationContextDocument(
        spec_version=SPEC_VERSION,
        object={"formal_statement": formal_statement},
        context=context,
        verdict={
            InfraDiagnosticStatus.VERIFIED: Verdict.VERIFIED,
            InfraDiagnosticStatus.UNVERIFIABLE: Verdict.UNVERIFIABLE,
            InfraDiagnosticStatus.BLOCKED: Verdict.BLOCKED,
        }[result.status],
        formalization=formalization,
    )