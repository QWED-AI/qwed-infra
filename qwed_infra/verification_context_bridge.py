"""
QWED-Infra Verification Context Bridge.

Converts InfraDiagnosticResult to Verification Context v1.0 document.
Mirrors qwed-verification/src/qwed_new/core/verification_context_bridge.py.
"""

from __future__ import annotations

import copy
from dataclasses import replace
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


def _validate_inputs(result, formal_statement, verifier, attestation_token):
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
    if attestation_token is not None and (
        not isinstance(attestation_token, str) or not attestation_token.strip()
    ):
        raise VerificationContextValidationError(
            "attestation_token must be a non-empty string or None"
        )


def _cast_status_preserving(result):
    """Return a copy of result with a valid enum status and dict developer_fields.

    Used for the audit-trail evidence path when the input is malformed (e.g. a
    string status or non-dict developer_fields). The reconstructed result keeps
    the original proof_ref and (when dict) developer_fields so evidence
    serialization retains the full diagnostic history.
    """
    try:
        result_status = InfraDiagnosticStatus(result.status)
    except ValueError:
        result_status = InfraDiagnosticStatus.BLOCKED
    dev = getattr(result, 'developer_fields', None)
    valid_dev = dev if isinstance(dev, dict) else {}
    if result_status is result.status and valid_dev is dev:
        return result
    rebuilt = object.__new__(InfraDiagnosticResult)
    object.__setattr__(rebuilt, 'status', result_status)
    object.__setattr__(rebuilt, 'agent_message', getattr(result, 'agent_message', ''))
    object.__setattr__(rebuilt, 'developer_fields', valid_dev)
    object.__setattr__(rebuilt, 'proof_ref', getattr(result, 'proof_ref', None))
    object.__setattr__(rebuilt, 'proof_data', getattr(result, 'proof_data', None))
    return rebuilt


def _normalize_status(result):
    """Cast malformed status to enum; rebuild as BLOCKED if not an enum instance."""
    try:
        result_status = InfraDiagnosticStatus(result.status)
    except ValueError:
        result_status = InfraDiagnosticStatus.BLOCKED
    if result_status is not result.status:
        return InfraDiagnosticResult.blocked(
            agent_message=f"Malformed status {result.status!r} demoted to BLOCKED",
            developer_fields={"constraint_id": "verification_context.malformed_status"},
        )
    return result


def _normalize_developer_fields(result):
    if not isinstance(result.developer_fields, dict):
        return InfraDiagnosticResult.blocked(
            agent_message="Diagnostic result is malformed",
            developer_fields={
                "constraint_id": "verification_context.malformed_developer_fields",
            },
        )
    return result


def _apply_attestation_policy(result, attestation_token, formal_statement):
    """Apply the #47 attestation trust boundary to a VERIFIED decision result.

    - VERIFIED + no token        → UNVERIFIABLE (fail-closed demotion, unchanged)
    - VERIFIED + token present   → cryptographically validated via
      enforce_trust_decision: signature/issuer/expiry/revocation plus claim
      binding (status match, query_hash == sha256(formal_statement),
      proof_hash == diagnostic proof_ref). Any failure → BLOCKED.
      Binding the formal_statement here means a token minted for one claim
      can never admit a different (e.g. broader) statement.
    - Non-VERIFIED statuses pass through unchanged (attestation irrelevant).
    """
    if result.status is not InfraDiagnosticStatus.VERIFIED:
        return result
    if attestation_token is None:
        return InfraDiagnosticResult.unverifiable(
            agent_message=result.agent_message,
            developer_fields=result.developer_fields,
        )
    from .diagnostics import enforce_trust_decision

    return enforce_trust_decision(
        result,
        attestation_token=attestation_token,
        require_attestation=True,
        query=formal_statement,
    )


def _extract_attested_identity(token_claims):
    """Extract (issuer, jti) from verified token claims for Proof.configuration."""
    raw_qwed = (token_claims or {}).get("qwed")
    return {
        "issuer": (token_claims or {}).get("iss", ""),
        "jti": (token_claims or {}).get("jti", ""),
        "query_hash": (raw_qwed or {}).get("query_hash", "") if isinstance(raw_qwed, dict) else "",
    }


def _build_evidence_payload(result):
    """Deep-copy result dict, move diagnostic proof_ref to nested key."""
    evidence_payload = copy.deepcopy(result.to_dict())
    diagnostic_proof_ref = evidence_payload.pop("proof_ref", None)
    if diagnostic_proof_ref is not None:
        evidence_payload["diagnostic_proof_ref"] = diagnostic_proof_ref
    return evidence_payload


def _compute_verified_proof_ref(formal_statement, interpretation, proof, evidence_payload, decision, formalization):
    """Compute document-bound proof_ref for VERIFIED documents."""
    from .verification_context import compute_document_proof_ref
    obj = {"formal_statement": formal_statement}
    if formalization is not None:
        obj["formalization"] = formalization.to_dict()
    doc_for_hash = {
        "spec_version": SPEC_VERSION,
        "object": obj,
        "context": {
            "interpretation": interpretation.to_dict(),
            "proof": proof.to_dict(),
            "evidence": {"payload": evidence_payload, "proof_ref": None},
            "decision": decision.to_dict(),
        },
        "verdict": Verdict.VERIFIED.value,
    }
    return compute_document_proof_ref(doc_for_hash)


_VERDICT_MAP = {
    InfraDiagnosticStatus.VERIFIED: Verdict.VERIFIED,
    InfraDiagnosticStatus.UNVERIFIABLE: Verdict.UNVERIFIABLE,
    InfraDiagnosticStatus.BLOCKED: Verdict.BLOCKED,
}


def verification_context_from_diagnostic_result(
    result: InfraDiagnosticResult,
    *,
    formal_statement: str,
    verifier: str,
    verifier_version: Optional[str] = None,
    attestation_token: Optional[str] = None,
    decision_status: Optional[InfraDiagnosticStatus] = None,
) -> VerificationContextDocument:
    _validate_inputs(result, formal_statement, verifier, attestation_token)
    if decision_status is not None:
        if not isinstance(decision_status, InfraDiagnosticStatus):
            raise VerificationContextValidationError(
                "decision_status must be an InfraDiagnosticStatus or None"
            )
        if decision_status is InfraDiagnosticStatus.VERIFIED:
            raise VerificationContextValidationError(
                "decision_status must be a fail-closed status "
                "(UNVERIFIABLE or BLOCKED); VERIFIED is the default path"
            )

    evidence_result = _cast_status_preserving(result)
    decision_result = _normalize_status(result)
    decision_result = _normalize_developer_fields(decision_result)
    if decision_status is not None:
        # Fail-closed decision override: evidence keeps the authoritative
        # diagnostic (status + proof_ref), decision derives from decision_status.
        decision_result = replace(
            decision_result,
            status=decision_status,
            proof_ref=None,
        )

    # #47 attestation trust boundary. For VERIFIED decisions with a supplied
    # token, enforce_trust_decision validates the JWT cryptographically and
    # binds its claims (status, query_hash == sha256(formal_statement),
    # proof_hash == diagnostic proof_ref) to this exact result + statement. Any
    # failure demotes the decision to BLOCKED (never ADMIT). No token keeps the
    # UNVERIFIABLE demotion. On success, the attested identity (issuer/jti/
    # query_hash) is bound into Proof.configuration so distinct accepted
    # attestations yield distinct document proof_refs.
    enforced = _apply_attestation_policy(decision_result, attestation_token, formal_statement)
    attested_claims = None
    if (
        enforced.status is InfraDiagnosticStatus.VERIFIED
        and attestation_token is not None
    ):
        from .attestation import get_attestation_service

        service = get_attestation_service()
        _is_valid, attested_claims, _error = service.verify_attestation(attestation_token)
        if not _is_valid:
            # Defensive: enforcement above already validated; never admit on an
            # unverifiable second look.
            enforced = InfraDiagnosticResult.blocked(
                agent_message="Verification blocked — attestation could not be re-verified",
                developer_fields={
                    "constraint_id": "trust_gate.attestation_recheck_failed",
                },
            )
            attested_claims = None

    interpretation = Interpretation(theory=f"{verifier} verification")
    configuration = {}
    if attested_claims is not None:
        configuration["attestation"] = _extract_attested_identity(attested_claims)
    proof = Proof(
        verifier=verifier,
        verifier_version=_resolved_verifier_version(verifier_version),
        configuration=configuration,
        theory_scope=f"{verifier} deterministic verification",
        trusted_dependencies=("qwed-infra",),
        outcome_treatment="unknown/timeout/error resolve to UNVERIFIABLE or BLOCKED",
    )
    formalization = Formalization(
        source_query=formal_statement,
        translator=verifier,
    )

    evidence_payload = _build_evidence_payload(evidence_result)

    if enforced.status is InfraDiagnosticStatus.VERIFIED:
        decision = Decision(admission=Admission.ADMIT)
        proof_ref = _compute_verified_proof_ref(
            formal_statement, interpretation, proof, evidence_payload, decision, formalization
        )
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
        verdict=_VERDICT_MAP[enforced.status],
        formalization=formalization,
    )