"""Verification Context v1.0 conformance tests (issue #42).

Acceptance-layer verification of the VC v1.0 contract end-to-end:
bridge + all four guard adapters + document validation.

Covers:
1. Bridge produces valid VC documents for VERIFIED / UNVERIFIABLE / BLOCKED inputs.
2. resolve_document_proof_ref returns True for VERIFIED documents.
3. vc.context.decision.admission matches the underlying outcome.
4. Documents validate against the v1.0 schema for all four guards.
5. Fail-closed: guard adapters map malformed verifier inputs to BLOCKED/UNVERIFIABLE
   (never ADMIT, never raise); bridge-level invalid inputs (result type,
   formal_statement, attestation_token) raise VerificationContextValidationError.
"""

from pathlib import Path

import pytest

from qwed_infra.diagnostics import InfraDiagnosticResult
from qwed_infra.guards.artifact_boundary_guard import ArtifactBoundaryGuard
from qwed_infra.guards.cost_guard import CostGuard
from qwed_infra.guards.iam_guard import IamGuard
from qwed_infra.guards.network_guard import NetworkGuard
from qwed_infra.verification_context import (
    Admission,
    SPEC_VERSION,
    Verdict,
    is_valid_document,
    resolve_document_proof_ref,
)
from qwed_infra.verification_context_bridge import verification_context_from_diagnostic_result

ATTESTATION = "attestation-fixture-opaque"
FORMAL_STATEMENT = "The infrastructure claim is safe to apply"


# ----------------------------------------------------------------------
# Fixtures: per-guard valid and violating raw inputs
# ----------------------------------------------------------------------

def _iam_allow_inputs():
    return {
        "policy": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
        "action": "s3:GetObject",
        "resource": "*",
    }


def _iam_deny_inputs():
    return {
        "policy": {"Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"},
        ]},
        "action": "s3:GetObject",
        "resource": "*",
    }


def _network_reachable_inputs():
    return {
        "resources": {
            "subnets": [{"id": "subnet-a", "security_groups": ["sg-allow-http"]}],
            "route_tables": [
                {"subnet_id": "subnet-a", "routes": {"0.0.0.0/0": "igw-123"}}
            ],
            "security_groups": {
                "sg-allow-http": {"ingress": [{"port": 80, "cidr": "0.0.0.0/0"}]}
            },
        },
        "source": "internet",
        "destination": "subnet-a",
        "port": 80,
    }


def _network_blocked_inputs():
    """Ingress allows TCP/80 but no route internet -> subnet-a. Isolates denial
    from graph reachability traversal, not port matching."""
    return {
        "resources": {
            "subnets": [{"id": "subnet-a", "security_groups": ["sg-allow-http"]}],
            "route_tables": [],
            "security_groups": {
                "sg-allow-http": {"ingress": [{"port": 80, "cidr": "0.0.0.0/0"}]}
            },
        },
        "source": "internet",
        "destination": "subnet-a",
        "port": 80,
    }


def _cost_within_budget_inputs():
    return {
        "resources": {"instances": [{"id": "web", "instance_type": "t3.medium", "count": 1}]},
        "budget_monthly": "100.00",
    }


def _cost_exceeds_budget_inputs():
    return {
        "resources": {"instances": [{"id": "gpu", "instance_type": "p4d.24xlarge", "count": 1}]},
        "budget_monthly": "100.00",
    }


def _cost_unknown_type_inputs():
    """Unknown instance type must fail closed (within_budget=False -> DENY)."""
    return {
        "resources": {"instances": [{"id": "gpu", "instance_type": "g6.xlarge", "count": 1}]},
        "budget_monthly": "100.00",
    }


def _artifact_safe_inputs(tmp_path: Path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[build-system]\nrequires = ['hatchling']\nbuild-backend = 'hatchling.build'\n\n"
        "[tool.hatch.build.targets.wheel]\npackages = ['mypkg']\n"
    )
    return {"package_dir": str(pkg), "pyproject_path": str(pyproject)}


def _artifact_unsafe_inputs(tmp_path: Path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    (pkg / ".env").write_text("SECRET=abc")
    return {"package_dir": str(pkg)}


# ----------------------------------------------------------------------
# Bridge: status-to-document conformance
# ----------------------------------------------------------------------

class TestBridgeStatusConformance:
    @staticmethod
    def _bridge(result, **kwargs):
        return verification_context_from_diagnostic_result(
            result,
            formal_statement=FORMAL_STATEMENT,
            verifier="Conformance",
            **kwargs,
        )

    def test_verified_with_attestation_verified_document(self):
        result = InfraDiagnosticResult.verified(
            agent_message="verified",
            developer_fields={"constraint_id": "conformance", "audit_trace": {"rule_id": "R", "outcome": "ALLOWED"}},
            evidence={"constraint_id": "conformance", "audit_trace": {"rule_id": "R", "outcome": "ALLOWED"}},
        )
        vc = self._bridge(result, attestation_token=ATTESTATION)
        assert vc.verdict == Verdict.VERIFIED
        assert vc.context.decision.admission == Admission.ADMIT
        doc = vc.to_dict()
        assert doc["spec_version"] == SPEC_VERSION == "1.0"
        assert is_valid_document(doc) is True
        assert resolve_document_proof_ref(doc) is True

    def test_verified_without_attestation_demoted_unverifiable(self):
        result = InfraDiagnosticResult.verified(
            agent_message="verified",
            developer_fields={"constraint_id": "conformance", "audit_trace": {"rule_id": "R", "outcome": "ALLOWED"}},
            evidence={"constraint_id": "conformance", "audit_trace": {"rule_id": "R", "outcome": "ALLOWED"}},
        )
        vc = self._bridge(result)
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True

    def test_unverifiable_fails_closed(self):
        result = InfraDiagnosticResult.unverifiable(
            agent_message="unverifiable",
            developer_fields={"constraint_id": "conformance", "audit_trace": {"rule_id": "R", "outcome": "UNVERIFIABLE"}},
        )
        vc = self._bridge(result, attestation_token=ATTESTATION)
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True

    def test_blocked_fails_closed(self):
        result = InfraDiagnosticResult.blocked(
            agent_message="blocked",
            developer_fields={"constraint_id": "conformance", "audit_trace": {"rule_id": "R", "outcome": "BLOCKED"}},
        )
        vc = self._bridge(result, attestation_token=ATTESTATION)
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True


class TestBridgeMalformedInputs:
    """Bridge-level malformed inputs reject with ValidationError (issue 5b)."""

    def _call(self, result=None, **kwargs):
        if result is None:
            result = InfraDiagnosticResult.blocked(
                agent_message="blocked",
                developer_fields={"constraint_id": "conformance"},
            )
        return verification_context_from_diagnostic_result(
            result,
            formal_statement=FORMAL_STATEMENT,
            verifier="Conformance",
            **kwargs,
        )

    def test_non_diagnostic_result_rejected(self):
        from qwed_infra.verification_context import VerificationContextValidationError

        with pytest.raises(VerificationContextValidationError):
            self._call(result={"not": "a diagnostic"})

    @pytest.mark.parametrize("formal_statement", ["", "   \n\t ", 123, None])
    def test_invalid_formal_statement_rejected(self, formal_statement):
        from qwed_infra.verification_context import VerificationContextValidationError

        result = InfraDiagnosticResult.blocked(
            agent_message="blocked",
            developer_fields={"constraint_id": "conformance"},
        )
        with pytest.raises(VerificationContextValidationError):
            verification_context_from_diagnostic_result(
                result,
                formal_statement=formal_statement,
                verifier="Conformance",
            )

    @pytest.mark.parametrize("bad_token", ["", "   ", 123, b"token"])
    def test_invalid_attestation_rejected(self, bad_token):
        from qwed_infra.verification_context import VerificationContextValidationError

        result = InfraDiagnosticResult.verified(
            agent_message="verified",
            developer_fields={"constraint_id": "conformance", "audit_trace": {"rule_id": "R", "outcome": "ALLOWED"}},
            evidence={"constraint_id": "conformance"},
        )
        with pytest.raises(VerificationContextValidationError):
            verification_context_from_diagnostic_result(
                result,
                formal_statement=FORMAL_STATEMENT,
                verifier="Conformance",
                attestation_token=bad_token,
            )


# ----------------------------------------------------------------------
# Guard conformance: each guard's valid path validates as v1.0 schema
# ----------------------------------------------------------------------

GUARD_CASES = [
    ("IamGuard", IamGuard, _iam_allow_inputs),
    ("NetworkGuard", NetworkGuard, _network_reachable_inputs),
    ("CostGuard", CostGuard, _cost_within_budget_inputs),
]


class TestGuardDocumentConformance:
    @pytest.mark.parametrize("guard_name,guard_cls,make_inputs", GUARD_CASES, ids=[g for g, _, _ in GUARD_CASES])
    def test_valid_outcome_document_is_valid_and_admitted(self, guard_name, guard_cls, make_inputs):
        guard = guard_cls()
        vc = guard.to_verification_context(
            **make_inputs(),
            formal_statement=FORMAL_STATEMENT,
            attestation_token=ATTESTATION,
        )
        assert vc.verdict == Verdict.VERIFIED
        assert vc.context.decision.admission == Admission.ADMIT
        assert vc.context.proof.verifier == guard_name
        doc = vc.to_dict()
        assert doc["spec_version"] == "1.0"
        assert is_valid_document(doc) is True
        assert resolve_document_proof_ref(doc) is True

    @pytest.mark.parametrize("guard_name,guard_cls,make_inputs", GUARD_CASES, ids=[g for g, _, _ in GUARD_CASES])
    def test_valid_outcome_without_attestation_demoted(self, guard_name, guard_cls, make_inputs):
        guard = guard_cls()
        vc = guard.to_verification_context(
            **make_inputs(),
            formal_statement=FORMAL_STATEMENT,
        )
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True

    def test_artifact_boundary_guard_document_valid(self, tmp_path):
        guard = ArtifactBoundaryGuard()
        vc = guard.to_verification_context(
            **_artifact_safe_inputs(tmp_path),
            formal_statement=FORMAL_STATEMENT,
            attestation_token=ATTESTATION,
        )
        assert vc.verdict == Verdict.VERIFIED
        assert vc.context.decision.admission == Admission.ADMIT
        assert vc.context.proof.verifier == "ArtifactBoundaryGuard"
        assert is_valid_document(vc.to_dict()) is True
        assert resolve_document_proof_ref(vc.to_dict()) is True


# ----------------------------------------------------------------------
# Admission matches outcome: violating paths never produce ADMIT
# ----------------------------------------------------------------------

GUARD_VIOLATION_CASES = [
    ("IamGuard", IamGuard, _iam_deny_inputs),
    ("NetworkGuard", NetworkGuard, _network_blocked_inputs),
    ("CostGuard", CostGuard, _cost_exceeds_budget_inputs),
]


class TestGuardViolationConformance:
    @pytest.mark.parametrize("guard_name,guard_cls,make_inputs", GUARD_VIOLATION_CASES, ids=[g for g, _, _ in GUARD_VIOLATION_CASES])
    def test_violating_inputs_never_admit(self, guard_name, guard_cls, make_inputs):
        guard = guard_cls()
        vc = guard.to_verification_context(
            **make_inputs(),
            formal_statement=FORMAL_STATEMENT,
            attestation_token=ATTESTATION,
        )
        assert vc.context.decision.admission == Admission.DENY
        assert vc.verdict in (Verdict.UNVERIFIABLE, Verdict.BLOCKED)
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True

    def test_artifact_boundary_guard_unsafe_never_admits(self, tmp_path):
        guard = ArtifactBoundaryGuard()
        vc = guard.to_verification_context(
            **_artifact_unsafe_inputs(tmp_path),
            formal_statement=FORMAL_STATEMENT,
            attestation_token=ATTESTATION,
        )
        assert vc.context.decision.admission == Admission.DENY
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True

    def test_unknown_instance_type_fails_closed(self):
        """Unknown instance type must yield within_budget=False in the VC (DENY)."""
        guard = CostGuard()
        vc = guard.to_verification_context(
            **_cost_unknown_type_inputs(),
            formal_statement=FORMAL_STATEMENT,
            attestation_token=ATTESTATION,
        )
        assert vc.context.decision.admission == Admission.DENY
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.evidence.proof_ref is None
        payload = vc.context.evidence.payload
        assert payload["developer_fields"]["within_budget"] is False
        assert payload["developer_fields"]["has_unknown_types"] is True


# ----------------------------------------------------------------------
# Malformed-input fail-closed conformance across all guards
# ----------------------------------------------------------------------

GUARD_MALFORMED_CASES = [
    ("IamGuard", IamGuard, {"policy": {"Statement": [{"Effect": "Allow", "Action": 123, "Resource": "*"}]}, "action": "s3:GetObject", "resource": "*"}),
    ("NetworkGuard", NetworkGuard, {"resources": None, "source": "internet", "destination": "subnet-a", "port": 80}),
    ("CostGuard", CostGuard, {"resources": {"instances": []}, "budget_monthly": "not-a-number"}),
    ("ArtifactBoundaryGuard", ArtifactBoundaryGuard, {"package_dir": None}),
]


class TestGuardMalformedInputConformance:
    @pytest.mark.parametrize("guard_name,guard_cls,make_inputs", GUARD_MALFORMED_CASES, ids=[g for g, _, _ in GUARD_MALFORMED_CASES])
    def test_malformed_inputs_fail_closed(self, guard_name, guard_cls, make_inputs):
        guard = guard_cls()
        vc = guard.to_verification_context(
            **make_inputs,
            formal_statement=FORMAL_STATEMENT,
            attestation_token=ATTESTATION,
        )
        assert vc.context.decision.admission == Admission.DENY
        assert vc.verdict in (Verdict.UNVERIFIABLE, Verdict.BLOCKED)
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True
