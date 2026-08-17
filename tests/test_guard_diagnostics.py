import pydantic
import pytest
from qwed_infra.diagnostics import InfraDiagnosticResult, InfraDiagnosticStatus
from qwed_infra.guards.iam_guard import IamGuard, VerificationResult
from qwed_infra.guards.network_guard import ComputedPath, NetworkGuard
from qwed_infra.guards.cost_guard import CostEstimate, CostGuard
from qwed_infra.verification_context import (
    Admission,
    Verdict,
    is_valid_document,
    resolve_document_proof_ref,
)


class TestIamGuardToDiagnostic:
    def test_verified_allowed(self):
        result = VerificationResult(verified=True, allowed=True, proof="Z3 sat")
        diagnostic = IamGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.VERIFIED
        assert diagnostic.is_verified is True
        assert diagnostic.proof_ref is not None
        assert diagnostic.developer_fields["allowed"] is True

    def test_verified_denied(self):
        result = VerificationResult(verified=True, allowed=False, proof="Z3 unsat")
        diagnostic = IamGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.VERIFIED
        assert diagnostic.is_verified is True
        assert diagnostic.proof_ref is not None
        assert diagnostic.developer_fields["allowed"] is False

    def test_not_verified(self):
        result = VerificationResult(
            verified=False,
            allowed=False,
            error="Something went wrong",
        )
        diagnostic = IamGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.UNVERIFIABLE
        assert diagnostic.is_verified is False
        assert diagnostic.is_fail_closed is True
        assert diagnostic.proof_ref is None
        assert "error" in diagnostic.developer_fields

    def test_with_audit_trace(self):
        result = VerificationResult(verified=True, allowed=True, proof="Z3 sat")
        trace = {"rule_id": "IAM_DENY_PRECEDENCE", "outcome": "ALLOWED"}
        diagnostic = IamGuard.to_diagnostic(result, audit_trace=trace)
        assert diagnostic.developer_fields["audit_trace"] == trace
        assert diagnostic.audit_trace == trace


class TestIamGuardToVerificationContext:
    def _verified_diagnostic(self):
        result = VerificationResult(verified=True, allowed=True, proof="Z3 sat")
        return IamGuard.to_diagnostic(result)

    def _denied_diagnostic(self):
        result = VerificationResult(verified=True, allowed=False, proof="Z3 unsat")
        return IamGuard.to_diagnostic(result)

    @staticmethod
    def _attestation_token():
        return "attestation-fixture-opaque"

    def test_verified_with_attestation(self):
        guard = IamGuard()
        diagnostic = self._verified_diagnostic()
        vc = guard.to_verification_context(
            diagnostic,
            formal_statement="IAM policy is safe to apply",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.VERIFIED
        assert vc.context.decision.admission == Admission.ADMIT
        assert vc.context.evidence.proof_ref.startswith("sha256:")
        assert len(vc.context.evidence.proof_ref) == 71
        doc_dict = vc.to_dict()
        assert is_valid_document(doc_dict) is True
        assert resolve_document_proof_ref(doc_dict) is True

    def test_verified_denial_never_admissible(self):
        guard = IamGuard()
        diagnostic = self._denied_diagnostic()
        assert diagnostic.status is InfraDiagnosticStatus.VERIFIED
        original_proof_ref = diagnostic.proof_ref
        vc = guard.to_verification_context(
            diagnostic,
            formal_statement="IAM policy is safe to apply",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True
        payload = vc.context.evidence.payload
        assert payload["developer_fields"]["allowed"] is False
        assert payload["developer_fields"]["proof"] == "Z3 unsat"
        assert payload["diagnostic_proof_ref"] == original_proof_ref

    def test_verified_denial_without_attestation(self):
        guard = IamGuard()
        diagnostic = self._denied_diagnostic()
        vc = guard.to_verification_context(
            diagnostic,
            formal_statement="IAM policy is safe to apply",
        )
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None

    def test_verified_without_attestation_demoted(self):
        guard = IamGuard()
        diagnostic = self._verified_diagnostic()
        vc = guard.to_verification_context(
            diagnostic,
            formal_statement="IAM policy is safe to apply",
        )
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        doc_dict = vc.to_dict()
        assert is_valid_document(doc_dict) is True

    def test_unverifiable(self):
        guard = IamGuard()
        result = VerificationResult(
            verified=False,
            allowed=False,
            error="Solver failed",
        )
        diagnostic = IamGuard.to_diagnostic(result)
        vc = guard.to_verification_context(
            diagnostic,
            formal_statement="IAM policy is safe to apply",
        )
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True

    def test_blocked(self):
        guard = IamGuard()
        diagnostic = InfraDiagnosticResult.blocked(
            agent_message="blocked by policy",
            developer_fields={"constraint_id": "iam_guard.blocked", "reason": "explicit deny"},
        )
        vc = guard.to_verification_context(
            diagnostic,
            formal_statement="IAM policy is safe to apply",
        )
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True

    def test_admission_matches_diagnostic(self):
        guard = IamGuard()
        diagnostic = self._verified_diagnostic()
        vc = guard.to_verification_context(
            diagnostic,
            formal_statement="IAM policy is safe to apply",
            attestation_token=self._attestation_token(),
        )
        assert vc.context.decision.admission is Admission.ADMIT
        assert diagnostic.is_verified is True

    def test_evidence_preserves_diagnostic_fields(self):
        guard = IamGuard()
        diagnostic = self._verified_diagnostic()
        vc = guard.to_verification_context(
            diagnostic,
            formal_statement="IAM policy is safe to apply",
            attestation_token=self._attestation_token(),
        )
        payload = vc.context.evidence.payload
        assert payload["developer_fields"]["constraint_id"] == "iam_guard.verify_access"
        assert payload["developer_fields"]["allowed"] is True
        assert payload["developer_fields"]["audit_trace"]["rule_id"] == "IAM_DENY_PRECEDENCE"

    @pytest.mark.parametrize(
        "formal_statement",
        [
            "",
            "   \n\t ",
            123,
            None,
        ],
    )
    def test_invalid_formal_statement_rejected(self, formal_statement):
        from qwed_infra.verification_context import VerificationContextValidationError

        guard = IamGuard()
        diagnostic = self._verified_diagnostic()
        attestation_token = self._attestation_token()
        with pytest.raises(VerificationContextValidationError):
            guard.to_verification_context(
                diagnostic,
                formal_statement=formal_statement,
                attestation_token=attestation_token,
            )

    def test_existing_to_diagnostic_still_passes(self):
        result = VerificationResult(verified=True, allowed=True, proof="Z3 sat")
        diagnostic = IamGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.VERIFIED
        assert diagnostic.proof_ref is not None


class TestNetworkGuardToDiagnostic:
    def test_reachable(self):
        result = ComputedPath(
            reachable=True,
            path=["internet", "subnet-a"],
            reason="Route exists and Security Groups allow traffic",
        )
        diagnostic = NetworkGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.VERIFIED
        assert diagnostic.is_verified is True
        assert diagnostic.proof_ref is not None
        assert diagnostic.developer_fields["reachable"] is True

    def test_blocked_by_sg(self):
        result = ComputedPath(
            reachable=False,
            path=["internet", "subnet-a"],
            reason="Routing exists but Security Group blocks port 80",
            failure_code="sg_ingress_blocked",
        )
        diagnostic = NetworkGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
        assert diagnostic.is_verified is False
        assert diagnostic.proof_ref is None

    def test_no_route(self):
        result = ComputedPath(
            reachable=False,
            path=[],
            reason="No Route exists between nodes",
            failure_code="no_route",
        )
        diagnostic = NetworkGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
        assert diagnostic.developer_fields["audit_trace"]["rule_id"] == "NETWORK_NO_ROUTE"
        assert diagnostic.developer_fields["failure_code"] == "no_route"

    def test_invalid_internal_source(self):
        result = ComputedPath(
            reachable=False,
            path=[],
            reason="Invalid internal source: 'not-an-ip'",
            failure_code="invalid_internal_source",
        )
        diagnostic = NetworkGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
        assert diagnostic.developer_fields["audit_trace"]["rule_id"] == "NETWORK_INVALID_INTERNAL"

    def test_unknown_destination(self):
        result = ComputedPath(
            reachable=False,
            path=[],
            reason="Destination 'subnet-ghost' not found in subnets",
            failure_code="unknown_destination",
        )
        diagnostic = NetworkGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
        assert diagnostic.developer_fields["audit_trace"]["rule_id"] == "NETWORK_UNKNOWN_DEST"


class TestNetworkGuardToVerificationContext:
    def _reachable_diagnostic(self):
        result = ComputedPath(
            reachable=True,
            path=["internet", "subnet-a"],
            reason="Route exists and Security Groups allow traffic",
        )
        return NetworkGuard.to_diagnostic(result)

    def _blocked_diagnostic(self, failure_code, reason):
        result = ComputedPath(
            reachable=False,
            path=[],
            reason=reason,
            failure_code=failure_code,
        )
        return NetworkGuard.to_diagnostic(result)

    def _unsupported_topology_diagnostic(self):
        result = ComputedPath(
            reachable=False,
            path=[],
            port=80,
            reason="Topology contains unsupported constructs — cannot verify",
            failure_code="unsupported_topology",
            unsupported_topology=True,
        )
        return NetworkGuard.to_diagnostic(result)

    @staticmethod
    def _attestation_token():
        return "attestation-fixture-opaque"

    def test_reachable_with_attestation(self):
        guard = NetworkGuard()
        diagnostic = self._reachable_diagnostic()
        vc = guard.to_verification_context(
            diagnostic,
            formal_statement="Traffic from internet to subnet-a on port 80 is safe",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.VERIFIED
        assert vc.context.decision.admission == Admission.ADMIT
        assert vc.context.evidence.proof_ref.startswith("sha256:")
        assert len(vc.context.evidence.proof_ref) == 71
        doc_dict = vc.to_dict()
        assert is_valid_document(doc_dict) is True
        assert resolve_document_proof_ref(doc_dict) is True

    def test_reachable_without_attestation_demoted(self):
        guard = NetworkGuard()
        diagnostic = self._reachable_diagnostic()
        vc = guard.to_verification_context(
            diagnostic,
            formal_statement="Traffic from internet to subnet-a on port 80 is safe",
        )
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True

    @pytest.mark.parametrize(
        "failure_code,reason,rule_id",
        [
            ("sg_ingress_blocked", "Security Group blocks port 80", "NETWORK_SG_INGRESS"),
            ("no_route", "No Route exists between nodes", "NETWORK_NO_ROUTE"),
            ("invalid_internal_source", "Invalid internal source: 'not-an-ip'", "NETWORK_INVALID_INTERNAL"),
            ("unknown_destination", "Destination not found", "NETWORK_UNKNOWN_DEST"),
        ],
    )
    def test_fail_closed_never_admissible(self, failure_code, reason, rule_id):
        guard = NetworkGuard()
        diagnostic = self._blocked_diagnostic(failure_code, reason)
        assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
        vc = guard.to_verification_context(
            diagnostic,
            formal_statement="Traffic from internet to subnet-a on port 80 is safe",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True
        payload = vc.context.evidence.payload
        assert payload["developer_fields"]["failure_code"] == failure_code
        assert payload["developer_fields"]["audit_trace"]["rule_id"] == rule_id

    def test_unsupported_topology_fail_closed(self):
        guard = NetworkGuard()
        diagnostic = self._unsupported_topology_diagnostic()
        assert diagnostic.status is InfraDiagnosticStatus.UNVERIFIABLE
        vc = guard.to_verification_context(
            diagnostic,
            formal_statement="Traffic from internet to subnet-a on port 80 is safe",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True
        assert vc.context.evidence.payload["developer_fields"]["unsupported_topology"] is True

    def test_evidence_preserves_diagnostic_fields(self):
        guard = NetworkGuard()
        diagnostic = self._reachable_diagnostic()
        vc = guard.to_verification_context(
            diagnostic,
            formal_statement="Traffic from internet to subnet-a on port 80 is safe",
            attestation_token=self._attestation_token(),
        )
        payload = vc.context.evidence.payload
        assert payload["developer_fields"]["constraint_id"] == "network_guard.verify_reachability"
        assert payload["developer_fields"]["reachable"] is True
        assert payload["developer_fields"]["path"] == ("internet", "subnet-a")

    @pytest.mark.parametrize(
        "formal_statement",
        [
            "",
            "   \n\t ",
            123,
            None,
        ],
    )
    def test_invalid_formal_statement_rejected(self, formal_statement):
        from qwed_infra.verification_context import VerificationContextValidationError

        guard = NetworkGuard()
        diagnostic = self._reachable_diagnostic()
        attestation_token = self._attestation_token()
        with pytest.raises(VerificationContextValidationError):
            guard.to_verification_context(
                diagnostic,
                formal_statement=formal_statement,
                attestation_token=attestation_token,
            )

    def test_existing_to_diagnostic_still_passes(self):
        result = ComputedPath(
            reachable=True,
            path=["internet", "subnet-a"],
            reason="Route exists and Security Groups allow traffic",
        )
        diagnostic = NetworkGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.VERIFIED
        assert diagnostic.proof_ref is not None


class TestCostGuardToDiagnostic:
    def test_within_budget(self):
        result = CostEstimate(
            total_monthly_cost="27.82",
            breakdown={"web": "27.82"},
            within_budget=True,
            budget="100.00",
            reason="Estimated cost $27.82 is within budget $100.00",
        )
        diagnostic = CostGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.VERIFIED
        assert diagnostic.is_verified is True
        assert diagnostic.proof_ref is not None
        assert diagnostic.developer_fields["within_budget"] is True

    def test_exceeds_budget(self):
        result = CostEstimate(
            total_monthly_cost="23922.10",
            breakdown={"web": "23922.10"},
            within_budget=False,
            budget="100.00",
            reason="Estimated cost $23922.10 EXCEEDS budget $100.00",
        )
        diagnostic = CostGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
        assert diagnostic.is_verified is False
        assert diagnostic.is_fail_closed is True
        assert diagnostic.proof_ref is None
        assert diagnostic.developer_fields["audit_trace"]["rule_id"] == "COST_BUDGET_EXCEEDED"

    def test_unknown_instance_type(self):
        result = CostEstimate(
            total_monthly_cost="50.00",
            breakdown={},
            within_budget=False,
            budget="100.00",
            reason="Cost estimate incomplete \u2014 unknown instance types: ['g6.xlarge']. Known cost $50.00 vs budget $100.00.",
            has_unknown_types=True,
        )
        diagnostic = CostGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
        assert diagnostic.is_verified is False
        assert diagnostic.proof_ref is None
        assert diagnostic.developer_fields["audit_trace"]["rule_id"] == "COST_UNKNOWN_RESOURCE"
        assert diagnostic.developer_fields["has_unknown_types"] is True

    def test_verify_budget_marks_unknown_types_blocked(self):
        estimate = CostGuard().verify_budget(
            {"instances": [{"id": "gpu-1", "instance_type": "g6.xlarge", "count": 1}]},
            budget_monthly=100.0,
        )
        assert estimate.has_unknown_types is True
        diagnostic = CostGuard.to_diagnostic(estimate)
        assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
        assert diagnostic.developer_fields["audit_trace"]["rule_id"] == "COST_UNKNOWN_RESOURCE"

    def test_mismatched_within_budget_blocked(self):
        result = CostEstimate(
            total_monthly_cost="200.00",
            breakdown={"web": "200.00"},
            within_budget=True,
            budget="100.00",
            reason="Cost exceeds budget but claims within_budget",
        )
        diagnostic = CostGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
        assert diagnostic.developer_fields["audit_trace"]["outcome"] == "INCONSISTENT"


class TestPydanticExtraForbid:
    def test_iam_policy_rejects_extra(self):
        from qwed_infra.guards.iam_guard import IamPolicy

        with pytest.raises(pydantic.ValidationError):
            IamPolicy(Version="2012-10-17", Statement=[], extra_field="bad")

    def test_verification_result_rejects_extra(self):
        from qwed_infra.guards.iam_guard import VerificationResult

        with pytest.raises(pydantic.ValidationError):
            VerificationResult(verified=True, allowed=True, extra="bad")

    def test_computed_path_rejects_extra(self):
        from qwed_infra.guards.network_guard import ComputedPath

        with pytest.raises(pydantic.ValidationError):
            ComputedPath(reachable=True, path=[], reason="ok", extra="bad")

    def test_cost_estimate_rejects_extra(self):
        from qwed_infra.guards.cost_guard import CostEstimate

        with pytest.raises(pydantic.ValidationError):
            CostEstimate(
                total_monthly_cost="0.00",
                breakdown={},
                within_budget=True,
                budget="100.00",
                reason="ok",
                extra="bad",
            )
