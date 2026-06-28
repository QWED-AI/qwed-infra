import pydantic
import pytest
from qwed_infra.diagnostics import InfraDiagnosticStatus
from qwed_infra.guards.iam_guard import IamGuard, VerificationResult
from qwed_infra.guards.network_guard import ComputedPath, NetworkGuard
from qwed_infra.guards.cost_guard import CostEstimate, CostGuard


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
        assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
        assert diagnostic.is_verified is False
        assert diagnostic.proof_ref is None
        assert "error" in diagnostic.developer_fields

    def test_with_audit_trace(self):
        result = VerificationResult(verified=True, allowed=True, proof="Z3 sat")
        trace = {"rule_id": "IAM_DENY_PRECEDENCE", "outcome": "ALLOWED"}
        diagnostic = IamGuard.to_diagnostic(result, audit_trace=trace)
        assert diagnostic.developer_fields["audit_trace"] == trace
        assert diagnostic.audit_trace == trace


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


class TestCostGuardToDiagnostic:
    def test_within_budget(self):
        result = CostEstimate(
            total_monthly_cost=50.0,
            breakdown={"web": 50.0},
            within_budget=True,
            budget=100.0,
            reason="Estimated cost $50.00 is within budget $100.00",
        )
        diagnostic = CostGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.VERIFIED
        assert diagnostic.is_verified is True
        assert diagnostic.proof_ref is not None
        assert diagnostic.developer_fields["within_budget"] is True

    def test_exceeds_budget(self):
        result = CostEstimate(
            total_monthly_cost=200.0,
            breakdown={"web": 200.0},
            within_budget=False,
            budget=100.0,
            reason="Estimated cost $200.00 EXCEEDS budget $100.00",
        )
        diagnostic = CostGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
        assert diagnostic.is_verified is False
        assert diagnostic.is_fail_closed is True
        assert diagnostic.proof_ref is None
        assert diagnostic.developer_fields["audit_trace"]["rule_id"] == "COST_BUDGET_EXCEEDED"

    def test_unknown_instance_type(self):
        result = CostEstimate(
            total_monthly_cost=50.0,
            breakdown={},
            within_budget=False,
            budget=100.0,
            reason="Cost estimate incomplete \u2014 unknown instance types: ['g6.xlarge']. Known cost $50.00 vs budget $100.00.",
            has_unknown_types=True,
        )
        diagnostic = CostGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
        assert diagnostic.is_verified is False
        assert diagnostic.proof_ref is None
        assert diagnostic.developer_fields["audit_trace"]["rule_id"] == "COST_UNKNOWN_RESOURCE"
        assert diagnostic.developer_fields["has_unknown_types"] is True


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
                total_monthly_cost=0,
                breakdown={},
                within_budget=True,
                budget=100,
                reason="ok",
                extra="bad",
            )
