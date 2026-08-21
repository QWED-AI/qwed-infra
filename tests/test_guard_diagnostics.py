import pydantic
import pytest
from qwed_infra.diagnostics import InfraDiagnosticStatus
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
    @staticmethod
    def _allow_policy():
        return {
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
        }

    @staticmethod
    def _deny_policy():
        return {
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
            ]
        }

    @staticmethod
    def _unverifiable_policy():
        return {"Statement": [{"Effect": "Allow", "Action": 123, "Resource": "*"}]}

    @staticmethod
    def _attestation_token():
        return "attestation-fixture-opaque"

    def test_verified_with_attestation(self):
        guard = IamGuard()
        vc = guard.to_verification_context(
            self._allow_policy(),
            "s3:GetObject",
            "*",
            formal_statement="IAM policy is safe to apply",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.VERIFIED
        assert vc.context.decision.admission == Admission.ADMIT
        assert vc.context.proof.verifier == "IamGuard"
        assert vc.context.evidence.proof_ref.startswith("sha256:")
        assert len(vc.context.evidence.proof_ref) == 71
        doc_dict = vc.to_dict()
        assert is_valid_document(doc_dict) is True
        assert resolve_document_proof_ref(doc_dict) is True

    def test_verified_denial_never_admissible(self):
        guard = IamGuard()
        result = guard.verify_access(self._deny_policy(), "s3:DeleteBucket", "*")
        assert result.verified is True
        assert result.allowed is False
        diagnostic = IamGuard.to_diagnostic(result)
        assert diagnostic.status is InfraDiagnosticStatus.VERIFIED
        original_proof_ref = diagnostic.proof_ref
        vc = guard.to_verification_context(
            self._deny_policy(),
            "s3:DeleteBucket",
            "*",
            formal_statement="IAM policy is safe to apply",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True
        payload = vc.context.evidence.payload
        assert payload["developer_fields"]["allowed"] is False
        assert payload["developer_fields"]["proof"] == "Z3 proved unsatisfiability (Access Denied)"
        assert payload["diagnostic_proof_ref"] == original_proof_ref

    def test_verified_denial_without_attestation(self):
        guard = IamGuard()
        vc = guard.to_verification_context(
            self._deny_policy(),
            "s3:DeleteBucket",
            "*",
            formal_statement="IAM policy is safe to apply",
        )
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None

    def test_verified_without_attestation_demoted(self):
        guard = IamGuard()
        vc = guard.to_verification_context(
            self._allow_policy(),
            "s3:GetObject",
            "*",
            formal_statement="IAM policy is safe to apply",
        )
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        doc_dict = vc.to_dict()
        assert is_valid_document(doc_dict) is True

    def test_unverifiable(self):
        guard = IamGuard()
        result = guard.verify_access(self._unverifiable_policy(), "s3:GetObject", "*")
        assert result.verified is False
        vc = guard.to_verification_context(
            self._unverifiable_policy(),
            "s3:GetObject",
            "*",
            formal_statement="IAM policy is safe to apply",
        )
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True

    def test_admission_matches_diagnostic(self):
        guard = IamGuard()
        vc = guard.to_verification_context(
            self._allow_policy(),
            "s3:GetObject",
            "*",
            formal_statement="IAM policy is safe to apply",
            attestation_token=self._attestation_token(),
        )
        assert vc.context.decision.admission is Admission.ADMIT
        assert IamGuard.to_diagnostic(
            guard.verify_access(self._allow_policy(), "s3:GetObject", "*")
        ).is_verified is True

    def test_evidence_preserves_diagnostic_fields(self):
        guard = IamGuard()
        vc = guard.to_verification_context(
            self._allow_policy(),
            "s3:GetObject",
            "*",
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
        policy = self._allow_policy()
        attestation_token = self._attestation_token()
        with pytest.raises(VerificationContextValidationError):
            guard.to_verification_context(
                policy,
                "s3:GetObject",
                "*",
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
    @staticmethod
    def _reachable_resources():
        return {
            "subnets": [{"id": "subnet-a", "security_groups": ["sg-allow-http"]}],
            "route_tables": [
                {"subnet_id": "subnet-a", "routes": {"0.0.0.0/0": "igw-123"}}
            ],
            "security_groups": {
                "sg-allow-http": {"ingress": [{"port": 80, "cidr": "0.0.0.0/0"}]}
            },
        }

    @staticmethod
    def _sg_blocked_resources():
        return {
            "subnets": [{"id": "subnet-a", "security_groups": ["sg-blocked"]}],
            "route_tables": [
                {"subnet_id": "subnet-a", "routes": {"0.0.0.0/0": "igw-123"}}
            ],
            "security_groups": {
                "sg-blocked": {"ingress": [{"port": 443, "cidr": "0.0.0.0/0"}]}
            },
        }

    @staticmethod
    def _no_route_resources():
        return {"subnets": [{"id": "subnet-a", "security_groups": []}]}

    @staticmethod
    def _attestation_token():
        return "attestation-fixture-opaque"

    def test_reachable_with_attestation(self):
        guard = NetworkGuard()
        resources = self._reachable_resources()
        vc = guard.to_verification_context(
            resources,
            "internet",
            "subnet-a",
            80,
            formal_statement="Traffic from internet to subnet-a on port 80 is safe",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.VERIFIED
        assert vc.context.decision.admission == Admission.ADMIT
        assert vc.context.proof.verifier == "NetworkGuard"
        assert vc.context.evidence.proof_ref.startswith("sha256:")
        assert len(vc.context.evidence.proof_ref) == 71
        doc_dict = vc.to_dict()
        assert is_valid_document(doc_dict) is True
        assert resolve_document_proof_ref(doc_dict) is True

    def test_reachable_without_attestation_demoted(self):
        guard = NetworkGuard()
        resources = self._reachable_resources()
        vc = guard.to_verification_context(
            resources,
            "internet",
            "subnet-a",
            80,
            formal_statement="Traffic from internet to subnet-a on port 80 is safe",
        )
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True

    @pytest.mark.parametrize(
        "resources,source,destination,port,failure_code,rule_id",
        [
            pytest.param(
                {
                    "subnets": [{"id": "subnet-a", "security_groups": ["sg-blocked"]}],
                    "route_tables": [
                        {"subnet_id": "subnet-a", "routes": {"0.0.0.0/0": "igw-123"}}
                    ],
                    "security_groups": {
                        "sg-blocked": {"ingress": [{"port": 443, "cidr": "0.0.0.0/0"}]}
                    },
                },
                "internet",
                "subnet-a",
                80,
                "sg_ingress_blocked",
                "NETWORK_SG_INGRESS",
            ),
            pytest.param(
                {"subnets": [{"id": "subnet-a", "security_groups": []}]},
                "internet",
                "subnet-a",
                80,
                "no_route",
                "NETWORK_NO_ROUTE",
            ),
            pytest.param(
                {"subnets": [{"id": "subnet-a", "security_groups": []}]},
                "not-an-ip",
                "subnet-a",
                80,
                "invalid_internal_source",
                "NETWORK_INVALID_INTERNAL",
            ),
            pytest.param(
                {"subnets": [{"id": "subnet-a", "security_groups": []}]},
                "10.0.0.5",
                "subnet-ghost",
                80,
                "unknown_destination",
                "NETWORK_UNKNOWN_DEST",
            ),
        ],
    )
    def test_fail_closed_never_admissible(
        self, resources, source, destination, port, failure_code, rule_id
    ):
        guard = NetworkGuard()
        result = guard.verify_reachability(resources, source, destination, port)
        assert NetworkGuard.to_diagnostic(result).status is InfraDiagnosticStatus.BLOCKED
        vc = guard.to_verification_context(
            resources,
            source,
            destination,
            port,
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
        resources = {"nat_gateways": [{"id": "nat-1"}]}
        result = guard.verify_reachability(resources, "internet", "subnet-a", 80)
        assert NetworkGuard.to_diagnostic(result).status is InfraDiagnosticStatus.UNVERIFIABLE
        vc = guard.to_verification_context(
            resources,
            "internet",
            "subnet-a",
            80,
            formal_statement="Traffic from internet to subnet-a on port 80 is safe",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True
        payload = vc.context.evidence.payload["developer_fields"]
        assert payload["unsupported_topology"] is True
        assert payload["failure_code"] == "unsupported_topology"

    def test_evidence_preserves_diagnostic_fields(self):
        guard = NetworkGuard()
        resources = self._reachable_resources()
        vc = guard.to_verification_context(
            resources,
            "internet",
            "subnet-a",
            80,
            formal_statement="Traffic from internet to subnet-a on port 80 is safe",
            attestation_token=self._attestation_token(),
        )
        payload = vc.context.evidence.payload
        assert payload["developer_fields"]["constraint_id"] == "network_guard.verify_reachability"
        assert payload["developer_fields"]["reachable"] is True
        assert payload["developer_fields"]["path"] == ("internet", "subnet-a")
        serialized = vc.context.evidence.to_dict()["payload"]["developer_fields"]["path"]
        assert serialized == ["internet", "subnet-a"]

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
        resources = self._reachable_resources()
        attestation_token = self._attestation_token()
        with pytest.raises(VerificationContextValidationError):
            guard.to_verification_context(
                resources,
                "internet",
                "subnet-a",
                80,
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


class TestCostGuardToVerificationContext:
    @staticmethod
    def _within_budget_resources():
        return {"instances": [{"id": "web", "instance_type": "t3.medium", "count": 1}]}

    @staticmethod
    def _exceeds_budget_resources():
        return {"instances": [{"id": "gpu", "instance_type": "p4d.24xlarge", "count": 1}]}

    @staticmethod
    def _unknown_type_resources():
        return {"instances": [{"id": "gpu-1", "instance_type": "g6.xlarge", "count": 1}]}

    @staticmethod
    def _attestation_token():
        return "attestation-fixture-opaque"

    def test_within_budget_with_attestation(self):
        guard = CostGuard()
        resources = self._within_budget_resources()
        vc = guard.to_verification_context(
            resources,
            "100.00",
            formal_statement="Estimated monthly cost is within the approved budget",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.VERIFIED
        assert vc.context.decision.admission == Admission.ADMIT
        assert vc.context.proof.verifier == "CostGuard"
        assert vc.context.evidence.proof_ref.startswith("sha256:")
        assert len(vc.context.evidence.proof_ref) == 71
        doc_dict = vc.to_dict()
        assert is_valid_document(doc_dict) is True
        assert resolve_document_proof_ref(doc_dict) is True

    def test_within_budget_without_attestation_demoted(self):
        guard = CostGuard()
        resources = self._within_budget_resources()
        vc = guard.to_verification_context(
            resources,
            "100.00",
            formal_statement="Estimated monthly cost is within the approved budget",
        )
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True

    def test_exceeds_budget_never_admissible(self):
        guard = CostGuard()
        resources = self._exceeds_budget_resources()
        result = guard.verify_budget(resources, "100.00")
        assert result.within_budget is False
        assert CostGuard.to_diagnostic(result).status is InfraDiagnosticStatus.BLOCKED
        vc = guard.to_verification_context(
            resources,
            "100.00",
            formal_statement="Estimated monthly cost is within the approved budget",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True
        payload = vc.context.evidence.payload
        assert payload["developer_fields"]["within_budget"] is False
        assert payload["developer_fields"]["audit_trace"]["rule_id"] == "COST_BUDGET_EXCEEDED"

    def test_unknown_type_never_admissible(self):
        guard = CostGuard()
        resources = self._unknown_type_resources()
        result = guard.verify_budget(resources, "100.00")
        assert result.has_unknown_types is True
        vc = guard.to_verification_context(
            resources,
            "100.00",
            formal_statement="Estimated monthly cost is within the approved budget",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        payload = vc.context.evidence.payload
        assert payload["developer_fields"]["has_unknown_types"] is True
        assert payload["developer_fields"]["audit_trace"]["rule_id"] == "COST_UNKNOWN_RESOURCE"

    def test_invalid_budget_input_never_admissible(self):
        guard = CostGuard()
        vc = guard.to_verification_context(
            self._within_budget_resources(),
            "not-a-number",
            formal_statement="Estimated monthly cost is within the approved budget",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True
        payload = vc.context.evidence.payload
        assert payload["developer_fields"]["within_budget"] is False
        assert payload["developer_fields"]["audit_trace"]["outcome"] == "INVALID_INPUT"

    @pytest.mark.parametrize(
        "resources",
        [
            {"instances": [None]},
            {"instances": None},
            "not-a-dict",
        ],
    )
    def test_malformed_resources_blocked(self, resources):
        guard = CostGuard()
        vc = guard.to_verification_context(
            resources,
            "100.00",
            formal_statement="Estimated monthly cost is within the approved budget",
            attestation_token=self._attestation_token(),
        )
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        assert is_valid_document(vc.to_dict()) is True

    def test_evidence_preserves_diagnostic_fields(self):
        guard = CostGuard()
        resources = self._within_budget_resources()
        vc = guard.to_verification_context(
            resources,
            "100.00",
            formal_statement="Estimated monthly cost is within the approved budget",
            attestation_token=self._attestation_token(),
        )
        payload = vc.context.evidence.payload
        assert payload["developer_fields"]["constraint_id"] == "cost_guard.verify_budget"
        assert payload["developer_fields"]["within_budget"] is True
        assert payload["developer_fields"]["total_monthly_cost"] == "30.37"
        assert payload["developer_fields"]["budget"] == "100.00"
        assert payload["developer_fields"]["audit_trace"]["rule_id"] == "COST_WITHIN_BUDGET"

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

        guard = CostGuard()
        resources = self._within_budget_resources()
        attestation_token = self._attestation_token()
        with pytest.raises(VerificationContextValidationError):
            guard.to_verification_context(
                resources,
                "100.00",
                formal_statement=formal_statement,
                attestation_token=attestation_token,
            )


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
