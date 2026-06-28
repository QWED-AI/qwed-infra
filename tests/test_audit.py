import pytest
from qwed_infra.audit import (
    COST_BUDGET_EXCEEDED,
    COST_UNKNOWN_RESOURCE,
    COST_WITHIN_BUDGET,
    IAM_DATE_CONDITION,
    IAM_DENY_PRECEDENCE,
    IAM_IP_CONDITION,
    IAM_STRING_CONDITION,
    IAM_UNKNOWN_OPERATOR,
    IAM_WILDCARD_MATCH,
    NETWORK_INVALID_INTERNAL,
    NETWORK_NO_ROUTE,
    NETWORK_REACHABILITY,
    NETWORK_SG_INGRESS,
    NETWORK_UNKNOWN_DEST,
    RuleRef,
    build_trace,
    trace_proof_ref,
)


class TestRuleRef:
    def test_frozen(self):
        r = RuleRef("TEST", "Test Statute")
        with pytest.raises(AttributeError):
            r.rule_id = "CHANGED"

    def test_default_jurisdiction(self):
        r = RuleRef("TEST", "Test Statute")
        assert r.jurisdiction == "GENERIC"

    def test_custom_jurisdiction(self):
        r = RuleRef("TEST", "Test Statute", jurisdiction="US")
        assert r.jurisdiction == "US"


class TestRuleRefConstants:
    def test_iam_constants_have_ids(self):
        for ref in [
            IAM_DENY_PRECEDENCE,
            IAM_WILDCARD_MATCH,
            IAM_IP_CONDITION,
            IAM_DATE_CONDITION,
            IAM_STRING_CONDITION,
            IAM_UNKNOWN_OPERATOR,
        ]:
            assert ref.rule_id.startswith("IAM_")

    def test_network_constants_have_ids(self):
        for ref in [
            NETWORK_SG_INGRESS,
            NETWORK_REACHABILITY,
            NETWORK_NO_ROUTE,
            NETWORK_INVALID_INTERNAL,
            NETWORK_UNKNOWN_DEST,
        ]:
            assert ref.rule_id.startswith("NETWORK_")

    def test_cost_constants_have_ids(self):
        for ref in [
            COST_BUDGET_EXCEEDED,
            COST_UNKNOWN_RESOURCE,
            COST_WITHIN_BUDGET,
        ]:
            assert ref.rule_id.startswith("COST_")


class TestBuildTrace:
    def test_basic_trace(self):
        trace = build_trace(IAM_DENY_PRECEDENCE, "DENIED")
        assert trace["rule_id"] == "IAM_DENY_PRECEDENCE"
        assert trace["outcome"] == "DENIED"
        assert trace["inputs"] == {}

    def test_trace_with_inputs(self):
        trace = build_trace(IAM_DENY_PRECEDENCE, "DENIED", {"action": "s3:GetObject"})
        assert trace["inputs"] == {"action": "s3:GetObject"}

    def test_inputs_copy(self):
        original = {"key": "value"}
        trace = build_trace(IAM_DENY_PRECEDENCE, "DENIED", original)
        original["key"] = "changed"
        assert trace["inputs"]["key"] == "value"


class TestTraceProofRef:
    def test_deterministic_hash(self):
        trace = build_trace(IAM_DENY_PRECEDENCE, "DENIED")
        h1 = trace_proof_ref(trace)
        h2 = trace_proof_ref(trace)
        assert h1 == h2
        assert h1.startswith("sha256:")

    def test_different_trace_different_hash(self):
        t1 = build_trace(IAM_DENY_PRECEDENCE, "DENIED")
        t2 = build_trace(IAM_WILDCARD_MATCH, "ALLOWED")
        assert trace_proof_ref(t1) != trace_proof_ref(t2)

    def test_non_json_serializable_raises(self):
        with pytest.raises(ValueError, match="JSON-serializable"):
            trace_proof_ref({"bad": object()})
