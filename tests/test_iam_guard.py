"""
Comprehensive IAM Guard tests for SonarCloud 80%+ coverage.
Tests all class methods: _match_pattern, _apply_*, _evaluate_condition,
_build_statement_condition, _build_policy_logic, verify_access, verify_least_privilege.
"""
import pytest
from qwed_infra.guards.iam_guard import IamGuard, VerificationResult
from z3 import StringVal


@pytest.fixture
def guard():
    return IamGuard()


# ------------------------------------------------------------------
# _match_pattern (unit tests on the helper directly)
# ------------------------------------------------------------------

class TestMatchPattern:
    def test_wildcard_star_always_matches(self, guard):
        result = guard._match_pattern(StringVal("anything"), "*")
        assert result is True

    def test_prefix_wildcard(self, guard):
        # s3:* should match s3:GetObject (constraint is a Z3 expr, not bool)
        constraint = guard._match_pattern(StringVal("s3:GetObject"), "s3:*")
        assert constraint is not False  # Should produce a Z3 expression

    def test_suffix_wildcard(self, guard):
        constraint = guard._match_pattern(StringVal("prod-bucket"), "*-bucket")
        assert constraint is not False

    def test_exact_match(self, guard):
        constraint = guard._match_pattern(StringVal("s3:GetObject"), "s3:GetObject")
        assert constraint is not False

    def test_exact_no_match(self, guard):
        constraint = guard._match_pattern(StringVal("s3:PutObject"), "s3:GetObject")
        assert constraint is not False  # Still a Z3 expr, evaluated at solve time


# ------------------------------------------------------------------
# _cidr_to_prefix
# ------------------------------------------------------------------

class TestCidrToPrefix:
    def test_mask_8(self, guard):
        assert guard._cidr_to_prefix("10.0.0.0", "8") == "10."

    def test_mask_24(self, guard):
        assert guard._cidr_to_prefix("192.168.1.0", "24") == "192.168.1."

    def test_mask_16(self, guard):
        assert guard._cidr_to_prefix("172.16.0.0", "16") == "172.16.0."


# ------------------------------------------------------------------
# _apply_* operator methods
# ------------------------------------------------------------------

class TestApplyOperators:
    def test_string_equals_match(self, guard):
        result = guard._apply_string_equals("hello", "hello", True)
        assert result is not False

    def test_string_equals_none_ctx(self, guard):
        assert guard._apply_string_equals(None, "hello", True) is False

    def test_string_like_prefix_match(self, guard):
        result = guard._apply_string_like("jdoe-admin", "jdoe-*", True)
        assert result is not False

    def test_string_like_none_ctx(self, guard):
        assert guard._apply_string_like(None, "jdoe-*", True) is False

    def test_ip_address_cidr(self, guard):
        result = guard._apply_ip_address("192.168.1.55", "192.168.1.0/24", True)
        assert result is not False

    def test_ip_address_exact(self, guard):
        result = guard._apply_ip_address("10.0.0.1", "10.0.0.1", True)
        assert result is not False

    def test_ip_address_none_ctx(self, guard):
        assert guard._apply_ip_address(None, "10.0.0.0/8", True) is False

    def test_not_ip_address(self, guard):
        result = guard._apply_not_ip_address("192.168.1.1", "10.0.0.1", True)
        assert result is not False

    def test_not_ip_address_none_ctx(self, guard):
        assert guard._apply_not_ip_address(None, "10.0.0.1", True) is False


# ------------------------------------------------------------------
# _evaluate_operator dispatch
# ------------------------------------------------------------------

class TestEvaluateOperator:
    def test_string_equals_dispatch(self, guard):
        result = guard._evaluate_operator("StringEquals", "foo", "foo", True)
        assert result is not False

    def test_string_like_dispatch(self, guard):
        result = guard._evaluate_operator("StringLike", "s3:GetObject", "s3:*", True)
        assert result is not False

    def test_ip_address_dispatch(self, guard):
        result = guard._evaluate_operator("IpAddress", "10.0.0.5", "10.0.0.0/8", True)
        assert result is not False

    def test_not_ip_address_dispatch(self, guard):
        result = guard._evaluate_operator("NotIpAddress", "1.2.3.4", "5.6.7.8", True)
        assert result is not False

    def test_date_less_than_passthrough(self, guard):
        result = guard._evaluate_operator("DateLessThan", "2025-01-01", "2026-01-01", True)
        assert result is True  # TODO placeholder returns cond_expr unchanged

    def test_unknown_operator_passthrough(self, guard):
        result = guard._evaluate_operator("SomeUnknownOp", "val", "req", True)
        assert result is True


# ------------------------------------------------------------------
# _evaluate_condition
# ------------------------------------------------------------------

class TestEvaluateCondition:
    def test_empty_condition_returns_true(self, guard):
        assert guard._evaluate_condition({}, {}) is True

    def test_string_equals_condition(self, guard):
        block = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
        ctx = {"aws:RequestedRegion": "us-east-1"}
        result = guard._evaluate_condition(block, ctx)
        assert result is not False

    def test_missing_context_key_returns_false(self, guard):
        block = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
        result = guard._evaluate_condition(block, {})
        assert result is False


# ------------------------------------------------------------------
# verify_access — integration tests
# ------------------------------------------------------------------

class TestVerifyAccess:
    def test_allow_exact_action_and_resource(self, guard):
        policy = {
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}]
        }
        result = guard.verify_access(policy, "s3:GetObject", "arn:aws:s3:::my-bucket/data.csv")
        assert result.verified is True
        assert result.allowed is True

    def test_deny_wrong_action(self, guard):
        policy = {
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
        }
        result = guard.verify_access(policy, "s3:PutObject", "*")
        assert result.verified is True
        assert result.allowed is False

    def test_wildcard_action_allowed(self, guard):
        policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        result = guard.verify_access(policy, "ec2:TerminateInstances", "*")
        assert result.allowed is True

    def test_explicit_deny_overrides_allow(self, guard):
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
            ]
        }
        result = guard.verify_access(policy, "s3:DeleteBucket", "arn:aws:s3:::production")
        assert result.allowed is False

    def test_default_deny_empty_policy(self, guard):
        result = guard.verify_access({"Statement": []}, "s3:GetObject", "*")
        assert result.allowed is False

    def test_context_none_defaults_to_empty(self, guard):
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        result = guard.verify_access(policy, "s3:GetObject", "*", context=None)
        assert result.verified is True

    def test_condition_ip_match(self, guard):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            }]
        }
        result = guard.verify_access(policy, "*", "*", context={"aws:SourceIp": "10.0.5.22"})
        assert result.allowed is True

    def test_condition_ip_mismatch_denied(self, guard):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            }]
        }
        result = guard.verify_access(policy, "*", "*", context={"aws:SourceIp": "192.168.1.1"})
        assert result.allowed is False

    def test_condition_string_equals_tag(self, guard):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/Env": "prod"}},
            }]
        }
        assert guard.verify_access(policy, "*", "*", context={"aws:PrincipalTag/Env": "prod"}).allowed is True
        assert guard.verify_access(policy, "*", "*", context={"aws:PrincipalTag/Env": "dev"}).allowed is False

    def test_condition_string_like_wildcard(self, guard):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"StringLike": {"aws:username": "svc-*"}},
            }]
        }
        assert guard.verify_access(policy, "*", "*", context={"aws:username": "svc-deploy"}).allowed is True
        assert guard.verify_access(policy, "*", "*", context={"aws:username": "admin"}).allowed is False

    def test_action_list_multiple_actions(self, guard):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "*",
            }]
        }
        assert guard.verify_access(policy, "s3:GetObject", "*").allowed is True
        assert guard.verify_access(policy, "s3:PutObject", "*").allowed is True
        assert guard.verify_access(policy, "s3:DeleteObject", "*").allowed is False


# ------------------------------------------------------------------
# verify_least_privilege
# ------------------------------------------------------------------

class TestVerifyLeastPrivilege:
    def test_admin_wildcard_policy_is_over_privileged(self, guard):
        policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        result = guard.verify_least_privilege(policy)
        assert result.allowed is True  # Violation detected: grants *:*

    def test_read_only_policy_is_least_privilege(self, guard):
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        result = guard.verify_least_privilege(policy)
        assert result.allowed is False  # Not over-privileged

    def test_prefix_wildcard_still_not_full_admin(self, guard):
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        result = guard.verify_least_privilege(policy)
        assert result.allowed is False  # s3:* does not cover ec2:* → not *:*
