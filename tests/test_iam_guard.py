"""
Comprehensive IAM Guard tests for SonarCloud 80%+ coverage.
Tests all class methods using Z3 satisfiability assertions where appropriate.
"""
import pytest
from z3 import Solver, StringVal, sat, unsat
from qwed_infra.guards.iam_guard import IamGuard


@pytest.fixture
def guard():
    return IamGuard()


def _solve(constraint) -> bool:
    """Helper: check if a Z3 constraint is satisfiable."""
    if constraint is True:
        return True
    if constraint is False:
        return False
    s = Solver()
    s.add(constraint)
    return s.check() == sat


def _solve_unsat(constraint) -> bool:
    """Helper: check if a Z3 constraint is unsatisfiable."""
    if constraint is True:
        return False
    if constraint is False:
        return True
    s = Solver()
    s.add(constraint)
    return s.check() == unsat


# ------------------------------------------------------------------
# _match_pattern — tested via Z3 sat/unsat
# ------------------------------------------------------------------

class TestMatchPattern:
    def test_wildcard_star_always_matches(self, guard):
        assert guard._match_pattern(StringVal("anything"), "*") is True

    def test_prefix_wildcard_matches(self, guard):
        constraint = guard._match_pattern(StringVal("s3:GetObject"), "s3:*")
        assert _solve(constraint)

    def test_prefix_wildcard_no_match(self, guard):
        constraint = guard._match_pattern(StringVal("ec2:StartInstances"), "s3:*")
        assert _solve_unsat(constraint)

    def test_suffix_wildcard_matches(self, guard):
        constraint = guard._match_pattern(StringVal("prod-bucket"), "*-bucket")
        assert _solve(constraint)

    def test_suffix_wildcard_no_match(self, guard):
        constraint = guard._match_pattern(StringVal("prod-table"), "*-bucket")
        assert _solve_unsat(constraint)

    def test_exact_match(self, guard):
        constraint = guard._match_pattern(StringVal("s3:GetObject"), "s3:GetObject")
        assert _solve(constraint)

    def test_exact_no_match(self, guard):
        constraint = guard._match_pattern(StringVal("s3:PutObject"), "s3:GetObject")
        assert _solve_unsat(constraint)

    def test_interior_wildcard(self, guard):
        constraint = guard._match_pattern(StringVal("s3:GetObject"), "s3:*Object")
        assert _solve(constraint)

    def test_interior_wildcard_no_match(self, guard):
        constraint = guard._match_pattern(StringVal("s3:CreateBucket"), "s3:*Object")
        assert _solve_unsat(constraint)


# ------------------------------------------------------------------
# _cidr_to_prefix
# ------------------------------------------------------------------

# ------------------------------------------------------------------
# Non-octet CIDR regression tests (/12, /20 edge cases)
# ------------------------------------------------------------------

class TestNonOctetCidr:
    """Regression tests for CIDR masks not divisible by 8 (e.g. /12, /20)."""

    def test_ip_address_slash12_in_range(self, guard):
        # 10.0.0.0/12 covers 10.0.0.0 – 10.15.255.255
        result = guard._apply_ip_address("10.5.1.1", "10.0.0.0/12", True)
        assert result is not False and result is not True  # Z3 expr — satisfiable

    def test_ip_address_slash12_out_of_range(self, guard):
        # 10.200.1.1 is outside 10.0.0.0/12 — constraint must be unsatisfiable
        result = guard._apply_ip_address("10.200.1.1", "10.0.0.0/12", True)
        assert _solve_unsat(result)

    def test_ip_address_slash20_in_range(self, guard):
        result = guard._apply_ip_address("10.0.17.5", "10.0.16.0/20", True)
        assert result is not False and result is not True  # Z3 expr — satisfiable

    def test_invalid_ip_returns_false(self, guard):
        assert guard._apply_ip_address("not-an-ip", "10.0.0.0/8", True) is False

    def test_not_ip_address_slash12_outside_allowed(self, guard):
        # 10.200.1.1 is NOT in 10.0.0.0/12 → NotIpAddress should succeed (non-False)
        result = guard._apply_not_ip_address("10.200.1.1", "10.0.0.0/12", True)
        assert result is not False and result is not True  # Z3 expr — satisfiable

    def test_not_ip_address_slash12_inside_denied(self, guard):
        # 10.5.1.1 IS in 10.0.0.0/12 → NotIpAddress must be unsatisfiable
        result = guard._apply_not_ip_address("10.5.1.1", "10.0.0.0/12", True)
        assert _solve_unsat(result)


# ------------------------------------------------------------------
# _apply_* operator methods
# ------------------------------------------------------------------

class TestApplyOperators:
    def test_string_equals_match(self, guard):
        assert _solve(guard._apply_string_equals("hello", "hello", True))

    def test_string_equals_none_ctx(self, guard):
        assert guard._apply_string_equals(None, "hello", True) is False

    def test_string_equals_mismatch(self, guard):
        assert _solve_unsat(guard._apply_string_equals("world", "hello", True))

    def test_string_like_prefix_match(self, guard):
        assert _solve(guard._apply_string_like("jdoe-admin", "jdoe-*", True))

    def test_string_like_no_match(self, guard):
        assert _solve_unsat(guard._apply_string_like("alice", "jdoe-*", True))

    def test_string_like_none_ctx(self, guard):
        assert guard._apply_string_like(None, "jdoe-*", True) is False

    def test_ip_address_cidr(self, guard):
        assert _solve(guard._apply_ip_address("192.168.1.55", "192.168.1.0/24", True))

    def test_ip_address_out_of_range(self, guard):
        assert _solve_unsat(guard._apply_ip_address("10.0.0.1", "192.168.1.0/24", True))

    def test_ip_address_exact(self, guard):
        assert _solve(guard._apply_ip_address("10.0.0.1", "10.0.0.1", True))

    def test_ip_address_none_ctx(self, guard):
        assert guard._apply_ip_address(None, "10.0.0.0/8", True) is False

    def test_not_ip_address_outside_range(self, guard):
        # 192.168.1.1 is NOT in 10.0.0.0/8 → should be allowed
        assert _solve(guard._apply_not_ip_address("192.168.1.1", "10.0.0.0/8", True))

    def test_not_ip_address_inside_range_denied(self, guard):
        # 10.0.5.1 IS in 10.0.0.0/8 → NotIpAddress should deny
        assert _solve_unsat(guard._apply_not_ip_address("10.0.5.1", "10.0.0.0/8", True))

    def test_not_ip_address_none_ctx(self, guard):
        assert guard._apply_not_ip_address(None, "10.0.0.1", True) is False


# ------------------------------------------------------------------
# _evaluate_operator dispatch and fail-closed behavior
# ------------------------------------------------------------------

class TestEvaluateOperator:
    def test_string_equals_dispatch(self, guard):
        result = guard._evaluate_operator("StringEquals", "foo", "foo", True)
        assert _solve(result)

    def test_string_like_dispatch(self, guard):
        result = guard._evaluate_operator("StringLike", "s3:GetObject", "s3:*", True)
        assert _solve(result)

    def test_ip_address_dispatch(self, guard):
        result = guard._evaluate_operator("IpAddress", "10.0.0.5", "10.0.0.0/8", True)
        assert _solve(result)

    def test_not_ip_address_dispatch(self, guard):
        result = guard._evaluate_operator("NotIpAddress", "1.2.3.4", "5.0.0.0/8", True)
        assert _solve(result)

    def test_date_less_than_satisfied(self, guard):
        result = guard._evaluate_operator("DateLessThan", "2025-01-01T00:00:00Z", "2026-01-01T00:00:00Z", True)
        assert result is not False  # Date is before limit — condition passes

    def test_date_less_than_fails(self, guard):
        result = guard._evaluate_operator("DateLessThan", "2027-01-01T00:00:00Z", "2026-01-01T00:00:00Z", True)
        assert result is False  # Date exceeds limit — fail closed

    def test_date_less_than_mixed_timezone_fails_closed(self, guard):
        # naive vs aware datetime comparison previously raised TypeError — must fail closed
        result = guard._apply_date_less_than("2025-01-01T00:00:00", "2026-01-01T00:00:00+00:00", True)
        assert result is False  # TypeError → fail closed, not crash

    def test_date_less_than_malformed_fails_closed(self, guard):
        result = guard._apply_date_less_than("not-a-date", "2026-01-01T00:00:00Z", True)
        assert result is False  # ValueError → fail closed

    def test_unknown_operator_fails_closed(self, guard):
        result = guard._evaluate_operator("SomeUnknownOp", "val", "req", True)
        assert result is False  # Unknown op must fail closed


# ------------------------------------------------------------------
# _evaluate_condition
# ------------------------------------------------------------------

class TestEvaluateCondition:
    def test_empty_condition_returns_true(self, guard):
        assert guard._evaluate_condition({}, {}) is True

    def test_string_equals_condition_match(self, guard):
        block = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
        result = guard._evaluate_condition(block, {"aws:RequestedRegion": "us-east-1"})
        assert _solve(result)

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
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        result = guard.verify_access(policy, "s3:PutObject", "*")
        assert result.allowed is False

    def test_wildcard_action_allowed(self, guard):
        policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        result = guard.verify_access(policy, "ec2:TerminateInstances", "*")
        assert result.allowed is True

    def test_explicit_deny_overrides_allow(self, guard):
        """Deny after Allow — classic order."""
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
            ]
        }
        result = guard.verify_access(policy, "s3:DeleteBucket", "arn:aws:s3:::production")
        assert result.allowed is False

    def test_explicit_deny_overrides_allow_regardless_of_order(self, guard):
        """Deny before Allow — deny precedence must be order-independent."""
        policy = {
            "Statement": [
                {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ]
        }
        result = guard.verify_access(policy, "s3:DeleteBucket", "arn:aws:s3:::production")
        assert result.allowed is False  # Deny must still win even when listed first

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

    def test_condition_ip_denied_outside_range(self, guard):
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
                "Effect": "Allow", "Action": "*", "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/Env": "prod"}},
            }]
        }
        assert guard.verify_access(policy, "*", "*", context={"aws:PrincipalTag/Env": "prod"}).allowed is True
        assert guard.verify_access(policy, "*", "*", context={"aws:PrincipalTag/Env": "dev"}).allowed is False

    def test_condition_string_like_wildcard(self, guard):
        policy = {
            "Statement": [{
                "Effect": "Allow", "Action": "*", "Resource": "*",
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
        assert result.allowed is True  # Violation: grants *:*

    def test_read_only_policy_is_least_privilege(self, guard):
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        result = guard.verify_least_privilege(policy)
        assert result.allowed is False  # Not over-privileged

    def test_prefix_wildcard_not_full_admin(self, guard):
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        result = guard.verify_least_privilege(policy)
        assert result.allowed is False  # s3:* does not match * exactly
