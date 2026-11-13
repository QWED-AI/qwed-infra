"""
Comprehensive IAM Guard tests for SonarCloud 80%+ coverage.
Tests all class methods using Z3 satisfiability assertions where appropriate.
"""
import pytest
from z3 import Solver, sat, unsat
from qwed_infra.guards._iam_matching import (
    CannotEvaluate,
    MatchContext,
    evaluate_condition,
    evaluate_entry,
    match_action,
    wildcard_match,
)
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
# wildcard matching — tested via Z3 sat/unsat
# ------------------------------------------------------------------

class TestMatchPattern:
    def test_wildcard_star_always_matches(self):
        assert wildcard_match("anything", "*") is True

    def test_prefix_wildcard_matches(self):
        assert _solve(wildcard_match("s3:GetObject", "s3:*"))

    def test_prefix_wildcard_no_match(self):
        assert _solve_unsat(wildcard_match("ec2:StartInstances", "s3:*"))

    def test_suffix_wildcard_matches(self):
        assert _solve(wildcard_match("prod-bucket", "*-bucket"))

    def test_suffix_wildcard_no_match(self):
        assert _solve_unsat(wildcard_match("prod-table", "*-bucket"))

    def test_exact_match(self):
        assert _solve(wildcard_match("s3:GetObject", "s3:GetObject"))

    def test_exact_no_match(self):
        assert _solve_unsat(wildcard_match("s3:PutObject", "s3:GetObject"))

    def test_interior_wildcard(self):
        assert _solve(wildcard_match("s3:GetObject", "s3:*Object"))

    def test_interior_wildcard_no_match(self):
        assert _solve_unsat(wildcard_match("s3:CreateBucket", "s3:*Object"))

    def test_question_mark_is_one_character(self):
        assert _solve(wildcard_match("bucket1", "bucket?"))
        assert _solve_unsat(wildcard_match("bucket", "bucket?"))
        assert _solve_unsat(wildcard_match("bucket12", "bucket?"))

    def test_star_matches_non_ascii(self):
        assert _solve(wildcard_match("b/ключ", "b/*"))
        assert _solve(wildcard_match("b/\U0001F600", "b/?"))

    def test_action_match_ignores_case(self):
        assert _solve(match_action("s3:GetObject", "S3:getobject"))


# ------------------------------------------------------------------
# Non-octet CIDR regression tests (/12, /20 edge cases)
# ------------------------------------------------------------------

def _ev(operator, ctx_val, required):
    """Evaluate one condition entry on key "k" (absent when ctx_val is None)."""
    context = {} if ctx_val is None else {"k": ctx_val}
    return evaluate_entry(operator, "k", required, MatchContext(context, variables=False))


class TestNonOctetCidr:
    """Regression tests for CIDR masks not divisible by 8 (e.g. /12, /20)."""

    def test_ip_address_slash12_in_range(self):
        assert _solve(_ev("IpAddress", "10.5.1.1", "10.0.0.0/12"))

    def test_ip_address_slash12_out_of_range(self):
        assert _solve_unsat(_ev("IpAddress", "10.200.1.1", "10.0.0.0/12"))

    def test_ip_address_slash20_in_range(self):
        assert _solve(_ev("IpAddress", "10.0.17.5", "10.0.16.0/20"))

    def test_invalid_ip_cannot_be_evaluated(self):
        with pytest.raises(CannotEvaluate):
            _ev("IpAddress", "not-an-ip", "10.0.0.0/8")

    def test_not_ip_address_slash12_outside_allowed(self):
        assert _solve(_ev("NotIpAddress", "10.200.1.1", "10.0.0.0/12"))

    def test_not_ip_address_slash12_inside_denied(self):
        assert _solve_unsat(_ev("NotIpAddress", "10.5.1.1", "10.0.0.0/12"))


# ------------------------------------------------------------------
# condition operators
# ------------------------------------------------------------------

class TestApplyOperators:
    def test_string_equals_match(self):
        assert _solve(_ev("StringEquals", "hello", "hello"))

    def test_string_equals_absent_key_is_false(self):
        assert _ev("StringEquals", None, "hello") is False

    def test_string_equals_mismatch(self):
        assert _solve_unsat(_ev("StringEquals", "world", "hello"))

    def test_string_like_prefix_match(self):
        assert _solve(_ev("StringLike", "jdoe-admin", "jdoe-*"))

    def test_string_like_no_match(self):
        assert _solve_unsat(_ev("StringLike", "alice", "jdoe-*"))

    def test_string_like_absent_key_is_false(self):
        assert _ev("StringLike", None, "jdoe-*") is False

    def test_ip_address_cidr(self):
        assert _solve(_ev("IpAddress", "192.168.1.55", "192.168.1.0/24"))

    def test_ip_address_out_of_range(self):
        assert _solve_unsat(_ev("IpAddress", "10.0.0.1", "192.168.1.0/24"))

    def test_ip_address_exact(self):
        assert _solve(_ev("IpAddress", "10.0.0.1", "10.0.0.1"))

    def test_ip_address_absent_key_is_false(self):
        assert _ev("IpAddress", None, "10.0.0.0/8") is False

    def test_not_ip_address_outside_range(self):
        assert _solve(_ev("NotIpAddress", "192.168.1.1", "10.0.0.0/8"))

    def test_not_ip_address_inside_range_denied(self):
        assert _solve_unsat(_ev("NotIpAddress", "10.0.5.1", "10.0.0.0/8"))

    def test_not_ip_address_absent_key_is_true(self):
        # AWS: a negated operator is true when the key is absent.
        assert _ev("NotIpAddress", None, "10.0.0.1") is True


class TestEvaluateOperator:
    def test_string_equals_dispatch(self):
        assert _solve(_ev("StringEquals", "foo", "foo"))

    def test_string_like_dispatch(self):
        assert _solve(_ev("StringLike", "s3:GetObject", "s3:*"))

    def test_ip_address_dispatch(self):
        assert _solve(_ev("IpAddress", "10.0.0.5", "10.0.0.0/8"))

    def test_not_ip_address_dispatch(self):
        assert _solve(_ev("NotIpAddress", "1.2.3.4", "5.0.0.0/8"))

    def test_date_less_than_satisfied(self):
        assert _solve(_ev("DateLessThan", "2025-01-01T00:00:00Z", "2026-01-01T00:00:00Z"))

    def test_date_less_than_fails(self):
        assert _ev("DateLessThan", "2027-01-01T00:00:00Z", "2026-01-01T00:00:00Z") is False

    def test_date_time_without_zone_cannot_be_evaluated(self):
        with pytest.raises(CannotEvaluate):
            _ev("DateLessThan", "2025-01-01T00:00:00", "2026-01-01T00:00:00+00:00")

    def test_malformed_date_cannot_be_evaluated(self):
        with pytest.raises(CannotEvaluate):
            _ev("DateLessThan", "not-a-date", "2026-01-01T00:00:00Z")

    def test_unknown_operator_cannot_be_evaluated(self):
        with pytest.raises(CannotEvaluate):
            _ev("SomeUnknownOp", "val", "req")


# ------------------------------------------------------------------
# evaluate_condition
# ------------------------------------------------------------------

class TestEvaluateCondition:
    def test_empty_condition_returns_true(self):
        assert evaluate_condition({}, MatchContext({}, variables=False)) is True

    def test_string_equals_condition_match(self):
        block = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
        ctx = MatchContext({"aws:RequestedRegion": "us-east-1"}, variables=False)
        assert _solve(evaluate_condition(block, ctx))

    def test_missing_context_key_returns_false(self):
        block = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
        assert evaluate_condition(block, MatchContext({}, variables=False)) is False


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
