"""IamGuard refuses what it does not model and what is too large to check
in bounded time, and keeps host detail out of its evidence (#67, #76, #87)."""

import json
import time

import pytest
from z3 import unknown

from qwed_infra.guards import iam_guard as iam_module
from qwed_infra.guards.iam_guard import IamGuard

ALLOW_ALL = {"Effect": "Allow", "Action": "*", "Resource": "*"}


@pytest.fixture
def guard():
    return IamGuard()


def assert_unverifiable(result):
    assert result.verified is False
    assert result.allowed is False
    diagnostic = IamGuard.to_diagnostic(result)
    assert diagnostic.status.value == "UNVERIFIABLE"


# ----------------------------------------------------------------------
# #67: NotAction / NotResource / NotPrincipal
# ----------------------------------------------------------------------

@pytest.mark.parametrize("statement", [
    {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
    {"Effect": "Allow", "Action": "*", "NotResource": "arn:aws:s3:::audit/*"},
    {"Effect": "Allow", "Action": "s3:*", "Resource": "*", "NotPrincipal": {"AWS": "arn:aws:iam::1:root"}},
])
def test_unmodelled_allow_elements_are_unverifiable(guard, statement):
    # Near-admin NotAction Allow used to model as matching nothing.
    result = guard.verify_access({"Statement": [statement]}, "ec2:RunInstances", "*")
    assert_unverifiable(result)
    assert "not modelled" in result.error


def test_notaction_near_admin_is_not_least_privilege_compliant(guard):
    policy = {"Statement": [{"Effect": "Allow", "NotAction": "s3:GetObject", "Resource": "*"}]}
    assert_unverifiable(guard.verify_least_privilege(policy))


@pytest.mark.parametrize("statement", [
    {"Effect": "Deny", "NotAction": "s3:GetObject", "Resource": "*"},
    {"Effect": "Deny", "Action": "*", "NotResource": "arn:aws:s3:::public/*"},
])
def test_unmodelled_deny_elements_are_not_dropped(guard, statement):
    # The Deny would block this request in AWS. It used to vanish, giving
    # a proven allow.
    policy = {"Statement": [ALLOW_ALL, statement]}
    result = guard.verify_access(policy, "s3:PutObject", "arn:aws:s3:::secret/k")
    assert_unverifiable(result)


@pytest.mark.parametrize("statement", [
    {"Effect": "Deny", "Resource": "*"},
    {"Effect": "Deny", "Action": "s3:*"},
])
def test_statement_missing_action_or_resource_is_unverifiable(guard, statement):
    result = guard.verify_access({"Statement": [ALLOW_ALL, statement]}, "s3:GetObject", "arn:aws:s3:::b/k")
    assert_unverifiable(result)
    assert "has no" in result.error


@pytest.mark.parametrize("principal", [
    {"AWS": "arn:aws:iam::111122223333:root"},
    {"Service": "lambda.amazonaws.com"},
    "arn:aws:iam::111122223333:root",
    {"AWS": ["*", "arn:aws:iam::1:root"]},
])
def test_restricted_principal_is_unverifiable(guard, principal):
    statement = {"Effect": "Allow", "Principal": principal, "Action": "s3:GetObject", "Resource": "*"}
    assert_unverifiable(guard.verify_access({"Statement": [statement]}, "s3:GetObject", "arn:aws:s3:::b/k"))


@pytest.mark.parametrize("principal", ["*", {"AWS": "*"}])
def test_unrestricted_principal_is_modelled(guard, principal):
    statement = {"Effect": "Allow", "Principal": principal, "Action": "s3:GetObject", "Resource": "*"}
    result = guard.verify_access({"Statement": [statement]}, "s3:GetObject", "arn:aws:s3:::b/k")
    assert result.verified is True
    assert result.allowed is True


@pytest.mark.parametrize("policy", [{}, {"Version": "2012-10-17"}])
def test_policy_without_statement_is_unverifiable(guard, policy):
    assert_unverifiable(guard.verify_access(policy, "s3:GetObject", "*"))


def test_single_object_statement_is_accepted(guard):
    deny = {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}
    policy = {"Statement": deny}
    result = guard.verify_access(policy, "s3:GetObject", "arn:aws:s3:::b/k")
    assert result.verified is True
    assert result.allowed is False
    allow = guard.verify_access({"Statement": ALLOW_ALL}, "s3:GetObject", "arn:aws:s3:::b/k")
    assert allow.verified is True
    assert allow.allowed is True
    assert policy == {"Statement": deny}


def test_vc_document_for_notaction_is_not_admitted(guard):
    policy = {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}
    doc = guard.to_verification_context(
        policy, "ec2:RunInstances", "*", formal_statement="policy allows ec2:RunInstances"
    ).to_dict()
    assert doc["context"]["decision"]["admission"] != "ADMIT"


# ----------------------------------------------------------------------
# #76: input bounds, flat expressions, unknown is not denied
# ----------------------------------------------------------------------

def test_large_pattern_list_finishes_quickly(guard):
    # 1,000 patterns took minutes before the request values were built
    # into the policy logic directly.
    policy = {"Statement": [{"Effect": "Allow", "Action": [f"s3:A{i}*" for i in range(1000)], "Resource": "*"}]}
    start = time.monotonic()
    result = guard.verify_access(policy, "s3:GetObject", "arn:aws:s3:::b/k")
    assert time.monotonic() - start < 30
    assert result.verified is True
    assert result.allowed is False


def test_matching_pattern_last_in_large_list_is_found(guard):
    actions = [f"s3:A{i}*" for i in range(999)] + ["s3:Get*"]
    policy = {"Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
    result = guard.verify_access(policy, "s3:GetObject", "arn:aws:s3:::b/k")
    assert result.verified is True
    assert result.allowed is True


def test_many_statements_keep_deny_precedence(guard):
    denies = [{"Effect": "Deny", "Action": f"s3:Put{i}*", "Resource": "*"} for i in range(998)]
    denies.append({"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"})
    policy = {"Statement": [ALLOW_ALL, *denies]}
    denied = guard.verify_access(policy, "s3:GetObject", "arn:aws:s3:::b/k")
    assert denied.verified is True
    assert denied.allowed is False
    allowed = guard.verify_access(policy, "s3:GetObject", "arn:aws:s3:::c/k")
    assert allowed.verified is True
    assert allowed.allowed is True


@pytest.mark.parametrize("policy,request_", [
    ({"Statement": [ALLOW_ALL] * (iam_module.MAX_STATEMENTS + 1)}, None),
    ({"Statement": [{"Effect": "Allow", "Action": ["s3:A"] * (iam_module.MAX_PATTERNS_PER_ELEMENT + 1), "Resource": "*"}]}, None),
    ({"Statement": [{"Effect": "Allow", "Action": ["s3:A"] * 1000, "Resource": ["r"] * 1000}] * 2}, None),
    ({"Statement": [{"Effect": "Allow", "Action": "s3:" + "a" * iam_module.MAX_PATTERN_LENGTH, "Resource": "*"}]}, None),
    ({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "a*" * (iam_module.MAX_WILDCARDS_PER_PATTERN + 1)}]}, None),
    ({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*",
                     "Condition": {"StringEquals": {f"k{i}": "v" for i in range(101)}}}]}, None),
    ({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*",
                     "Condition": {"StringEquals": {f"k{i}": "v" for i in range(100)}}}] * 11}, None),
    ({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*",
                     "Condition": {"StringLike": {"aws:userid": "a*" * 65}}}]}, None),
    ({"Statement": [ALLOW_ALL]}, ("s3:" + "a" * iam_module.MAX_REQUEST_LENGTH, "*")),
    ({"Statement": [ALLOW_ALL]}, (42, "*")),
    ({"Statement": {"Effect": "Allow"}}, None),
    ([ALLOW_ALL], None),
])
def test_over_bound_inputs_are_unverifiable(guard, policy, request_):
    action, resource = request_ or ("s3:GetObject", "arn:aws:s3:::b/k")
    start = time.monotonic()
    result = guard.verify_access(policy, action, resource)
    assert time.monotonic() - start < 5
    assert_unverifiable(result)


@pytest.mark.parametrize("context", [
    {"aws:userid": "a" * (iam_module.MAX_REQUEST_LENGTH + 1)},
    {"k" * (iam_module.MAX_REQUEST_LENGTH + 1): "v"},
    {f"k{i}": "v" for i in range(iam_module.MAX_CONTEXT_ENTRIES + 1)},
    {"aws:TagKeys": ["t"] * (iam_module.MAX_LIST_VALUE_ENTRIES + 1)},
    {"aws:TagKeys": ["a" * (iam_module.MAX_REQUEST_LENGTH + 1)]},
    {"aws:TagKeys": [["nested"]]},
    {"aws:userid": {"nested": "mapping"}},
])
def test_over_bound_context_is_unverifiable(guard, context):
    result = guard.verify_access({"Statement": [ALLOW_ALL]}, "s3:GetObject", "*", context)
    assert_unverifiable(result)


@pytest.mark.parametrize("value", [
    ["10.0.0.0/8"] * (iam_module.MAX_LIST_VALUE_ENTRIES + 1),
    ["a" * (iam_module.MAX_PATTERN_LENGTH + 1)],
    ["a*" * (iam_module.MAX_WILDCARDS_PER_PATTERN + 1)],
    {"nested": "mapping"},
])
def test_over_bound_list_condition_value_is_unverifiable(guard, value):
    policy = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*",
                             "Condition": {"StringLike": {"aws:userid": value}}}]}
    start = time.monotonic()
    result = guard.verify_access(policy, "s3:GetObject", "*", {"aws:userid": "x"})
    assert time.monotonic() - start < 5
    assert_unverifiable(result)


@pytest.mark.parametrize("condition,context", [
    ({"StringEquals": {1: "alice"}}, {1: "alice"}),
    ({"StringEquals": {"aws:userid": "alice"}}, {1: "alice", "aws:userid": "alice"}),
    ({1: {"aws:userid": "alice"}}, {"aws:userid": "alice"}),
    ({"S" * (iam_module.MAX_REQUEST_LENGTH + 1): {"aws:userid": "alice"}}, {"aws:userid": "alice"}),
])
def test_non_string_or_oversized_keys_are_unverifiable(guard, condition, context):
    policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": condition}]}
    assert_unverifiable(guard.verify_access(policy, "s3:GetObject", "*", context))


def test_context_within_bounds_still_evaluates(guard):
    policy = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*",
                             "Condition": {"StringEquals": {"aws:userid": "alice"}}}]}
    context = {"aws:userid": "alice", "aws:TagKeys": ["a", "b"], "aws:MultiFactorAuthAge": 30}
    result = guard.verify_access(policy, "s3:GetObject", "*", context)
    assert result.verified is True
    assert result.allowed is True


def test_bounds_are_inclusive(guard):
    pattern = "s3:" + "a" * (iam_module.MAX_PATTERN_LENGTH - 4) + "*"
    assert len(pattern) == iam_module.MAX_PATTERN_LENGTH
    policy = {"Statement": [{"Effect": "Allow", "Action": pattern, "Resource": "*"}]}
    assert guard.verify_access(policy, "s3:GetObject", "*").verified is True


def test_solver_unknown_is_not_a_proven_denial(guard, monkeypatch):
    monkeypatch.setattr(guard.solver, "check", lambda *a, **k: unknown)
    result = guard.verify_access({"Statement": [ALLOW_ALL]}, "s3:GetObject", "*")
    assert_unverifiable(result)
    assert result.error == "Z3 returned unknown"


# ----------------------------------------------------------------------
# #87: no traceback or host paths in evidence
# ----------------------------------------------------------------------

def test_unexpected_exception_records_type_only(guard):
    # An exception the guard did not raise itself: its message may carry
    # host detail, so only the type is recorded.
    class Exploding(dict):
        def get(self, key, default=None):
            if key == "Effect":
                raise RuntimeError("C:\\secret\\path\\module.py line 12")
            return super().get(key, default)

    statement = Exploding(Action="s3:*", Resource="*")
    result = guard.verify_access({"Statement": [statement]}, "s3:GetObject", "*")
    assert result.verified is False
    assert result.error == "RuntimeError"


@pytest.mark.parametrize("policy", [{"Statement": 42}, {"Statement": [42]}, "not a policy"])
def test_vc_evidence_carries_no_traceback(guard, policy):
    doc = guard.to_verification_context(
        policy, "s3:GetObject", "arn:aws:s3:::b/k", formal_statement="access is allowed"
    ).to_dict()
    text = json.dumps(doc)
    assert "Traceback" not in text
    assert ".py" not in text
    assert doc["context"]["decision"]["admission"] != "ADMIT"
