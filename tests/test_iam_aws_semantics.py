"""IamGuard follows AWS matching and condition semantics, and never reads
"cannot evaluate" as "does not match".

Each case pairs a broad Allow with one Deny that AWS enforces for the
request. The guard must report the request denied, or UNVERIFIABLE; it must
never return a verified allow.
"""
import pytest

from qwed_infra.guards.iam_guard import IamGuard

ALLOW_ALL = {"Effect": "Allow", "Action": "*", "Resource": "*"}
ACTION = "s3:GetObject"
RESOURCE = "arn:aws:s3:::b/k"


def _check(deny, action=ACTION, resource=RESOURCE, context=None, version=None):
    policy = {"Statement": [ALLOW_ALL, deny]}
    if version:
        policy["Version"] = version
    return IamGuard().verify_access(policy, action, resource, context or {})


def _deny(condition=None, action="s3:*", resource="*"):
    stmt = {"Effect": "Deny", "Action": action, "Resource": resource}
    if condition is not None:
        stmt["Condition"] = condition
    return stmt


def _assert_denied(result):
    assert result.verified is True, result.error
    assert result.allowed is False


def _assert_unverifiable(result):
    assert result.verified is False
    assert result.allowed is False


# ----------------------------------------------------------------------
# Operators the guard implements: AWS deny and allow outcomes
# ----------------------------------------------------------------------

DENIED_CASES = [
    ("Bool", "aws:SecureTransport", "false", {"aws:SecureTransport": "false"}),
    ("Bool", "aws:SecureTransport", False, {"aws:SecureTransport": False}),
    ("StringNotEquals", "aws:PrincipalOrgID", "o-good", {"aws:PrincipalOrgID": "o-evil"}),
    ("StringNotEquals", "aws:RequestedRegion", ["eu-west-1", "eu-west-2"], {"aws:RequestedRegion": "us-east-1"}),
    ("StringEqualsIgnoreCase", "aws:RequestedRegion", "US-EAST-1", {"aws:RequestedRegion": "us-east-1"}),
    ("StringNotLike", "aws:userid", "AIDA*", {"aws:userid": "AROA123"}),
    ("ArnEquals", "aws:PrincipalArn", "arn:aws:iam::111122223333:role/bad", {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/bad"}),
    ("ArnLike", "aws:PrincipalArn", "arn:aws:iam::*:role/bad-*", {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/bad-1"}),
    ("ArnNotEquals", "aws:SourceArn", "arn:aws:sns:us-east-1:1:good", {"aws:SourceArn": "arn:aws:sns:us-east-1:1:evil"}),
    ("ArnNotLike", "aws:PrincipalArn", "arn:aws:iam::*:role/admin-*", {"aws:PrincipalArn": "arn:aws:iam::1:role/dev"}),
    ("NumericGreaterThan", "s3:max-keys", "10", {"s3:max-keys": "100"}),
    ("NumericLessThanEquals", "s3:max-keys", "10", {"s3:max-keys": "10"}),
    ("NumericNotEquals", "s3:max-keys", "10", {"s3:max-keys": "11"}),
    ("DateGreaterThan", "aws:CurrentTime", "2020-01-01T00:00:00Z", {"aws:CurrentTime": "2026-10-27T12:00:00Z"}),
    ("DateLessThan", "aws:CurrentTime", "2030-01-01", {"aws:CurrentTime": "2026-10-27T12:00:00Z"}),
    ("DateLessThan", "aws:CurrentTime", "1893456000", {"aws:CurrentTime": "2026-10-27T12:00:00Z"}),
    ("DateLessThan", "aws:CurrentTime", "2030-01-01T00:00:00Z", {"aws:CurrentTime": "2026-10-27T12:00:00Z"}),
    ("IpAddress", "aws:SourceIp", ["10.0.0.0/8", "203.0.113.0/24"], {"aws:SourceIp": "203.0.113.9"}),
    ("NotIpAddress", "aws:SourceIp", "203.0.113.0/24", {"aws:SourceIp": "198.51.100.7"}),
    ("Null", "aws:MultiFactorAuthAge", "true", {}),
]


@pytest.mark.parametrize("operator,key,value,context", DENIED_CASES)
def test_deny_with_implemented_operator_applies(operator, key, value, context):
    _assert_denied(_check(_deny({operator: {key: value}}), context=context))


ALLOWED_CASES = [
    ("Bool", "aws:SecureTransport", "false", {"aws:SecureTransport": "true"}),
    ("StringNotEquals", "aws:PrincipalOrgID", "o-good", {"aws:PrincipalOrgID": "o-good"}),
    ("StringNotEquals", "aws:RequestedRegion", ["eu-west-1", "eu-west-2"], {"aws:RequestedRegion": "eu-west-2"}),
    ("ArnLike", "aws:PrincipalArn", "arn:aws:iam::*:role/bad-*", {"aws:PrincipalArn": "arn:aws:iam::1:role/good"}),
    ("NumericGreaterThan", "s3:max-keys", "10", {"s3:max-keys": "10"}),
    ("DateLessThan", "aws:CurrentTime", "2020-01-01", {"aws:CurrentTime": "2026-10-27T12:00:00Z"}),
    ("NotIpAddress", "aws:SourceIp", "203.0.113.0/24", {"aws:SourceIp": "203.0.113.5"}),
    ("Null", "aws:MultiFactorAuthAge", "true", {"aws:MultiFactorAuthAge": "30"}),
    ("StringEquals", "aws:PrincipalTag/team", "red", {}),
]


@pytest.mark.parametrize("operator,key,value,context", ALLOWED_CASES)
def test_deny_that_does_not_apply_leaves_allow(operator, key, value, context):
    result = _check(_deny({operator: {key: value}}), context=context)
    assert result.verified is True, result.error
    assert result.allowed is True


# ----------------------------------------------------------------------
# Absent keys: negated and IfExists operators are true
# ----------------------------------------------------------------------

@pytest.mark.parametrize("operator,value", [
    ("NotIpAddress", "203.0.113.0/24"),
    ("StringNotEquals", "o-good"),
    ("StringNotLike", "o-*"),
    ("ArnNotLike", "arn:aws:iam::*:role/x"),
    ("NumericNotEquals", "5"),
    ("DateNotEquals", "2030-01-01T00:00:00Z"),
    ("StringEqualsIfExists", "o-good"),
    ("BoolIfExists", "true"),
])
def test_absent_key_applies_negated_and_ifexists_deny(operator, value):
    _assert_denied(_check(_deny({operator: {"aws:SomeKey": value}})))


def test_absent_key_matching_allow_mirror_is_permitted():
    allow = {"Effect": "Allow", "Action": "s3:*", "Resource": "*",
             "Condition": {"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}}}
    result = IamGuard().verify_access({"Statement": [allow]}, ACTION, RESOURCE, {})
    assert result.verified is True and result.allowed is True


# ----------------------------------------------------------------------
# Conditions the guard cannot evaluate: UNVERIFIABLE, never allow
# ----------------------------------------------------------------------

@pytest.mark.parametrize("condition,context", [
    ({"ForAnyValue:StringEquals": {"aws:TagKeys": "env"}}, {"aws:TagKeys": ["env"]}),
    ({"ForAllValues:StringLike": {"aws:TagKeys": "x-*"}}, {}),
    ({"SomeFutureOperator": {"aws:SourceIp": "1.2.3.4"}}, {}),
    ({"NullIfExists": {"aws:SourceIp": "true"}}, {}),
    ({"Null": {"aws:SourceIp": "maybe"}}, {}),
    ({"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}}, {"aws:SourceIp": "not-an-ip"}),
    ({"IpAddress": {"aws:SourceIp": ["203.0.113.0/24"]}}, {"aws:SourceIp": ["203.0.113.5"]}),
    ({"IpAddress": {"aws:SourceIp": "not-a-cidr"}}, {"aws:SourceIp": "203.0.113.5"}),
    ({"DateLessThan": {"aws:CurrentTime": "2030"}}, {"aws:CurrentTime": "2026-10-27T12:00:00Z"}),
    ({"DateLessThan": {"aws:CurrentTime": "2030-01-01T00:00:00"}}, {"aws:CurrentTime": "2026-10-27T12:00:00Z"}),
    ({"DateLessThan": {"aws:CurrentTime": "soon"}}, {"aws:CurrentTime": "2026-10-27T12:00:00Z"}),
    ({"NumericLessThan": {"s3:max-keys": "ten"}}, {"s3:max-keys": "5"}),
    ({"NumericLessThan": {"s3:max-keys": "NaN"}}, {"s3:max-keys": "5"}),
    ({"ArnEquals": {"aws:PrincipalArn": "not-an-arn"}}, {"aws:PrincipalArn": "arn:aws:iam::1:role/x"}),
    ({"StringEquals": {"aws:SourceVpc": []}}, {"aws:SourceVpc": "vpc-1"}),
    ({"StringEquals": {"aws:SourceVpc": 1.5}}, {"aws:SourceVpc": "vpc-1"}),
])
def test_deny_that_cannot_be_evaluated_is_unverifiable(condition, context):
    _assert_unverifiable(_check(_deny(condition), context=context))


def test_allow_that_cannot_be_evaluated_is_unverifiable():
    allow = {"Effect": "Allow", "Action": "s3:*", "Resource": "*",
             "Condition": {"SomeFutureOperator": {"aws:SourceIp": "1.2.3.4"}}}
    _assert_unverifiable(
        IamGuard().verify_access({"Statement": [allow]}, ACTION, RESOURCE, {})
    )


def test_unevaluable_condition_on_unrelated_statement_is_ignored():
    deny = _deny({"SomeFutureOperator": {"aws:SourceIp": "1.2.3.4"}}, action="ec2:*")
    result = _check(deny)
    assert result.verified is True and result.allowed is True


# ----------------------------------------------------------------------
# Matching: action case, ?, Unicode, policy variables, key case
# ----------------------------------------------------------------------

def test_action_matching_ignores_case():
    _assert_denied(_check(_deny(action="S3:*")))
    _assert_denied(_check(_deny(action="s3:getobject")))


def test_allow_action_matching_ignores_case():
    allow = {"Effect": "Allow", "Action": "S3:GETOBJECT", "Resource": "*"}
    result = IamGuard().verify_access({"Statement": [allow]}, ACTION, RESOURCE, {})
    assert result.verified is True and result.allowed is True


def test_resource_matching_keeps_case():
    result = _check(_deny(resource="arn:aws:s3:::B/K"))
    assert result.verified is True and result.allowed is True


def test_question_mark_matches_exactly_one_character():
    deny = _deny(resource="arn:aws:s3:::secret-bucke?/*")
    _assert_denied(_check(deny, resource="arn:aws:s3:::secret-bucket/k"))
    result = _check(deny, resource="arn:aws:s3:::secret-bucke/k")
    assert result.verified is True and result.allowed is True


@pytest.mark.parametrize("key", ["ключ", "été.txt", "\U0001F600"])
def test_star_matches_non_ascii_keys(key):
    deny = _deny(resource="arn:aws:s3:::secret-bucket/*")
    _assert_denied(_check(deny, resource=f"arn:aws:s3:::secret-bucket/{key}"))


def test_policy_variable_is_substituted_under_2012_version():
    deny = _deny(resource="arn:aws:s3:::home/${aws:username}/*")
    result = _check(deny, resource="arn:aws:s3:::home/alice/f",
                    context={"aws:username": "alice"}, version="2012-10-17")
    _assert_denied(result)
    other = _check(deny, resource="arn:aws:s3:::home/bob/f",
                   context={"aws:username": "alice"}, version="2012-10-17")
    assert other.verified is True and other.allowed is True


def test_policy_variable_in_condition_value_is_substituted():
    deny = _deny({"StringNotEquals": {"aws:PrincipalTag/owner": "${aws:username}"}})
    _assert_denied(_check(deny, context={"aws:username": "alice", "aws:PrincipalTag/owner": "bob"},
                          version="2012-10-17"))


def test_unresolved_policy_variable_is_unverifiable():
    deny = _deny(resource="arn:aws:s3:::home/${aws:username}/*")
    _assert_unverifiable(_check(deny, resource="arn:aws:s3:::home/alice/f", version="2012-10-17"))


@pytest.mark.parametrize("pattern", [
    "arn:aws:s3:::home/${aws:username, 'x'}/*",
    "arn:aws:s3:::home/${aws:username/*",
])
def test_unmodelled_policy_variable_form_is_unverifiable(pattern):
    deny = _deny(resource=pattern)
    _assert_unverifiable(_check(deny, context={"aws:username": "alice"}, version="2012-10-17"))


def test_policy_variable_with_wildcard_value_is_unverifiable():
    deny = _deny(resource="arn:aws:s3:::home/${aws:username}/*")
    _assert_unverifiable(_check(deny, resource="arn:aws:s3:::home/a/f",
                                context={"aws:username": "*"}, version="2012-10-17"))


def test_escaped_wildcard_variable_is_literal():
    deny = _deny(resource="arn:aws:s3:::b/${*}")
    _assert_denied(_check(deny, resource="arn:aws:s3:::b/*", version="2012-10-17"))
    result = _check(deny, resource="arn:aws:s3:::b/k", version="2012-10-17")
    assert result.verified is True and result.allowed is True


def test_policy_variable_is_literal_without_2012_version():
    deny = _deny(resource="arn:aws:s3:::home/${aws:username}/*")
    result = _check(deny, resource="arn:aws:s3:::home/alice/f", context={"aws:username": "alice"})
    assert result.verified is True and result.allowed is True
    _assert_denied(_check(deny, resource="arn:aws:s3:::home/${aws:username}/f"))


def test_condition_key_lookup_ignores_case():
    deny = _deny({"IpAddress": {"aws:sourceip": "203.0.113.0/24"}})
    _assert_denied(_check(deny, context={"aws:SourceIp": "203.0.113.5"}))


def test_context_keys_differing_only_in_case_are_unverifiable():
    deny = _deny({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}})
    _assert_unverifiable(_check(deny, context={"aws:SourceIp": "203.0.113.5",
                                               "aws:sourceip": "198.51.100.1"}))


def test_long_mixed_wildcard_patterns_finish_quickly():
    # Long values against patterns that mix ? and *, up to the bounds, must
    # not stall, including on periodic values that give many candidates.
    import time

    patterns = ["*" + "ab" * 15 + "?" + "ab" * 15 + "*" + str(i) for i in range(1800)]
    deny = _deny(resource=patterns[:900])
    deny2 = _deny(resource=patterns[900:])
    start = time.monotonic()
    result = IamGuard().verify_access({"Statement": [ALLOW_ALL, deny, deny2]}, ACTION, "ab" * 1024, {})
    assert time.monotonic() - start < 30
    assert result.verified is True and result.allowed is True


def test_question_marks_count_toward_the_wildcard_bound():
    deny = _deny(resource="arn:aws:s3:::" + "?" * 65)
    _assert_unverifiable(_check(deny))


def test_total_pattern_text_is_bounded():
    patterns = ["arn:aws:s3:::" + "a" * 2000 + str(i) for i in range(70)]
    result = _check(_deny(resource=patterns))
    _assert_unverifiable(result)
    assert "characters of pattern text" in result.error


# ----------------------------------------------------------------------
# Strings are compared as written, never decoded
# ----------------------------------------------------------------------

def test_escape_sequences_in_context_are_not_decoded():
    allow = {"Effect": "Allow", "Action": "s3:*", "Resource": "*",
             "Condition": {"StringEquals": {"s3:prefix": "home/alice"}}}
    result = IamGuard().verify_access({"Statement": [allow]}, ACTION, RESOURCE,
                                      {"s3:prefix": "home/\\u{61}lice"})
    assert result.verified is True and result.allowed is False


def test_escape_sequences_do_not_drop_a_negated_deny():
    deny = _deny({"StringNotEquals": {"aws:PrincipalOrgID": "o-good"}})
    _assert_denied(_check(deny, context={"aws:PrincipalOrgID": "\\u{6f}-good"}))


def test_escape_sequences_in_policy_variable_values_are_not_decoded():
    allow = {"Effect": "Allow", "Action": "s3:*", "Resource": "*",
             "Condition": {"StringEquals": {"s3:prefix": "home/${aws:username}"}}}
    policy = {"Version": "2012-10-17", "Statement": [allow]}
    result = IamGuard().verify_access(policy, ACTION, RESOURCE,
                                      {"s3:prefix": "home/alice", "aws:username": "\\u{61}lice"})
    assert result.verified is True and result.allowed is False


def test_non_ascii_action_pattern_is_unverifiable():
    # The Kelvin sign folds to "k" in some case-folding rules; that is not
    # modelled, so it must not decide the request either way.
    deny = _deny(action="s3:ListBucKet")
    _assert_unverifiable(_check(deny, action="s3:ListBucket"))


def test_condition_evaluations_are_labelled_python():
    deny = _deny({"StringEquals": {"aws:SourceVpc": "vpc-1"}})
    result = _check(deny, context={"aws:SourceVpc": "vpc-2"})
    assert result.condition_evaluations
    assert {e["evaluated_in"] for e in result.condition_evaluations} == {"python"}


# ----------------------------------------------------------------------
# Least privilege: conditional guard-rails do not hide admin access
# ----------------------------------------------------------------------

@pytest.mark.parametrize("condition", [
    {"Null": {"aws:MultiFactorAuthAge": "true"}},
    {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
    {"StringNotEquals": {"aws:PrincipalOrgID": "o-1"}},
    {"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}},
])
def test_least_privilege_ignores_conditional_deny(condition):
    policy = {"Statement": [ALLOW_ALL, {"Effect": "Deny", "Action": "*", "Resource": "*",
                                        "Condition": condition}]}
    result = IamGuard().verify_least_privilege(policy)
    assert result.verified is True and result.allowed is True


def test_least_privilege_counts_conditional_allow():
    allow = {"Effect": "Allow", "Action": "*", "Resource": "*",
             "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}
    result = IamGuard().verify_least_privilege({"Statement": [allow]})
    assert result.verified is True and result.allowed is True


def test_least_privilege_unconditional_deny_still_applies():
    policy = {"Statement": [ALLOW_ALL, {"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    result = IamGuard().verify_least_privilege(policy)
    assert result.verified is True and result.allowed is False


def test_least_privilege_scoped_policy_is_compliant():
    allow = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
    result = IamGuard().verify_least_privilege({"Statement": [allow]})
    assert result.verified is True and result.allowed is False


def test_least_privilege_unrelated_variable_statement_does_not_hide_admin():
    policy = {"Version": "2012-10-17", "Statement": [
        ALLOW_ALL,
        {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::${aws:username}/*"},
    ]}
    result = IamGuard().verify_least_privilege(policy)
    assert result.verified is True and result.allowed is True


# ----------------------------------------------------------------------
# Bounded work
# ----------------------------------------------------------------------

def test_policy_variable_expansion_is_bounded():
    import time

    pattern = "arn:aws:s3:::" + "${k}" * 505
    deny = _deny(resource=[pattern] * 100)
    start = time.monotonic()
    result = _check(deny, resource="arn:aws:s3:::x", context={"k": "a" * 2048}, version="2012-10-17")
    assert time.monotonic() - start < 30
    _assert_unverifiable(result)


def test_expanded_pattern_longer_than_request_does_not_match():
    deny = _deny(resource="arn:aws:s3:::${k}${k}")
    result = _check(deny, resource="arn:aws:s3:::short", context={"k": "a" * 1000}, version="2012-10-17")
    assert result.verified is True and result.allowed is True


def test_condition_value_count_is_bounded():
    values = [f"v{i}-*" for i in range(100)]
    statements = [ALLOW_ALL] + [
        {"Effect": "Deny", "Action": "s3:*", "Resource": "*",
         "Condition": {"StringLike": {f"k{j}": values for j in range(10)}}}
        for _ in range(3)
    ]
    result = IamGuard().verify_access({"Statement": statements}, ACTION, RESOURCE, {})
    _assert_unverifiable(result)
    assert "condition values" in result.error


def test_many_stringlike_values_finish_quickly():
    import time

    # 25 keys of 100 patterns each, all evaluated: the condition value
    # bound, within the pattern text bound.
    values = ["x" * 20 + "*" + "y" * 20 + str(i) for i in range(100)]
    keys = [f"k{j}" for j in range(25)]
    deny = _deny({"StringNotLike": {key: values for key in keys}})
    start = time.monotonic()
    result = _check(deny, context={key: "x" * 2040 for key in keys})
    assert time.monotonic() - start < 30
    _assert_denied(result)


# ----------------------------------------------------------------------
# Ambiguous inputs
# ----------------------------------------------------------------------

def test_condition_keys_differing_only_in_case_are_unverifiable():
    deny = _deny({"StringEquals": {"aws:SourceVpc": "vpc-a", "aws:sourcevpc": "vpc-b"}})
    _assert_unverifiable(_check(deny, context={"aws:SourceVpc": "vpc-b"}))


def test_condition_operators_differing_only_in_case_are_unverifiable():
    deny = _deny({"StringEquals": {"aws:SourceVpc": "vpc-a"}, "stringequals": {"aws:SourceVpc": "vpc-b"}})
    _assert_unverifiable(_check(deny, context={"aws:SourceVpc": "vpc-b"}))


@pytest.mark.parametrize("value", [None, []])
def test_null_or_empty_context_values_are_unverifiable(value):
    deny = _deny({"Null": {"aws:MultiFactorAuthAge": "true"}})
    _assert_unverifiable(_check(deny, context={"aws:MultiFactorAuthAge": value}))


@pytest.mark.parametrize("condition", [
    {"NotIpAddress": {"aws:SourceIp": "not-a-cidr"}},
    {"DateLessThanIfExists": {"aws:CurrentTime": "garbage"}},
    {"NumericLessThanIfExists": {"s3:max-keys": "ten"}},
    {"BoolIfExists": {"aws:SecureTransport": "yes"}},
])
def test_malformed_policy_value_with_absent_key_is_unverifiable(condition):
    allow = {"Effect": "Allow", "Action": "s3:*", "Resource": "*", "Condition": condition}
    _assert_unverifiable(IamGuard().verify_access({"Statement": [allow]}, ACTION, RESOURCE, {}))


@pytest.mark.parametrize("operator,value,ctx_value", [
    ("NumericNotEquals", "10", "1_0"),
    ("NumericNotEquals", "10", " 10 "),
    ("NumericNotEquals", "10", "1e1"),
    ("DateNotEquals", "2020-01-01T00:00:00Z", "20200101T000000Z"),
    ("DateNotEquals", "2020-01-01T00:00:00Z", "2020-W01-1"),
    ("DateNotEquals", "2020-01-01T00:00:00Z", "2020-01-01 00:00:00Z"),
    ("Bool", "true", "0"),
])
def test_loose_number_date_and_bool_forms_are_unverifiable(operator, value, ctx_value):
    deny = _deny({operator: {"k": value}})
    _assert_unverifiable(_check(deny, context={"k": ctx_value}))


@pytest.mark.parametrize("operator,value,ctx_value", [
    ("NumericEquals", "10.0", "10"),
    ("NumericLessThan", "-1", "-2"),
    ("DateEquals", "2020-01-01", "2020-01-01T00:00:00Z"),
    ("DateEquals", "2020-01-01T01:00:00+01:00", "2020-01-01T00:00:00Z"),
    ("DateGreaterThanEquals", "2020-01-01T00:00:00.5Z", "2020-01-01T00:00:00.500Z"),
])
def test_strict_number_and_date_forms_compare(operator, value, ctx_value):
    _assert_denied(_check(_deny({operator: {"k": value}}), context={"k": ctx_value}))


def test_arn_like_with_a_variable_in_the_account_component():
    deny = _deny({"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::${aws:PrincipalAccount}:role/x"}})
    context = {"aws:PrincipalAccount": "111122223333", "aws:PrincipalArn": "arn:aws:iam::111122223333:role/x"}
    _assert_denied(_check(deny, context=context, version="2012-10-17"))
    other = dict(context, **{"aws:PrincipalArn": "arn:aws:iam::999:role/x"})
    result = _check(deny, context=other, version="2012-10-17")
    assert result.verified is True and result.allowed is True


def test_unresolved_variable_that_cannot_match_is_a_plain_no_match():
    allow = {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::home/${aws:username}/*"}
    policy = {"Version": "2012-10-17", "Statement": [allow]}
    result = IamGuard().verify_access(policy, ACTION, "arn:aws:s3:::other/x", {})
    assert result.verified is True and result.allowed is False


def test_applying_deny_decides_despite_an_unevaluable_allow():
    unknown_allow = {"Effect": "Allow", "Action": "s3:*", "Resource": "*",
                     "Condition": {"SomeFutureOperator": {"k": "v"}}}
    policy = {"Statement": [ALLOW_ALL, unknown_allow, _deny()]}
    _assert_denied(IamGuard().verify_access(policy, ACTION, RESOURCE, {}))


def test_applying_allow_decides_despite_an_unevaluable_allow():
    unknown_allow = {"Effect": "Allow", "Action": "s3:*", "Resource": "*",
                     "Condition": {"SomeFutureOperator": {"k": "v"}}}
    result = IamGuard().verify_access({"Statement": [ALLOW_ALL, unknown_allow]}, ACTION, RESOURCE, {})
    assert result.verified is True and result.allowed is True


@pytest.mark.parametrize("value,pattern,expected", [
    ("a", "a*a", False),
    ("aa", "a*a", True),
    ("", "", True),
    ("x", "", False),
    ("abc", "**", True),
    ("xabdabdy", "x*abd*y", True),
    ("ab", "?*?", True),
    ("a", "?*?", False),
    ("a\nb", "a?b", True),
    ("a\nb", "a*", True),
])
def test_glob_edge_cases(value, pattern, expected):
    from qwed_infra.guards._iam_matching import wildcard_match

    assert wildcard_match(value, pattern) is expected


# ----------------------------------------------------------------------
# Second review: least privilege, ARN segments, case folding, statements
# ----------------------------------------------------------------------

@pytest.mark.parametrize("deny", [
    {"Effect": "Deny", "Action": "?", "Resource": "*"},
    {"Effect": "Deny", "Action": "*", "Resource": "?"},
    {"Effect": "Deny", "Action": "*", "Resource": "${*}"},
    {"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
])
def test_least_privilege_deny_must_name_everything(deny):
    policy = {"Version": "2012-10-17", "Statement": [ALLOW_ALL, deny]}
    result = IamGuard().verify_least_privilege(policy)
    assert result.verified is True and result.allowed is True


def test_least_privilege_deny_with_repeated_stars_names_everything():
    policy = {"Statement": [ALLOW_ALL, {"Effect": "Deny", "Action": "**", "Resource": ["x", "*"]}]}
    result = IamGuard().verify_least_privilege(policy)
    assert result.verified is True and result.allowed is False


def test_distinct_expanded_patterns_finish_quickly():
    import time

    patterns = [f"?${{a}}${{a}}${{a}}${{a}}{i}" for i in range(2400)]
    statements = [ALLOW_ALL] + [
        {"Effect": "Deny", "Action": "*", "Resource": patterns[k:k + 800]} for k in range(0, 2400, 800)
    ]
    start = time.monotonic()
    result = IamGuard().verify_access({"Version": "2012-10-17", "Statement": statements},
                                      ACTION, "short", {"a": "a" * 2040})
    assert time.monotonic() - start < 30
    assert result.verified is False or result.allowed is True


def test_substitution_budget_bounds_search_work():
    import time

    patterns = [f"*?${{a}}b{i}*" for i in range(2400)]
    statements = [ALLOW_ALL] + [
        {"Effect": "Deny", "Action": "*", "Resource": patterns[k:k + 800]} for k in range(0, 2400, 800)
    ]
    start = time.monotonic()
    result = IamGuard().verify_access({"Version": "2012-10-17", "Statement": statements},
                                      ACTION, "a" * 2048, {"a": "a" * 1022})
    assert time.monotonic() - start < 30
    _assert_unverifiable(result)


@pytest.mark.parametrize("pattern,resource", [
    ("arn:aws:a?b:r:acct:res", "arn:aws:a:b:r:acct:res"),
    ("arn:aws:s3*x:::b", "arn:aws:s3:::x:::b"),
])
def test_resource_wildcard_across_arn_colon_is_unverifiable(pattern, resource):
    allow = {"Effect": "Allow", "Action": "*", "Resource": pattern}
    _assert_unverifiable(IamGuard().verify_access({"Statement": [allow]}, ACTION, resource, {}))


@pytest.mark.parametrize("pattern,resource", [
    ("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a:b:c"),
    ("arn:aws:lambda:*:*:function:*", "arn:aws:lambda:us-east-1:1:function:f:alias"),
    ("arn:aws:s3:::b?cket/k", "arn:aws:s3:::bucket/k"),
])
def test_resource_wildcards_within_arn_segments_match(pattern, resource):
    _assert_denied(_check(_deny(resource=pattern), resource=resource))


def test_resource_wildcard_cannot_reach_across_a_colon_it_does_not_end():
    result = _check(_deny(resource="arn:aws:s3:::x*y"), resource="arn:aws:s3:::x:z")
    assert result.verified is True and result.allowed is True


@pytest.mark.parametrize("operator,value,ctx_value", [
    ("StringNotEqualsIgnoreCase", "ÉCOLE", "école"),
    ("StringEqualsIgnoreCase", "kevin", "Kevin"),
])
def test_non_ascii_ignore_case_comparisons_are_unverifiable(operator, value, ctx_value):
    _assert_unverifiable(_check(_deny({operator: {"k": value}}), context={"k": ctx_value}))


@pytest.mark.parametrize("statement", [
    {"Effect": "Allow", "Action": "*", "Resource": "*", "Conditon": {"Bool": {"k": "true"}}},
    {"Effect": "allow", "Action": "*", "Resource": "*"},
    {"Action": "*", "Resource": "*"},
])
def test_unknown_statement_elements_and_bad_effects_are_unverifiable(statement):
    _assert_unverifiable(IamGuard().verify_access({"Statement": [statement]}, ACTION, RESOURCE, {}))


def test_least_privilege_statement_without_effect_is_unverifiable():
    policy = {"Statement": [ALLOW_ALL, {"Action": "*", "Resource": "*"}]}
    result = IamGuard().verify_least_privilege(policy)
    assert result.verified is False


def test_arn_like_star_matches_any_arn():
    _assert_denied(_check(_deny({"ArnLike": {"aws:SourceArn": "*"}}),
                          context={"aws:SourceArn": "arn:aws:sns:us-east-1:1:t"}))


def test_malformed_arn_value_with_absent_key_is_unverifiable():
    allow = {"Effect": "Allow", "Action": "s3:*", "Resource": "*",
             "Condition": {"ArnNotLike": {"aws:SourceArn": "garbage"}}}
    _assert_unverifiable(IamGuard().verify_access({"Statement": [allow]}, ACTION, RESOURCE, {}))


@pytest.mark.parametrize("value,ctx_value", [
    ("10.0.0.0/0.0.0.255", "10.0.0.5"),
    ("10.0.0.0/255.255.255.0", "10.0.0.5"),
    ("10.0.0.0/8", "::ffff:10.0.0.5"),
])
def test_ambiguous_ip_forms_are_unverifiable(value, ctx_value):
    _assert_unverifiable(_check(_deny({"IpAddress": {"aws:SourceIp": value}}),
                                context={"aws:SourceIp": ctx_value}))


def test_non_ascii_context_keys_are_unverifiable():
    _assert_unverifiable(_check(_deny({"StringEquals": {"k": "v"}}), context={"K": "v"}))


@pytest.mark.parametrize("action,resource", [("*:*", "*"), ("*", "arn:*"), ("*:*", "arn:*:*:*:*:*")])
def test_least_privilege_counts_allows_that_cover_everything(action, resource):
    allow = {"Effect": "Allow", "Action": action, "Resource": resource}
    result = IamGuard().verify_least_privilege({"Statement": [allow]})
    assert result.verified is True and result.allowed is True


@pytest.mark.parametrize("action,resource", [("s3:*", "*"), ("*", "arn:aws:s3:::*"), ("s3:Get*", "arn:*")])
def test_least_privilege_scoped_allows_are_not_full_access(action, resource):
    allow = {"Effect": "Allow", "Action": action, "Resource": resource}
    result = IamGuard().verify_least_privilege({"Statement": [allow]})
    assert result.verified is True and result.allowed is False


# ----------------------------------------------------------------------
# Third review: least-privilege coverage, ARN prefix rules, policy shape
# ----------------------------------------------------------------------

@pytest.mark.parametrize("action,resource", [
    ("?*:*", "*"), ("*:?*", "*"), ("??*", "*"),
    ("*", "??*"), ("*", "arn*"), ("*", "arn:?*"),
])
def test_least_privilege_counts_wildcard_shaped_full_access(action, resource):
    allow = {"Effect": "Allow", "Action": action, "Resource": resource}
    result = IamGuard().verify_least_privilege({"Statement": [allow]})
    assert result.verified is True and result.allowed is True


@pytest.mark.parametrize("action,resource", [
    ([f"{c}*" for c in "abcdefghijklmnopqrstuvwxyz"], "*"),
    ("*", "arn:aws:*"),
    ("*", "arn:*:s3:::*"),
    ("*", "${aws:username}"),
])
def test_least_privilege_undecidable_coverage_is_unverifiable(action, resource):
    allow = {"Effect": "Allow", "Action": action, "Resource": resource}
    policy = {"Version": "2012-10-17", "Statement": [allow]}
    result = IamGuard().verify_least_privilege(policy)
    assert result.verified is False


@pytest.mark.parametrize("pattern", ["*3:::secret/k", "arn?aws?s3???secret/k"])
def test_unprefixed_resource_wildcards_respect_arn_segments(pattern):
    allow = {"Effect": "Allow", "Action": "*", "Resource": pattern}
    _assert_unverifiable(IamGuard().verify_access({"Statement": [allow]}, ACTION, "arn:aws:s3:::secret/k", {}))


@pytest.mark.parametrize("pattern,context", [
    ("arn:aws:iam::${aws:PrincipalAccount}:user/x", {"aws:PrincipalAccount": "123"}),
    ("arn:aws:${aws:x}:::secret/k", {"x": "s3"}),
    ("arn:aws:*:::secret/k", {}),
])
def test_variables_and_service_wildcards_before_the_fifth_colon_are_unverifiable(pattern, context):
    allow = {"Effect": "Allow", "Action": "*", "Resource": pattern}
    policy = {"Version": "2012-10-17", "Statement": [allow]}
    resource = "arn:aws:iam::123:user/x" if "iam" in pattern else "arn:aws:s3:::secret/k"
    _assert_unverifiable(IamGuard().verify_access(policy, ACTION, resource, context))


@pytest.mark.parametrize("policy", [
    {"Version": "2012", "Statement": [ALLOW_ALL]},
    {"Version": "2012-10-18", "Statement": [ALLOW_ALL]},
    {"Statement": [ALLOW_ALL], "Statment": []},
    {"Statement": [ALLOW_ALL, {"Effect": "Deny", "Action": [], "Resource": "*"}]},
])
def test_malformed_policy_shapes_are_unverifiable(policy):
    _assert_unverifiable(IamGuard().verify_access(policy, ACTION, RESOURCE, {}))


def test_policy_id_and_both_versions_are_accepted():
    for version in ("2012-10-17", "2008-10-17"):
        result = IamGuard().verify_access({"Version": version, "Id": "p1", "Statement": [ALLOW_ALL]},
                                          ACTION, RESOURCE, {})
        assert result.verified is True and result.allowed is True


def test_scoped_ipv6_request_address_is_unverifiable():
    _assert_unverifiable(_check(_deny({"IpAddress": {"aws:SourceIp": "fe80::/10"}}),
                                context={"aws:SourceIp": "fe80::1%eth0"}))


# ----------------------------------------------------------------------
# Fourth review: bounded error text, thread safety
# ----------------------------------------------------------------------

def test_unknown_element_errors_are_bounded():
    statement = dict(ALLOW_ALL, **{f"k{i}" + "x" * 5000: 1 for i in range(50)})
    result = IamGuard().verify_access({"Statement": [statement]}, ACTION, RESOURCE, {})
    _assert_unverifiable(result)
    assert len(result.error) < 1000
    big = {"Statement": [ALLOW_ALL], "y" * 1_000_000: 1}
    result = IamGuard().verify_access(big, ACTION, RESOURCE, {})
    _assert_unverifiable(result)
    assert len(result.error) < 1000


@pytest.mark.parametrize("shared", [True, False])
def test_guards_are_safe_across_threads(shared):
    import threading

    shared_guard = IamGuard()
    allow = {"Statement": [ALLOW_ALL]}
    deny = {"Statement": [ALLOW_ALL, _deny()]}
    errors = []

    def run(policy, expected):
        guard = shared_guard if shared else IamGuard()
        for _ in range(200):
            result = guard.verify_access(policy, ACTION, RESOURCE, {})
            if result.verified is not True or result.allowed is not expected:
                errors.append(result)

    threads = [threading.Thread(target=run, args=(allow, True)) for _ in range(2)]
    threads += [threading.Thread(target=run, args=(deny, False)) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    assert not any(thread.is_alive() for thread in threads)
    assert errors == []
