import pytest
from qwed_infra.guards.iam_guard import IamGuard

@pytest.fixture
def guard():
    return IamGuard()

def test_iam_guard_allow_s3(guard):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }
    
    result = guard.verify_access(policy, action="s3:GetObject", resource="arn:aws:s3:::my-bucket/data.csv")
    assert result.verified is True
    assert result.allowed is True
    assert "Z3 found a satisfying model" in result.proof

def test_iam_guard_deny_overrides_allow(guard):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            },
            {
                "Effect": "Deny",
                "Action": "s3:DeleteBucket",
                "Resource": "*"
            }
        ]
    }
    
    # Check DeleteBucket - Should be DENIED (Explicit Deny)
    result = guard.verify_access(policy, action="s3:DeleteBucket", resource="arn:aws:s3:::production")
    assert result.verified is True
    assert result.allowed is False
    assert "unsatisfiability" in result.proof or "Access Denied" in result.proof

    # Check GetObject - Should be ALLOWED
    result = guard.verify_access(policy, action="s3:GetObject", resource="arn:aws:s3:::production")
    assert result.verified is True
    assert result.allowed is True

def test_least_privilege(guard):
    admin_policy = {
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }
    res = guard.verify_least_privilege(admin_policy)
    assert res.allowed is True # It IS allowed, which means it violates Least Privilege if we expected False, but here we just check reachability.
    
    readonly_policy = {
        "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]
    }
    res = guard.verify_least_privilege(readonly_policy)
    assert res.allowed is False # Cannot do * on *
