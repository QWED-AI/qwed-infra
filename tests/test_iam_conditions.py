import pytest
from qwed_infra.guards.iam_guard import IamGuard

@pytest.fixture
def guard():
    return IamGuard()

def test_condition_ip_address_allowed(guard):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "IpAddress": {"aws:SourceIp": "192.168.1.0/24"}
                }
            }
        ]
    }
    
    # Matching IP
    res1 = guard.verify_access(
        policy, "s3:GetObject", "arn:aws:s3:::bucket/data",
        context={"aws:SourceIp": "192.168.1.55"}
    )
    assert res1.allowed is True
    
    # Non-Matching IP
    res2 = guard.verify_access(
        policy, "s3:GetObject", "arn:aws:s3:::bucket/data",
        context={"aws:SourceIp": "10.0.0.1"}
    )
    assert res2.allowed is False

def test_condition_string_equals_project(guard):
    policy = {
        "Statement": [
            {
                "Effect": "Allow", 
                "Action": "*", 
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:PrincipalTag/Project": "Secret"}
                }
            }
        ]
    }
    
    # Correct Tag
    res1 = guard.verify_access(
        policy, "ec2:StartInstances", "*",
        context={"aws:PrincipalTag/Project": "Secret"}
    )
    assert res1.allowed is True
    
    # Wrong Tag
    res2 = guard.verify_access(
        policy, "ec2:StartInstances", "*",
        context={"aws:PrincipalTag/Project": "Public"}
    )
    assert res2.allowed is False
    
    # Missing Tag
    res3 = guard.verify_access(
        policy, "ec2:StartInstances", "*",
        context={}
    )
    assert res3.allowed is False

def test_condition_string_like_wildcard(guard):
    policy = {
        "Statement": [
            {
                "Effect": "Allow", 
                "Action": "*", 
                "Resource": "*",
                "Condition": {
                    "StringLike": {"aws:username": "jdoe-*"}
                }
            }
        ]
    }
    
    # Matches jdoe-admin
    res1 = guard.verify_access(policy, "*", "*", context={"aws:username": "jdoe-admin"})
    assert res1.allowed is True
    
    # Does not match alice
    res2 = guard.verify_access(policy, "*", "*", context={"aws:username": "alice"})
    assert res2.allowed is False
