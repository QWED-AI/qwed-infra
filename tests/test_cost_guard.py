import pytest
from qwed_infra.guards.cost_guard import CostGuard

@pytest.fixture
def guard():
    return CostGuard()

def test_cost_under_budget(guard):
    resources = {
        "instances": [
            {"id": "web-1", "instance_type": "t3.micro", "count": 2}, # 0.0104 * 2 = 0.0208/hr
            {"id": "db-1", "instance_type": "db.t3.micro", "count": 1} # 0.017/hr
        ],
        "volumes": [
            {"id": "vol-1", "volume_type": "gp2", "size_gb": 10} # 10 * 0.0000315 = 0.000315/hr
        ]
    }
    # Total/hr = 0.038115
    # Total/mo (730hr) = $27.82
    
    result = guard.verify_budget(resources, budget_monthly=50.0)
    assert result.within_budget is True
    assert result.total_monthly_cost < 30.0
    assert result.total_monthly_cost > 25.0

def test_cost_exceeds_budget(guard):
    resources = {
        "instances": [
            {"id": "train-job", "instance_type": "p4d.24xlarge", "count": 1} # $32.77/hr
        ]
    }
    # Total/mo = ~$23,922
    
    result = guard.verify_budget(resources, budget_monthly=500.0)
    assert result.within_budget is False
    assert "EXCEEDS budget" in result.reason
    assert result.total_monthly_cost > 23000

def test_unknown_instance_type_handled(guard):
    resources = {
        "instances": [
            {"id": "weird-instance", "instance_type": "quantum.bit", "count": 1}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=10.0)
    # Unknown instance type → fail closed: cannot prove budget is within limits
    assert result.within_budget is False
    assert "unknown instance types" in result.reason.lower()
    assert "quantum.bit" in result.reason
    assert "unknown-weird-instance" in result.breakdown  # keyed by inst id


def test_known_io2_volume_within_budget(guard):
    resources = {
        "volumes": [
            {"id": "vol-io2-1", "volume_type": "io2", "size_gb": 100}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    # io2 is in the catalog → should be known and within budget
    assert result.within_budget is True
    assert result.has_unknown_types is False


def test_unknown_volume_type_unknown_fails_closed(guard):
    resources = {
        "volumes": [
            {"id": "vol-magic", "volume_type": "magic-storage", "size_gb": 100}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=1000.0)
    assert result.within_budget is False
    assert result.has_unknown_types is True
    assert "unknown volume types" in result.reason.lower()
    assert "magic-storage" in result.reason


def test_mixed_known_and_unknown_volumes(guard):
    resources = {
        "volumes": [
            {"id": "vol-known", "volume_type": "gp2", "size_gb": 10},
            {"id": "vol-unknown", "volume_type": "super-disk", "size_gb": 50},
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=1000.0)
    assert result.within_budget is False
    assert result.has_unknown_types is True
    assert "super-disk" in result.reason
    assert "unknown-vol-unknown" in result.breakdown


def test_known_volume_type_correctly_priced(guard):
    resources = {
        "volumes": [
            {"id": "gp2-vol", "volume_type": "gp2", "size_gb": 10},
            {"id": "io1-vol", "volume_type": "io1", "size_gb": 10},
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.within_budget is True
    assert result.has_unknown_types is False
    # io1 is more expensive than gp2 — both should be priced
    assert "vol-gp2-vol" in result.breakdown
    assert "vol-io1-vol" in result.breakdown
    assert result.breakdown["vol-io1-vol"] > result.breakdown["vol-gp2-vol"]


def test_unknown_volume_type_to_diagnostic_blocked(guard):
    resources = {
        "volumes": [
            {"id": "vol-bad", "volume_type": "nonexistent-raid", "size_gb": 100}
        ]
    }
    estimate = guard.verify_budget(resources, budget_monthly=1000.0)
    diagnostic = CostGuard.to_diagnostic(estimate)
    assert diagnostic.status.value == "BLOCKED"
    assert diagnostic.developer_fields["has_unknown_types"] is True
    assert diagnostic.developer_fields["audit_trace"]["rule_id"] == "COST_UNKNOWN_RESOURCE"
