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
            {"id": "vol-1", "size_gb": 10} # 10 * 0.0000315 = 0.000315/hr
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
    # Should calculate as 0 cost for now, so passes budget
    assert result.within_budget is True
    assert "unknown-quantum.bit" in result.breakdown
