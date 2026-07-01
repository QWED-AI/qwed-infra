from decimal import Decimal
import pytest
from qwed_infra.guards.cost_guard import CostGuard

@pytest.fixture
def guard():
    return CostGuard()

def test_cost_under_budget(guard):
    resources = {
        "instances": [
            {"id": "web-1", "instance_type": "t3.micro", "count": 2},
            {"id": "db-1", "instance_type": "db.t3.micro", "count": 1}
        ],
        "volumes": [
            {"id": "vol-1", "volume_type": "gp2", "size_gb": 10}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=50.0)
    assert result.within_budget is True
    assert Decimal(result.total_monthly_cost) < Decimal("30")
    assert Decimal(result.total_monthly_cost) > Decimal("25")

def test_cost_exceeds_budget(guard):
    resources = {
        "instances": [
            {"id": "train-job", "instance_type": "p4d.24xlarge", "count": 1}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=500.0)
    assert result.within_budget is False
    assert "EXCEEDS budget" in result.reason
    assert Decimal(result.total_monthly_cost) > Decimal("23000")

def test_unknown_instance_type_handled(guard):
    resources = {
        "instances": [
            {"id": "weird-instance", "instance_type": "quantum.bit", "count": 1}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=10.0)
    assert result.within_budget is False
    assert "unknown instance types" in result.reason.lower()
    assert "quantum.bit" in result.reason
    assert "unknown-weird-instance" in result.breakdown


def test_io2_volume_unknown_fails_closed(guard):
    resources = {
        "volumes": [
            {"id": "vol-io2-1", "volume_type": "io2", "size_gb": 100}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.within_budget is False
    assert result.has_unknown_types is True
    assert "io2" in result.reason


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
            {"id": "st1-vol", "volume_type": "st1", "size_gb": 10},
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.within_budget is True
    assert result.has_unknown_types is False
    assert "vol-gp2-vol" in result.breakdown
    assert "vol-st1-vol" in result.breakdown
    assert Decimal(result.breakdown["vol-st1-vol"]) > Decimal(result.breakdown["vol-gp2-vol"])


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


def test_missing_instance_type_fails_closed(guard):
    resources = {
        "instances": [
            {"id": "no-type-instance", "count": 1}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.within_budget is False
    assert result.has_unknown_types is True
    assert "<missing>" in result.reason
    assert "unknown-no-type-instance" in result.breakdown


def test_missing_instance_id_fails_closed(guard):
    resources = {
        "instances": [
            {"instance_type": "nano.unknown"}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.within_budget is False
    assert result.has_unknown_types is True
    assert "unknown-nano.unknown" in result.breakdown


def test_missing_both_id_and_type_fails_closed(guard):
    resources = {
        "instances": [{}]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.within_budget is False
    assert result.has_unknown_types is True
    assert "<missing>" in result.reason
    assert "unknown-<missing-id>" in result.breakdown


def test_id_less_instances_no_breakdown_collision(guard):
    resources = {
        "instances": [
            {"instance_type": "t3.micro", "count": 2},
            {"instance_type": "t3.micro", "count": 3},
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.within_budget is True
    assert "t3.micro" in result.breakdown
    assert "t3.micro#1" in result.breakdown
    assert Decimal(result.breakdown["t3.micro"]) == Decimal("0.0104") * 2 * Decimal("730")
    assert Decimal(result.breakdown["t3.micro#1"]) == Decimal("0.0104") * 3 * Decimal("730")


def test_id_none_renders_as_missing_id(guard):
    resources = {
        "instances": [{"id": None}]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.has_unknown_types is True
    assert "unknown-<missing-id>" in result.breakdown


def test_duplicate_unknown_instance_types_no_collision(guard):
    resources = {
        "instances": [
            {"instance_type": "nonexistent-1x.small"},
            {"instance_type": "nonexistent-1x.small"},
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.has_unknown_types is True
    assert "unknown-nonexistent-1x.small" in result.breakdown
    assert "unknown-nonexistent-1x.small#1" in result.breakdown


def test_duplicate_missing_volume_type_no_collision(guard):
    resources = {
        "volumes": [
            {"size_gb": 10},
            {"size_gb": 20},
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.has_unknown_types is True
    assert "unknown-missing-volume-type" in result.breakdown
    assert "unknown-missing-volume-type#1" in result.breakdown


def test_duplicate_unknown_volume_type_no_collision(guard):
    resources = {
        "volumes": [
            {"volume_type": "nonexistent-storage", "size_gb": 10},
            {"volume_type": "nonexistent-storage", "size_gb": 20},
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.has_unknown_types is True
    assert "unknown-nonexistent-storage" in result.breakdown
    assert "unknown-nonexistent-storage#1" in result.breakdown


def test_float_drift_no_false_positive(guard):
    resources = {
        "instances": [
            {"id": "a", "instance_type": "t3.micro", "count": 1},
            {"id": "b", "instance_type": "t3.micro", "count": 1},
        ]
    }
    result = guard.verify_budget(resources, budget_monthly="15.18")
    assert result.within_budget is True
    assert "within budget" in result.reason.lower()


def test_float_drift_at_boundary(guard):
    resources = {
        "instances": [
            {"id": "a", "instance_type": "t3.micro", "count": 1},
        ]
    }
    result = guard.verify_budget(resources, budget_monthly="7.59")
    assert result.within_budget is True
    result_below = guard.verify_budget(resources, budget_monthly="7.58")
    assert result_below.within_budget is False


def test_invalid_count_non_int(guard):
    resources = {
        "instances": [
            {"id": "bad", "instance_type": "t3.micro", "count": "two"}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.has_unknown_types is True
    assert "invalid-count-bad" in result.breakdown
    assert "invalid count" in result.reason


def test_invalid_count_negative(guard):
    resources = {
        "instances": [
            {"id": "bad", "instance_type": "t3.micro", "count": -1}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.has_unknown_types is True
    assert "invalid-count-bad" in result.breakdown


def test_invalid_size_gb_non_int(guard):
    resources = {
        "volumes": [
            {"id": "bad", "volume_type": "gp2", "size_gb": "large"}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.has_unknown_types is True
    assert "invalid-size-bad" in result.breakdown
    assert "invalid size_gb" in result.reason


def test_invalid_size_gb_negative(guard):
    resources = {
        "volumes": [
            {"id": "bad", "volume_type": "gp2", "size_gb": -5}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.has_unknown_types is True
    assert "invalid-size-bad" in result.breakdown


def test_missing_size_gb_fails_closed(guard):
    resources = {
        "volumes": [
            {"id": "no-size", "volume_type": "gp2"}
        ]
    }
    result = guard.verify_budget(resources, budget_monthly=100.0)
    assert result.has_unknown_types is True
    assert "invalid-size-no-size" in result.breakdown


def test_to_diagnostic_malformed_total(guard):
    result = guard.verify_budget({"volumes": []}, budget_monthly=100.0)
    result.total_monthly_cost = "not-a-number"
    diagnostic = CostGuard.to_diagnostic(result)
    assert diagnostic.status.value == "BLOCKED"
    assert diagnostic.developer_fields["audit_trace"]["outcome"] == "INVALID_INPUT"


def test_to_diagnostic_malformed_budget(guard):
    result = guard.verify_budget({"volumes": []}, budget_monthly=100.0)
    result.budget = "bad-budget"
    diagnostic = CostGuard.to_diagnostic(result)
    assert diagnostic.status.value == "BLOCKED"
    assert diagnostic.developer_fields["audit_trace"]["outcome"] == "INVALID_INPUT"
