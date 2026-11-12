import json
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
    # AWS list price: gp2 $0.10 per GB-month, st1 $0.045 (#102).
    assert Decimal(result.breakdown["vol-gp2-vol"]) > Decimal(result.breakdown["vol-st1-vol"])


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


def test_sub_cent_overrun_is_not_certified(guard):
    # Exact cost 0.0104 * 2 * 730 = 15.184, over a 15.18 budget by 0.004.
    # Both sides used to be rounded to the cent before the comparison (#75).
    resources = {
        "instances": [
            {"id": "a", "instance_type": "t3.micro", "count": 1},
            {"id": "b", "instance_type": "t3.micro", "count": 1},
        ]
    }
    result = guard.verify_budget(resources, budget_monthly="15.18")
    assert result.within_budget is False
    assert "EXCEEDS budget" in result.reason
    assert CostGuard.to_diagnostic(result).status.value == "BLOCKED"
    assert guard.verify_budget(resources, budget_monthly="15.184").within_budget is True


def test_exact_boundary_comparison(guard):
    resources = {
        "instances": [
            {"id": "a", "instance_type": "t3.micro", "count": 1},
        ]
    }
    # Exact cost 7.592.
    assert guard.verify_budget(resources, budget_monthly="7.592").within_budget is True
    assert guard.verify_budget(resources, budget_monthly="7.5919").within_budget is False
    assert guard.verify_budget(resources, budget_monthly="7.59").within_budget is False
    assert guard.verify_budget(resources, budget_monthly="7.60").within_budget is True


def test_published_figures_round_conservatively(guard):
    resources = {"instances": [{"id": "a", "instance_type": "t3.micro", "count": 1}]}
    result = guard.verify_budget(resources, budget_monthly="7.599")
    # Total rounds up, budget rounds down.
    assert result.total_monthly_cost == "7.60"
    assert result.budget == "7.59"


def test_to_diagnostic_rejects_hand_built_sub_cent_overrun(guard):
    result = guard.verify_budget({"instances": []}, budget_monthly="15.18")
    result.total_monthly_cost = "15.184"
    result.within_budget = True
    diagnostic = CostGuard.to_diagnostic(result)
    assert diagnostic.status.value == "BLOCKED"
    assert diagnostic.developer_fields["audit_trace"]["outcome"] == "INCONSISTENT"


@pytest.mark.parametrize("budget", ["7.592", "7.595", "7.5999"])
def test_sub_cent_margin_within_budget_is_verified(guard, budget):
    # Exact cost 7.592. The published total (7.60) is above the published
    # budget (7.59), but the decision and its re-check use the exact figures.
    resources = {"instances": [{"id": "a", "instance_type": "t3.micro", "count": 1}]}
    result = guard.verify_budget(resources, budget_monthly=budget)
    assert result.within_budget is True
    assert result.exact_total_monthly_cost == "7.5920"
    assert result.exact_budget == budget
    assert CostGuard.to_diagnostic(result).status.value == "VERIFIED"


@pytest.mark.parametrize("field,value", [
    ("exact_total_monthly_cost", "7.50"),
    ("exact_budget", "8.00"),
    ("exact_total_monthly_cost", "not-a-number"),
])
def test_to_diagnostic_rejects_exact_figures_that_disagree(guard, field, value):
    resources = {"instances": [{"id": "a", "instance_type": "t3.micro", "count": 1}]}
    result = guard.verify_budget(resources, budget_monthly="7.592")
    result = result.model_copy(update={field: value})
    assert CostGuard.to_diagnostic(result).status.value == "BLOCKED"


@pytest.mark.parametrize("field", ["exact_total_monthly_cost", "exact_budget"])
def test_to_diagnostic_huge_exact_figure_blocks_instead_of_raising(guard, field):
    # Rounding 1e100 to cents exceeds the default Decimal precision.
    result = guard.verify_budget({"instances": []}, budget_monthly="100")
    result = result.model_copy(update={field: "1e100"})
    diagnostic = CostGuard.to_diagnostic(result)
    assert diagnostic.status.value == "BLOCKED"
    assert diagnostic.developer_fields["audit_trace"]["outcome"] == "INVALID_INPUT"


@pytest.mark.parametrize("budget", ["1e1000000000", "1e30"])
def test_to_diagnostic_huge_published_budget_without_exact_figures_blocks(guard, budget):
    result = guard.verify_budget({"instances": []}, budget_monthly="100")
    result = result.model_copy(update={
        "budget": budget, "exact_total_monthly_cost": None, "exact_budget": None,
    })
    diagnostic = CostGuard.to_diagnostic(result)
    assert diagnostic.status.value == "BLOCKED"
    assert diagnostic.developer_fields["audit_trace"]["outcome"] == "INVALID_INPUT"


def test_to_diagnostic_accepts_hand_built_estimate_in_cents(guard):
    result = guard.verify_budget({"instances": []}, budget_monthly="100")
    result = result.model_copy(update={"exact_total_monthly_cost": None, "exact_budget": None})
    assert CostGuard.to_diagnostic(result).status.value == "VERIFIED"


def test_verified_diagnostic_records_exact_figures_and_region(guard):
    resources = {"instances": [{"id": "a", "instance_type": "t3.micro", "count": 1}]}
    diagnostic = CostGuard.to_diagnostic(guard.verify_budget(resources, budget_monthly="7.595"))
    assert diagnostic.status.value == "VERIFIED"
    for source in (diagnostic.developer_fields, json.loads(diagnostic.proof_data)):
        assert source["exact_total_monthly_cost"] == "7.5920"
        assert source["exact_budget"] == "7.595"
        assert source["pricing_region"] == "us-east-1"
        assert source["pricing_catalogue_sha256"] == CostGuard.pricing_catalogue_sha256()


def test_estimate_keeps_the_catalogue_it_was_priced_with(guard, monkeypatch):
    resources = {"volumes": [{"id": "v", "volume_type": "gp3", "size_gb": 1000}]}
    result = guard.verify_budget(resources, budget_monthly="100")
    assert result.pricing_catalogue_sha256 == CostGuard.pricing_catalogue_sha256()
    # The catalogue changes after the estimate was made: it is not certified.
    monkeypatch.setitem(CostGuard.VOLUME_PRICING, "gp3", "0.081")
    diagnostic = CostGuard.to_diagnostic(result)
    assert diagnostic.status.value == "BLOCKED"
    assert diagnostic.developer_fields["audit_trace"]["outcome"] == "INCONSISTENT"


def test_catalogue_identifier_changes_with_any_price(guard, monkeypatch):
    before = CostGuard.pricing_catalogue_sha256()
    assert len(before) == 64
    monkeypatch.setitem(CostGuard.VOLUME_PRICING, "gp3", "0.081")
    assert CostGuard.pricing_catalogue_sha256() != before
    monkeypatch.undo()
    assert CostGuard.pricing_catalogue_sha256() == before
    monkeypatch.setitem(CostGuard.INSTANCE_PRICING, "t3.micro", "0.0105")
    assert CostGuard.pricing_catalogue_sha256() != before


def test_to_diagnostic_rejects_exact_overrun_even_if_published_fits(guard):
    resources = {"instances": [{"id": "a", "instance_type": "t3.micro", "count": 2}]}
    result = guard.verify_budget(resources, budget_monthly="15.19")
    assert result.within_budget is True
    result.exact_budget = "15.18"
    result.budget = "15.18"
    diagnostic = CostGuard.to_diagnostic(result)
    assert diagnostic.status.value == "BLOCKED"
    assert diagnostic.developer_fields["audit_trace"]["outcome"] == "INCONSISTENT"


def test_standard_volume_fails_closed(guard):
    # Magnetic volumes also bill per I/O request, which cannot be priced
    # before deployment.
    resources = {"volumes": [{"id": "v", "volume_type": "standard", "size_gb": 100}]}
    result = guard.verify_budget(resources, budget_monthly="1000")
    assert result.within_budget is False
    assert result.has_unknown_types is True
    assert "standard" in result.reason


@pytest.mark.parametrize("storage_key", [
    "gp2-storage-gb", "gp3-storage-gb", "st1-storage-gb",
    "sc1-storage-gb", "standard-storage-gb", "gp2", "gp3",
])
def test_storage_key_as_instance_type_is_unknown(guard, storage_key):
    # #104: volume prices must not be reachable from an instance lookup.
    resources = {"instances": [{"id": "a", "instance_type": storage_key, "count": 1}]}
    result = guard.verify_budget(resources, budget_monthly="100")
    assert result.within_budget is False
    assert result.has_unknown_types is True
    assert storage_key in result.reason
    assert CostGuard.to_diagnostic(result).status.value == "BLOCKED"


@pytest.mark.parametrize("instance_type", ["t3.micro", "p4d.24xlarge", "db.t3.micro"])
def test_instance_type_as_volume_type_is_unknown(guard, instance_type):
    resources = {"volumes": [{"id": "v", "volume_type": instance_type, "size_gb": 10}]}
    result = guard.verify_budget(resources, budget_monthly="1000000")
    assert result.within_budget is False
    assert result.has_unknown_types is True


@pytest.mark.parametrize("vol_type,monthly,budget", [
    ("gp3", "80.00", "25"),
    ("gp2", "100.00", "50"),
])
def test_gp2_gp3_priced_at_aws_list_price(guard, vol_type, monthly, budget):
    # #102: 1000 GB at $0.08 (gp3) and $0.10 (gp2) per GB-month, us-east-1.
    resources = {"volumes": [{"id": "v", "volume_type": vol_type, "size_gb": 1000}]}
    result = guard.verify_budget(resources, budget_monthly=budget)
    assert result.total_monthly_cost == monthly
    assert result.within_budget is False
    assert CostGuard.to_diagnostic(result).status.value == "BLOCKED"
    assert guard.verify_budget(resources, budget_monthly=monthly).within_budget is True


def test_volume_count_multiplies_cost(guard):
    # #92: 50 x 1000 GB gp3 is 50 x $80.
    single = {"volumes": [{"id": "v", "volume_type": "gp3", "size_gb": 1000}]}
    fifty = {"volumes": [{"id": "v", "volume_type": "gp3", "size_gb": 1000, "count": 50}]}
    assert guard.verify_budget(single, budget_monthly="1000").within_budget is True
    result = guard.verify_budget(fifty, budget_monthly="1000")
    assert result.total_monthly_cost == "4000.00"
    assert result.within_budget is False
    assert CostGuard.to_diagnostic(result).status.value == "BLOCKED"


@pytest.mark.parametrize("count", [0, -1, "50", 1.5, True, None])
def test_invalid_volume_count_fails_closed(guard, count):
    resources = {"volumes": [{"id": "v", "volume_type": "gp3", "size_gb": 10, "count": count}]}
    result = guard.verify_budget(resources, budget_monthly="1000")
    assert result.within_budget is False
    assert result.has_unknown_types is True
    assert "invalid-count-v" in result.breakdown


@pytest.mark.parametrize("extra", [
    {"iops": 3000},
    {"throughput": 125},
    {"iops": 3000, "throughput": 125},
])
def test_gp3_baseline_performance_is_included(guard, extra):
    resources = {"volumes": [{"id": "v", "volume_type": "gp3", "size_gb": 100, **extra}]}
    result = guard.verify_budget(resources, budget_monthly="100")
    assert result.within_budget is True
    assert result.total_monthly_cost == "8.00"


@pytest.mark.parametrize("vol_type,extra", [
    ("gp3", {"iops": 16000}),
    ("gp3", {"throughput": 1000}),
    ("gp3", {"iops": "16000"}),
    ("gp3", {"iops": 0}),
    ("gp2", {"iops": 3000}),
    ("st1", {"throughput": 500}),
])
def test_unpriced_provisioned_performance_fails_closed(guard, vol_type, extra):
    resources = {"volumes": [{"id": "v", "volume_type": vol_type, "size_gb": 100, **extra}]}
    result = guard.verify_budget(resources, budget_monthly="100000")
    assert result.within_budget is False
    assert result.has_unknown_types is True
    assert "unpriced-v" in result.breakdown
    assert CostGuard.to_diagnostic(result).status.value == "BLOCKED"


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
