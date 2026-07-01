from qwed_infra.guards.network_guard import NetworkGuard
from qwed_infra.guards.cost_guard import CostGuard


def test_network_guard_readme_example():
    net = NetworkGuard()
    infra = {
        "subnets": [
            {"id": "subnet-web", "security_groups": ["sg-web"]},
        ],
        "route_tables": [
            {
                "subnet_id": "subnet-web",
                "routes": {"0.0.0.0/0": "igw-main"},
            }
        ],
        "security_groups": {
            "sg-web": {"ingress": [{"port": 80, "cidr": "0.0.0.0/0"}]},
        },
    }
    result = net.verify_reachability(infra, "internet", "subnet-web", port=80)
    assert result.reachable is True
    diagnostic = NetworkGuard.to_diagnostic(result)
    assert diagnostic.status.value in ("VERIFIED", "BLOCKED", "UNVERIFIABLE")


def test_cost_guard_readme_example():
    cost = CostGuard()
    resources = {
        "instances": [
            {"id": "gpu", "instance_type": "p4d.24xlarge", "count": 2}
        ]
    }
    result = cost.verify_budget(resources, budget_monthly=1000)
    assert result.within_budget is False
    assert result.total_monthly_cost == "47844.20"
    assert result.budget == "1000.00"
    assert result.reason == "Estimated cost $47844.20 EXCEEDS budget $1000.00"
