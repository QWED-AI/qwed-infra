import pytest
from qwed_infra.guards.network_guard import NetworkGuard

@pytest.fixture
def guard():
    return NetworkGuard()

@pytest.fixture
def mock_infra():
    return {
        "subnets": [
            {"id": "subnet-public", "security_groups": ["sg-web"]},
            {"id": "subnet-private", "security_groups": ["sg-db"]}
        ],
        "route_tables": [
            {
                "subnet_id": "subnet-public",
                "routes": {
                    "0.0.0.0/0": "igw-main"
                }
            },
            {
                "subnet_id": "subnet-private",
                "routes": {
                    # No route to IGW, only local VPC
                }
            }
        ],
        "security_groups": {
            "sg-web": {
                "ingress": [
                    {"port": 80, "cidr": "0.0.0.0/0"},
                    {"port": 443, "cidr": "0.0.0.0/0"}
                ]
            },
            "sg-db": {
                "ingress": [
                    {"port": 5432, "cidr": "10.0.0.0/16"} # Internal only
                ]
            }
        }
    }

def test_public_reachability_allowed(guard, mock_infra):
    # Public Subnet should be reachable on Port 80 from Internet
    # 1. Route exists (subnet-public -> igw-main -> internet) in our undirected assumption or implicit return
    # Wait, our graph logic for 'internet' -> 'subnet' node edge creation needs review.
    # In implementation:
    # if destination == "0.0.0.0/0" and target.startswith("igw"):
    #   self.graph.add_edge("internet", subnet_id, via=target)
    
    result = guard.verify_reachability(
        mock_infra, 
        source="internet", 
        destination="subnet-public", 
        port=80
    )
    assert result.reachable is True
    assert "Route exists" in result.reason

def test_public_reachability_blocked_by_sg(guard, mock_infra):
    # Port 22 (SSH) is NOT in sg-web
    result = guard.verify_reachability(
        mock_infra, 
        source="internet", 
        destination="subnet-public", 
        port=22
    )
    assert result.reachable is False
    assert "Security Group blocks" in result.reason

def test_private_reachability_no_route(guard, mock_infra):
    # Internet to Private Subnet - No Route
    result = guard.verify_reachability(
        mock_infra, 
        source="internet", 
        destination="subnet-private", 
        port=5432
    )
    assert result.reachable is False
    assert "No Route exists" in result.reason
