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


@pytest.fixture
def internal_infra():
    """Infrastructure with internal subnet-to-subnet routing + CIDR-restricted SG."""
    return {
        "subnets": [
            {"id": "subnet-app", "security_groups": ["sg-app"]},
            {"id": "subnet-db", "security_groups": ["sg-db"]},
            {"id": "subnet-mgmt", "security_groups": ["sg-mgmt"]},
        ],
        "route_tables": [
            {
                "subnet_id": "subnet-app",
                "routes": {"0.0.0.0/0": "igw-main"}
            },
            {
                "subnet_id": "subnet-db",
                "routes": {"0.0.0.0/0": "igw-main"}
            },
            {
                "subnet_id": "subnet-mgmt",
                "routes": {"0.0.0.0/0": "igw-main"}
            },
        ],
        "security_groups": {
            "sg-app": {
                "ingress": [{"port": 80, "cidr": "0.0.0.0/0"}]
            },
            "sg-db": {
                "ingress": [{"port": 5432, "cidr": "10.0.0.0/16"}]
            },
            "sg-mgmt": {
                "ingress": [{"port": 22, "cidr": "10.0.0.0/16"}]
            },
        },
    }


def test_internal_cidr_allowed(guard, internal_infra):
    """Internal source within CIDR range should be reachable (#14)."""
    result = guard.verify_reachability(
        internal_infra,
        source="10.0.1.5",
        destination="subnet-db",
        port=5432,
    )
    assert result.reachable is True
    assert "Security Groups allow" in result.reason


def test_internal_cidr_blocked(guard, internal_infra):
    """Internal source OUTSIDE CIDR range must be blocked — was false negative (#14)."""
    result = guard.verify_reachability(
        internal_infra,
        source="192.168.1.100",
        destination="subnet-db",
        port=5432,
    )
    assert result.reachable is False
    assert "Security Group blocks" in result.reason


def test_internal_port_match_cidr_mismatch_blocked(guard, internal_infra):
    """Port matches but CIDR doesn't — must be blocked (#14)."""
    result = guard.verify_reachability(
        internal_infra,
        source="172.16.0.1",
        destination="subnet-db",
        port=5432,
    )
    assert result.reachable is False


def test_internal_ssh_cidr_restricted(guard, internal_infra):
    """SSH from within CIDR is allowed, from outside is blocked (#14)."""
    # Within CIDR
    result_in = guard.verify_reachability(
        internal_infra, source="10.0.0.50", destination="subnet-mgmt", port=22
    )
    assert result_in.reachable is True

    # Outside CIDR
    result_out = guard.verify_reachability(
        internal_infra, source="192.168.1.50", destination="subnet-mgmt", port=22
    )
    assert result_out.reachable is False


def test_internet_cidr_still_works(guard, internal_infra):
    """Internet source with 0.0.0.0/0 rule should still work (regression)."""
    result = guard.verify_reachability(
        internal_infra, source="internet", destination="subnet-app", port=80
    )
    assert result.reachable is True


def test_internet_specific_public_cidr_allowed(guard, internal_infra):
    """Internet source with specific public CIDR (8.8.8.0/24) must be allowed."""
    infra = {
        "subnets": [{"id": "subnet-public", "security_groups": ["sg-specific"]}],
        "route_tables": [{"subnet_id": "subnet-public", "routes": {"0.0.0.0/0": "igw-main"}}],
        "security_groups": {
            "sg-specific": {"ingress": [{"port": 443, "cidr": "8.8.8.0/24"}]},
        },
    }
    result = guard.verify_reachability(
        infra, source="internet", destination="subnet-public", port=443
    )
    assert result.reachable is True
    assert "Security Groups allow" in result.reason


def test_internet_ipv6_wildcard_allowed(guard, internal_infra):
    """Internet source against IPv6 ::/0 rule must be allowed (not silently blocked)."""
    infra = {
        "subnets": [{"id": "subnet-v6", "security_groups": ["sg-v6"]}],
        "route_tables": [{"subnet_id": "subnet-v6", "routes": {"::/0": "igw-main"}}],
        "security_groups": {
            "sg-v6": {"ingress": [{"port": 443, "cidr": "::/0"}]},
        },
    }
    result = guard.verify_reachability(
        infra, source="internet", destination="subnet-v6", port=443
    )
    assert result.reachable is True


def test_internet_reserved_cidr_blocked(guard, internal_infra):
    """Reserved CIDR (0.0.0.0/8) must NOT match as internet-reachable."""
    infra = {
        "subnets": [{"id": "subnet-reserved", "security_groups": ["sg-reserved"]}],
        "route_tables": [{"subnet_id": "subnet-reserved", "routes": {"0.0.0.0/0": "igw-main"}}],
        "security_groups": {
            "sg-reserved": {"ingress": [{"port": 443, "cidr": "0.0.0.0/8"}]},
        },
    }
    result = guard.verify_reachability(
        infra, source="internet", destination="subnet-reserved", port=443
    )
    assert result.reachable is False
    assert "Security Group blocks" in result.reason


def test_internet_blocked_by_cidr_restricted_sg(guard, internal_infra):
    """Internet source hitting CIDR-restricted SG (10.0.0.0/16) must be blocked."""
    result = guard.verify_reachability(
        internal_infra, source="internet", destination="subnet-db", port=5432
    )
    assert result.reachable is False
    assert "Security Group blocks" in result.reason


def test_invalid_cidr_fails_closed(guard, internal_infra):
    """Invalid CIDR in SG rule must fail-closed, not silently pass (#14)."""
    infra = {
        "subnets": [{"id": "subnet-bad", "security_groups": ["sg-bad"]}],
        "route_tables": [{"subnet_id": "subnet-bad", "routes": {"0.0.0.0/0": "igw-main"}}],
        "security_groups": {
            "sg-bad": {"ingress": [{"port": 80, "cidr": "not-a-cidr"}]},
        },
    }
    result = guard.verify_reachability(
        infra, source="10.0.0.1", destination="subnet-bad", port=80
    )
    assert result.reachable is False


def test_invalid_internal_source_rejected(guard, internal_infra):
    """Non-IP internal source must fail-closed."""
    result = guard.verify_reachability(
        internal_infra, source="not-an-ip", destination="subnet-app", port=80
    )
    assert result.reachable is False
    assert "Invalid internal source" in result.reason


def test_internal_source_unknown_destination(guard, internal_infra):
    """Internal source targeting non-existent subnet must fail-closed."""
    result = guard.verify_reachability(
        internal_infra, source="10.0.0.1", destination="subnet-ghost", port=80
    )
    assert result.reachable is False
    assert "not found in subnets" in result.reason
