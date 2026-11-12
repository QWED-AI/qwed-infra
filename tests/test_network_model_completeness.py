"""NetworkGuard refuses what it does not model, by allowlist rather than
by a list of known spellings (#81, #82, #88, #94)."""

import json

import pytest

from qwed_infra.guards.network_guard import NetworkGuard


@pytest.fixture
def guard():
    return NetworkGuard()


def infra(rule=None, routes=None, extra=None, sg_extra=None, subnet_extra=None):
    subnet = {"id": "subnet-web", "security_groups": ["sg-web"], **(subnet_extra or {})}
    resources = {
        "subnets": [subnet],
        "route_tables": [{"subnet_id": "subnet-web", "routes": routes or {"0.0.0.0/0": "igw-main"}}],
        "security_groups": {
            "sg-web": {"ingress": [rule or {"port": 22, "cidr": "0.0.0.0/0"}], **(sg_extra or {})},
        },
    }
    resources.update(extra or {})
    return resources


def status(guard, resources, port=22):
    return NetworkGuard.to_diagnostic(
        guard.verify_reachability(resources, "internet", "subnet-web", port)
    ).status.value


def admission(guard, resources, port=22):
    doc = guard.to_verification_context(
        resources, "internet", "subnet-web", port,
        formal_statement="subnet-web is reachable from the internet on the port",
    ).to_dict()
    return doc["context"]["decision"]["admission"]


def test_control_open_ssh_is_reachable(guard):
    result = guard.verify_reachability(infra(), "internet", "subnet-web", 22)
    assert result.reachable is True


# ----------------------------------------------------------------------
# #81: unknown topology keys and route targets
# ----------------------------------------------------------------------

@pytest.mark.parametrize("key", [
    "network_acls", "network_acl", "vpc_peering_connection", "gateway_endpoints",
    "firewall", "modules", "nacls", "nat_gateways", "instances",
])
def test_unknown_topology_key_is_unverifiable(guard, key):
    resources = infra(extra={key: [{"id": "x", "deny": "0.0.0.0/0"}]})
    assert status(guard, resources) == "UNVERIFIABLE"
    assert admission(guard, resources) != "ADMIT"


@pytest.mark.parametrize("key", ["network_acls", "nacls"])
def test_unknown_key_refused_even_when_empty(guard, key):
    assert status(guard, infra(extra={key: []})) == "UNVERIFIABLE"


@pytest.mark.parametrize("target", ["pcc-12345", "natgw-1", "tgw", "vgw-1", "eni-1", "vpce-1", "eigw-1", "i-123"])
def test_unmodelled_route_target_is_unverifiable(guard, target):
    resources = infra(routes={"0.0.0.0/0": "igw-main", "10.1.0.0/16": target})
    assert status(guard, resources) == "UNVERIFIABLE"


@pytest.mark.parametrize("routes", [{"not-a-cidr": "igw-main"}, {"0.0.0.0/0": "igw-main", "10.0.0.0/16": "local", "x": "local"}])
def test_route_destination_must_be_a_cidr(guard, routes):
    assert status(guard, infra(routes=routes)) == "UNVERIFIABLE"


def test_local_route_is_modelled(guard):
    resources = infra(routes={"0.0.0.0/0": "igw-main", "10.0.0.0/16": "local"})
    assert status(guard, resources) == "VERIFIED"


@pytest.mark.parametrize("subnet_extra", [{"nacl_id": "acl-1"}, {"route_table_id": "rtb-1"}])
def test_unmodelled_subnet_field_is_unverifiable(guard, subnet_extra):
    assert status(guard, infra(subnet_extra=subnet_extra)) == "UNVERIFIABLE"


def test_unmodelled_security_group_field_is_unverifiable(guard):
    assert status(guard, infra(sg_extra={"vpc_id": "vpc-1"})) == "UNVERIFIABLE"


def test_egress_rules_are_not_read_for_inbound_queries(guard):
    open_egress = infra(sg_extra={"egress": [{"port": 22, "cidr": "0.0.0.0/0"}]})
    assert status(guard, open_egress) == "VERIFIED"
    egress_only = infra(rule={"port": 80, "cidr": "10.0.0.0/8"}, sg_extra={"egress": [{"port": 22, "cidr": "0.0.0.0/0"}]})
    assert status(guard, egress_only) == "BLOCKED"


# ----------------------------------------------------------------------
# #82: rule fields, sentinel, coercion, families, duplicates
# ----------------------------------------------------------------------

@pytest.mark.parametrize("rule", [
    {"port": 53, "protocol": "udp", "cidr": "0.0.0.0/0"},
    {"port": 53, "ip_protocol": "udp", "cidr": "0.0.0.0/0"},
    {"port": 22, "prefix_list_id": "pl-1"},
    {"port": 22, "source_security_group_id": "sg-2"},
    {"port": 22, "cidr": "0.0.0.0/0", "description": "ssh"},
    {"port": 22, "cidr": "0.0.0.0/0", "egress": True},
])
def test_unmodelled_rule_fields_are_unverifiable(guard, rule):
    port = rule.get("port", 22)
    assert status(guard, infra(rule=rule), port=port) == "UNVERIFIABLE"


@pytest.mark.parametrize("rule,port", [
    ({"from_port": 443, "to_port": -1, "cidr": "0.0.0.0/0"}, 22),
    ({"from_port": -1, "to_port": 80, "cidr": "0.0.0.0/0"}, 65535),
    ({"from_port": 79.5, "to_port": 80.5, "cidr": "0.0.0.0/0"}, 79),
    ({"port": "８０", "cidr": "0.0.0.0/0"}, 80),
    ({"port": "8_0", "cidr": "0.0.0.0/0"}, 80),
    ({"port": 70000, "cidr": "0.0.0.0/0"}, 22),
    ({"port": 22.0, "cidr": "0.0.0.0/0"}, 22),
    ({"from_port": 22, "cidr": "0.0.0.0/0"}, 22),
])
def test_invalid_rule_ports_are_unverifiable(guard, rule, port):
    assert status(guard, infra(rule=rule), port=port) == "UNVERIFIABLE"


@pytest.mark.parametrize("port", [99999, -1, 22.5, "22", True, float("inf")])
def test_invalid_query_port_is_unverifiable(guard, port):
    resources = infra(rule={"port": -1, "cidr": "0.0.0.0/0"})
    result = guard.verify_reachability(resources, "internet", "subnet-web", port)
    assert result.reachable is False
    assert NetworkGuard.to_diagnostic(result).status.value == "UNVERIFIABLE"


@pytest.mark.parametrize("rule,port", [
    ({"from_port": -1, "to_port": -1, "cidr": "0.0.0.0/0"}, 65535),
    ({"port": -1, "cidr": "0.0.0.0/0"}, 1),
    ({"port": "22", "cidr": "0.0.0.0/0"}, 22),
    ({"from_port": "20", "to_port": "30", "cidr": "0.0.0.0/0"}, 22),
])
def test_valid_port_forms_still_match(guard, rule, port):
    assert status(guard, infra(rule=rule), port=port) == "VERIFIED"


def test_reversed_range_still_does_not_match(guard):
    assert status(guard, infra(rule={"from_port": 443, "to_port": 80, "cidr": "0.0.0.0/0"}), port=100) == "BLOCKED"


def test_address_families_must_match(guard):
    v4_route_v6_rule = infra(rule={"port": 22, "cidr": "::/0"}, routes={"0.0.0.0/0": "igw-main"})
    assert status(guard, v4_route_v6_rule) == "BLOCKED"
    v6_route_v4_rule = infra(rule={"port": 22, "cidr": "0.0.0.0/0"}, routes={"::/0": "igw-main"})
    assert status(guard, v6_route_v4_rule) == "BLOCKED"
    dual = infra(rule={"port": 22, "cidr": "::/0"}, routes={"0.0.0.0/0": "igw-main", "::/0": "igw-main"})
    assert status(guard, dual) == "VERIFIED"


@pytest.mark.parametrize("open_first", [True, False])
def test_duplicate_subnet_ids_are_unverifiable(guard, open_first):
    resources = infra()
    resources["security_groups"]["sg-closed"] = {"ingress": []}
    open_subnet = {"id": "subnet-web", "security_groups": ["sg-web"]}
    closed_subnet = {"id": "subnet-web", "security_groups": ["sg-closed"]}
    resources["subnets"] = [open_subnet, closed_subnet] if open_first else [closed_subnet, open_subnet]
    assert status(guard, resources) == "UNVERIFIABLE"


def test_two_route_tables_for_one_subnet_are_unverifiable(guard):
    resources = infra()
    resources["route_tables"].append({"subnet_id": "subnet-web", "routes": {}})
    assert status(guard, resources) == "UNVERIFIABLE"


# ----------------------------------------------------------------------
# #88: OverflowError from port coercion
# ----------------------------------------------------------------------

@pytest.mark.parametrize("value", [float("inf"), float("-inf"), json.loads("1e999")])
def test_infinite_rule_port_fails_closed_without_raising(guard, value):
    resources = infra(rule={"port": value, "cidr": "0.0.0.0/0"})
    assert admission(guard, resources) != "ADMIT"
    assert status(guard, resources) == "UNVERIFIABLE"


def test_infinite_query_port_fails_closed_without_raising(guard):
    assert admission(guard, infra(), port=float("inf")) != "ADMIT"


# ----------------------------------------------------------------------
# #94: split ranges cover the internet like 0.0.0.0/0
# ----------------------------------------------------------------------

@pytest.mark.parametrize("cidrs", [
    ["0.0.0.0/1", "128.0.0.0/1"],
    ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/1"],
    ["::/1", "8000::/1"],
])
def test_split_rule_ranges_are_internet(guard, cidrs):
    family_route = "::/0" if ":" in cidrs[0] else "0.0.0.0/0"
    resources = infra(routes={family_route: "igw-main"})
    resources["security_groups"]["sg-web"]["ingress"] = [{"port": 5432, "cidr": c} for c in cidrs]
    assert status(guard, resources, port=5432) == "VERIFIED"


def test_split_ranges_across_security_groups_are_internet(guard):
    resources = infra(rule={"port": 5432, "cidr": "0.0.0.0/1"})
    resources["subnets"][0]["security_groups"].append("sg-other")
    resources["security_groups"]["sg-other"] = {"ingress": [{"port": 5432, "cidr": "128.0.0.0/1"}]}
    assert status(guard, resources, port=5432) == "VERIFIED"


def test_split_routes_are_an_internet_route(guard):
    resources = infra(routes={"0.0.0.0/1": "igw-main", "128.0.0.0/1": "igw-main"})
    result = guard.verify_reachability(resources, "internet", "subnet-web", 22)
    assert result.reachable is True


@pytest.mark.parametrize("cidrs", [["0.0.0.0/1"], ["0.0.0.0/1", "128.0.0.0/2"]])
def test_partial_cover_is_not_the_whole_internet(guard, cidrs):
    resources = infra()
    resources["security_groups"]["sg-web"]["ingress"] = [{"port": 22, "cidr": c} for c in cidrs]
    assert status(guard, resources) == "BLOCKED"


def test_split_rule_on_other_port_does_not_count(guard):
    resources = infra()
    resources["security_groups"]["sg-web"]["ingress"] = [
        {"port": 22, "cidr": "0.0.0.0/1"},
        {"port": 23, "cidr": "128.0.0.0/1"},
    ]
    assert status(guard, resources) == "BLOCKED"
