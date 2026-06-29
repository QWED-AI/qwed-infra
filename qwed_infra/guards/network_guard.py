from typing import List, Dict, Any
import ipaddress
import networkx as nx
from pydantic import BaseModel

from qwed_infra.audit import (
    NETWORK_INVALID_INTERNAL,
    NETWORK_NO_ROUTE,
    NETWORK_REACHABILITY,
    NETWORK_SG_INGRESS,
    NETWORK_UNKNOWN_DEST,
    NETWORK_UNSUPPORTED_TOPOLOGY,
    build_trace,
)
from qwed_infra.diagnostics import InfraDiagnosticResult

_NETWORK_CONSTRAINT_ID = "network_guard.verify_reachability"


class ComputedPath(BaseModel):
    model_config = {"extra": "forbid"}
    reachable: bool
    path: List[str]
    reason: str
    port: int = 0
    failure_code: str = ""
    unsupported_topology: bool = False


class NetworkGuard:
    """
    Network Reachability Verification using Graph Theory (NetworkX).

    Topology limitations (fail-closed if any are present):
      - NAT Gateways (cannot model private subnet internet access)
      - VPC Peering (cannot model cross-VPC routing)
      - NACLs (not modeled — stateless firewall rules)
      - Transit Gateway (cannot model multi-VPC hub routing)

    If the input topology contains any of these constructs, the guard
    returns UNVERIFIABLE — a result that carries no proof and must not
    be used for authorization decisions.
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.has_unsupported_topology = False

    def _check_unsupported_topology(self, resources: Dict[str, Any]) -> None:
        """Scan resources for unsupported topology constructs and set flag."""
        if resources.get("nacls"):
            self.has_unsupported_topology = True
            return

        if resources.get("vpc_peering"):
            self.has_unsupported_topology = True
            return

        route_tables = resources.get("route_tables", [])
        for rt in route_tables:
            routes = rt.get("routes", {})
            for _dest, target in routes.items():
                t = target.lower()
                if any(kw in t for kw in ("nat", "ngw", "tgw", "pcx")):
                    self.has_unsupported_topology = True
                    return

    def build_graph(self, resources: Dict[str, Any]):
        """Builds a NetworkX graph from a simplified infrastructure definition."""
        self.graph.clear()
        self.has_unsupported_topology = False
        self._check_unsupported_topology(resources)

        subnets = resources.get("subnets", [])
        for subnet in subnets:
            self.graph.add_node(subnet["id"], type="subnet", sgs=subnet.get("security_groups", []))

        self.graph.add_node("internet", type="external")

        route_tables = resources.get("route_tables", [])
        for rt in route_tables:
            subnet_id = rt.get("subnet_id")
            if not subnet_id:
                continue
            routes = rt.get("routes", {})

            for destination in routes:
                target = routes[destination]

                if destination in ("0.0.0.0/0", "::/0") and target.startswith("igw"):
                    self.graph.add_edge(subnet_id, "internet", via=target)
                    self.graph.add_edge("internet", subnet_id, via=target)

    def verify_reachability(self, resources: Dict[str, Any], source: str, destination: str, port: int) -> ComputedPath:
        """
        Checks if traffic can flow from Source to Destination on a specific Port.
        Requires:
        1. Routing Validation (Graph Path exists)
        2. Security Group Validation (Rules allow Ingress/Egress)
        """
        self.build_graph(resources)

        if self.has_unsupported_topology:
            return ComputedPath(
                reachable=False, path=[], port=port, failure_code="unsupported_topology",
                reason="Topology contains unsupported constructs (NAT, NACL, peering, transit gateway) — cannot verify",
                unsupported_topology=True,
            )

        if source == "internet":
            try:
                path = nx.shortest_path(self.graph, source, destination)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                return ComputedPath(reachable=False, path=[], reason="No Route exists between nodes", port=port, failure_code="no_route")
        else:
            try:
                addr = ipaddress.ip_address(source)
            except ValueError:
                return ComputedPath(reachable=False, path=[], reason=f"Invalid internal source: '{source}'", port=port, failure_code="invalid_internal_source")
            if not addr.is_private:
                return ComputedPath(reachable=False, path=[], reason=f"Internal source '{source}' is not a private IP", port=port, failure_code="invalid_internal_source")
            dest_exists = any(s["id"] == destination for s in resources.get("subnets", []))
            if not dest_exists:
                return ComputedPath(reachable=False, path=[], reason=f"Destination '{destination}' not found in subnets", port=port, failure_code="unknown_destination")
            path = [source, destination]

        target_sgs = []

        for s in resources.get("subnets", []):
            if s["id"] == destination:
                target_sgs = s.get("security_groups", [])
                break

        security_groups = resources.get("security_groups", {})

        ingress_allowed = False

        for sg_id in target_sgs:
            rules = security_groups.get(sg_id, {}).get("ingress", [])
            for rule in rules:
                rule_port = rule.get("port")
                rule_from = rule.get("from_port")
                rule_to = rule.get("to_port")
                rule_cidr = rule.get("cidr")

                if rule_port is not None:
                    port_match = (rule_port == port) or (rule_port == -1)
                elif rule_from is not None and rule_to is not None:
                    port_match = (rule_from <= port <= rule_to) or (rule_from == -1)
                else:
                    port_match = False

                if not port_match:
                    continue

                if rule_cidr is None:
                    continue

                try:
                    network = ipaddress.ip_network(rule_cidr, strict=False)
                    if source == "internet":
                        cidr_match = rule_cidr in ("0.0.0.0/0", "::/0")
                    else:
                        addr = ipaddress.ip_address(source)
                        cidr_match = addr in network
                except (ValueError, TypeError):
                    cidr_match = False

                if cidr_match:
                    ingress_allowed = True
                    break
            if ingress_allowed:
                break

        if not target_sgs:
            ingress_allowed = False

        if not ingress_allowed:
            return ComputedPath(reachable=False, path=path, reason=f"Routing exists but Security Group blocks port {port}", port=port, failure_code="sg_ingress_blocked")

        return ComputedPath(reachable=True, path=path, reason="Route exists and Security Groups allow traffic", port=port)

    @staticmethod
    def to_diagnostic(result: ComputedPath) -> InfraDiagnosticResult:
        """Convert a ComputedPath to an InfraDiagnosticResult."""
        if result.unsupported_topology:
            trace = build_trace(NETWORK_UNSUPPORTED_TOPOLOGY, "UNVERIFIABLE")
            return InfraDiagnosticResult.unverifiable(
                agent_message="Network reachability cannot be verified — topology contains unsupported constructs",
                developer_fields={
                    "constraint_id": _NETWORK_CONSTRAINT_ID,
                    "reachable": False,
                    "path": [],
                    "port": result.port,
                    "reason": result.reason,
                    "unsupported_topology": True,
                    "audit_trace": trace,
                },
            )

        if result.reachable:
            trace = build_trace(NETWORK_REACHABILITY, "ALLOWED")
            return InfraDiagnosticResult.verified(
                agent_message="Network reachability verified",
                developer_fields={
                    "constraint_id": _NETWORK_CONSTRAINT_ID,
                    "reachable": result.reachable,
                    "path": result.path,
                    "port": result.port,
                    "reason": result.reason,
                    "audit_trace": trace,
                },
                evidence={**trace, "path": result.path, "port": result.port, "reason": result.reason},
            )

        rule_map = {
            "no_route": NETWORK_NO_ROUTE,
            "invalid_internal_source": NETWORK_INVALID_INTERNAL,
            "unknown_destination": NETWORK_UNKNOWN_DEST,
            "sg_ingress_blocked": NETWORK_SG_INGRESS,
        }
        if not result.failure_code or result.failure_code not in rule_map:
            raise ValueError(
                f"ComputedPath missing or invalid failure_code: {result.failure_code!r}"
            )
        rule = rule_map[result.failure_code]
        trace = build_trace(rule, "BLOCKED")
        return InfraDiagnosticResult.blocked(
            agent_message="Network reachability blocked",
            developer_fields={
                "constraint_id": _NETWORK_CONSTRAINT_ID,
                "reachable": result.reachable,
                "path": result.path,
                "port": result.port,
                "reason": result.reason,
                "failure_code": result.failure_code,
                "audit_trace": trace,
            },
        )
