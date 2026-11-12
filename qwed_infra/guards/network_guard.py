from typing import List, Dict, Any, Optional
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
from qwed_infra.diagnostics import InfraDiagnosticResult, InfraDiagnosticStatus
from qwed_infra.verification_context import VerificationContextDocument

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

    The guard models exactly these inputs, and returns UNVERIFIABLE (a
    result that carries no proof and must not be used for authorization
    decisions) for anything else:

      - top-level keys ``subnets``, ``route_tables`` and ``security_groups``
      - subnets with ``id`` and ``security_groups``; each id once
      - route tables with ``subnet_id`` and ``routes``; one per subnet;
        route targets ``igw...`` (internet gateway) or ``local``
      - security groups with ``ingress`` (and ``egress``, which an inbound
        query never reads: security groups are stateful)
      - ingress rules with ``port``, ``from_port``/``to_port`` and ``cidr``

    So NAT gateways, VPC peering, NACLs, transit gateways, endpoints,
    protocol-scoped rules, prefix lists and security-group references are
    all refused, whatever they are called, instead of being ignored.
    """

    _SUPPORTED_TOPOLOGY_KEYS = frozenset({"subnets", "route_tables", "security_groups"})
    _SUBNET_KEYS = frozenset({"id", "security_groups"})
    _ROUTE_TABLE_KEYS = frozenset({"subnet_id", "routes"})
    _SECURITY_GROUP_KEYS = frozenset({"ingress", "egress"})
    _RULE_KEYS = frozenset({"port", "from_port", "to_port", "cidr"})

    _IPV4_INTERNET = ipaddress.ip_network("0.0.0.0/0")
    _IPV6_INTERNET = ipaddress.ip_network("::/0")

    def __init__(self):
        self.graph = nx.DiGraph()
        self.has_unsupported_topology = False
        self.unsupported_reason = ""

    @staticmethod
    def _normalize_port(value: Any) -> Optional[int]:
        """Return a port number, or None for anything that is not one.

        Accepts an int or a string of ASCII digits (with an optional
        leading minus for the -1 sentinel). Floats, full-width digits,
        underscores and out-of-range values are not ports.
        """
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            number = value
        elif isinstance(value, str):
            text = value[1:] if value.startswith("-") else value
            if not text or not text.isascii() or not text.isdigit():
                return None
            try:
                number = int(value)
            except (ValueError, OverflowError):
                return None
        else:
            return None
        if number == -1 or 0 <= number <= 65535:
            return number
        return None

    def _refuse(self, reason: str) -> None:
        if not self.has_unsupported_topology:
            self.has_unsupported_topology = True
            self.unsupported_reason = reason

    def _check_unsupported_topology(self, resources: Dict[str, Any]) -> None:
        """Refuse every construct outside the modelled set (see class doc).

        Malformed input (wrong container types, a subnet without an id)
        raises TypeError, which to_verification_context maps to BLOCKED.
        Well-formed input the model does not cover marks the topology
        unsupported, which maps to UNVERIFIABLE.
        """
        if not isinstance(resources, dict):
            raise TypeError("resources must be a mapping")
        unknown = sorted(set(resources) - self._SUPPORTED_TOPOLOGY_KEYS, key=str)
        if unknown:
            self._refuse(f"unmodelled topology keys: {unknown}")
            return

        subnets = resources.get("subnets", [])
        if not isinstance(subnets, list):
            raise TypeError("subnets must be a list")
        seen_subnets = set()
        for subnet in subnets:
            if not isinstance(subnet, dict) or "id" not in subnet:
                raise TypeError("each subnet must be a mapping with an id")
            if set(subnet) - self._SUBNET_KEYS:
                self._refuse("subnet has unmodelled fields")
                return
            subnet_id = subnet.get("id")
            if subnet_id in seen_subnets:
                self._refuse(f"duplicate subnet id {subnet_id!r}")
                return
            seen_subnets.add(subnet_id)

        route_tables = resources.get("route_tables", [])
        if not isinstance(route_tables, list):
            raise TypeError("route_tables must be a list")
        routed_subnets = set()
        for rt in route_tables:
            if not isinstance(rt, dict):
                raise TypeError("each route table must be a mapping")
            if set(rt) - self._ROUTE_TABLE_KEYS:
                self._refuse("route table has unmodelled fields")
                return
            subnet_id = rt.get("subnet_id")
            if subnet_id in routed_subnets:
                self._refuse(f"more than one route table for subnet {subnet_id!r}")
                return
            routed_subnets.add(subnet_id)
            routes = rt.get("routes", {})
            if not isinstance(routes, dict):
                raise TypeError("routes must be a mapping")
            for destination, target in routes.items():
                if not isinstance(target, str):
                    self._refuse("route target is not a string")
                    return
                t = target.lower()
                if not (t == "local" or t.startswith("igw")):
                    self._refuse(f"unmodelled route target {target!r}")
                    return
                try:
                    ipaddress.ip_network(destination, strict=False)
                except (TypeError, ValueError):
                    self._refuse(f"route destination {destination!r} is not a CIDR")
                    return

        security_groups = resources.get("security_groups", {})
        if not isinstance(security_groups, dict):
            raise TypeError("security_groups must be a mapping")
        for sg in security_groups.values():
            if not isinstance(sg, dict):
                raise TypeError("each security group must be a mapping")
            if set(sg) - self._SECURITY_GROUP_KEYS:
                self._refuse("security group has unmodelled fields")
                return
            rules = sg.get("ingress", [])
            if not isinstance(rules, list):
                raise TypeError("ingress must be a list")
            for rule in rules:
                if not isinstance(rule, dict):
                    raise TypeError("each ingress rule must be a mapping")
                if set(rule) - self._RULE_KEYS:
                    self._refuse(
                        "ingress rule has unmodelled fields "
                        "(protocol, prefix lists and group references are not modelled)"
                    )
                    return
                if not self._rule_ports_valid(rule):
                    self._refuse("ingress rule has an invalid port specification")
                    return
                try:
                    ipaddress.ip_network(rule.get("cidr"), strict=False)
                except (TypeError, ValueError):
                    self._refuse("ingress rule has no valid cidr")
                    return

    def _rule_ports_valid(self, rule: Dict[str, Any]) -> bool:
        """A rule must use exactly one port form, ``port`` or both
        ``from_port`` and ``to_port``, with port values; -1 must be the AWS
        form: a single ``port`` of -1, or both range ends -1."""
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        if rule.get("port") is not None:
            if from_port is not None or to_port is not None:
                return False
            return self._normalize_port(rule["port"]) is not None
        if from_port is None or to_port is None:
            return False
        low = self._normalize_port(from_port)
        high = self._normalize_port(to_port)
        if low is None or high is None:
            return False
        return (low == -1) == (high == -1)

    @classmethod
    def _internet_families(cls, cidrs: List[Any]) -> set:
        """Return the address families (4, 6) whose whole internet the
        union of ``cidrs`` covers, so split ranges such as 0.0.0.0/1 plus
        128.0.0.0/1 count the same as 0.0.0.0/0."""
        by_family: Dict[int, list] = {4: [], 6: []}
        for cidr in cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except (TypeError, ValueError):
                continue
            by_family[network.version].append(network)
        covered = set()
        for version, whole in ((4, cls._IPV4_INTERNET), (6, cls._IPV6_INTERNET)):
            if whole in ipaddress.collapse_addresses(by_family[version]):
                covered.add(version)
        return covered

    def build_graph(self, resources: Dict[str, Any]):
        """Builds a NetworkX graph from a simplified infrastructure definition."""
        self.graph.clear()
        self.has_unsupported_topology = False
        self.unsupported_reason = ""
        self._check_unsupported_topology(resources)
        if self.has_unsupported_topology:
            return

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
            igw_destinations = [
                destination for destination, target in routes.items()
                if target.lower().startswith("igw")
            ]
            families = self._internet_families(igw_destinations)
            if families:
                via = sorted({routes[d] for d in igw_destinations})
                self.graph.add_edge(subnet_id, "internet", via=via, families=families)
                self.graph.add_edge("internet", subnet_id, via=via, families=families)

    def verify_reachability(self, resources: Dict[str, Any], source: str, destination: str, port: int) -> ComputedPath:
        """
        Checks if traffic can flow from Source to Destination on a specific Port.
        Requires:
        1. Routing Validation (Graph Path exists)
        2. Security Group Validation (Rules allow Ingress/Egress)
        """
        # The queried port must be an int in range; rule fields may also be
        # digit strings, but the query is typed as an int. Checked first, so
        # every return path carries a valid port.
        query_port = self._normalize_port(port) if isinstance(port, int) else None
        if query_port is None or query_port == -1:
            return ComputedPath(
                reachable=False, path=[], port=0, failure_code="unsupported_topology",
                reason=f"Queried port {port!r} is not a port number — cannot verify",
                unsupported_topology=True,
            )
        port = query_port

        self.build_graph(resources)

        if self.has_unsupported_topology:
            return ComputedPath(
                reachable=False, path=[], port=port, failure_code="unsupported_topology",
                reason=f"Topology contains unsupported constructs ({self.unsupported_reason}) — cannot verify",
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
            return ComputedPath(
                reachable=False, path=[], port=port, failure_code="unsupported_topology",
                reason="Internal source reachability is not graph-modeled — cannot verify",
                unsupported_topology=True,
            )

        target_sgs = []

        for s in resources.get("subnets", []):
            if s["id"] == destination:
                target_sgs = s.get("security_groups", [])
                break

        security_groups = resources.get("security_groups", {})

        # Address families the route to the internet carries.
        routed_families = set()
        if source == "internet" and len(path) > 1:
            routed_families = self.graph.edges[path[0], path[1]].get("families", set())

        matching_cidrs = []
        for sg_id in target_sgs:
            rules = security_groups.get(sg_id, {}).get("ingress", [])
            for rule in rules:
                if self._rule_matches_port(rule, port) and rule.get("cidr") is not None:
                    matching_cidrs.append(rule["cidr"])

        # The internet reaches the subnet only if, in one address family,
        # both the routes and the union of matching rule ranges cover it.
        ingress_allowed = bool(routed_families & self._internet_families(matching_cidrs))

        if not target_sgs:
            ingress_allowed = False

        if not ingress_allowed:
            return ComputedPath(reachable=False, path=path, reason=f"Routing exists but Security Group blocks port {port}", port=port, failure_code="sg_ingress_blocked")

        return ComputedPath(reachable=True, path=path, reason="Route exists and Security Groups allow traffic", port=port)

    def _rule_matches_port(self, rule: Dict[str, Any], port: int) -> bool:
        """Port fields were validated by _check_unsupported_topology."""
        if rule.get("port") is not None:
            return self._normalize_port(rule["port"]) in (port, -1)
        if rule.get("from_port") is None:
            return False
        low = self._normalize_port(rule["from_port"])
        high = self._normalize_port(rule["to_port"])
        if low == -1 and high == -1:
            return True
        return low <= high and low <= port <= high

    @staticmethod
    def to_diagnostic(result: ComputedPath) -> InfraDiagnosticResult:
        """Convert a ComputedPath to an InfraDiagnosticResult."""
        if result.unsupported_topology or result.failure_code == "unsupported_topology":
            trace = build_trace(NETWORK_UNSUPPORTED_TOPOLOGY, "UNVERIFIABLE")
            return InfraDiagnosticResult.unverifiable(
                agent_message="Network reachability cannot be verified — topology contains unsupported constructs",
                developer_fields={
                    "constraint_id": _NETWORK_CONSTRAINT_ID,
                    "reachable": False,
                    "path": [],
                    "port": result.port,
                    "reason": result.reason,
                    "failure_code": result.failure_code,
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
            "unsupported_topology": NETWORK_UNSUPPORTED_TOPOLOGY,
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

    def to_verification_context(
        self,
        resources: Dict[str, Any],
        source: str,
        destination: str,
        port: int,
        *,
        formal_statement: str,
        attestation_token: Optional[str] = None,
    ) -> VerificationContextDocument:
        """Run the reachability check and map the result to a VC v1.0 document.

        The guard performs the computation itself via verify_reachability(),
        so a caller cannot inject a result object of any kind. Malformed
        inputs (non-dict resources, missing subnet "id" keys, etc.) map to a
        fail-closed BLOCKED diagnostic rather than propagating an exception.
        The provenance gate remains as defense-in-depth: only a VERIFIED
        diagnostic carrying NetworkGuard provenance and an explicit
        reachable=True outcome is admitted; anything else is BLOCKED.
        """
        try:
            result = self.verify_reachability(resources, source, destination, port)
        except (TypeError, ValueError, AttributeError, KeyError, OverflowError):
            diagnostic = InfraDiagnosticResult.blocked(
                agent_message="Network reachability could not be verified",
                developer_fields={
                    "constraint_id": _NETWORK_CONSTRAINT_ID,
                    "reachable": False,
                    "reason": "Invalid inputs to the reachability check — fail closed",
                    "audit_trace": build_trace(NETWORK_UNSUPPORTED_TOPOLOGY, "INVALID_INPUT"),
                },
            )
        else:
            diagnostic = self.to_diagnostic(result)
        decision_status = None
        if diagnostic.status is InfraDiagnosticStatus.VERIFIED and not (
            diagnostic.developer_fields.get("constraint_id") == _NETWORK_CONSTRAINT_ID
            and diagnostic.developer_fields.get("reachable") is True
        ):
            decision_status = InfraDiagnosticStatus.BLOCKED

        from qwed_infra.verification_context_bridge import (
            verification_context_from_diagnostic_result,
        )

        return verification_context_from_diagnostic_result(
            diagnostic,
            formal_statement=formal_statement,
            attestation_token=attestation_token,
            verifier="NetworkGuard",
            decision_status=decision_status,
        )
