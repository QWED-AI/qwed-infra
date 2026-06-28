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
    build_trace,
)
from qwed_infra.diagnostics import InfraDiagnosticResult

_NETWORK_CONSTRAINT_ID = "network_guard.verify_reachability"

class NetworkNode(BaseModel):
    model_config = {"extra": "forbid"}
    id: str
    type: str # 'subnet', 'internet', 'instance'
    security_groups: List[str] = []

class Route(BaseModel):
    model_config = {"extra": "forbid"}
    source: str
    destination: str
    target: str # e.g. 'igw', 'nat'

class ComputedPath(BaseModel):
    model_config = {"extra": "forbid"}
    reachable: bool
    path: List[str]
    reason: str
    port: int = 0
    failure_code: str = ""

class NetworkGuard:
    """
    Deterministic Network Reachability Verification using Graph Theory (NetworkX).
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()
        
    def build_graph(self, resources: Dict[str, Any]):
        """
        Builds a NetworkX graph from a simplified infrastructure definition.
        """
        self.graph.clear()
        
        # 1. Add Nodes (Subnets, Internet)
        subnets = resources.get("subnets", [])
        for subnet in subnets:
            self.graph.add_node(subnet["id"], type="subnet", sgs=subnet.get("security_groups", []))
            
        # Always add Internet node
        self.graph.add_node("internet", type="external")
        
        # 2. Add Edges based on Route Tables
        # Simplified: If a route exists, valid path (ignoring NACLs for v1)
        route_tables = resources.get("route_tables", [])
        for rt in route_tables:
            subnet_id = rt["subnet_id"]
            routes = rt["routes"]
            
            for destination in routes:
                target = routes[destination] # e.g. 'igw-123'
                
                if destination in ("0.0.0.0/0", "::/0") and target.startswith("igw"):
                    # Route to Internet
                    self.graph.add_edge(subnet_id, "internet", via=target)
                    self.graph.add_edge("internet", subnet_id, via=target) # Assume stateful return for now implies reachability? No, let's keep it directed.
                    # Actually, for "Accessibility", typically we care if Ingress is allowed.
                    # Routing is necessary but not sufficient.
                    
                # TODO: Peering, NAT Gateway logic
                
    def verify_reachability(self, resources: Dict[str, Any], source: str, destination: str, port: int) -> ComputedPath:
        """
        Checks if traffic can flow from Source to Destination on a specific Port.
        Requires:
        1. Routing Validation (Graph Path exists)
        2. Security Group Validation (Rules allow Ingress/Egress)
        """
        
        # 1. Build Graph for Routing
        self.build_graph(resources)

        # 2. Check Physical Path (Routing)
        # For internet sources, check graph path (IGW routing)
        # For internal sources (IP addresses), skip graph check — internal
        # VPC routing is implicit and does not require an IGW route entry.
        if source == "internet":
            try:
                path = nx.shortest_path(self.graph, source, destination)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                return ComputedPath(reachable=False, path=[], reason="No Route exists between nodes", port=port, failure_code="no_route")
        else:
            # Internal source — verify source is a valid private IP address
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
            
        # 3. Check Security Groups (Firewall Logic)
        target_sgs = []
        
        # Find dest subnet definition
        for s in resources.get("subnets", []):
            if s["id"] == destination:
                target_sgs = s.get("security_groups", [])
                break
        
        security_groups = resources.get("security_groups", {})
        
        # Check if ANY attached SG allows ingress on this port
        ingress_allowed = False

        for sg_id in target_sgs:
            rules = security_groups.get(sg_id, {}).get("ingress", [])
            for rule in rules:
                rule_port = rule.get("port")
                rule_cidr = rule.get("cidr")

                port_match = (rule_port == port) or (rule_port == -1)
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
        rule = rule_map.get(result.failure_code, NETWORK_SG_INGRESS)
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
