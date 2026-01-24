from typing import List, Dict, Any, Optional, Set
import networkx as nx
from pydantic import BaseModel

class NetworkNode(BaseModel):
    id: str
    type: str # 'subnet', 'internet', 'instance'
    security_groups: List[str] = []

class Route(BaseModel):
    source: str
    destination: str
    target: str # e.g. 'igw', 'nat'

class ComputedPath(BaseModel):
    reachable: bool
    path: List[str]
    reason: str

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
                
                if destination == "0.0.0.0/0" and target.startswith("igw"):
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
        try:
            path = nx.shortest_path(self.graph, source, destination)
        except nx.NetworkXNoPath:
            return ComputedPath(reachable=False, path=[], reason="No Route exists between nodes")
            
        # 3. Check Security Groups (Firewall Logic)
        # simplified: check destination ingress
        dest_node = resources.get("subnets", []) # simplistic lookup
        target_sgs = []
        
        # Find dest subnet definition
        for s in resources.get("subnets", []):
            if s["id"] == destination:
                target_sgs = s.get("security_groups", [])
                break
        
        security_groups = resources.get("security_groups", {})
        
        # Check if ANY attached SG allows ingress on this port
        ingress_allowed = False
        
        if source == "internet":
            # Public Access Check
            for sg_id in target_sgs:
                rules = security_groups.get(sg_id, {}).get("ingress", [])
                for rule in rules:
                    # simplistic rule check
                    rule_port = rule.get("port")
                    rule_cidr = rule.get("cidr")
                    
                    port_match = (rule_port == port) or (rule_port == -1) # -1 is ALL
                    cidr_match = (rule_cidr == "0.0.0.0/0")
                    
                    if port_match and cidr_match:
                        ingress_allowed = True
                        break
                if ingress_allowed: break
        else:
            # Internal Traffic logic (TODO)
            ingress_allowed = True # Assume internal open for v0.1
            
        if not ingress_allowed:
             return ComputedPath(reachable=False, path=path, reason=f"Routing exists but Security Group blocks port {port}")

        return ComputedPath(reachable=True, path=path, reason="Route exists and Security Groups allow traffic")
