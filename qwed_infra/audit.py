"""
Structured audit trace for guard verdicts.

Provides canonical rule references and trace-building utilities
so that all guards produce machine-readable audit trails instead
of free-text reason strings.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class RuleRef:
    """A canonical, immutable (rule_id, statute, jurisdiction) reference."""

    rule_id: str
    statute: str
    jurisdiction: str = "GENERIC"


# --- Infrastructure Rule References ---------------------------------------

# IAM Guard
IAM_DENY_PRECEDENCE = RuleRef(
    "IAM_DENY_PRECEDENCE",
    "AWS IAM Evaluation Logic (deny precedence)",
)
IAM_WILDCARD_MATCH = RuleRef(
    "IAM_WILDCARD_MATCH",
    "AWS IAM Action/Resource Wildcard Matching",
)
IAM_IP_CONDITION = RuleRef(
    "IAM_IP_CONDITION",
    "AWS IAM Condition Keys (aws:SourceIp)",
)
IAM_DATE_CONDITION = RuleRef(
    "IAM_DATE_CONDITION",
    "AWS IAM Condition Keys (aws:CurrentTime)",
)
IAM_STRING_CONDITION = RuleRef(
    "IAM_STRING_CONDITION",
    "AWS IAM Condition Keys (StringEquals / StringLike)",
)
IAM_UNKNOWN_OPERATOR = RuleRef(
    "IAM_UNKNOWN_OPERATOR",
    "AWS IAM Condition Operators (unknown operator — fail closed)",
)

# Network Guard
NETWORK_SG_INGRESS = RuleRef(
    "NETWORK_SG_INGRESS",
    "AWS Security Group Ingress Rules",
)
NETWORK_REACHABILITY = RuleRef(
    "NETWORK_REACHABILITY",
    "AWS VPC Routing + SG Evaluation",
)
NETWORK_NO_ROUTE = RuleRef(
    "NETWORK_NO_ROUTE",
    "AWS VPC Routing (no path between nodes)",
)
NETWORK_INVALID_INTERNAL = RuleRef(
    "NETWORK_INVALID_INTERNAL",
    "AWS VPC (invalid internal source IP)",
)
NETWORK_UNKNOWN_DEST = RuleRef(
    "NETWORK_UNKNOWN_DEST",
    "AWS VPC (destination subnet not found)",
)
NETWORK_UNSUPPORTED_TOPOLOGY = RuleRef(
    "NETWORK_UNSUPPORTED_TOPOLOGY",
    "AWS VPC Topology (unsupported constructs — cannot verify)",
)

# Cost Guard
COST_BUDGET_EXCEEDED = RuleRef(
    "COST_BUDGET_EXCEEDED",
    "AWS Pricing + Budget Policy",
)
COST_UNKNOWN_RESOURCE = RuleRef(
    "COST_UNKNOWN_RESOURCE",
    "AWS Pricing Catalog (unknown instance type)",
)
COST_WITHIN_BUDGET = RuleRef(
    "COST_WITHIN_BUDGET",
    "AWS Pricing + Budget Policy (within budget)",
)

# Artifact Boundary Guard
ARTIFACT_SECRET_LEAK = RuleRef(
    "ARTIFACT_SECRET_LEAK",
    "Artifact boundary — secret or credentials in release surface",
)
ARTIFACT_DEBUG_INCLUSION = RuleRef(
    "ARTIFACT_DEBUG_INCLUSION",
    "Artifact boundary — debug or test artifact in release surface",
)
ARTIFACT_UNKNOWN_BOUNDARY = RuleRef(
    "ARTIFACT_UNKNOWN_BOUNDARY",
    "Artifact boundary — uninspectable release surface",
)
ARTIFACT_MISSING_CONTROL = RuleRef(
    "ARTIFACT_MISSING_CONTROL",
    "Artifact boundary — missing package boundary controls",
)


def build_trace(
    rule: RuleRef,
    outcome: str,
    inputs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build a structured audit-trace entry for a guard verdict.
    """
    return {
        "rule_id": rule.rule_id,
        "statute": rule.statute,
        "jurisdiction": rule.jurisdiction,
        "outcome": outcome,
        "inputs": copy.deepcopy(inputs) if inputs else {},
    }


def trace_proof_ref(trace: Dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 proof reference from an audit trace."""
    try:
        payload = json.dumps(trace, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Audit trace must be JSON-serializable for proof_ref hashing: {exc}"
        ) from exc
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


__all__ = [
    "RuleRef",
    "build_trace",
    "trace_proof_ref",
    "IAM_DENY_PRECEDENCE",
    "IAM_WILDCARD_MATCH",
    "IAM_IP_CONDITION",
    "IAM_DATE_CONDITION",
    "IAM_STRING_CONDITION",
    "IAM_UNKNOWN_OPERATOR",
    "NETWORK_SG_INGRESS",
    "NETWORK_REACHABILITY",
    "NETWORK_NO_ROUTE",
    "NETWORK_INVALID_INTERNAL",
    "NETWORK_UNKNOWN_DEST",
    "NETWORK_UNSUPPORTED_TOPOLOGY",
    "COST_BUDGET_EXCEEDED",
    "COST_UNKNOWN_RESOURCE",
    "COST_WITHIN_BUDGET",
    "ARTIFACT_SECRET_LEAK",
    "ARTIFACT_DEBUG_INCLUSION",
    "ARTIFACT_UNKNOWN_BOUNDARY",
    "ARTIFACT_MISSING_CONTROL",
]
