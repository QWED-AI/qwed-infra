from typing import Any, Dict

from pydantic import BaseModel

from qwed_infra.audit import (
    COST_BUDGET_EXCEEDED,
    COST_UNKNOWN_RESOURCE,
    COST_WITHIN_BUDGET,
    build_trace,
)
from qwed_infra.diagnostics import InfraDiagnosticResult

_COST_CONSTRAINT_ID = "cost_guard.verify_budget"


class CostEstimate(BaseModel):
    model_config = {"extra": "forbid"}
    total_monthly_cost: float
    currency: str = "USD"
    breakdown: Dict[str, float]
    within_budget: bool
    budget: float
    reason: str
    has_unknown_types: bool = False


class CostGuard:
    """
    Deterministic Cloud Cost Verification.
    Prevents over-provisioning by checking estimated costs against a budget.
    """
    
    # Simplified Static Pricing Catalog (USD per hour)
    PRICING_CATALOG = {
        "t3.micro": 0.0104,
        "t3.small": 0.0208,
        "t3.medium": 0.0416,
        "m5.large": 0.096,
        "c5.large": 0.085,
        "g4dn.xlarge": 0.526,
        "p4d.24xlarge": 32.77,
        "db.t3.micro": 0.017,
        "db.m5.large": 0.142,
        "gp2-storage-gb": 0.0000315,
    }
    
    HOURS_PER_MONTH = 730
    
    def verify_budget(self, resources: Dict[str, Any], budget_monthly: float) -> CostEstimate:
        total_hourly_cost = 0.0
        breakdown = {}
        unknown_instance_types = []

        instances = resources.get("instances", [])
        for inst in instances:
            inst_type = inst.get("instance_type", "t3.micro")
            count = inst.get("count", 1)
            price = self.PRICING_CATALOG.get(inst_type)
            if price is None:
                breakdown[f"unknown-{inst.get('id', inst_type)}"] = 0.0
                unknown_instance_types.append(inst_type)
                continue

            cost = price * count
            total_hourly_cost += cost
            breakdown[inst['id']] = cost * self.HOURS_PER_MONTH

        volumes = resources.get("volumes", [])
        for vol in volumes:
            size_gb = vol.get("size_gb", 10)
            price_per_gb_hour = self.PRICING_CATALOG.get("gp2-storage-gb", 0.0)
            cost = size_gb * price_per_gb_hour
            total_hourly_cost += cost
            breakdown[f"vol-{vol.get('id', 'unknown')}"] = cost * self.HOURS_PER_MONTH

        total_monthly = total_hourly_cost * self.HOURS_PER_MONTH
        has_unknown = bool(unknown_instance_types)
        within_budget = (total_monthly <= budget_monthly) and not has_unknown

        if has_unknown:
            reason = (
                f"Cost estimate incomplete — unknown instance types: "
                f"{sorted(set(unknown_instance_types))}. "
                f"Known cost ${total_monthly:.2f} vs budget ${budget_monthly:.2f}."
            )
        elif within_budget:
            reason = f"Estimated cost ${total_monthly:.2f} is within budget ${budget_monthly:.2f}"
        else:
            reason = f"Estimated cost ${total_monthly:.2f} EXCEEDS budget ${budget_monthly:.2f}"

        return CostEstimate(
            total_monthly_cost=total_monthly,
            breakdown=breakdown,
            within_budget=within_budget,
            budget=budget_monthly,
            reason=reason,
            has_unknown_types=has_unknown,
        )

    @staticmethod
    def to_diagnostic(result: CostEstimate) -> InfraDiagnosticResult:
        if result.has_unknown_types:
            trace = build_trace(COST_UNKNOWN_RESOURCE, "INCOMPLETE")
            return InfraDiagnosticResult.blocked(
                agent_message="Cost estimate incomplete — unknown resource types",
                developer_fields={
                    "constraint_id": _COST_CONSTRAINT_ID,
                    "within_budget": result.within_budget,
                    "total_monthly_cost": result.total_monthly_cost,
                    "budget": result.budget,
                    "reason": result.reason,
                    "has_unknown_types": result.has_unknown_types,
                    "audit_trace": trace,
                },
            )

        if not result.within_budget:
            trace = build_trace(COST_BUDGET_EXCEEDED, "EXCEEDED")
            return InfraDiagnosticResult.blocked(
                agent_message="Cost estimate exceeds budget",
                developer_fields={
                    "constraint_id": _COST_CONSTRAINT_ID,
                    "within_budget": result.within_budget,
                    "total_monthly_cost": result.total_monthly_cost,
                    "budget": result.budget,
                    "reason": result.reason,
                    "audit_trace": trace,
                },
            )

        trace = build_trace(COST_WITHIN_BUDGET, "ALLOWED")
        return InfraDiagnosticResult.verified(
            agent_message="Cost estimate within budget",
            developer_fields={
                "constraint_id": _COST_CONSTRAINT_ID,
                "within_budget": result.within_budget,
                "total_monthly_cost": result.total_monthly_cost,
                "budget": result.budget,
                "reason": result.reason,
                "audit_trace": trace,
            },
            evidence={**trace, "total_monthly_cost": result.total_monthly_cost, "budget": result.budget},
        )
