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

    PRICING_CATALOG = {
        # EC2 instances (USD per hour)
        "t3.micro": 0.0104,
        "t3.small": 0.0208,
        "t3.medium": 0.0416,
        "m5.large": 0.096,
        "c5.large": 0.085,
        "g4dn.xlarge": 0.526,
        "p4d.24xlarge": 32.77,
        # RDS instances (USD per hour)
        "db.t3.micro": 0.017,
        "db.m5.large": 0.142,
        # EBS storage (USD per GB-hour)
        "gp2-storage-gb": 0.0000315,
        "gp3-storage-gb": 0.0000288,
        # io1/io2 per-GB storage cost only — provisioned IOPS charges
        # (approx $0.065/IOPS-month) are not captured in this estimate
        "io1-storage-gb": 0.000171,
        "io2-storage-gb": 0.000171,
        "st1-storage-gb": 0.000062,
        "sc1-storage-gb": 0.000021,
        "standard-storage-gb": 0.000068,
    }

    HOURS_PER_MONTH = 730

    @staticmethod
    def _unique_key(breakdown: dict, key: str) -> str:
        if key not in breakdown:
            return key
        suffix = sum(1 for k in breakdown if k == key or k.startswith(f"{key}#"))
        return f"{key}#{suffix}"

    @staticmethod
    def _build_reason(
        total_monthly: float,
        budget_monthly: float,
        unknown_instance_types: list,
        unknown_volume_types: list,
    ) -> tuple:
        parts = []
        if unknown_instance_types:
            parts.append(f"unknown instance types: {sorted(set(unknown_instance_types))}")
        if unknown_volume_types:
            parts.append(f"unknown volume types: {sorted(set(unknown_volume_types))}")
        if parts:
            reason = (
                f"Cost estimate incomplete — {'; '.join(parts)}. "
                f"Known cost ${total_monthly:.2f} vs budget ${budget_monthly:.2f}."
            )
            return reason, False
        if total_monthly <= budget_monthly:
            return (
                f"Estimated cost ${total_monthly:.2f} is within budget ${budget_monthly:.2f}",
                True,
            )
        return (
            f"Estimated cost ${total_monthly:.2f} EXCEEDS budget ${budget_monthly:.2f}",
            False,
        )

    def verify_budget(self, resources: Dict[str, Any], budget_monthly: float) -> CostEstimate:
        total_hourly_cost = 0.0
        breakdown = {}
        unknown_instance_types = []
        unknown_volume_types = []

        instances = resources.get("instances", [])
        for inst in instances:
            inst_type = inst.get("instance_type")
            if inst_type is None:
                inst_id = inst.get("id") or "<missing-id>"
                key = self._unique_key(breakdown, f"unknown-{inst_id}")
                breakdown[key] = 0.0
                unknown_instance_types.append("<missing>")
                continue
            count = inst.get("count", 1)
            price = self.PRICING_CATALOG.get(inst_type)
            if price is None:
                key = self._unique_key(breakdown, f"unknown-{inst.get('id') or inst_type}")
                breakdown[key] = 0.0
                unknown_instance_types.append(inst_type)
                continue

            cost = price * count
            total_hourly_cost += cost
            key = self._unique_key(breakdown, inst.get('id') or inst_type)
            breakdown[key] = cost * self.HOURS_PER_MONTH

        volumes = resources.get("volumes", [])
        for vol in volumes:
            vol_type = vol.get("volume_type")
            size_gb = vol.get("size_gb", 10)
            if vol_type is None:
                key = self._unique_key(breakdown, f"unknown-{vol.get('id') or 'missing-volume-type'}")
                breakdown[key] = 0.0
                unknown_volume_types.append("<missing>")
                continue
            key = f"{vol_type}-storage-gb"
            price_per_gb_hour = self.PRICING_CATALOG.get(key)
            if price_per_gb_hour is None:
                key = self._unique_key(breakdown, f"unknown-{vol.get('id') or vol_type}")
                breakdown[key] = 0.0
                unknown_volume_types.append(vol_type)
                continue
            cost = size_gb * price_per_gb_hour
            total_hourly_cost += cost
            key = self._unique_key(breakdown, f"vol-{vol.get('id', 'unknown')}")
            breakdown[key] = cost * self.HOURS_PER_MONTH

        total_monthly = total_hourly_cost * self.HOURS_PER_MONTH
        has_unknown = bool(unknown_instance_types) or bool(unknown_volume_types)
        reason, within_budget = self._build_reason(
            total_monthly, budget_monthly, unknown_instance_types, unknown_volume_types
        )

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
        expected_within_budget = (
            result.total_monthly_cost <= result.budget
            and not result.has_unknown_types
        )
        if result.within_budget != expected_within_budget:
            trace_rule = (
                COST_UNKNOWN_RESOURCE
                if result.has_unknown_types
                else COST_BUDGET_EXCEEDED
            )
            trace = build_trace(trace_rule, "INCONSISTENT")
            return InfraDiagnosticResult.blocked(
                agent_message="Cost estimate could not be verified",
                developer_fields={
                    "constraint_id": _COST_CONSTRAINT_ID,
                    "within_budget": result.within_budget,
                    "expected_within_budget": expected_within_budget,
                    "total_monthly_cost": result.total_monthly_cost,
                    "budget": result.budget,
                    "reason": result.reason,
                    "has_unknown_types": result.has_unknown_types,
                    "audit_trace": trace,
                },
            )

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
