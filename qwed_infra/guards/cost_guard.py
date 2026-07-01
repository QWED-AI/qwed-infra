from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict
from pydantic import BaseModel
from qwed_infra.audit import (
    COST_BUDGET_EXCEEDED,
    COST_UNKNOWN_RESOURCE,
    COST_WITHIN_BUDGET,
    build_trace,
)
from qwed_infra.diagnostics import InfraDiagnosticResult
from qwed_infra.numeric import decimal_text, parse_decimal_input

_COST_CONSTRAINT_ID = "cost_guard.verify_budget"

TWO_PLACES = Decimal("0.01")


class CostEstimate(BaseModel):
    model_config = {"extra": "forbid"}
    total_monthly_cost: str
    currency: str = "USD"
    breakdown: Dict[str, str]
    within_budget: bool
    budget: str
    reason: str
    has_unknown_types: bool = False


class CostGuard:
    """
    Deterministic Cloud Cost Verification.
    Prevents over-provisioning by checking estimated costs against a budget.
    """

    PRICING_CATALOG = {
        # EC2 instances (USD per hour)
        "t3.micro": "0.0104",
        "t3.small": "0.0208",
        "t3.medium": "0.0416",
        "m5.large": "0.096",
        "c5.large": "0.085",
        "g4dn.xlarge": "0.526",
        "p4d.24xlarge": "32.77",
        # RDS instances (USD per hour)
        "db.t3.micro": "0.017",
        "db.m5.large": "0.142",
        # EBS storage (USD per GB-hour)
        "gp2-storage-gb": "0.0000315",
        "gp3-storage-gb": "0.0000288",
        # io1/io2 IOPS charges (~$0.065/IOPS-month) not captured — omit to fail closed
        "st1-storage-gb": "0.000062",
        "sc1-storage-gb": "0.000021",
        "standard-storage-gb": "0.000068",
    }

    HOURS_PER_MONTH = Decimal("730")

    @staticmethod
    def _unique_key(breakdown: dict, key: str) -> str:
        if key not in breakdown:
            return key
        suffix = sum(1 for k in breakdown if k == key or k.startswith(f"{key}#"))
        return f"{key}#{suffix}"

    @staticmethod
    def _build_reason(
        total_monthly: Decimal,
        budget_monthly: Decimal,
        unknown_instance_types: list,
        unknown_volume_types: list,
    ) -> tuple:
        parts = []
        if unknown_instance_types:
            parts.append(f"unknown instance types: {sorted(set(unknown_instance_types))}")
        if unknown_volume_types:
            parts.append(f"unknown volume types: {sorted(set(unknown_volume_types))}")
        total_q = total_monthly.quantize(TWO_PLACES, rounding=ROUND_HALF_UP)
        budget_q = budget_monthly.quantize(TWO_PLACES, rounding=ROUND_HALF_UP)
        if parts:
            reason = (
                f"Cost estimate incomplete — {'; '.join(parts)}. "
                f"Known cost ${decimal_text(total_q)} vs budget ${decimal_text(budget_q)}."
            )
            return reason, False
        if total_q <= budget_q:
            return (
                f"Estimated cost ${decimal_text(total_q)} is within budget ${decimal_text(budget_q)}",
                True,
            )
        return (
            f"Estimated cost ${decimal_text(total_q)} EXCEEDS budget ${decimal_text(budget_q)}",
            False,
        )

    def _process_instance(
        self, inst: dict, breakdown: dict, unknown_instance_types: list
    ) -> Decimal:
        inst_type = inst.get("instance_type")
        if inst_type is None:
            inst_id = inst.get("id") or "<missing-id>"
            key = self._unique_key(breakdown, f"unknown-{inst_id}")
            breakdown[key] = decimal_text(Decimal("0.00"))
            unknown_instance_types.append("<missing>")
            return Decimal("0")
        count = inst.get("count", 1)
        if not isinstance(count, int) or count < 1:
            inst_id = inst.get("id") or inst_type
            key = self._unique_key(breakdown, f"invalid-count-{inst_id}")
            breakdown[key] = decimal_text(Decimal("0.00"))
            unknown_instance_types.append(f"invalid count ({count})")
            return Decimal("0")
        price_str = self.PRICING_CATALOG.get(inst_type)
        if price_str is None:
            key = self._unique_key(breakdown, f"unknown-{inst.get('id') or inst_type}")
            breakdown[key] = decimal_text(Decimal("0.00"))
            unknown_instance_types.append(inst_type)
            return Decimal("0")
        price = Decimal(price_str)
        cost = price * int(count)
        monthly = cost * self.HOURS_PER_MONTH
        key = self._unique_key(breakdown, inst.get('id') or inst_type)
        breakdown[key] = decimal_text(monthly)
        return cost

    def _process_volume(
        self, vol: dict, breakdown: dict, unknown_volume_types: list
    ) -> Decimal:
        vol_type = vol.get("volume_type")
        if vol_type is None:
            key = self._unique_key(breakdown, f"unknown-{vol.get('id') or 'missing-volume-type'}")
            breakdown[key] = decimal_text(Decimal("0.00"))
            unknown_volume_types.append("<missing>")
            return Decimal("0")
        size_gb = vol.get("size_gb")
        if not isinstance(size_gb, int) or size_gb < 1:
            key = self._unique_key(breakdown, f"invalid-size-{vol.get('id') or vol_type}")
            breakdown[key] = decimal_text(Decimal("0.00"))
            unknown_volume_types.append(f"invalid size_gb ({size_gb})")
            return Decimal("0")
        key = f"{vol_type}-storage-gb"
        price_str = self.PRICING_CATALOG.get(key)
        if price_str is None:
            key = self._unique_key(breakdown, f"unknown-{vol.get('id') or vol_type}")
            breakdown[key] = decimal_text(Decimal("0.00"))
            unknown_volume_types.append(vol_type)
            return Decimal("0")
        price_per_gb = Decimal(price_str)
        cost = price_per_gb * int(size_gb)
        monthly = cost * self.HOURS_PER_MONTH
        key = self._unique_key(breakdown, f"vol-{vol.get('id', 'unknown')}")
        breakdown[key] = decimal_text(monthly)
        return cost

    def verify_budget(self, resources: Dict[str, Any], budget_monthly: object) -> CostEstimate:
        budget = parse_decimal_input(budget_monthly, "budget_monthly")
        total_hourly_cost = Decimal("0")
        breakdown = {}
        unknown_instance_types = []
        unknown_volume_types = []

        for inst in resources.get("instances", []):
            total_hourly_cost += self._process_instance(inst, breakdown, unknown_instance_types)
        for vol in resources.get("volumes", []):
            total_hourly_cost += self._process_volume(vol, breakdown, unknown_volume_types)

        total_monthly = total_hourly_cost * self.HOURS_PER_MONTH
        total_q = total_monthly.quantize(TWO_PLACES, rounding=ROUND_HALF_UP)
        has_unknown = bool(unknown_instance_types) or bool(unknown_volume_types)
        reason, within_budget = self._build_reason(
            total_monthly, budget, unknown_instance_types, unknown_volume_types
        )

        return CostEstimate(
            total_monthly_cost=decimal_text(total_q),
            breakdown=breakdown,
            within_budget=within_budget,
            budget=decimal_text(budget.quantize(TWO_PLACES, rounding=ROUND_HALF_UP)),
            reason=reason,
            has_unknown_types=has_unknown,
        )

    @staticmethod
    def to_diagnostic(result: CostEstimate) -> InfraDiagnosticResult:
        try:
            total = parse_decimal_input(result.total_monthly_cost, "total_monthly_cost")
            budget = parse_decimal_input(result.budget, "budget")
        except ValueError:
            return InfraDiagnosticResult.blocked(
                agent_message="Cost estimate could not be verified",
                developer_fields={
                    "constraint_id": _COST_CONSTRAINT_ID,
                    "within_budget": result.within_budget,
                    "total_monthly_cost": result.total_monthly_cost,
                    "budget": result.budget,
                    "reason": result.reason,
                    "has_unknown_types": result.has_unknown_types,
                    "audit_trace": build_trace(COST_UNKNOWN_RESOURCE, "INVALID_INPUT"),
                },
            )
        total_q = total.quantize(TWO_PLACES, rounding=ROUND_HALF_UP)
        budget_q = budget.quantize(TWO_PLACES, rounding=ROUND_HALF_UP)
        expected_within_budget = (
            total_q <= budget_q
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
