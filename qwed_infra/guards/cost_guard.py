from decimal import Decimal, DecimalException, ROUND_CEILING, ROUND_FLOOR
from typing import Any, Dict, Optional
from pydantic import BaseModel
from qwed_infra.audit import (
    COST_BUDGET_EXCEEDED,
    COST_UNKNOWN_RESOURCE,
    COST_WITHIN_BUDGET,
    build_trace,
)
from qwed_infra.diagnostics import InfraDiagnosticResult, InfraDiagnosticStatus
from qwed_infra.numeric import decimal_text, parse_decimal_input
from qwed_infra.verification_context import VerificationContextDocument

_COST_CONSTRAINT_ID = "cost_guard.verify_budget"
_INVALID_INPUT_MESSAGE = "Cost estimate could not be verified"

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
    # Unrounded figures the budget decision was made on. The published
    # total_monthly_cost is rounded up to the cent and budget down, so a
    # re-check on those alone would reject a plan within budget by less
    # than a cent. None for estimates built by hand.
    exact_total_monthly_cost: Optional[str] = None
    exact_budget: Optional[str] = None


class CostGuard:
    """
    Deterministic Cloud Cost Verification.
    Prevents over-provisioning by checking estimated costs against a budget.
    """

    # Instance and volume prices live in separate tables. A volume price key
    # must never be found by an instance lookup, or a made-up instance type
    # is priced at a storage rate instead of tripping the unknown-type check.
    INSTANCE_PRICING = {
        # EC2 instances (USD per instance-hour)
        "t3.micro": "0.0104",
        "t3.small": "0.0208",
        "t3.medium": "0.0416",
        "m5.large": "0.096",
        "c5.large": "0.085",
        "g4dn.xlarge": "0.526",
        "p4d.24xlarge": "32.77",
        # RDS instances (USD per instance-hour)
        "db.t3.micro": "0.017",
        "db.m5.large": "0.142",
    }

    # EBS storage (USD per GB-month), us-east-1 on-demand list prices from
    # https://aws.amazon.com/ebs/pricing/. Prices differ by region; this
    # catalogue prices us-east-1 only.
    # Omitted on purpose, so they stay unknown and fail closed:
    # - io1/io2: their provisioned IOPS charge is not modelled.
    # - standard (magnetic): it also bills per I/O request, a usage-based
    #   charge that cannot be known before deployment.
    VOLUME_PRICING = {
        "gp2": "0.10",
        "gp3": "0.08",
        "st1": "0.045",
        "sc1": "0.015",
    }

    # Region the whole catalogue is priced for. It is recorded in every
    # VERIFIED diagnostic so the figure says what it was priced from.
    PRICING_REGION = "us-east-1"

    # gp3 includes this baseline performance in the storage price. Anything
    # provisioned above it is billed separately and is not priced here.
    GP3_BASELINE_IOPS = 3000
    GP3_BASELINE_THROUGHPUT_MIBPS = 125

    HOURS_PER_MONTH = Decimal("730")

    @staticmethod
    def _unique_key(breakdown: dict, key: str) -> str:
        if key not in breakdown:
            return key
        suffix = sum(1 for k in breakdown if k == key or k.startswith(f"{key}#"))
        return f"{key}#{suffix}"

    @staticmethod
    def _display_total(total_monthly: Decimal) -> Decimal:
        """Round a cost up to the cent, so the published figure never
        understates the exact estimate."""
        return total_monthly.quantize(TWO_PLACES, rounding=ROUND_CEILING)

    @staticmethod
    def _display_budget(budget_monthly: Decimal) -> Decimal:
        """Round a budget down to the cent, so the published figure never
        overstates the budget that was checked."""
        return budget_monthly.quantize(TWO_PLACES, rounding=ROUND_FLOOR)

    @staticmethod
    def _exact_or_published(
        exact: Optional[str], published: Decimal, field_name: str
    ) -> Decimal:
        """Parse an exact figure, or use the published one when the estimate
        carries none (an estimate built by hand)."""
        if exact is None:
            return published
        return parse_decimal_input(exact, field_name)

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
        total_q = CostGuard._display_total(total_monthly)
        budget_q = CostGuard._display_budget(budget_monthly)
        if parts:
            reason = (
                f"Cost estimate incomplete — {'; '.join(parts)}. "
                f"Known cost ${decimal_text(total_q)} vs budget ${decimal_text(budget_q)}."
            )
            return reason, False
        # Compare the exact values. Rounding either side first would certify
        # a plan that is over budget by less than a cent.
        if total_monthly <= budget_monthly:
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
        if not self._is_positive_int(count):
            inst_id = inst.get("id") or inst_type
            key = self._unique_key(breakdown, f"invalid-count-{inst_id}")
            breakdown[key] = decimal_text(Decimal("0.00"))
            unknown_instance_types.append(f"invalid count ({count})")
            return Decimal("0")
        price_str = (
            self.INSTANCE_PRICING.get(inst_type)
            if isinstance(inst_type, str)
            else None
        )
        if price_str is None:
            key = self._unique_key(breakdown, f"unknown-{inst.get('id') or inst_type}")
            breakdown[key] = decimal_text(Decimal("0.00"))
            unknown_instance_types.append(inst_type)
            return Decimal("0")
        price = Decimal(price_str)
        monthly = price * int(count) * self.HOURS_PER_MONTH
        key = self._unique_key(breakdown, inst.get('id') or inst_type)
        breakdown[key] = decimal_text(monthly)
        return monthly

    @staticmethod
    def _is_positive_int(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value >= 1

    def _unpriced_performance(self, vol_type: str, vol: dict) -> Optional[str]:
        """Return a description of any provisioned performance this
        catalogue cannot price, or None when the storage price covers it."""
        for attr, baseline in (
            ("iops", self.GP3_BASELINE_IOPS),
            ("throughput", self.GP3_BASELINE_THROUGHPUT_MIBPS),
        ):
            value = vol.get(attr)
            if value is None:
                continue
            if vol_type != "gp3":
                return f"unpriced {attr} on {vol_type} ({value})"
            if not self._is_positive_int(value):
                return f"invalid {attr} ({value})"
            if value > baseline:
                return f"unpriced gp3 {attr} above baseline ({value})"
        return None

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
        if not self._is_positive_int(size_gb):
            key = self._unique_key(breakdown, f"invalid-size-{vol.get('id') or vol_type}")
            breakdown[key] = decimal_text(Decimal("0.00"))
            unknown_volume_types.append(f"invalid size_gb ({size_gb})")
            return Decimal("0")
        count = vol.get("count", 1)
        if not self._is_positive_int(count):
            key = self._unique_key(breakdown, f"invalid-count-{vol.get('id') or vol_type}")
            breakdown[key] = decimal_text(Decimal("0.00"))
            unknown_volume_types.append(f"invalid count ({count})")
            return Decimal("0")
        price_str = (
            self.VOLUME_PRICING.get(vol_type) if isinstance(vol_type, str) else None
        )
        if price_str is None:
            key = self._unique_key(breakdown, f"unknown-{vol.get('id') or vol_type}")
            breakdown[key] = decimal_text(Decimal("0.00"))
            unknown_volume_types.append(vol_type)
            return Decimal("0")
        unpriced = self._unpriced_performance(vol_type, vol)
        if unpriced is not None:
            key = self._unique_key(breakdown, f"unpriced-{vol.get('id') or vol_type}")
            breakdown[key] = decimal_text(Decimal("0.00"))
            unknown_volume_types.append(unpriced)
            return Decimal("0")
        monthly = Decimal(price_str) * int(size_gb) * int(count)
        key = self._unique_key(breakdown, f"vol-{vol.get('id', 'unknown')}")
        breakdown[key] = decimal_text(monthly)
        return monthly

    def verify_budget(self, resources: Dict[str, Any], budget_monthly: object) -> CostEstimate:
        budget = parse_decimal_input(budget_monthly, "budget_monthly")
        total_monthly = Decimal("0")
        breakdown = {}
        unknown_instance_types = []
        unknown_volume_types = []

        for inst in resources.get("instances", []):
            total_monthly += self._process_instance(inst, breakdown, unknown_instance_types)
        for vol in resources.get("volumes", []):
            total_monthly += self._process_volume(vol, breakdown, unknown_volume_types)

        total_q = self._display_total(total_monthly)
        has_unknown = bool(unknown_instance_types) or bool(unknown_volume_types)
        reason, within_budget = self._build_reason(
            total_monthly, budget, unknown_instance_types, unknown_volume_types
        )

        return CostEstimate(
            total_monthly_cost=decimal_text(total_q),
            breakdown=breakdown,
            within_budget=within_budget,
            budget=decimal_text(self._display_budget(budget)),
            reason=reason,
            has_unknown_types=has_unknown,
            exact_total_monthly_cost=decimal_text(total_monthly),
            exact_budget=decimal_text(budget),
        )

    @staticmethod
    def to_diagnostic(result: CostEstimate) -> InfraDiagnosticResult:
        try:
            total = parse_decimal_input(result.total_monthly_cost, "total_monthly_cost")
            budget = parse_decimal_input(result.budget, "budget")
            exact_total = CostGuard._exact_or_published(
                result.exact_total_monthly_cost, total, "exact_total_monthly_cost"
            )
            exact_budget = CostGuard._exact_or_published(
                result.exact_budget, budget, "exact_budget"
            )
            # The published figures must be the conservative roundings of
            # the exact ones, or the estimate is inconsistent. Without exact
            # figures this requires published figures already in cents.
            # Rounding a huge value raises, so it stays inside this guarded
            # block and no unbounded figure is ever formatted.
            published_consistent = (
                CostGuard._display_total(exact_total) == total
                and CostGuard._display_budget(exact_budget) == budget
            )
        except (ValueError, DecimalException):
            return InfraDiagnosticResult.blocked(
                agent_message=_INVALID_INPUT_MESSAGE,
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
        # Re-check the decision on the exact figures, without rounding.
        expected_within_budget = (
            exact_total <= exact_budget
            and not result.has_unknown_types
            and published_consistent
        )
        if result.within_budget != expected_within_budget:
            trace_rule = (
                COST_UNKNOWN_RESOURCE
                if result.has_unknown_types
                else COST_BUDGET_EXCEEDED
            )
            trace = build_trace(trace_rule, "INCONSISTENT")
            return InfraDiagnosticResult.blocked(
                agent_message=_INVALID_INPUT_MESSAGE,
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

        decision_figures = {
            "exact_total_monthly_cost": decimal_text(exact_total),
            "exact_budget": decimal_text(exact_budget),
            "pricing_region": CostGuard.PRICING_REGION,
        }
        trace = build_trace(COST_WITHIN_BUDGET, "ALLOWED")
        return InfraDiagnosticResult.verified(
            agent_message="Cost estimate within budget",
            developer_fields={
                "constraint_id": _COST_CONSTRAINT_ID,
                "within_budget": result.within_budget,
                "total_monthly_cost": result.total_monthly_cost,
                "budget": result.budget,
                **decision_figures,
                "reason": result.reason,
                "audit_trace": trace,
            },
            evidence={
                **trace,
                "total_monthly_cost": result.total_monthly_cost,
                "budget": result.budget,
                **decision_figures,
            },
        )

    def to_verification_context(
        self,
        resources: Dict[str, Any],
        budget_monthly: object,
        *,
        formal_statement: str,
        attestation_token: Optional[str] = None,
    ) -> VerificationContextDocument:
        """Run the budget check and map the result to a VC v1.0 document.

        The guard performs the computation itself via verify_budget(), so a
        caller cannot inject a result object of any kind. Malformed inputs
        (undecimal budget, non-dict resources, non-dict entries) map to a
        fail-closed BLOCKED diagnostic rather than propagating an exception.
        The provenance gate remains as defense-in-depth: only a VERIFIED
        diagnostic carrying CostGuard provenance and an explicit
        within_budget=True outcome is admitted; anything else is BLOCKED.
        """
        try:
            result = self.verify_budget(resources, budget_monthly)
        except (ValueError, TypeError, AttributeError, DecimalException):
            diagnostic = InfraDiagnosticResult.blocked(
                agent_message=_INVALID_INPUT_MESSAGE,
                developer_fields={
                    "constraint_id": _COST_CONSTRAINT_ID,
                    "within_budget": False,
                    "audit_trace": build_trace(COST_UNKNOWN_RESOURCE, "INVALID_INPUT"),
                },
            )
        else:
            diagnostic = self.to_diagnostic(result)
        decision_status = None
        if diagnostic.status is InfraDiagnosticStatus.VERIFIED and not (
            diagnostic.developer_fields.get("constraint_id") == _COST_CONSTRAINT_ID
            and diagnostic.developer_fields.get("within_budget") is True
        ):
            decision_status = InfraDiagnosticStatus.BLOCKED

        from qwed_infra.verification_context_bridge import (
            verification_context_from_diagnostic_result,
        )

        return verification_context_from_diagnostic_result(
            diagnostic,
            formal_statement=formal_statement,
            attestation_token=attestation_token,
            verifier="CostGuard",
            decision_status=decision_status,
        )
