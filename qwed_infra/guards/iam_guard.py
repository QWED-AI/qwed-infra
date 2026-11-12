"""
IAM Policy Verification using Z3 SMT Solver.
Provides deterministic proof of whether a policy allows/denies access.
"""
import ipaddress
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel
from z3 import And, InRe, Not, Or, Solver, StringVal, sat, unsat

from qwed_infra.audit import (
    IAM_DENY_PRECEDENCE,
    build_trace,
)
from qwed_infra.diagnostics import InfraDiagnosticResult, InfraDiagnosticStatus
from qwed_infra.verification_context import VerificationContextDocument

_IAM_CONSTRAINT_ID = "iam_guard.verify_access"


class UnverifiablePolicyError(ValueError):
    """Raised for a policy the guard refuses to model.

    Its message is written by the guard and carries no host detail, so it
    is safe to record in diagnostics and VC evidence. Any other exception
    is recorded by type name only.
    """


# Input bounds (#76). Z3 cost grows faster than linearly in these, so a
# hostile but well-formed policy could hold a gate worker for minutes. Each
# bound sits well above what AWS accepts in one policy document (customer
# managed policies are capped at 6,144 characters, the largest resource
# policies at tens of kilobytes; ARNs at 2,048 characters). A policy over
# any bound is UNVERIFIABLE, never allowed or denied.
MAX_STATEMENTS = 1000
MAX_PATTERNS_PER_ELEMENT = 1000
MAX_PATTERNS_PER_POLICY = 2500
MAX_PATTERN_LENGTH = 2048
MAX_WILDCARDS_PER_PATTERN = 64
MAX_CONDITION_ENTRIES_PER_STATEMENT = 100
MAX_CONDITION_ENTRIES_PER_POLICY = 1000
MAX_REQUEST_LENGTH = 2048

# Statement elements the model does not represent (#67). A statement that
# uses one is refused, never modelled as matching nothing.
_UNMODELLED_STATEMENT_ELEMENTS = ("NotAction", "NotResource", "NotPrincipal")


class IamPolicy(BaseModel):
    model_config = {"extra": "forbid"}
    Version: str
    Statement: List[Dict[str, Any]]


class VerificationResult(BaseModel):
    model_config = {"extra": "forbid"}
    verified: bool
    allowed: bool
    proof: Optional[str] = None
    error: Optional[str] = None
    condition_evaluations: List[Dict[str, Any]] = []


class IamGuard:
    """
    Deterministic IAM Policy Verification using Z3 Solver.
    Proves if a policy allows access to a specific action/resource.
    """

    def __init__(self):
        self.solver = Solver()

    # ------------------------------------------------------------------
    # Pattern Matching (Z3 Regex — handles interior/multiple wildcards)
    # ------------------------------------------------------------------

    def _match_pattern(self, z3_variable, pattern: str):
        """
        Return a Z3 constraint matching variable against an IAM wildcard pattern.
        Translates '*' to Z3 Kleene star over any character.
        Handles patterns with zero or more wildcards (including interior ones).
        """
        if pattern == "*":
            return True

        from z3 import Concat, Re, Star, Range
        any_char_star = Star(Range(StringVal("\x00"), StringVal("\xff")))

        parts = pattern.split("*")
        if len(parts) == 1:
            # No wildcard — exact match
            return z3_variable == StringVal(pattern)

        # Build regex: literal [.* literal]* anchored implicitly by Z3 InRe
        if not parts[0]:
            regex = any_char_star
        else:
            regex = Re(StringVal(parts[0]))

        for part in parts[1:]:
            if part:
                regex = Concat(regex, any_char_star, Re(StringVal(part)))
            else:
                regex = Concat(regex, any_char_star)

        return InRe(z3_variable, regex)


    # ------------------------------------------------------------------
    # Condition Operators
    # ------------------------------------------------------------------

    def _apply_string_equals(self, ctx_val: Optional[str], required_val: str, cond_expr):
        """Apply StringEquals condition operator."""
        if ctx_val is None:
            return False
        return And(cond_expr, StringVal(ctx_val) == StringVal(required_val))

    def _apply_string_like(self, ctx_val: Optional[str], required_val: str, cond_expr):
        """Apply StringLike condition operator (supports IAM wildcards)."""
        if ctx_val is None:
            return False
        return And(cond_expr, self._match_pattern(StringVal(ctx_val), required_val))

    def _apply_ip_address(self, ctx_val: Optional[str], required_val: str, cond_expr):
        """
        Apply IpAddress condition operator using exact ipaddress membership.
        Correctly handles all CIDR mask sizes including /12, /20, etc.
        """
        if ctx_val is None:
            return False
        try:
            ctx_ip = ipaddress.ip_address(ctx_val)
            if "/" not in required_val:
                return And(cond_expr, ctx_ip == ipaddress.ip_address(required_val))
            return And(cond_expr, ctx_ip in ipaddress.ip_network(required_val, strict=False))
        except ValueError:
            return False

    def _apply_not_ip_address(self, ctx_val: Optional[str], required_val: str, cond_expr):
        """
        Apply NotIpAddress condition operator using exact ipaddress membership.
        Correctly handles all CIDR mask sizes including /12, /20, etc.
        """
        if ctx_val is None:
            return False
        try:
            ctx_ip = ipaddress.ip_address(ctx_val)
            if "/" not in required_val:
                return And(cond_expr, ctx_ip != ipaddress.ip_address(required_val))
            return And(cond_expr, ctx_ip not in ipaddress.ip_network(required_val, strict=False))
        except ValueError:
            return False

    def _apply_date_less_than(self, ctx_val: Optional[str], required_val: str, cond_expr):
        """
        Apply DateLessThan operator using ISO8601 string comparison.
        ISO8601 dates are lexicographically sortable when same length/format.
        """
        if ctx_val is None:
            return False
        try:
            ctx_dt = datetime.fromisoformat(ctx_val.replace("Z", "+00:00"))
            req_dt = datetime.fromisoformat(required_val.replace("Z", "+00:00"))
            if ctx_dt < req_dt:
                return cond_expr  # Condition satisfied — keep existing constraints
            return False  # Date condition fails → deny
        except (ValueError, TypeError):
            return False  # Malformed date or naive/aware mismatch → fail closed

    # ------------------------------------------------------------------
    # Condition Block Evaluation
    # ------------------------------------------------------------------

    def _evaluate_operator(self, operator: str, ctx_val, required_val, cond_expr):
        """
        Dispatch to the correct condition operator handler.
        Returns False (fail-closed) for unknown/unimplemented operators.
        """
        if operator == "StringEquals":
            return self._apply_string_equals(ctx_val, required_val, cond_expr)
        if operator == "StringLike":
            return self._apply_string_like(ctx_val, required_val, cond_expr)
        if operator == "IpAddress":
            return self._apply_ip_address(ctx_val, required_val, cond_expr)
        if operator == "NotIpAddress":
            return self._apply_not_ip_address(ctx_val, required_val, cond_expr)
        if operator == "DateLessThan":
            return self._apply_date_less_than(ctx_val, required_val, cond_expr)
        # Unknown operator: fail closed (deny access) to prevent privilege escalation
        return False

    def _evaluate_condition(self, condition_block: Dict, context: Dict) -> Any:
        """
        Evaluate an IAM condition block against a request context.
        Returns a Z3 expression (or bool) representing the combined condition.
        """
        cond_expr = True
        for operator, restrictions in condition_block.items():
            for key, required_val in restrictions.items():
                ctx_val = context.get(key)
                cond_expr = self._evaluate_operator(operator, ctx_val, required_val, cond_expr)
        return cond_expr

    # ------------------------------------------------------------------
    # Statement Building
    # ------------------------------------------------------------------

    def _build_match_list(self, z3_var, patterns: List[str]):
        """Build a Z3 OR-expression matching a variable against a list of patterns.

        The disjunction is built flat: a left-nested chain of binary Or
        terms grows the expression depth with the list length and can
        overflow the native stack inside Z3.
        """
        constraints = [
            True if pattern == "*" else self._match_pattern(z3_var, pattern)
            for pattern in patterns
        ]
        if not constraints:
            return False
        if len(constraints) == 1:
            return constraints[0]
        return Or(*constraints)

    def _build_statement_condition(self, stmt: Dict, s_action, s_resource, context: Dict):
        """Build the Z3 condition for a single IAM statement."""
        unmodelled = [e for e in _UNMODELLED_STATEMENT_ELEMENTS if e in stmt]
        if unmodelled:
            raise UnverifiablePolicyError(
                f"statement uses {', '.join(unmodelled)}, which is not modelled"
            )
        for element in ("Action", "Resource"):
            if element not in stmt:
                raise UnverifiablePolicyError(f"statement has no {element}")
        p_actions = stmt.get("Action", [])
        if isinstance(p_actions, str):
            p_actions = [p_actions]

        p_resources = stmt.get("Resource", [])
        if isinstance(p_resources, str):
            p_resources = [p_resources]

        action_match = self._build_match_list(s_action, p_actions)
        resource_match = self._build_match_list(s_resource, p_resources)
        condition_match = self._evaluate_condition(stmt.get("Condition", {}), context)

        return And(action_match, resource_match, condition_match)

    # ------------------------------------------------------------------
    # Policy Logic (order-independent deny precedence)
    # ------------------------------------------------------------------

    def _build_policy_logic(self, policy: Dict, s_action, s_resource, context: Dict):
        """
        Build Z3 logic for the full policy with correct IAM deny precedence.
        Explicit Deny always overrides Allow, regardless of statement order.
        Pattern: And(Or(all_allows), And(Not(deny1), Not(deny2), ...))
        """
        allows = []
        denies = []

        for stmt in policy.get("Statement", []):
            stmt_cond = self._build_statement_condition(stmt, s_action, s_resource, context)
            if stmt.get("Effect", "Deny") == "Allow":
                allows.append(stmt_cond)
            else:
                denies.append(Not(stmt_cond))

        # Built flat for the same reason as _build_match_list.
        allow_logic = Or(*allows) if len(allows) > 1 else (allows[0] if allows else False)
        deny_logic = And(*denies) if len(denies) > 1 else (denies[0] if denies else True)

        # Access granted only if: some Allow matches AND no Deny matches
        return And(allow_logic, deny_logic)

    @staticmethod
    def _as_pattern_list(value: Any, element: str) -> List[Any]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return value
        raise UnverifiablePolicyError(f"{element} is not a string or a list")

    @staticmethod
    def _check_pattern_size(pattern: str, what: str) -> None:
        if len(pattern) > MAX_PATTERN_LENGTH:
            raise UnverifiablePolicyError(
                f"{what} is longer than {MAX_PATTERN_LENGTH} characters"
            )
        if pattern.count("*") > MAX_WILDCARDS_PER_PATTERN:
            raise UnverifiablePolicyError(
                f"{what} has more than {MAX_WILDCARDS_PER_PATTERN} wildcards"
            )

    @classmethod
    def _check_input_bounds(
        cls, policy: Any, action: Any, resource: Any, context: Any
    ) -> None:
        """Refuse inputs whose size could stall the solver (#76)."""
        for name, value in (("action", action), ("resource", resource)):
            if not isinstance(value, str):
                raise UnverifiablePolicyError(f"request {name} is not a string")
            if len(value) > MAX_REQUEST_LENGTH:
                raise UnverifiablePolicyError(
                    f"request {name} is longer than {MAX_REQUEST_LENGTH} characters"
                )
        if not isinstance(context, dict):
            raise UnverifiablePolicyError("request context is not a mapping")
        if not isinstance(policy, dict):
            raise UnverifiablePolicyError("policy is not a mapping")
        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            raise UnverifiablePolicyError("Statement is not a list")
        if len(statements) > MAX_STATEMENTS:
            raise UnverifiablePolicyError(
                f"policy has more than {MAX_STATEMENTS} statements"
            )
        total_patterns = 0
        total_condition_entries = 0
        for stmt in statements:
            if not isinstance(stmt, dict):
                raise UnverifiablePolicyError("a statement is not a mapping")
            for element in ("Action", "Resource"):
                patterns = cls._as_pattern_list(stmt.get(element, []), element)
                if len(patterns) > MAX_PATTERNS_PER_ELEMENT:
                    raise UnverifiablePolicyError(
                        f"{element} has more than {MAX_PATTERNS_PER_ELEMENT} entries"
                    )
                total_patterns += len(patterns)
                for pattern in patterns:
                    if not isinstance(pattern, str):
                        raise UnverifiablePolicyError(f"{element} entry is not a string")
                    cls._check_pattern_size(pattern, f"{element} entry")
            conditions = stmt.get("Condition", {})
            if not isinstance(conditions, dict):
                raise UnverifiablePolicyError("Condition is not a mapping")
            entries = 0
            for restrictions in conditions.values():
                if not isinstance(restrictions, dict):
                    raise UnverifiablePolicyError("a Condition operator block is not a mapping")
                entries += len(restrictions)
                for value in restrictions.values():
                    if isinstance(value, str):
                        # StringLike values are wildcard patterns too.
                        cls._check_pattern_size(value, "Condition value")
            if entries > MAX_CONDITION_ENTRIES_PER_STATEMENT:
                raise UnverifiablePolicyError(
                    f"statement has more than {MAX_CONDITION_ENTRIES_PER_STATEMENT} condition entries"
                )
            total_condition_entries += entries
        if total_condition_entries > MAX_CONDITION_ENTRIES_PER_POLICY:
            raise UnverifiablePolicyError(
                f"policy has more than {MAX_CONDITION_ENTRIES_PER_POLICY} condition entries"
            )
        if total_patterns > MAX_PATTERNS_PER_POLICY:
            raise UnverifiablePolicyError(
                f"policy has more than {MAX_PATTERNS_PER_POLICY} Action and Resource entries"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify_access(
        self,
        policy: Dict[str, Any],
        action: str,
        resource: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        """
        Check if the given policy allows the specific action on the resource.

        Args:
            policy:   IAM policy dict with Statement list.
            action:   AWS action string, e.g. "s3:GetObject".
            resource: AWS resource ARN string.
            context:  Request context, e.g. {"aws:SourceIp": "10.0.0.5"}.

        Returns:
            VerificationResult with verified/allowed flags and Z3 proof string.
        """
        if context is None:
            context = {}
        try:
            self._check_input_bounds(policy, action, resource, context)
            # The request is concrete, so the policy is built directly over
            # the request values. Pinning free variables to the same values
            # with an equality is equivalent but leaves Z3 far more work
            # (minutes for a policy with a thousand patterns, see #76).
            s_action = StringVal(action)
            s_resource = StringVal(resource)

            # Collect condition metadata for audit trace
            _Z3_OPS = {"StringEquals", "StringLike"}
            condition_evaluations = []
            for stmt in policy.get("Statement", []):
                conditions = stmt.get("Condition", {})
                for operator, restrictions in conditions.items():
                    evaluated_in = "z3" if operator in _Z3_OPS else "python"
                    for key, required_val in restrictions.items():
                        condition_evaluations.append({
                            "operator": operator,
                            "key": key,
                            "context_value": str(context.get(key)),
                            "required_value": str(required_val),
                            "evaluated_in": evaluated_in,
                        })

            policy_logic = self._build_policy_logic(policy, s_action, s_resource, context)

            self.solver.reset()
            self.solver.add(policy_logic)

            outcome = self.solver.check()
            if outcome == sat:
                return VerificationResult(
                    verified=True,
                    allowed=True,
                    proof="Z3 found a satisfying model (Access Allowed)",
                    condition_evaluations=condition_evaluations,
                )
            if outcome == unsat:
                return VerificationResult(
                    verified=True,
                    allowed=False,
                    proof="Z3 proved unsatisfiability (Access Denied)",
                    condition_evaluations=condition_evaluations,
                )
            # unknown: Z3 gave no answer. That is not a proof of denial.
            return VerificationResult(
                verified=False,
                allowed=False,
                error="Z3 returned unknown",
            )
        except UnverifiablePolicyError as exc:
            return VerificationResult(verified=False, allowed=False, error=str(exc))
        except Exception as exc:  # noqa: BLE001
            # Record the exception type only: its message or a traceback can
            # carry host paths and internals into portable VC evidence (#87).
            return VerificationResult(
                verified=False,
                allowed=False,
                error=type(exc).__name__,
            )

    def verify_least_privilege(self, policy: Dict[str, Any]) -> VerificationResult:
        """
        Prove that the policy does NOT allow full admin access ("*" on "*").
        Returns allowed=True if the policy IS over-privileged (violation).
        """
        return self.verify_access(
            policy,
            action="*",
            resource="*",
            context={
                "aws:SourceIp": "0.0.0.0",
                "aws:CurrentTime": "2100-01-01T00:00:00Z",
            },
        )

    @staticmethod
    def to_diagnostic(
        result: VerificationResult,
        audit_trace: Optional[Dict[str, Any]] = None,
    ) -> InfraDiagnosticResult:
        """Convert a VerificationResult to an InfraDiagnosticResult."""
        if not result.verified:
            trace = audit_trace if audit_trace is not None else build_trace(IAM_DENY_PRECEDENCE, "UNVERIFIABLE")
            return InfraDiagnosticResult.unverifiable(
                agent_message="IAM policy verification could not be completed",
                developer_fields={
                    "constraint_id": _IAM_CONSTRAINT_ID,
                    "error": result.error,
                    "audit_trace": trace,
                },
            )

        rule = IAM_DENY_PRECEDENCE
        if result.allowed:
            outcome = "ALLOWED"
        else:
            outcome = "DENIED"

        trace_inputs = {"condition_evaluations": result.condition_evaluations} if result.condition_evaluations else None
        if audit_trace is not None:
            trace = dict(audit_trace)
            if trace_inputs:
                trace["inputs"] = {**trace.get("inputs", {}), **trace_inputs}
        else:
            trace = build_trace(rule, outcome, inputs=trace_inputs)

        evidence = {
            "verified": result.verified,
            "allowed": result.allowed,
            "proof": result.proof,
            "audit_trace": trace,
        }
        if result.condition_evaluations:
            evidence["condition_evaluations"] = result.condition_evaluations

        agent_msg = "IAM policy access: allowed" if result.allowed else "IAM policy access: denied"
        return InfraDiagnosticResult.verified(
            agent_message=agent_msg,
            developer_fields={
                "constraint_id": _IAM_CONSTRAINT_ID,
                "allowed": result.allowed,
                "proof": result.proof,
                "audit_trace": trace,
            },
            evidence=evidence,
        )

    def to_verification_context(
        self,
        policy: Dict[str, Any],
        action: str,
        resource: str,
        context: Optional[Dict[str, Any]] = None,
        *,
        formal_statement: str,
        attestation_token: Optional[str] = None,
    ) -> VerificationContextDocument:
        """Run the access check and map the result to a VC v1.0 document.

        The guard performs the computation itself via verify_access(), so a
        caller cannot inject a result object of any kind. The provenance
        gate remains as defense-in-depth: only a VERIFIED diagnostic
        carrying IamGuard provenance and an explicit allowed=True outcome is
        admitted; a proven denial or any other result is BLOCKED.
        """
        result = self.verify_access(policy, action, resource, context)
        diagnostic = IamGuard.to_diagnostic(result)
        decision_status = None
        if diagnostic.status is InfraDiagnosticStatus.VERIFIED and not (
            diagnostic.developer_fields.get("constraint_id") == _IAM_CONSTRAINT_ID
            and diagnostic.developer_fields.get("allowed") is True
        ):
            decision_status = InfraDiagnosticStatus.BLOCKED

        from qwed_infra.verification_context_bridge import (
            verification_context_from_diagnostic_result,
        )

        return verification_context_from_diagnostic_result(
            diagnostic,
            formal_statement=formal_statement,
            attestation_token=attestation_token,
            verifier="IamGuard",
            decision_status=decision_status,
        )


