"""
IAM Policy Verification using Z3 SMT Solver.
Provides deterministic proof of whether a policy allows/denies access.
"""
import ipaddress
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel
from z3 import And, InRe, Not, Or, Solver, String, StringVal, sat


class IamPolicy(BaseModel):
    Version: str
    Statement: List[Dict[str, Any]]


class VerificationResult(BaseModel):
    verified: bool
    allowed: bool
    proof: Optional[str] = None
    error: Optional[str] = None


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
    # CIDR helpers
    # ------------------------------------------------------------------

    def _cidr_to_prefix(self, cidr_base: str, mask: str) -> str:
        """
        Convert a CIDR block to a string prefix for simple prefix matching.
        Uses Python's ipaddress module for correct octet count per mask.
        e.g. 10.0.0.0/8 → "10.", 192.168.1.0/24 → "192.168.1.", 172.16.0.0/16 → "172.16."
        """
        network = ipaddress.ip_network(f"{cidr_base}/{mask}", strict=False)
        full_octets = int(mask) // 8
        octets = str(network.network_address).split(".")
        return ".".join(octets[:full_octets]) + "."

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
        """Build a Z3 OR-expression matching a variable against a list of patterns."""
        match_expr = False
        for pattern in patterns:
            constraint = True if pattern == "*" else self._match_pattern(z3_var, pattern)
            match_expr = Or(match_expr, constraint) if match_expr is not False else constraint
        return match_expr

    def _build_statement_condition(self, stmt: Dict, s_action, s_resource, context: Dict):
        """Build the Z3 condition for a single IAM statement."""
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
        allow_logic = False  # Default deny: no allows yet
        deny_logic = True    # No denies yet (vacuously true)

        for stmt in policy.get("Statement", []):
            stmt_cond = self._build_statement_condition(stmt, s_action, s_resource, context)
            if stmt.get("Effect", "Deny") == "Allow":
                allow_logic = Or(allow_logic, stmt_cond)
            else:
                deny_logic = And(deny_logic, Not(stmt_cond))

        # Access granted only if: some Allow matches AND no Deny matches
        return And(allow_logic, deny_logic)

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
            s_action = String("action")
            s_resource = String("resource")
            query = And(s_action == StringVal(action), s_resource == StringVal(resource))

            policy_logic = self._build_policy_logic(policy, s_action, s_resource, context)

            self.solver.reset()
            self.solver.add(query)
            self.solver.add(policy_logic)

            if self.solver.check() == sat:
                return VerificationResult(
                    verified=True,
                    allowed=True,
                    proof="Z3 found a satisfying model (Access Allowed)",
                )
            return VerificationResult(
                verified=True,
                allowed=False,
                proof="Z3 proved unsatisfiability (Access Denied)",
            )
        except Exception as exc:  # noqa: BLE001
            return VerificationResult(
                verified=False,
                allowed=False,
                error=str(exc) + " " + traceback.format_exc(),
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


