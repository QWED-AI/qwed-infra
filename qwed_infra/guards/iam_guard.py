"""
IAM Policy Verification using Z3 SMT Solver.
Provides deterministic proof of whether a policy allows/denies access.
"""
import traceback
from typing import Any, Dict, List, Optional

from pydantic import BaseModel
from z3 import And, Length, Not, Or, Solver, String, StringVal, SubString, sat


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
    # Pattern Matching
    # ------------------------------------------------------------------

    def _match_pattern(self, z3_variable, pattern: str):
        """Return a Z3 constraint matching variable against an IAM wildcard pattern."""
        if pattern == "*":
            return True
        if pattern.endswith("*") and pattern.count("*") == 1:
            prefix = pattern[:-1]
            z3_prefix = StringVal(prefix)
            return SubString(z3_variable, 0, Length(z3_prefix)) == z3_prefix
        if pattern.startswith("*") and pattern.count("*") == 1:
            suffix = pattern[1:]
            z3_suffix = StringVal(suffix)
            var_len = Length(z3_variable)
            suff_len = Length(z3_suffix)
            return SubString(z3_variable, var_len - suff_len, suff_len) == z3_suffix
        return z3_variable == StringVal(pattern)

    # ------------------------------------------------------------------
    # Condition Operators
    # ------------------------------------------------------------------

    def _apply_string_equals(self, ctx_val: Optional[str], required_val: str, cond_expr):
        """Apply StringEquals condition operator."""
        if ctx_val is None:
            return False
        return And(cond_expr, StringVal(ctx_val) == StringVal(required_val))

    def _apply_string_like(self, ctx_val: Optional[str], required_val: str, cond_expr):
        """Apply StringLike condition operator (supports wildcards)."""
        if ctx_val is None:
            return False
        return And(cond_expr, self._match_pattern(StringVal(ctx_val), required_val))

    def _apply_ip_address(self, ctx_val: Optional[str], required_val: str, cond_expr):
        """Apply IpAddress condition operator with simplified CIDR prefix matching."""
        if ctx_val is None:
            return False
        if "/" not in required_val:
            return And(cond_expr, StringVal(ctx_val) == StringVal(required_val))
        cidr_base, mask = required_val.split("/")
        prefix_part = self._cidr_to_prefix(cidr_base, mask)
        return And(cond_expr, self._match_pattern(StringVal(ctx_val), prefix_part + "*"))

    def _apply_not_ip_address(self, ctx_val: Optional[str], required_val: str, cond_expr):
        """Apply NotIpAddress condition operator."""
        if ctx_val is None:
            return False
        return And(cond_expr, StringVal(ctx_val) != StringVal(required_val))

    def _cidr_to_prefix(self, cidr_base: str, mask: str) -> str:
        """Convert a CIDR base+mask to a simplified string prefix for matching."""
        if mask == "8":
            return cidr_base.split(".")[0] + "."
        return cidr_base.rsplit(".", 1)[0] + "."

    # ------------------------------------------------------------------
    # Condition Block Evaluation
    # ------------------------------------------------------------------

    def _evaluate_operator(self, operator: str, ctx_val, required_val, cond_expr):
        """Dispatch to the correct condition operator handler."""
        if operator == "StringEquals":
            return self._apply_string_equals(ctx_val, required_val, cond_expr)
        if operator == "StringLike":
            return self._apply_string_like(ctx_val, required_val, cond_expr)
        if operator == "IpAddress":
            return self._apply_ip_address(ctx_val, required_val, cond_expr)
        if operator == "NotIpAddress":
            return self._apply_not_ip_address(ctx_val, required_val, cond_expr)
        if operator == "DateLessThan":
            # TODO: Implement ISO8601 date comparison via integer conversion
            return cond_expr
        return cond_expr

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

    def _build_policy_logic(self, policy: Dict, s_action, s_resource, context: Dict):
        """Fold all IAM statements into a single Z3 expression (default-deny)."""
        full_logic = False  # Default Deny
        for stmt in policy.get("Statement", []):
            stmt_cond = self._build_statement_condition(stmt, s_action, s_resource, context)
            if stmt.get("Effect", "Deny") == "Allow":
                full_logic = Or(full_logic, stmt_cond)
            else:
                full_logic = And(full_logic, Not(stmt_cond))
        return full_logic

    def verify_least_privilege(self, policy: Dict[str, Any]) -> VerificationResult:
        """
        Prove that the policy does NOT allow full admin access ("*" on "*").
        Returns allowed=True if the policy IS over-privileged (fail).
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
