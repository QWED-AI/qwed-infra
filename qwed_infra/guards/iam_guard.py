"""
IAM Policy Verification using Z3 SMT Solver.
Provides deterministic proof of whether a policy allows/denies access.
"""
import threading
from typing import Any, Dict, List, Optional

from pydantic import BaseModel
from z3 import And, Not, Or, Solver, sat, unsat

from qwed_infra.audit import (
    IAM_DENY_PRECEDENCE,
    build_trace,
)
from qwed_infra.diagnostics import InfraDiagnosticResult, InfraDiagnosticStatus
from qwed_infra.guards._iam_matching import (
    POLICY_VARIABLES_VERSION,
    CannotEvaluate,
    MatchContext,
    any_of,
    evaluate_condition,
    match_action,
    match_resource,
)
from qwed_infra.verification_context import VerificationContextDocument

_IAM_CONSTRAINT_ID = "iam_guard.verify_access"

# Z3 objects share one global context, which is not thread-safe: concurrent
# solver calls can abort the process. Solver use is serialised.
_Z3_LOCK = threading.Lock()


def _name_list(names: List[str], limit: int = 5, width: int = 64) -> str:
    """Up to ``limit`` names, each cut to ``width`` characters, and a count
    of the rest, so a hostile document cannot fill diagnostics."""
    shown = [repr(name[:width]) for name in names[:limit]]
    if len(names) > limit:
        shown.append(f"and {len(names) - limit} more")
    return ", ".join(shown)


class UnverifiablePolicyError(ValueError):
    """Raised for a policy the guard refuses to model.

    Its message is written by the guard and carries no host detail, so it
    is safe to record in diagnostics and VC evidence. Any other exception
    is recorded by type name only.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _StatementUnevaluable(UnverifiablePolicyError):
    """A statement whose resource or condition cannot be evaluated for this
    request. The decision is UNVERIFIABLE unless it does not depend on that
    statement."""


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
MAX_CONTEXT_ENTRIES = 100
MAX_LIST_VALUE_ENTRIES = 100
MAX_CONDITION_VALUES_PER_POLICY = 2500
# Total characters of Action, Resource and condition value text in one
# policy. Matching cost grows with request length times pattern text, and
# AWS policy documents stay far below this (tens of kilobytes at most).
MAX_PATTERN_CHARACTERS_PER_POLICY = 131072

# Statement elements the model does not represent (#67). A statement that
# uses one is refused, never modelled as matching nothing.
_UNMODELLED_STATEMENT_ELEMENTS = ("NotAction", "NotResource", "NotPrincipal")

_STATEMENT = "Statement"
_ACTION = "Action"
_RESOURCE = "Resource"
_CONDITION = "Condition"
_EFFECT = "Effect"
_ALLOW = "Allow"
_DENY = "Deny"

# Least-privilege scope of an Allow's Action or Resource list: it covers
# everything, it cannot cover everything, or the guard cannot tell.
_SCOPE_ALL = "all"
_SCOPE_UNKNOWN = "unknown"
_SCOPE_SOME = "some"
_WILDCARD_ONLY = frozenset("*?:")

_POLICY_VERSIONS = ("2012-10-17", "2008-10-17")
_POLICY_ELEMENTS = frozenset({"Version", "Id", _STATEMENT})


def _wildcard_only(text: str) -> bool:
    """Only "*", "?" and ":", with at least one "*": such a pattern matches
    every action or ARN, or all but some too short to exist. Counting it
    as full access can only over-report a violation."""
    return "*" in text and set(text) <= _WILDCARD_ONLY


def _action_scope(pattern: Any) -> str:
    if not isinstance(pattern, str):
        return _SCOPE_UNKNOWN
    if _wildcard_only(pattern):
        return _SCOPE_ALL
    prefix = pattern.split(":", 1)[0]
    if "*" in prefix or "?" in prefix:
        return _SCOPE_UNKNOWN  # e.g. one of "a*", "b*", ... covering all
    return _SCOPE_SOME


def _resource_scope(pattern: Any) -> str:
    if not isinstance(pattern, str):
        return _SCOPE_UNKNOWN
    if _wildcard_only(pattern) or (pattern[:3].lower() == "arn" and _wildcard_only(pattern[3:])):
        return _SCOPE_ALL
    head = pattern.split(":", 5)
    if "${" in ":".join(head[:5]) or not pattern.startswith("arn:") or any(
        "*" in part or "?" in part for part in head[1:3]
    ):
        return _SCOPE_UNKNOWN  # partition or service wildcarded, or not an ARN
    return _SCOPE_SOME


def _list_scope(patterns: List[Any], scope_of) -> str:
    scopes = {scope_of(p) for p in patterns}
    for scope in (_SCOPE_ALL, _SCOPE_UNKNOWN):
        if scope in scopes:
            return scope
    return _SCOPE_SOME


# Every element a statement may carry. Anything else (a misspelt
# "Conditon", say) is refused: AWS rejects such a policy, and ignoring the
# key would drop what it was meant to say.
_STATEMENT_ELEMENTS = frozenset({
    "Sid", _EFFECT, "Principal", _ACTION, _RESOURCE, _CONDITION,
    *_UNMODELLED_STATEMENT_ELEMENTS,
})


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
        with _Z3_LOCK:
            self.solver = Solver()

    # ------------------------------------------------------------------
    # Statement Building
    # ------------------------------------------------------------------

    def _build_statement_condition(
        self,
        stmt: Dict,
        action: str,
        resource: str,
        ctx: MatchContext,
        least_privilege: bool = False,
    ) -> bool:
        """Whether a single IAM statement applies to the request.

        A resource or condition that cannot be evaluated raises
        _StatementUnevaluable when the statement's action matches; the
        policy logic then decides whether the result depends on it.

        In least-privilege mode the question is whether some request context
        reaches the action, so a statement's Condition is not evaluated
        against the synthetic context: a conditional Allow counts as
        applying and a conditional Deny as not applying.
        """
        is_allow = self._statement_effect(stmt) == _ALLOW
        unknown = sorted(str(key) for key in stmt if key not in _STATEMENT_ELEMENTS)
        if unknown:
            raise UnverifiablePolicyError(
                f"statement has elements that are not part of the policy language: {_name_list(unknown)}"
            )
        unmodelled = [e for e in _UNMODELLED_STATEMENT_ELEMENTS if e in stmt]
        if unmodelled:
            raise UnverifiablePolicyError(
                f"statement uses {', '.join(unmodelled)}, which is not modelled"
            )
        for element in (_ACTION, _RESOURCE):
            if element not in stmt:
                raise UnverifiablePolicyError(f"statement has no {element}")
        # The request carries no principal, so the model is principal
        # agnostic. That is exact only for a Principal that names everyone.
        if "Principal" in stmt and stmt["Principal"] not in ("*", {"AWS": "*"}):
            raise UnverifiablePolicyError(
                "statement restricts Principal, which is not modelled"
            )
        p_actions = self._as_pattern_list(stmt.get(_ACTION, []), _ACTION)
        p_resources = self._as_pattern_list(stmt.get(_RESOURCE, []), _RESOURCE)
        conditions = stmt.get(_CONDITION, {})
        if least_privilege:
            return self._least_privilege_applies(is_allow, conditions, p_actions, p_resources)
        try:
            if not any_of(lambda p=p: match_action(action, p) for p in p_actions):
                return False
            if not any_of(lambda p=p: match_resource(resource, p, ctx) for p in p_resources):
                return False
            if least_privilege:
                return True
            return evaluate_condition(conditions, ctx)
        except CannotEvaluate as exc:
            raise _StatementUnevaluable(exc.reason) from None

    @classmethod
    def _least_privilege_applies(
        cls, is_allow: bool, conditions: Any, p_actions: List[Any], p_resources: List[Any]
    ) -> bool:
        """Whether a statement grants full access in least-privilege mode,
        judged from its patterns rather than by matching the synthetic "*"
        request."""
        if not is_allow:
            # The synthetic "*" request is not a real action or resource, so
            # a Deny counts only when it names every action and every
            # resource outright, and has no condition some context could
            # avoid.
            return not conditions and cls._names_everything(p_actions) and cls._names_everything(p_resources)
        scopes = {_list_scope(p_actions, _action_scope), _list_scope(p_resources, _resource_scope)}
        if scopes == {_SCOPE_ALL}:
            return True
        if _SCOPE_SOME in scopes:
            return False
        raise _StatementUnevaluable(
            "least-privilege check cannot tell whether this Allow covers every action and resource"
        )

    @staticmethod
    def _statement_effect(stmt: Dict[str, Any]) -> str:
        effect = stmt.get(_EFFECT)
        if effect not in (_ALLOW, _DENY):
            raise UnverifiablePolicyError("statement Effect is not Allow or Deny")
        return effect

    @staticmethod
    def _names_everything(patterns: List[Any]) -> bool:
        """A pattern made only of "*" matches every action or resource."""
        return any(isinstance(p, str) and p and set(p) == {"*"} for p in patterns)

    # ------------------------------------------------------------------
    # Policy Logic (order-independent deny precedence)
    # ------------------------------------------------------------------

    def _build_policy_logic(
        self,
        policy: Dict,
        action: str,
        resource: str,
        ctx: MatchContext,
        least_privilege: bool = False,
    ):
        """
        Build Z3 logic for the full policy with correct IAM deny precedence.
        Explicit Deny always overrides Allow, regardless of statement order.
        Pattern: And(Or(all_allows), And(Not(deny1), Not(deny2), ...))

        Statements that cannot be evaluated are set aside. The decision
        stands without them when a Deny that could be evaluated applies, or
        when every one of them is an Allow and an evaluated Allow already
        applies. Otherwise the decision is UNVERIFIABLE.
        """
        allows: List[bool] = []
        denies: List[bool] = []
        unevaluable = {_ALLOW: [], _DENY: []}

        for stmt in policy.get(_STATEMENT, []):
            effect = self._statement_effect(stmt)
            try:
                applies = self._build_statement_condition(
                    stmt, action, resource, ctx, least_privilege
                )
            except _StatementUnevaluable as exc:
                unevaluable[effect].append(exc.reason)
                continue
            (allows if effect == _ALLOW else denies).append(applies)

        if not any(denies):
            if unevaluable[_DENY]:
                raise UnverifiablePolicyError(unevaluable[_DENY][0])
            if unevaluable[_ALLOW] and not any(allows):
                raise UnverifiablePolicyError(unevaluable[_ALLOW][0])

        # Built flat for the same reason as _build_match_list in earlier
        # versions: deep binary chains can overflow Z3's native stack.
        allow_logic = self._flat(Or, allows, empty=False)
        deny_logic = self._flat(And, [Not(d) for d in denies], empty=True)

        # Access granted only if: some Allow matches AND no Deny matches
        return And(allow_logic, deny_logic)

    @staticmethod
    def _flat(combine, terms: List[Any], empty: bool):
        """Combine terms with one flat Or/And; the identity when empty."""
        if not terms:
            return empty
        if len(terms) == 1:
            return terms[0]
        return combine(*terms)

    @staticmethod
    def _normalize_statement_list(policy: Any) -> Any:
        """Require a Statement element, and accept AWS's single-object form
        by wrapping it in a list (on a copy; the caller's policy is not
        changed)."""
        if not isinstance(policy, dict):
            raise UnverifiablePolicyError("policy is not a mapping")
        unknown = sorted(str(key) for key in policy if key not in _POLICY_ELEMENTS)
        if unknown:
            raise UnverifiablePolicyError(
                f"policy has elements that are not part of the policy language: {_name_list(unknown)}"
            )
        if "Version" in policy and policy["Version"] not in _POLICY_VERSIONS:
            raise UnverifiablePolicyError("policy Version is not 2012-10-17 or 2008-10-17")
        if _STATEMENT not in policy:
            raise UnverifiablePolicyError("policy has no Statement")
        if isinstance(policy[_STATEMENT], dict):
            return {**policy, _STATEMENT: [policy[_STATEMENT]]}
        return policy

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
        if pattern.count("*") + pattern.count("?") > MAX_WILDCARDS_PER_PATTERN:
            raise UnverifiablePolicyError(
                f"{what} has more than {MAX_WILDCARDS_PER_PATTERN} wildcards"
            )

    @staticmethod
    def _check_key(key: Any, what: str) -> None:
        """Policy documents are JSON, so every key is a string."""
        if not isinstance(key, str):
            raise UnverifiablePolicyError(f"{what} is not a string")
        if len(key) > MAX_REQUEST_LENGTH:
            raise UnverifiablePolicyError(
                f"{what} is longer than {MAX_REQUEST_LENGTH} characters"
            )

    @classmethod
    def _check_value_size(cls, value: Any, what: str, pattern: bool = False) -> None:
        """Bound a string, or each string in a list, used as a condition key,
        condition value or context value. Other scalars are left to the
        evaluator."""
        if isinstance(value, list):
            if len(value) > MAX_LIST_VALUE_ENTRIES:
                raise UnverifiablePolicyError(
                    f"{what} list has more than {MAX_LIST_VALUE_ENTRIES} entries"
                )
            for item in value:
                if isinstance(item, (list, dict)):
                    raise UnverifiablePolicyError(f"{what} list holds a nested container")
                cls._check_value_size(item, what, pattern)
            return
        if isinstance(value, dict):
            raise UnverifiablePolicyError(f"{what} is a mapping")
        if isinstance(value, str):
            if pattern:
                cls._check_pattern_size(value, what)
            elif len(value) > MAX_REQUEST_LENGTH:
                raise UnverifiablePolicyError(
                    f"{what} is longer than {MAX_REQUEST_LENGTH} characters"
                )

    @staticmethod
    def _check_request(action: Any, resource: Any, context: Any) -> None:
        for name, value in (("action", action), ("resource", resource)):
            if not isinstance(value, str):
                raise UnverifiablePolicyError(f"request {name} is not a string")
            if len(value) > MAX_REQUEST_LENGTH:
                raise UnverifiablePolicyError(
                    f"request {name} is longer than {MAX_REQUEST_LENGTH} characters"
                )
        if not isinstance(context, dict):
            raise UnverifiablePolicyError("request context is not a mapping")
        if len(context) > MAX_CONTEXT_ENTRIES:
            raise UnverifiablePolicyError(
                f"request context has more than {MAX_CONTEXT_ENTRIES} entries"
            )
        for key, value in context.items():
            IamGuard._check_key(key, "request context key")
            IamGuard._check_value_size(value, "request context value")

    @classmethod
    def _check_statement_patterns(cls, stmt: Dict[str, Any]) -> int:
        """Bound the Action and Resource entries; return how many there are."""
        total = 0
        for element in (_ACTION, _RESOURCE):
            patterns = cls._as_pattern_list(stmt.get(element, []), element)
            if element in stmt and not patterns:
                raise UnverifiablePolicyError(f"{element} is empty")
            if len(patterns) > MAX_PATTERNS_PER_ELEMENT:
                raise UnverifiablePolicyError(
                    f"{element} has more than {MAX_PATTERNS_PER_ELEMENT} entries"
                )
            total += len(patterns)
            for pattern in patterns:
                if not isinstance(pattern, str):
                    raise UnverifiablePolicyError(f"{element} entry is not a string")
                cls._check_pattern_size(pattern, f"{element} entry")
        return total

    @classmethod
    def _check_statement_conditions(cls, stmt: Dict[str, Any]) -> int:
        """Bound the Condition block; return how many entries it has."""
        conditions = stmt.get(_CONDITION, {})
        if not isinstance(conditions, dict):
            raise UnverifiablePolicyError("Condition is not a mapping")
        entries = 0
        for operator, restrictions in conditions.items():
            cls._check_key(operator, "Condition operator")
            if not isinstance(restrictions, dict):
                raise UnverifiablePolicyError("a Condition operator block is not a mapping")
            entries += len(restrictions)
            for key, value in restrictions.items():
                cls._check_key(key, "Condition key")
                # StringLike values are wildcard patterns, so the wildcard
                # bound applies to them too.
                cls._check_value_size(value, "Condition value", pattern=True)
        if entries > MAX_CONDITION_ENTRIES_PER_STATEMENT:
            raise UnverifiablePolicyError(
                f"statement has more than {MAX_CONDITION_ENTRIES_PER_STATEMENT} condition entries"
            )
        return entries

    @staticmethod
    def _count_condition_values(stmt: Dict[str, Any]) -> int:
        """Each value in a condition list is a separate comparison (for
        StringLike, a separate pattern)."""
        return sum(
            len(value) if isinstance(value, list) else 1
            for restrictions in stmt.get(_CONDITION, {}).values()
            for value in restrictions.values()
        )

    @classmethod
    def _count_pattern_characters(cls, stmt: Dict[str, Any]) -> int:
        """Characters of Action, Resource and condition value text."""
        texts = cls._as_pattern_list(stmt.get(_ACTION, []), _ACTION) + cls._as_pattern_list(
            stmt.get(_RESOURCE, []), _RESOURCE
        )
        for restrictions in stmt.get(_CONDITION, {}).values():
            for value in restrictions.values():
                texts.extend(value if isinstance(value, list) else [value])
        return sum(len(text) for text in texts if isinstance(text, str))

    @classmethod
    def _check_input_bounds(
        cls, policy: Any, action: Any, resource: Any, context: Any
    ) -> None:
        """Refuse inputs whose size could stall the solver (#76)."""
        cls._check_request(action, resource, context)
        if not isinstance(policy, dict):
            raise UnverifiablePolicyError("policy is not a mapping")
        statements = policy.get(_STATEMENT, [])
        if not isinstance(statements, list):
            raise UnverifiablePolicyError("Statement is not a list")
        if len(statements) > MAX_STATEMENTS:
            raise UnverifiablePolicyError(
                f"policy has more than {MAX_STATEMENTS} statements"
            )
        total_patterns = 0
        total_condition_entries = 0
        total_condition_values = 0
        total_characters = 0
        for stmt in statements:
            if not isinstance(stmt, dict):
                raise UnverifiablePolicyError("a statement is not a mapping")
            total_patterns += cls._check_statement_patterns(stmt)
            total_condition_entries += cls._check_statement_conditions(stmt)
            total_condition_values += cls._count_condition_values(stmt)
            total_characters += cls._count_pattern_characters(stmt)
        if total_characters > MAX_PATTERN_CHARACTERS_PER_POLICY:
            raise UnverifiablePolicyError(
                f"policy has more than {MAX_PATTERN_CHARACTERS_PER_POLICY} characters of pattern text"
            )
        if total_condition_values > MAX_CONDITION_VALUES_PER_POLICY:
            raise UnverifiablePolicyError(
                f"policy has more than {MAX_CONDITION_VALUES_PER_POLICY} condition values"
            )
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
        return self._verify(policy, action, resource, context)

    @staticmethod
    def _collect_condition_evaluations(policy: Dict[str, Any], ctx: MatchContext) -> List[Dict[str, Any]]:
        """Condition metadata for the audit trace. Every condition is decided
        in Python on the concrete request; Z3 combines the outcomes under
        Deny precedence."""
        evaluations = []
        for stmt in policy.get(_STATEMENT, []):
            for operator, restrictions in stmt.get(_CONDITION, {}).items():
                for key, required_val in restrictions.items():
                    present, value = ctx.lookup(key)
                    evaluations.append({
                        "operator": operator,
                        "key": key,
                        "context_value": str(value) if present else "None",
                        "required_value": str(required_val),
                        "evaluated_in": "python",
                    })
        return evaluations

    def _verify(
        self,
        policy: Any,
        action: Any,
        resource: Any,
        context: Optional[Dict[str, Any]],
        least_privilege: bool = False,
    ) -> VerificationResult:
        if context is None:
            context = {}
        try:
            policy = self._normalize_statement_list(policy)
            self._check_input_bounds(policy, action, resource, context)
            # Policy variables are substituted only under the 2012-10-17
            # policy language version; with any other or no version AWS
            # reads them as literal text.
            ctx = MatchContext(
                context, variables=policy.get("Version") == POLICY_VARIABLES_VERSION
            )
            condition_evaluations = self._collect_condition_evaluations(policy, ctx)
            # The request is concrete, so each statement is decided on the
            # request values directly; Z3 combines them under Deny
            # precedence (#76).
            with _Z3_LOCK:
                # Building the formula also touches Z3's shared context.
                policy_logic = self._build_policy_logic(
                    policy, action, resource, ctx, least_privilege
                )
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
        except (UnverifiablePolicyError, CannotEvaluate) as exc:
            return VerificationResult(verified=False, allowed=False, error=exc.reason)
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

        The question is whether any request context reaches full access, so
        a conditional Allow is counted as applying, and a Deny counts only
        when it is unconditional and names every action and every resource
        with a pattern made of "*" alone. A conditional guard-rail such as
        "deny without MFA" does not make an admin policy compliant.
        """
        return self._verify(
            policy,
            action="*",
            resource="*",
            context={
                "aws:SourceIp": "0.0.0.0",
                "aws:CurrentTime": "2100-01-01T00:00:00Z",
            },
            least_privilege=True,
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


