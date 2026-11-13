"""IAM matching and condition evaluation for IamGuard.

Every check here has three outcomes: it matches, it does not match, or it
cannot be evaluated. The third raises ``CannotEvaluate``. IamGuard turns it
into UNVERIFIABLE whenever the result depends on it, for Allow and Deny
alike, because "cannot evaluate" read as "does not match" silently drops a
Deny.

The request is concrete, so every check is decided here in Python and
returns a plain bool. Z3 string values are not used for request or policy
text: ``StringVal`` decodes escape sequences such as ``\\u{61}``, so two
different strings could compare equal.

Semantics follow the AWS IAM policy language:

* Actions match case-insensitively; resources and condition values match
  case-sensitively unless the operator says otherwise. Case folding is
  ASCII only; non-ASCII text compared case-insensitively cannot be
  evaluated.
* ``*`` matches any run of characters (including none) and ``?`` exactly one,
  over the whole Unicode range. In a resource ARN they stay within one
  colon-separated segment, except a ``*`` that ends the last segment; a
  match that needs any other crossing cannot be evaluated.
* Condition key names match case-insensitively.
* Policy variables (``${aws:username}`` and the ``${*}``, ``${?}``, ``${$}``
  escapes) are substituted in resources and condition values when the
  policy's ``Version`` is ``2012-10-17``. With any other or no version they
  are literal text, as in AWS.
* A key absent from the request makes a condition false, except for a
  negated operator (``StringNotEquals``, ``NotIpAddress`` and the other
  ``...Not...`` forms) or an ``...IfExists`` operator, where it is true.
  ``Null`` tests presence.
* Numbers, dates and booleans are parsed strictly: decimal digits with an
  optional sign and fraction; W3C dates and date-times with a zone, or
  epoch seconds; ``true`` or ``false``.
"""
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from functools import lru_cache
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

POLICY_VARIABLES_VERSION = "2012-10-17"

# A pattern longer than this after policy variable substitution is refused,
# so a short pattern cannot expand into a huge one.
MAX_SUBSTITUTED_LENGTH = 8192

# Characters that policy variable substitution may add across one request.
# Without it, variables would multiply matching work past the guard's bound
# on pattern text.
MAX_SUBSTITUTED_CHARACTERS = 131072

# Token kinds for a parsed pattern.
_LITERAL = "literal"  # text as written in the pattern (or an escape)
_VALUE = "value"  # a substituted policy variable value
_ONE = "one"
_RUN = "run"

_VARIABLE_ESCAPES = {"*": "*", "?": "?", "$": "$"}

_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def ascii_lower(text: str) -> str:
    return text.translate(_ASCII_LOWER)


def ascii_fold(text: str, what: str) -> str:
    """Case-fold text compared case-insensitively. Non-ASCII text is
    refused: how AWS folds it (the Kelvin sign, dotless i and others) is
    not modelled, and a different answer could drop a Deny."""
    if not text.isascii():
        raise CannotEvaluate(f"{what} has non-ASCII characters, whose case folding is not modelled")
    return ascii_lower(text)


class CannotEvaluate(Exception):
    """A check whose outcome the guard cannot decide.

    Its reason is written here and carries no host detail."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _Unresolved(CannotEvaluate):
    """A policy variable with no value in the request."""


def any_of(checks: Iterable[Callable[[], bool]]) -> bool:
    """True if any check is true, even when others cannot be evaluated;
    otherwise raise the first CannotEvaluate, or return False."""
    error: Optional[CannotEvaluate] = None
    for check in checks:
        try:
            if check():
                return True
        except CannotEvaluate as exc:
            error = error or exc
    if error is not None:
        raise error
    return False


def all_of(checks: Iterable[Callable[[], bool]]) -> bool:
    """False if any check is false, even when others cannot be evaluated;
    otherwise raise the first CannotEvaluate, or return True."""
    return not any_of(lambda check=check: not check() for check in checks)


class MatchContext:
    """The request context, with case-insensitive key lookup, and whether
    policy variables are substituted."""

    def __init__(self, context: Dict[str, Any], variables: bool):
        self.variables = variables
        self.substituted = 0
        self._values: Dict[str, Any] = {}
        for key, value in context.items():
            if value is None or value == []:
                # AWS has no null or empty value: a key is present or not.
                raise CannotEvaluate(f"request context value for {key!r} is null or empty")
            folded = ascii_fold(key, "request context key")
            if folded in self._values:
                raise CannotEvaluate(
                    f"request context has two keys that differ only in case ({key!r})"
                )
            self._values[folded] = value

    def add_substituted(self, count: int) -> None:
        self.substituted += count
        if self.substituted > MAX_SUBSTITUTED_CHARACTERS:
            raise CannotEvaluate("policy variable substitution adds too much text for one request")

    def lookup(self, key: str) -> Tuple[bool, Any]:
        folded = ascii_fold(key, "condition key")
        if folded in self._values:
            return True, self._values[folded]
        return False, None


# ----------------------------------------------------------------------
# Patterns
# ----------------------------------------------------------------------

def _variable_value(name: str, ctx: MatchContext) -> str:
    if name in _VARIABLE_ESCAPES:
        return _VARIABLE_ESCAPES[name]
    if not name or "," in name or "'" in name:
        raise CannotEvaluate("policy variable form is not modelled")
    present, value = ctx.lookup(name)
    if not present:
        raise _Unresolved(f"policy variable {name!r} has no value in the request")
    if not isinstance(value, str):
        raise CannotEvaluate(f"policy variable {name!r} is not a single string")
    if "*" in value or "?" in value:
        raise CannotEvaluate(f"policy variable {name!r} value contains a wildcard")
    return value


_WILDCARD_TOKENS = {"*": _RUN, "?": _ONE}

_SPECIALS = {
    (True, True): re.compile(r"\$\{|[*?]"),
    (True, False): re.compile(r"\$\{"),
    (False, True): re.compile(r"[*?]"),
}


def tokenize(
    text: str, ctx: Optional[MatchContext], wildcards: bool, unresolved_as_run: bool = False
) -> List[Tuple[str, str]]:
    """Split ``text`` into tokens: literal text as written, substituted
    variable values, single characters (``?``) and runs (``*``). Policy
    variables are substituted when ``ctx`` enables them. Without
    ``wildcards``, ``*`` and ``?`` are literal. With ``unresolved_as_run``,
    a variable with no value becomes a run, which over-approximates every
    value it could take."""
    variables = ctx is not None and ctx.variables
    if not variables and not wildcards:
        return [(_LITERAL, text)] if text else []
    specials = _SPECIALS[(variables, wildcards)]
    tokens: List[Tuple[str, str]] = []
    length = 0
    position = 0
    while position < len(text):
        found = specials.search(text, position)
        end = found.start() if found else len(text)
        if end > position:
            tokens.append((_LITERAL, text[position:end]))
            length += end - position
        if found is None:
            break
        position, added = _special_token(text, found, ctx, unresolved_as_run, tokens)
        length += added
        if length > MAX_SUBSTITUTED_LENGTH:
            raise CannotEvaluate("pattern is too long after policy variable substitution")
    return tokens


def _special_token(
    text: str, found: "re.Match", ctx: Optional[MatchContext], unresolved_as_run: bool,
    tokens: List[Tuple[str, str]],
) -> Tuple[int, int]:
    """Append the token for a ``*``, ``?`` or ``${`` match; return the
    position after it and the number of characters it adds."""
    if found.group() in _WILDCARD_TOKENS:
        tokens.append((_WILDCARD_TOKENS[found.group()], ""))
        return found.end(), 0
    return _variable_token(text, found.end(), ctx, unresolved_as_run, tokens)


def _variable_token(
    text: str, start: int, ctx: Optional[MatchContext], unresolved_as_run: bool,
    tokens: List[Tuple[str, str]],
) -> Tuple[int, int]:
    """Append the token for the variable whose name starts at ``start``;
    return the position after it and the number of characters added."""
    end = text.find("}", start)
    if end == -1:
        raise CannotEvaluate("policy variable is not closed")
    name = text[start:end]
    try:
        value = _variable_value(name, ctx)
    except _Unresolved:
        if not unresolved_as_run:
            raise
        tokens.append((_RUN, ""))
        return end + 1, 0
    tokens.append((_LITERAL if name in _VARIABLE_ESCAPES else _VALUE, value))
    ctx.add_substituted(len(value))
    return end + 1, len(value)


def substitute(text: str, ctx: Optional[MatchContext]) -> str:
    """Resolve policy variables in a value compared exactly."""
    return "".join(value for _, value in tokenize(text, ctx, wildcards=False))


@lru_cache(maxsize=512)
def _compiled(regex: str):
    return re.compile(regex, re.DOTALL)


class _Segment:
    """A run-free part of a pattern: literal text and single characters,
    with a fixed length. Literal-only segments are matched with str
    methods; others with a regex of literals and ``.`` only, which has no
    repetition and so never backtracks."""

    def __init__(self, tokens: List[Tuple[str, str]]):
        self.length = sum(1 if kind == _ONE else len(value) for kind, value in tokens)
        self.literal: Optional[str] = None
        self.regex = None
        if all(kind != _ONE for kind, _ in tokens):
            self.literal = "".join(value for _, value in tokens)
        else:
            self.regex = _compiled(
                "".join("." if kind == _ONE else re.escape(value) for kind, value in tokens)
            )

    def at(self, value: str, position: int) -> bool:
        if self.literal is not None:
            return value.startswith(self.literal, position)
        return self.regex.match(value, position, position + self.length) is not None

    def find(self, value: str, start: int, end: int) -> int:
        """Leftmost start of a match within value[start:end], or -1."""
        if self.literal is not None:
            return value.find(self.literal, start, end)
        found = self.regex.search(value, start, end)
        return -1 if found is None else found.start()


def _glob_match(value: str, tokens: List[Tuple[str, str]]) -> bool:
    """Match ``value`` against wildcard tokens.

    The pattern is split at each ``*`` into fixed-length segments. The first
    must match at the start and the last at the end; each middle segment is
    taken at its leftmost match, which is exact for ``*`` and ``?``
    patterns."""
    fixed = sum(1 if kind == _ONE else len(text) for kind, text in tokens if kind != _RUN)
    if fixed > len(value):
        return False  # checked before any segment is compiled
    groups: List[List[Tuple[str, str]]] = [[]]
    for kind, token_value in tokens:
        if kind == _RUN:
            groups.append([])
        else:
            groups[-1].append((kind, token_value))
    segments = [_Segment(group) for group in groups]
    if len(segments) == 1:
        return segments[0].length == len(value) and segments[0].at(value, 0)
    first, *middle, last = segments
    if not first.at(value, 0):
        return False
    position = first.length
    tail_start = len(value) - last.length
    for segment in middle:
        found = segment.find(value, position, tail_start)
        if found == -1:
            return False
        position = found + segment.length
    return position <= tail_start and last.at(value, tail_start)


def _pattern_tokens(value: str, pattern: str, ctx: Optional[MatchContext]) -> Optional[List[Tuple[str, str]]]:
    """The pattern's tokens, or None when it cannot match ``value``.

    A policy variable with no value in the request cannot be evaluated,
    unless the pattern cannot match whatever value the variable takes."""
    try:
        return tokenize(pattern, ctx, wildcards=True)
    except _Unresolved:
        if not _glob_match(value, tokenize(pattern, ctx, wildcards=True, unresolved_as_run=True)):
            return None
        raise


def wildcard_match(value: str, pattern: str, ctx: Optional[MatchContext] = None) -> bool:
    """``value`` matches the IAM wildcard ``pattern``."""
    if pattern == "*":
        return True
    tokens = _pattern_tokens(value, pattern, ctx)
    return tokens is not None and _glob_match(value, tokens)


def match_action(action: str, pattern: str) -> bool:
    """Actions are case-insensitive and take no policy variables."""
    return wildcard_match(ascii_fold(action, "action"), ascii_fold(pattern, "Action entry"))


def match_resource(resource: str, pattern: str, ctx: MatchContext) -> bool:
    """For a request resource with colons (an ARN), ``*`` and ``?`` match
    within one colon-separated segment; only a ``*`` that ends a segment may run past colons. A plain
    wildcard match bounds that from above and a segment-by-segment match
    from below; when they disagree outside the cases modelled here, the
    match cannot be evaluated. Policy variables and wildcards are not
    modelled in the service segment, and variables not before the fifth
    colon."""
    if pattern == "*":
        return True
    if resource.startswith("arn:"):
        _check_arn_prefix(pattern, ctx)
    if not wildcard_match(resource, pattern, ctx):
        return False
    if ":" not in resource:
        return True
    pieces = _colon_pieces(tokenize(pattern, ctx, wildcards=True))
    values = resource.split(":")
    if len(values) == len(pieces) and all(map(_glob_match, values, pieces)):
        return True
    head, last = pieces[:-1], pieces[-1]
    if (
        last and last[-1][0] == _RUN and len(values) > len(pieces)
        and all(map(_glob_match, values[: len(head)], head))
        and _glob_match(values[len(head)], last)
    ):
        return True
    raise CannotEvaluate("resource wildcard would have to match across an ARN colon")


def _check_arn_prefix(pattern: str, ctx: MatchContext) -> None:
    """AWS does not allow a variable before the fifth colon of a resource
    ARN, or a wildcard in its service segment; how it reads one is not
    modelled."""
    head = pattern.split(":", 5)[:5]
    if any("${" in part for part in head) and ctx.variables:
        raise CannotEvaluate("policy variable before the fifth colon of a resource ARN is not modelled")
    if len(head) > 2 and ("*" in head[2] or "?" in head[2]):
        raise CannotEvaluate("wildcard in the service segment of a resource ARN is not modelled")


def _colon_pieces(tokens: List[Tuple[str, str]]) -> List[List[Tuple[str, str]]]:
    """Split pattern tokens at every colon written in the pattern."""
    pieces: List[List[Tuple[str, str]]] = [[]]
    for kind, value in tokens:
        if kind == _VALUE and ":" in value:
            raise CannotEvaluate("policy variable value in an ARN contains a colon")
        if kind != _LITERAL:
            pieces[-1].append((kind, value))
            continue
        for index, piece in enumerate(value.split(":")):
            if index:
                pieces.append([])
            if piece:
                pieces[-1].append((_LITERAL, piece))
    return pieces


# ----------------------------------------------------------------------
# Condition values
# ----------------------------------------------------------------------

def _scalar_text(value: Any, what: str) -> str:
    """Condition and context values are strings in AWS. JSON booleans and
    integers are accepted in their string form; anything else is refused."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value
    raise CannotEvaluate(f"{what} is not a string")


def _policy_values(required: Any) -> List[str]:
    values = required if isinstance(required, list) else [required]
    if not values:
        raise CannotEvaluate("condition has an empty value list")
    return [_scalar_text(v, "condition value") for v in values]


_NUMBER = re.compile(r"-?[0-9]+(?:\.[0-9]+)?")
_EPOCH = re.compile(r"[0-9]{5,}")
_DATE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
_DATE_TIME = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})"
    r"(?::([0-9]{2})(?:\.([0-9]+))?)?(Z|[+-][0-9]{2}:[0-9]{2})"
)


def _parse_number(text: str) -> Decimal:
    if not _NUMBER.fullmatch(text):
        raise CannotEvaluate("numeric value is not a decimal number")
    return Decimal(text)


def _zone(text: str) -> timezone:
    if text == "Z":
        return timezone.utc
    sign = -1 if text[0] == "-" else 1
    hours, minutes = int(text[1:3]), int(text[4:6])
    if hours > 23 or minutes > 59:
        raise CannotEvaluate("date-time zone offset is out of range")
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def _parse_date(text: str) -> datetime:
    """W3C date (midnight UTC), W3C date-time with a zone, or epoch
    seconds, as an aware datetime. Bare years and months are refused: "2030"
    is also an epoch second."""
    try:
        if _EPOCH.fullmatch(text):
            return datetime.fromtimestamp(int(text), tz=timezone.utc)
        match = _DATE.fullmatch(text)
        if match:
            year, month, day = (int(g) for g in match.groups())
            return datetime(year, month, day, tzinfo=timezone.utc)
        match = _DATE_TIME.fullmatch(text)
        if match:
            year, month, day, hour, minute, second, fraction, zone = match.groups()
            micro = int((fraction or "0")[:6].ljust(6, "0"))
            return datetime(
                int(year), int(month), int(day), int(hour), int(minute),
                int(second or 0), micro, tzinfo=_zone(zone),
            )
    except (OverflowError, OSError, ValueError):
        raise CannotEvaluate("date value is out of range") from None
    raise CannotEvaluate("date value is not a W3C date, a date-time with a zone, or epoch seconds")


def _parse_bool(text: str) -> str:
    lowered = ascii_lower(text)
    if lowered not in ("true", "false"):
        raise CannotEvaluate("Bool value is not true or false")
    return lowered


def _parse_network(text: str):
    """An address or CIDR. Netmask and hostmask forms are refused."""
    _, slash, prefix = text.partition("/")
    if slash and not (prefix.isascii() and prefix.isdigit()):
        raise CannotEvaluate("IP condition value is not an address or CIDR")
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise CannotEvaluate("IP condition value is not an address or CIDR") from None


def _parse_address(text: str):
    if "%" in text:
        raise CannotEvaluate("request IP value has a zone index")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise CannotEvaluate("request IP value is not an address") from None
    if address.version == 6 and address.ipv4_mapped is not None:
        # Whether AWS compares it as IPv4 or IPv6 is not modelled.
        raise CannotEvaluate("request IP value is an IPv4-mapped IPv6 address")
    return address


_ORDER = {
    "Equals": lambda a, b: a == b,
    "LessThan": lambda a, b: a < b,
    "LessThanEquals": lambda a, b: a <= b,
    "GreaterThan": lambda a, b: a > b,
    "GreaterThanEquals": lambda a, b: a >= b,
}


def _split_arn_literal(value: str, components: List[List[Tuple[str, str]]]) -> None:
    """Add literal text to the components, starting a new component at each
    colon until there are six; later colons belong to the resource part."""
    for index, piece in enumerate(value.split(":")):
        if index and len(components) < 6:
            components.append([])
        elif index:
            components[-1].append((_LITERAL, ":"))
        if piece:
            components[-1].append((_LITERAL, piece))


def _arn_components(tokens: List[Tuple[str, str]]) -> List[List[Tuple[str, str]]]:
    """Split pattern tokens into the six ARN components at the first five
    colons written in the pattern."""
    components: List[List[Tuple[str, str]]] = [[]]
    for kind, value in tokens:
        if kind == _VALUE and ":" in value:
            raise CannotEvaluate("policy variable value in an ARN contains a colon")
        if kind == _LITERAL:
            _split_arn_literal(value, components)
        else:
            components[-1].append((kind, value))
    if len(components) != 6:
        raise CannotEvaluate("ARN condition value does not have six components")
    return components


def _arn_match(ctx_value: str, pattern: str, ctx: MatchContext) -> bool:
    if pattern == "*":
        return True
    actual = ctx_value.split(":", 5)
    if len(actual) != 6:
        raise CannotEvaluate("request ARN value does not have six components")
    tokens = _pattern_tokens(ctx_value, pattern, ctx)
    if tokens is None:
        return False
    return all(
        _glob_match(part, component)
        for part, component in zip(actual, _arn_components(tokens), strict=True)
    )


def _string_equals(c, p, ctx):
    return c == substitute(p, ctx)


def _string_equals_ignore_case(c, p, ctx):
    return ascii_fold(c, "request value") == ascii_fold(substitute(p, ctx), "condition value")


def _string_like(c, p, ctx):
    return wildcard_match(c, p, ctx)


def _bool(c, p, _ctx):
    return _parse_bool(c) == _parse_bool(p)


def _ip(c, p, _ctx):
    return _parse_address(c) in _parse_network(p)


def _ordered(parse, relation):
    return lambda c, p, _ctx: relation(parse(c), parse(p))


def _no_check(_value):
    return None


def _check_arn(value: str) -> None:
    """An ARN condition value is "*" or has six components (a value with
    policy variables is checked once they are substituted)."""
    if value != "*" and "${" not in value and value.count(":") < 5:
        raise CannotEvaluate("ARN condition value does not have six components")


# Each base operator maps to (comparison, negated, policy value check). The
# comparison takes (context value, policy value, match context) and returns
# a bool for one value. The check runs on every policy value, present key or
# not, so a malformed value is refused even where it would not be compared.
_OPERATORS: Dict[str, Tuple[Any, bool, Callable[[str], Any]]] = {
    "StringEquals": (_string_equals, False, _no_check),
    "StringNotEquals": (_string_equals, True, _no_check),
    "StringEqualsIgnoreCase": (_string_equals_ignore_case, False, _no_check),
    "StringNotEqualsIgnoreCase": (_string_equals_ignore_case, True, _no_check),
    "StringLike": (_string_like, False, _no_check),
    "StringNotLike": (_string_like, True, _no_check),
    "ArnEquals": (_arn_match, False, _check_arn),
    "ArnLike": (_arn_match, False, _check_arn),
    "ArnNotEquals": (_arn_match, True, _check_arn),
    "ArnNotLike": (_arn_match, True, _check_arn),
    "Bool": (_bool, False, _parse_bool),
    "IpAddress": (_ip, False, _parse_network),
    "NotIpAddress": (_ip, True, _parse_network),
    "NumericNotEquals": (_ordered(_parse_number, _ORDER["Equals"]), True, _parse_number),
    "DateNotEquals": (_ordered(_parse_date, _ORDER["Equals"]), True, _parse_date),
}
for _name, _relation in _ORDER.items():
    _OPERATORS[f"Numeric{_name}"] = (_ordered(_parse_number, _relation), False, _parse_number)
    _OPERATORS[f"Date{_name}"] = (_ordered(_parse_date, _relation), False, _parse_date)
del _name, _relation


def split_operator(operator: str) -> Tuple[str, bool]:
    """Return (base operator, IfExists flag). Set operators
    (``ForAnyValue:``, ``ForAllValues:``) are not modelled."""
    if ":" in operator:
        raise CannotEvaluate(f"condition operator {operator!r} is not modelled")
    if operator.endswith("IfExists"):
        return operator[: -len("IfExists")], True
    return operator, False


def _evaluate_null(present: bool, required: Any, if_exists: bool) -> bool:
    if if_exists:
        raise CannotEvaluate("condition operator 'NullIfExists' is not modelled")
    outcomes = []
    for value in _policy_values(required):
        lowered = ascii_lower(value)
        if lowered not in ("true", "false"):
            raise CannotEvaluate("Null condition value is not true or false")
        outcomes.append((not present) if lowered == "true" else present)
    return any(outcomes)


def evaluate_entry(operator: str, key: str, required: Any, ctx: MatchContext) -> bool:
    """One operator applied to one condition key."""
    base, if_exists = split_operator(operator)
    present, raw = ctx.lookup(key)
    if base == "Null":
        return _evaluate_null(present, required, if_exists)
    if base not in _OPERATORS:
        raise CannotEvaluate(f"condition operator {operator!r} is not modelled")
    compare, negated, check = _OPERATORS[base]
    values = _policy_values(required)
    for value in values:
        check(value)
    if not present:
        return if_exists or negated
    if isinstance(raw, list):
        raise CannotEvaluate(
            f"request value for {key!r} is multi-valued; set operators are not modelled"
        )
    ctx_value = _scalar_text(raw, "request context value")
    # OR across values; a negated operator is the NOR.
    any_match = any_of(lambda v=v: compare(ctx_value, v, ctx) for v in values)
    return not any_match if negated else any_match


def _check_block_keys(block: Dict[str, Any]) -> None:
    """AWS reads operator and key names case-insensitively, so two names
    that differ only in case have no defined meaning."""
    operators = [ascii_fold(name, "condition operator") for name in block]
    if len(set(operators)) != len(operators):
        raise CannotEvaluate("Condition has operators that differ only in case")
    for restrictions in block.values():
        keys = [ascii_fold(key, "condition key") for key in restrictions]
        if len(set(keys)) != len(keys):
            raise CannotEvaluate("Condition has keys that differ only in case")


def evaluate_condition(block: Dict[str, Any], ctx: MatchContext) -> bool:
    """All operators and keys in a Condition block, combined with AND."""
    _check_block_keys(block)
    return all_of(
        lambda op=operator, k=key, r=required: evaluate_entry(op, k, r, ctx)
        for operator, restrictions in block.items()
        for key, required in restrictions.items()
    )
