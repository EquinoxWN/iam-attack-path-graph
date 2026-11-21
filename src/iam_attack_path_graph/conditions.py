"""Condition block evaluation in three-valued logic.

Each operator in a statement must hold (AND), each key in an operator must hold (AND), and a key
holds when any of its policy values matches (OR), as in AWS's documented evaluation logic.
A key whose value is unknown makes the result UNKNOWN unless another part is already FALSE.
"""

from __future__ import annotations

import ipaddress
import operator
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from . import wildcard
from .context import AbsentError, Context, UnresolvedError, has_variable, substitute
from .tristate import Tri, all_of

Matcher = Callable[[str, str], bool]


def _date(text: str) -> datetime:
    """An ISO 8601 date or an epoch-seconds value, as an aware UTC datetime."""
    stripped = text.strip()
    if stripped.lstrip("-").isdigit():
        return datetime.fromtimestamp(int(stripped), tz=UTC)
    parsed = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _ip(value: str, network: str) -> bool:
    """Whether an address lies inside a CIDR block."""
    return ipaddress.ip_address(value) in ipaddress.ip_network(network, strict=False)


def _cmp(parse: Callable[[str], Any], op: Callable[[Any, Any], bool]) -> Matcher:
    """A matcher comparing parsed request and policy values."""

    def matcher(request: str, policy: str) -> bool:
        """Compare one pair."""
        return op(parse(request), parse(policy))

    return matcher


def _like(request: str, policy: str) -> bool:
    """Case-sensitive wildcard match."""
    return wildcard.match(policy, request)


# Base operator name -> (matcher, negated, accepts policy variables).
_OPERATORS: Mapping[str, tuple[Matcher, bool, bool]] = {
    "stringequals": (lambda r, p: r == p, False, True),
    "stringnotequals": (lambda r, p: r == p, True, True),
    "stringequalsignorecase": (lambda r, p: r.casefold() == p.casefold(), False, True),
    "stringnotequalsignorecase": (lambda r, p: r.casefold() == p.casefold(), True, True),
    "stringlike": (_like, False, True),
    "stringnotlike": (_like, True, True),
    "numericequals": (_cmp(float, operator.eq), False, False),
    "numericnotequals": (_cmp(float, operator.eq), True, False),
    "numericlessthan": (_cmp(float, operator.lt), False, False),
    "numericlessthanequals": (_cmp(float, operator.le), False, False),
    "numericgreaterthan": (_cmp(float, operator.gt), False, False),
    "numericgreaterthanequals": (_cmp(float, operator.ge), False, False),
    "dateequals": (_cmp(_date, operator.eq), False, False),
    "datenotequals": (_cmp(_date, operator.eq), True, False),
    "datelessthan": (_cmp(_date, operator.lt), False, False),
    "datelessthanequals": (_cmp(_date, operator.le), False, False),
    "dategreaterthan": (_cmp(_date, operator.gt), False, False),
    "dategreaterthanequals": (_cmp(_date, operator.ge), False, False),
    "bool": (lambda r, p: r.lower() == p.lower(), False, False),
    "binaryequals": (lambda r, p: r == p, False, False),
    "ipaddress": (_ip, False, False),
    "notipaddress": (_ip, True, False),
    "arnequals": (_like, False, True),
    "arnlike": (_like, False, True),
    "arnnotequals": (_like, True, True),
    "arnnotlike": (_like, True, True),
}


@dataclass(frozen=True)
class Operator:
    """A parsed condition operator such as `ForAnyValue:StringLikeIfExists`."""

    base: str
    set_qualifier: str  # "", "forallvalues" or "foranyvalue"
    if_exists: bool

    @staticmethod
    def parse(name: str) -> Operator:
        """Split qualifiers off an operator name."""
        lowered = name.lower()
        qualifier = ""
        for q in ("forallvalues:", "foranyvalue:"):
            if lowered.startswith(q):
                qualifier, lowered = q[:-1], lowered[len(q) :]
        if_exists = lowered.endswith("ifexists") and lowered != "ifexists"
        if if_exists:
            lowered = lowered[: -len("ifexists")]
        return Operator(base=lowered, set_qualifier=qualifier, if_exists=if_exists)


def supported(name: str) -> bool:
    """Whether the operator is one this evaluator implements."""
    op = Operator.parse(name)
    return op.base == "null" or op.base in _OPERATORS


def _safe(matcher: Matcher, request: str, policy: str) -> bool:
    """Apply a matcher; a value that does not parse as its type does not match."""
    try:
        return matcher(request, policy)
    except (ValueError, TypeError, OverflowError):
        return False


def _key(op: Operator, key: str, policy_values: tuple[str, ...], ctx: Context) -> Tri:
    """Evaluate one key of one operator."""
    request = ctx.lookup(key)
    if op.base == "null":
        if request is None and ctx.is_unknown(key):
            return Tri.UNKNOWN
        absent = request is None
        return Tri.of(any(absent == (p.lower() == "true") for p in policy_values))
    if request is None:
        if ctx.is_unknown(key):
            return Tri.UNKNOWN
        negated = _OPERATORS[op.base][1]
        if op.if_exists or op.set_qualifier == "forallvalues":
            return Tri.TRUE
        if op.set_qualifier == "foranyvalue":
            return Tri.FALSE
        return Tri.of(negated)
    matcher, negated, takes_variables = _OPERATORS[op.base]
    resolved: list[str] = []
    for p in policy_values:
        if takes_variables and has_variable(p):
            try:
                resolved.append(substitute(p, ctx))
            except UnresolvedError:
                return Tri.UNKNOWN
            except AbsentError:
                continue
        else:
            resolved.append(p)

    def positive(v: str) -> bool:
        """Whether a request value matches any policy value."""
        return any(_safe(matcher, v, p) for p in resolved)

    if op.set_qualifier == "forallvalues":
        return Tri.of(all(positive(v) != negated for v in request))
    if op.set_qualifier == "foranyvalue":
        return Tri.of(any(positive(v) != negated for v in request))
    if negated:
        return Tri.of(not any(positive(v) for v in request))
    return Tri.of(any(positive(v) for v in request))


def evaluate(
    conditions: Mapping[str, Mapping[str, tuple[str, ...]]], ctx: Context
) -> tuple[Tri, list[str]]:
    """Evaluate a statement's Condition block; returns the result and why it is not TRUE."""
    results: list[Tri] = []
    reasons: list[str] = []
    for name, block in conditions.items():
        op = Operator.parse(name)
        if op.base != "null" and op.base not in _OPERATORS:
            results.append(Tri.UNKNOWN)
            reasons.append(f"unsupported condition operator {name}")
            continue
        for key, values in block.items():
            r = _key(op, key, values, ctx)
            results.append(r)
            if r is Tri.UNKNOWN:
                reasons.append(f"{name} on {key} depends on the request")
    return all_of(results), reasons
