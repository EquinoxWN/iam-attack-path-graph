"""Identity-policy evaluation for one principal and one request.

Follows AWS's documented order for a single account without Organizations: an explicit deny in
any identity policy or permissions boundary wins; otherwise the action must be allowed by an
identity policy and, when a boundary is attached, by the boundary too. Anything that depends on
request details that are not known (condition keys, policy variables, "some resources") makes
the answer CONDITIONAL instead of a guess.

`ANY` ("*") as the request action or resource means "every action" / "every resource": a
statement only fully covers it with the pattern `*`; narrower patterns cover it partly.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum

from . import conditions, wildcard
from .context import AbsentError, Context, UnresolvedError, has_variable, substitute, widen
from .policy import PolicyDocument, Statement
from .tristate import Tri, all_of, any_of

ANY = "*"
_ACTION = re.compile(r"^[A-Za-z0-9-]{1,64}:[A-Za-z0-9*?]{1,128}$")
MAX_RESOURCE_CHARS = 2_048


class Decision(Enum):
    """The outcome for one request."""

    ALLOWED = "allowed"
    CONDITIONAL = "conditional"
    EXPLICIT_DENY = "explicit-deny"
    IMPLICIT_DENY = "implicit-deny"


class RequestError(ValueError):
    """A request whose action or resource is malformed."""


@dataclass(frozen=True)
class Request:
    """An action on a resource with what is known about the request context."""

    action: str
    resource: str = ANY
    context: Context = field(default_factory=Context)

    def __post_init__(self) -> None:
        """Reject malformed actions and oversized resources."""
        if self.action != ANY and not _ACTION.match(self.action):
            raise RequestError(f"action must look like service:Name, got {self.action!r}")
        if not self.resource or len(self.resource) > MAX_RESOURCE_CHARS:
            raise RequestError(f"resource must be 1 to {MAX_RESOURCE_CHARS} chars")


@dataclass(frozen=True)
class Match:
    """A statement that applies (TRUE) or may apply (UNKNOWN) to the request."""

    policy: str
    index: int
    sid: str
    effect: str
    applies: Tri
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class Evaluation:
    """The decision and the statements behind it."""

    decision: Decision
    matches: tuple[Match, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class PolicySet:
    """Everything that governs one principal's identity-based permissions."""

    identity: tuple[PolicyDocument, ...]
    boundary: PolicyDocument | None = None


def _covers_all_actions(pattern: str) -> bool:
    """Whether an action pattern matches every possible action (`*` or `*:*`)."""
    return pattern.replace(":", "") != "" and set(pattern) <= {"*", ":"} and pattern.count(":") <= 1


def _action_matches(stmt: Statement, action: str) -> tuple[Tri, str | None]:
    """Whether the statement's Action/NotAction covers the action."""
    if action == ANY:
        # An Action-list allow must cover every action; NotAction allows and narrower denies
        # may cover all but some, so they make the answer conditional instead of a no.
        if stmt.not_actions is None and any(_covers_all_actions(p) for p in stmt.actions):
            return Tri.TRUE, None
        if stmt.effect == "Allow" and stmt.not_actions is not None:
            return Tri.UNKNOWN, "NotAction allows every action except " + ", ".join(
                stmt.not_actions
            )
        if stmt.effect == "Allow":
            return Tri.FALSE, None
        return Tri.UNKNOWN, "a deny covers some actions"
    if stmt.not_actions is not None:
        hit = any(wildcard.match(p, action, case_sensitive=False) for p in stmt.not_actions)
        return Tri.of(not hit), None
    hit = any(wildcard.match(p, action, case_sensitive=False) for p in stmt.actions)
    return Tri.of(hit), None


def _one_resource(pattern: str, resource: str, ctx: Context, variables: bool) -> Tri:
    """Whether one resource pattern (possibly with policy variables) matches."""
    if variables and has_variable(pattern):
        try:
            pattern = substitute(pattern, ctx)
        except AbsentError:
            return Tri.FALSE
        except UnresolvedError:
            return Tri.UNKNOWN if wildcard.match(widen(pattern), resource) else Tri.FALSE
    return Tri.of(wildcard.match(pattern, resource))


def _resource_matches(stmt: Statement, req: Request, variables: bool) -> tuple[Tri, str | None]:
    """Whether the statement's Resource/NotResource covers the resource."""
    if stmt.not_resources is not None:
        if req.resource == ANY:
            return Tri.UNKNOWN, "NotResource covers only some resources"
        hit = any_of(
            _one_resource(p, req.resource, req.context, variables) for p in stmt.not_resources
        )
        return hit.negate(), (
            "NotResource depends on policy variables" if hit is Tri.UNKNOWN else None
        )
    if not stmt.resources:
        return Tri.TRUE, None
    if req.resource == ANY:
        if ANY in stmt.resources:
            return Tri.TRUE, None
        return Tri.UNKNOWN, "statement covers only some resources: " + ", ".join(stmt.resources)
    hit = any_of(_one_resource(p, req.resource, req.context, variables) for p in stmt.resources)
    return hit, ("resource depends on policy variables" if hit is Tri.UNKNOWN else None)


def statement_applies(
    stmt: Statement, req: Request, variables: bool = True
) -> tuple[Tri, list[str]]:
    """Whether a statement applies to the request, with reasons when it only may apply."""
    reasons: list[str] = []
    action, why = _action_matches(stmt, req.action)
    if why:
        reasons.append(why)
    if action is Tri.FALSE:
        return Tri.FALSE, []
    resource, why = _resource_matches(stmt, req, variables)
    if why:
        reasons.append(why)
    if resource is Tri.FALSE:
        return Tri.FALSE, []
    cond, why_cond = conditions.evaluate(stmt.conditions, req.context)
    reasons.extend(why_cond)
    result = all_of((action, resource, cond))
    return result, reasons if result is Tri.UNKNOWN else []


def _evaluate_documents(
    docs: Sequence[PolicyDocument], req: Request
) -> tuple[Tri, Tri, list[Match]]:
    """Allow and deny state of a group of documents, plus the statements that matched."""
    allows: list[Tri] = []
    denies: list[Tri] = []
    matches: list[Match] = []
    for doc in docs:
        variables = doc.version == "2012-10-17"
        for i, stmt in enumerate(doc.statements):
            applies, reasons = statement_applies(stmt, req, variables)
            if applies is Tri.FALSE:
                continue
            (allows if stmt.effect == "Allow" else denies).append(applies)
            matches.append(Match(doc.name, i, stmt.sid, stmt.effect, applies, tuple(reasons)))
    return any_of(allows), any_of(denies), matches


def evaluate(policies: PolicySet, req: Request) -> Evaluation:
    """Decide one request for one principal."""
    allow, deny, matches = _evaluate_documents(policies.identity, req)
    reasons: list[str] = []
    if policies.boundary is not None:
        b_allow, b_deny, b_matches = _evaluate_documents((policies.boundary,), req)
        matches.extend(b_matches)
        deny = any_of((deny, b_deny))
        if b_allow is not Tri.TRUE and allow is not Tri.FALSE:
            reasons.append(
                "permissions boundary does not allow it"
                if b_allow is Tri.FALSE
                else "permissions boundary allows it only partly"
            )
        allow = all_of((allow, b_allow))
    if deny is Tri.TRUE:
        decision = Decision.EXPLICIT_DENY
    elif allow is Tri.FALSE:
        decision = Decision.IMPLICIT_DENY
    elif allow is Tri.TRUE and deny is Tri.FALSE:
        decision = Decision.ALLOWED
    else:
        decision = Decision.CONDITIONAL
        if deny is Tri.UNKNOWN:
            reasons.append("a deny statement may apply")
        for m in matches:
            if m.applies is Tri.UNKNOWN:
                reasons.extend(f"{m.policy}#{m.sid or m.index}: {r}" for r in m.reasons)
    if decision is not Decision.CONDITIONAL:
        reasons = [r for r in reasons if decision is Decision.IMPLICIT_DENY]
    return Evaluation(decision, tuple(matches), tuple(dict.fromkeys(reasons)))
