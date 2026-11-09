"""Each principal's effective permissions over the action catalog."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .catalog import CATALOG, ESCALATION
from .context import Context
from .evaluator import ANY, Decision, Evaluation, Request, evaluate
from .snapshot import Principal, Snapshot

__all__ = ["CATALOG", "ESCALATION", "PrincipalReport", "check", "report", "report_all", "summary"]


@dataclass(frozen=True)
class ActionResult:
    """One action's decision for every resource, and the resources an allow is scoped to."""

    action: str
    decision: Decision
    scoped_to: tuple[str, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class PrincipalReport:
    """A principal's admin status and catalog decisions."""

    arn: str
    kind: str
    name: str
    admin: Decision
    actions: tuple[ActionResult, ...]

    def escalation_actions(self) -> list[str]:
        """Escalation actions that are allowed or conditionally allowed."""
        return [
            a.action
            for a in self.actions
            if a.action in ESCALATION and a.decision in (Decision.ALLOWED, Decision.CONDITIONAL)
        ]

    def to_dict(self) -> dict[str, object]:
        """A JSON-ready view."""
        return {
            "arn": self.arn,
            "kind": self.kind,
            "name": self.name,
            "admin": self.admin.value,
            "escalation_actions": self.escalation_actions(),
            "actions": {
                a.action: {
                    "decision": a.decision.value,
                    "scoped_to": list(a.scoped_to),
                    "reasons": list(a.reasons),
                }
                for a in self.actions
            },
        }


def check(
    principal: Principal, action: str, resource: str = ANY, extra: Context | None = None
) -> Evaluation:
    """Decide one request for a principal, filling in its own context keys."""
    ctx = principal.context()
    if extra is not None:
        ctx = extra.merged(ctx.values)
    return evaluate(principal.policies, Request(action, resource, ctx))


def _scopes(ev: Evaluation, principal: Principal) -> tuple[str, ...]:
    """Resource patterns of the allow statements that may apply."""
    out: list[str] = []
    docs = {d.name: d for d in principal.policies.identity}
    for m in ev.matches:
        if m.effect != "Allow" or m.policy not in docs:
            continue
        stmt = docs[m.policy].statements[m.index]
        if stmt.not_resources is not None:
            out.extend(f"NOT {r}" for r in stmt.not_resources)
        else:
            out.extend(stmt.resources)
    return tuple(dict.fromkeys(out))


def report(principal: Principal, actions: Iterable[str] = CATALOG) -> PrincipalReport:
    """Admin status and per-action decisions for one principal."""
    results = []
    for action in actions:
        ev = check(principal, action)
        results.append(ActionResult(action, ev.decision, _scopes(ev, principal), ev.reasons))
    admin = check(principal, ANY).decision
    return PrincipalReport(principal.arn, principal.kind, principal.name, admin, tuple(results))


def report_all(snapshot: Snapshot, actions: Iterable[str] = CATALOG) -> list[PrincipalReport]:
    """Reports for every principal, sorted by ARN."""
    acts = list(actions)
    return [report(snapshot.principals[a], acts) for a in sorted(snapshot.principals)]


def summary(reports: Iterable[PrincipalReport]) -> Mapping[str, int]:
    """Counts of admins and principals holding escalation actions."""
    rs = list(reports)
    return {
        "principals": len(rs),
        "admins": sum(r.admin is Decision.ALLOWED for r in rs),
        "conditional_admins": sum(r.admin is Decision.CONDITIONAL for r in rs),
        "with_escalation_actions": sum(bool(r.escalation_actions()) for r in rs),
    }
