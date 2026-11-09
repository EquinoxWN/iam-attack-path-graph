"""Who a role's trust policy lets in: the raw material for M2's AssumeRole and PassRole edges."""

from __future__ import annotations

from dataclasses import dataclass

from . import wildcard
from .snapshot import Principal

_ASSUME_ACTIONS = ("sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity")


@dataclass(frozen=True)
class TrustGrant:
    """One principal (or service) an Allow statement in a trust policy names."""

    role_arn: str
    principal_type: str  # AWS, Service, Federated or CanonicalUser
    principal: str
    actions: tuple[str, ...]
    conditional: bool


def trusted(role: Principal) -> list[TrustGrant]:
    """Principals the role's trust policy allows to assume it (before any deny)."""
    if role.trust_policy is None:
        return []
    out: list[TrustGrant] = []
    for stmt in role.trust_policy.statements:
        if stmt.effect != "Allow" or not stmt.principals:
            continue
        acts = tuple(
            a
            for a in _ASSUME_ACTIONS
            if (
                stmt.not_actions is None
                and any(wildcard.match(p, a, case_sensitive=False) for p in stmt.actions)
            )
            or (
                stmt.not_actions is not None
                and not any(wildcard.match(p, a, case_sensitive=False) for p in stmt.not_actions)
            )
        )
        if not acts:
            continue
        for kind, ids in sorted(stmt.principals.items()):
            out.extend(
                TrustGrant(role.arn, kind, ident, acts, bool(stmt.conditions)) for ident in ids
            )
    return out


def account_root_trusted(grant: TrustGrant, account_id: str) -> bool:
    """Whether a grant trusts a whole account (its root ARN, bare ID or `*`)."""
    return grant.principal_type == "AWS" and grant.principal in (
        "*",
        account_id,
        f"arn:aws:iam::{account_id}:root",
    )
