"""Shared test helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from iam_attack_path_graph.context import Context
from iam_attack_path_graph.evaluator import ANY, Decision, PolicySet, Request, evaluate
from iam_attack_path_graph.policy import PolicyDocument, parse_policy

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "examples" / "lab-snapshot.json"
READONLY_POLICY = ROOT / "deploy" / "readonly-role" / "permissions-policy.json"
TRUST_POLICY = ROOT / "deploy" / "readonly-role" / "trust-policy.json"


def doc(
    *statements: dict[str, Any], name: str = "p", version: str = "2012-10-17"
) -> PolicyDocument:
    """A parsed policy with the given statements."""
    return parse_policy({"Version": version, "Statement": list(statements)}, name)


def allow(action: Any = "*", resource: Any = "*", **extra: Any) -> dict[str, Any]:
    """An Allow statement."""
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def deny(action: Any = "*", resource: Any = "*", **extra: Any) -> dict[str, Any]:
    """A Deny statement."""
    return {"Effect": "Deny", "Action": action, "Resource": resource, **extra}


def decide(
    policies: list[PolicyDocument] | PolicyDocument,
    action: str,
    resource: str = ANY,
    ctx: Context | None = None,
    boundary: PolicyDocument | None = None,
) -> Decision:
    """The decision for one request."""
    docs = (policies,) if isinstance(policies, PolicyDocument) else tuple(policies)
    req = Request(action, resource, ctx or Context())
    return evaluate(PolicySet(docs, boundary), req).decision
