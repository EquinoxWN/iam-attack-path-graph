"""Effective permissions on the lab account, and the read-only collection role's own policy."""

from __future__ import annotations

import json

import pytest
from helpers import LAB, READONLY_POLICY

from iam_attack_path_graph.catalog import CATALOG, ESCALATION
from iam_attack_path_graph.context import Context
from iam_attack_path_graph.effective import check, report, report_all, summary
from iam_attack_path_graph.evaluator import Decision, PolicySet
from iam_attack_path_graph.policy import parse_policy
from iam_attack_path_graph.snapshot import Principal, load_snapshot

A, C, X, N = Decision.ALLOWED, Decision.CONDITIONAL, Decision.EXPLICIT_DENY, Decision.IMPLICIT_DENY
SNAP = load_snapshot(LAB)


@pytest.mark.parametrize(
    ("name", "admin"),
    [
        ("alice", A),  # AdministratorAccess through the admins group
        ("lambda-admin", A),
        ("dave", N),  # admin group, but the boundary allows only s3 and lambda
        ("carol", N),  # iam:* with MFA is not every action
        ("bob", N),
        ("iamgraph-readonly", N),
    ],
)
def test_admin_status(name: str, admin: Decision) -> None:
    assert report(SNAP.find(name)).admin is admin


@pytest.mark.parametrize(
    ("name", "action", "decision"),
    [
        ("bob", "iam:PassRole", A),
        ("bob", "lambda:CreateFunction", A),
        ("bob", "iam:CreateAccessKey", N),
        ("bob", "s3:GetObject", A),  # *:Get* from the readers group
        ("carol", "iam:AttachUserPolicy", C),  # needs MFA
        ("carol", "iam:CreateAccessKey", X),  # explicit deny beats iam:*
        ("dave", "lambda:CreateFunction", A),
        ("dave", "iam:PassRole", N),  # blocked by the boundary
        ("erin", "iam:CreateAccessKey", C),  # only on her own user
        ("frank", "iam:CreatePolicyVersion", C),  # only on customer policies
        ("ci-deploy", "iam:AttachRolePolicy", C),  # app-* roles in one region
        ("auditor", "sts:AssumeRole", C),  # only the read-only role
    ],
)
def test_catalog_decisions(name: str, action: str, decision: Decision) -> None:
    by_action = {a.action: a for a in report(SNAP.find(name)).actions}
    assert by_action[action].decision is decision


def test_scoped_resources_are_reported() -> None:
    by_action = {a.action: a for a in report(SNAP.find("frank")).actions}
    assert by_action["iam:CreatePolicyVersion"].scoped_to == ("arn:aws:iam::123456789012:policy/*",)
    erin = {a.action: a for a in report(SNAP.find("erin")).actions}
    assert erin["iam:CreateAccessKey"].scoped_to == (
        "arn:aws:iam::123456789012:user/${aws:username}",
    )


def test_check_fills_in_the_principals_own_keys() -> None:
    erin = SNAP.find("erin")
    assert check(erin, "iam:CreateAccessKey", "arn:aws:iam::123456789012:user/erin").decision is A
    assert check(erin, "iam:CreateAccessKey", "arn:aws:iam::123456789012:user/alice").decision is N
    carol = SNAP.find("carol")
    mfa = Context({"aws:MultiFactorAuthPresent": ("true",)})
    assert (
        check(carol, "iam:AttachUserPolicy", "arn:aws:iam::123456789012:user/carol", mfa).decision
        is A
    )


def test_summary_and_json_view() -> None:
    reports = report_all(SNAP)
    assert [r.name for r in reports][:3] == ["ci-deploy", "iamgraph-readonly", "lambda-admin"]
    assert dict(summary(reports)) == {
        "principals": 10,
        "admins": 2,
        "conditional_admins": 0,
        "with_escalation_actions": 9,
    }
    view = report(SNAP.find("bob")).to_dict()
    json.dumps(view)
    assert view["escalation_actions"] == [
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
    ]


def test_the_read_only_role_policy_grants_no_catalog_action_and_no_write() -> None:
    policy = parse_policy(json.loads(READONLY_POLICY.read_text(encoding="utf-8")), "readonly")
    role = Principal(
        "role", "ro", "arn:aws:iam::123456789012:role/ro", "AROA", PolicySet((policy,))
    )
    r = report(role)
    assert r.admin is N
    assert all(a.decision is N for a in r.actions), [
        a.action for a in r.actions if a.decision is not N
    ]
    assert check(role, "iam:GetAccountAuthorizationDetails").decision is A
    for write in (
        "iam:CreateUser",
        "iam:DeleteRole",
        "iam:UpdateAccessKey",
        "s3:PutObject",
        "sts:AssumeRole",
    ):
        assert check(role, write).decision is N


def test_lab_read_only_role_uses_the_shipped_policy() -> None:
    shipped = parse_policy(json.loads(READONLY_POLICY.read_text(encoding="utf-8")), "readonly")
    lab_role = SNAP.find("iamgraph-readonly")
    assert lab_role.policies.identity[0].statements == shipped.statements


def test_catalog_is_well_formed() -> None:
    assert set(ESCALATION) <= set(CATALOG)
    assert all(":" in a and desc for a, desc in CATALOG.items())
