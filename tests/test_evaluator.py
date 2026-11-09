"""The evaluator: deny precedence, wildcards, Not* elements, boundaries, variables and properties."""

from __future__ import annotations

import random
from typing import Any

import pytest
from helpers import allow, decide, deny, doc

from iam_attack_path_graph.context import Context
from iam_attack_path_graph.evaluator import (
    ANY,
    Decision,
    PolicySet,
    Request,
    RequestError,
    evaluate,
    statement_applies,
)
from iam_attack_path_graph.tristate import Tri

A, C, X, N = Decision.ALLOWED, Decision.CONDITIONAL, Decision.EXPLICIT_DENY, Decision.IMPLICIT_DENY
BUCKET = "arn:aws:s3:::reports/2026/q4.csv"


def test_no_policy_means_implicit_deny() -> None:
    assert decide([], "s3:GetObject", BUCKET) is N


def test_allow_and_explicit_deny_precedence() -> None:
    p = doc(allow("s3:*"), deny("s3:DeleteObject"))
    assert decide(p, "s3:GetObject", BUCKET) is A
    assert decide(p, "s3:DeleteObject", BUCKET) is X


def test_deny_in_another_policy_still_wins() -> None:
    assert (
        decide(
            [doc(allow()), doc(deny("iam:*"), name="q")], "iam:CreateUser", "arn:aws:iam::1:user/x"
        )
        is X
    )


def test_action_matching_is_case_insensitive_resource_is_not() -> None:
    p = doc(allow("S3:getobject", "arn:aws:s3:::reports/*"))
    assert decide(p, "s3:GetObject", BUCKET) is A
    assert decide(p, "s3:GetObject", "arn:aws:s3:::Reports/x") is N


def test_not_action_and_not_resource() -> None:
    p = doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    assert decide(p, "s3:GetObject", BUCKET) is A
    assert decide(p, "iam:CreateUser", "arn:aws:iam::1:user/x") is N
    q = doc(
        {"Effect": "Deny", "Action": "s3:*", "NotResource": "arn:aws:s3:::public/*"}, allow("s3:*")
    )
    assert decide(q, "s3:GetObject", "arn:aws:s3:::public/a") is A
    assert decide(q, "s3:GetObject", BUCKET) is X


def test_conditions_unknown_known_and_complete_context() -> None:
    p = doc(allow("iam:*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}))
    assert decide(p, "iam:CreateUser") is C
    assert decide(p, "iam:CreateUser", ctx=Context({"aws:MultiFactorAuthPresent": ("true",)})) is A
    assert decide(p, "iam:CreateUser", ctx=Context({"aws:MultiFactorAuthPresent": ("false",)})) is N
    assert decide(p, "iam:CreateUser", ctx=Context(complete=True)) is N


def test_conditional_deny_makes_an_allow_conditional() -> None:
    p = doc(allow(), deny(Condition={"IpAddress": {"aws:SourceIp": "198.51.100.0/24"}}))
    assert decide(p, "s3:GetObject", BUCKET) is C
    assert decide(p, "s3:GetObject", BUCKET, Context({"aws:SourceIp": ("198.51.100.9",)})) is X
    assert decide(p, "s3:GetObject", BUCKET, Context({"aws:SourceIp": ("203.0.113.9",)})) is A


def test_permissions_boundary_intersects_and_its_deny_counts() -> None:
    admin = doc(allow())
    boundary = doc(allow(["s3:*", "lambda:*"]), deny("s3:DeleteBucket"), name="b")
    assert decide(admin, "s3:GetObject", BUCKET, boundary=boundary) is A
    assert decide(admin, "iam:CreateUser", boundary=boundary) is N
    assert decide(admin, "s3:DeleteBucket", "arn:aws:s3:::reports", boundary=boundary) is X
    assert decide([], "s3:GetObject", BUCKET, boundary=boundary) is N


def test_boundary_reason_is_given_for_implicit_deny() -> None:
    ev = evaluate(
        PolicySet((doc(allow()),), doc(allow("s3:*"), name="b")), Request("iam:CreateUser")
    )
    assert ev.decision is N
    assert ev.reasons == ("permissions boundary does not allow it",)


def test_policy_variables_resolve_from_the_context() -> None:
    p = doc(allow("iam:CreateAccessKey", "arn:aws:iam::123456789012:user/${aws:username}"))
    own = "arn:aws:iam::123456789012:user/erin"
    ctx = Context({"aws:username": ("erin",)})
    assert decide(p, "iam:CreateAccessKey", own, ctx) is A
    assert decide(p, "iam:CreateAccessKey", "arn:aws:iam::123456789012:user/alice", ctx) is N
    assert decide(p, "iam:CreateAccessKey", own) is C
    assert decide(p, "iam:CreateAccessKey", "arn:aws:iam::999999999999:user/x") is N
    assert decide(p, "iam:CreateAccessKey", own, Context(complete=True)) is N


def test_variable_default_value_and_old_version_treats_variables_literally() -> None:
    p = doc(allow("s3:GetObject", "arn:aws:s3:::b/${aws:PrincipalTag/team, 'shared'}/*"))
    assert decide(p, "s3:GetObject", "arn:aws:s3:::b/shared/x", Context(complete=True)) is A
    old = doc(allow("s3:GetObject", "arn:aws:s3:::b/${aws:username}"), version="2008-10-17")
    assert (
        decide(old, "s3:GetObject", "arn:aws:s3:::b/alice", Context({"aws:username": ("alice",)}))
        is N
    )
    assert decide(old, "s3:GetObject", "arn:aws:s3:::b/${aws:username}") is A


def test_any_resource_needs_a_star_resource_to_be_allowed_everywhere() -> None:
    assert decide(doc(allow("s3:GetObject")), "s3:GetObject") is A
    assert decide(doc(allow("s3:GetObject", "arn:aws:s3:::b/*")), "s3:GetObject") is C
    assert (
        decide(
            doc(allow("s3:GetObject"), deny("s3:GetObject", "arn:aws:s3:::secret/*")),
            "s3:GetObject",
        )
        is C
    )
    assert (
        decide(
            doc({"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::x"}),
            "s3:GetObject",
        )
        is C
    )


def test_any_action_is_admin_only_with_a_full_wildcard() -> None:
    assert decide(doc(allow()), ANY) is A
    assert decide(doc(allow("*:*")), ANY) is A
    assert decide(doc(allow(["iam:*", "s3:*"])), ANY) is N
    assert decide(doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}), ANY) is C
    assert decide(doc(allow(), deny("s3:DeleteBucket")), ANY) is C
    assert decide(doc(allow(), deny()), ANY) is X


def test_not_action_allow_is_a_conditional_admin_with_the_exclusions_named() -> None:
    near_admin = doc(
        {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"}
    )
    ev = evaluate(PolicySet((near_admin,)), Request(ANY))
    assert ev.decision is C
    assert any(
        "NotAction allows every action except iam:*, organizations:*" in r for r in ev.reasons
    )


def test_matches_name_the_statements_behind_a_decision() -> None:
    p = doc(allow("s3:*", Sid="Read"), deny("s3:Delete*", Sid="NoDelete"), name="team")
    ev = evaluate(PolicySet((p,)), Request("s3:DeleteObject", BUCKET))
    assert [(m.policy, m.sid, m.effect, m.applies) for m in ev.matches] == [
        ("team", "Read", "Allow", Tri.TRUE),
        ("team", "NoDelete", "Deny", Tri.TRUE),
    ]


def test_statement_without_resource_applies_to_any_resource() -> None:
    trust = doc(
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    )
    assert (
        statement_applies(trust.statements[0], Request("sts:AssumeRole", "arn:aws:iam::1:role/r"))[
            0
        ]
        is Tri.TRUE
    )


@pytest.mark.parametrize("action", ["", "s3", "s3:Get Object", "a:b:c", "x" * 200 + ":y"])
def test_malformed_requests_are_rejected(action: str) -> None:
    with pytest.raises(RequestError):
        Request(action)
    with pytest.raises(RequestError):
        Request("s3:GetObject", "x" * 3000)


ACTIONS = ["s3:GetObject", "s3:PutObject", "iam:CreateUser", "iam:PassRole", "ec2:RunInstances"]
PATTERNS = ["*", "s3:*", "iam:*", "s3:Get*", "iam:Pass?ole", "ec2:RunInstances", "*:Get*"]
RESOURCES = ["*", "arn:aws:s3:::b/*", "arn:aws:iam::1:role/*", "arn:aws:s3:::b/x"]
REQ_RESOURCES = ["arn:aws:s3:::b/x", "arn:aws:iam::1:role/r", "arn:aws:s3:::c/y"]


def _random_statement(rng: random.Random) -> dict[str, Any]:
    """A random statement without conditions."""
    key = "Action" if rng.random() < 0.8 else "NotAction"
    return {
        "Effect": rng.choice(["Allow", "Allow", "Deny"]),
        key: rng.sample(PATTERNS, rng.randint(1, 2)),
        "Resource": rng.sample(RESOURCES, rng.randint(1, 2)),
    }


def test_randomized_properties_of_deny_and_allow() -> None:
    rng = random.Random(7)
    for _ in range(300):
        stmts = [_random_statement(rng) for _ in range(rng.randint(1, 4))]
        p = doc(*stmts)
        action, resource = rng.choice(ACTIONS), rng.choice(REQ_RESOURCES)
        before = decide(p, action, resource)
        assert before in (A, X, N), "no conditions and concrete request: never conditional"
        # Adding deny-all always gives an explicit deny.
        assert decide(doc(*stmts, deny()), action, resource) is X
        # Adding allow-all never turns an explicit deny into anything else and fixes implicit denies.
        after = decide(doc(*stmts, allow()), action, resource)
        assert after is (X if before is X else A)
        # Removing every Allow leaves no way to be allowed.
        only_denies = [s for s in stmts if s["Effect"] == "Deny"]
        if only_denies:
            assert decide(doc(*only_denies), action, resource) in (X, N)
