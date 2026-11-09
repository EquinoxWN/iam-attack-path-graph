"""Trust policy reading."""

from __future__ import annotations

from helpers import LAB, doc

from iam_attack_path_graph.evaluator import PolicySet
from iam_attack_path_graph.snapshot import Principal, load_snapshot
from iam_attack_path_graph.trust import TrustGrant, account_root_trusted, trusted

SNAP = load_snapshot(LAB)


def _role(*statements: dict[str, object]) -> Principal:
    """A role with the given trust statements."""
    return Principal(
        "role",
        "r",
        "arn:aws:iam::123456789012:role/r",
        "AROA",
        PolicySet(()),
        trust_policy=doc(*statements),
    )


def test_lab_trust_grants() -> None:
    assert trusted(SNAP.find("lambda-admin")) == [
        TrustGrant(
            "arn:aws:iam::123456789012:role/lambda-admin",
            "Service",
            "lambda.amazonaws.com",
            ("sts:AssumeRole",),
            False,
        )
    ]
    ro = trusted(SNAP.find("iamgraph-readonly"))
    assert [(g.principal, g.conditional) for g in ro] == [
        ("arn:aws:iam::123456789012:user/auditor", True)
    ]


def test_account_root_trust_is_detected() -> None:
    (grant,) = trusted(SNAP.find("ci-deploy"))
    assert account_root_trusted(grant, "123456789012")
    assert not account_root_trusted(trusted(SNAP.find("lambda-admin"))[0], "123456789012")


def test_deny_other_actions_and_users_are_skipped() -> None:
    role = _role(
        {"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"},
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::1:user/x"},
            "Action": "sts:TagSession",
        },
        {
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWith*",
        },
        {"Effect": "Allow", "Principal": {"AWS": "*"}, "NotAction": "sts:AssumeRole"},
    )
    grants = trusted(role)
    assert [(g.principal_type, g.actions) for g in grants] == [
        ("Federated", ("sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity")),
        ("AWS", ("sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity")),
    ]


def test_users_have_no_trust_grants() -> None:
    assert trusted(SNAP.find("alice")) == []
