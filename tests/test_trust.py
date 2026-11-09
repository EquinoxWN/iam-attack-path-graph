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


def test_not_principal_allow_is_reported_as_wildcard_trust() -> None:
    role = _role(
        {
            "Effect": "Allow",
            "NotPrincipal": {"AWS": ["arn:aws:iam::123456789012:user/blocked"]},
            "Action": "sts:AssumeRole",
        }
    )
    (grant,) = trusted(role)
    assert (grant.principal_type, grant.principal) == ("AWS", "*")
    assert grant.excluded == ("arn:aws:iam::123456789012:user/blocked",)
    assert account_root_trusted(grant, "123456789012")


def test_account_root_is_recognised_in_every_partition() -> None:
    for arn in (
        "arn:aws:iam::123456789012:root",
        "arn:aws-cn:iam::123456789012:root",
        "arn:aws-us-gov:iam::123456789012:root",
    ):
        grant = TrustGrant(
            "arn:aws:iam::123456789012:role/r", "AWS", arn, ("sts:AssumeRole",), False
        )
        assert account_root_trusted(grant, "123456789012"), arn
    other = TrustGrant("r", "AWS", "arn:aws-cn:iam::999999999999:root", ("sts:AssumeRole",), False)
    assert not account_root_trusted(other, "123456789012")
    service = TrustGrant("r", "Service", "123456789012", ("sts:AssumeRole",), False)
    assert not account_root_trusted(service, "123456789012")
