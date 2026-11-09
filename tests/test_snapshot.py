"""Snapshot parsing from GetAccountAuthorizationDetails output."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from helpers import LAB

from iam_attack_path_graph import snapshot as snapshot_mod
from iam_attack_path_graph.snapshot import SnapshotError, load_snapshot, parse_snapshot
from iam_attack_path_graph.synthetic import account


def lab() -> dict[str, Any]:
    """A fresh copy of the lab snapshot document."""
    data: dict[str, Any] = json.loads(LAB.read_text(encoding="utf-8"))
    return data


def test_lab_snapshot_parses_every_principal() -> None:
    snap = load_snapshot(LAB)
    assert snap.account_id == "123456789012"
    assert snap.collected_at == "2026-11-09T00:00:00Z"
    users = sorted(p.name for p in snap.principals.values() if p.kind == "user")
    roles = sorted(p.name for p in snap.principals.values() if p.kind == "role")
    assert users == ["alice", "auditor", "bob", "carol", "dave", "erin", "frank"]
    assert roles == ["ci-deploy", "iamgraph-readonly", "lambda-admin"]
    assert snap.warnings == ()


def test_user_gets_inline_attached_and_group_policies() -> None:
    bob = load_snapshot(LAB).find("bob")
    names = [d.name for d in bob.policies.identity]
    assert names == [
        "user/bob:inline/deploy-functions",
        "arn:aws:iam::123456789012:policy/read-everything",
    ]
    assert bob.groups == ("readers",)


def test_managed_policy_uses_the_default_version_not_the_first() -> None:
    snap = load_snapshot(LAB)
    doc = snap.managed_policies["arn:aws:iam::123456789012:policy/read-everything"]
    assert doc.statements[0].actions == ("*:Get*", "*:List*", "*:Describe*")


def test_boundary_and_trust_policy_are_attached() -> None:
    snap = load_snapshot(LAB)
    dave = snap.find("dave")
    assert dave.policies.boundary is not None
    assert dave.policies.boundary.name == "arn:aws:iam::123456789012:policy/dev-boundary"
    assert snap.find("lambda-admin").trust_policy is not None
    assert snap.find("alice").trust_policy is None


def test_principal_context_has_identity_keys_and_tags() -> None:
    d = lab()
    d["UserDetailList"][0]["Tags"] = [{"Key": "team", "Value": "platform"}]
    alice = parse_snapshot(d).find("alice")
    ctx = alice.context()
    assert ctx.lookup("aws:username") == ("alice",)
    assert ctx.lookup("AWS:PrincipalTag/team") == ("platform",)
    assert ctx.lookup("aws:PrincipalType") == ("User",)
    assert ctx.is_unknown("aws:SourceIp")
    role_ctx = parse_snapshot(d).find("ci-deploy").context()
    assert role_ctx.lookup("aws:username") is None
    assert role_ctx.lookup("aws:PrincipalType") == ("AssumedRole",)


def test_missing_managed_policy_group_and_boundary_become_warnings() -> None:
    d = lab()
    d["Policies"] = [
        p for p in d["Policies"] if p["PolicyName"] not in ("AdministratorAccess", "dev-boundary")
    ]
    d["UserDetailList"][1]["GroupList"].append("ghosts")
    snap = parse_snapshot(d)
    text = "\n".join(snap.warnings)
    assert "AdministratorAccess is not in the snapshot" in text
    assert "group ghosts is not in the snapshot" in text
    assert (
        "permissions boundary arn:aws:iam::123456789012:policy/dev-boundary is not in the snapshot"
        in text
    )


def test_find_by_arn_name_unknown_and_ambiguous() -> None:
    d = lab()
    snap = parse_snapshot(d)
    assert snap.find("arn:aws:iam::123456789012:user/alice").name == "alice"
    with pytest.raises(SnapshotError, match="no principal named"):
        snap.find("mallory")
    d["RoleDetailList"][0]["RoleName"] = "alice"
    with pytest.raises(SnapshotError, match="ambiguous"):
        parse_snapshot(d).find("alice")


def _broken(edit: str) -> dict[str, Any]:
    """The lab document with one deliberate defect."""
    d = copy.deepcopy(lab())
    if edit == "users-not-list":
        d["UserDetailList"] = {}
    elif edit == "user-no-name":
        del d["UserDetailList"][0]["UserName"]
    elif edit == "bad-arn":
        d["UserDetailList"][0]["Arn"] = "user/alice"
    elif edit == "no-default-version":
        d["Policies"][0]["PolicyVersionList"][0]["IsDefaultVersion"] = False
        d["Policies"][0]["DefaultVersionId"] = "v9"
    elif edit == "bad-inline":
        d["UserDetailList"][2]["UserPolicyList"][0]["PolicyDocument"] = {"Statement": "x"}
    elif edit == "bad-tag":
        d["UserDetailList"][0]["Tags"] = [{"Value": "x"}]
    return d


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        ("users-not-list", "UserDetailList must be a list"),
        ("user-no-name", r"UserDetailList\[0\].UserName"),
        ("bad-arn", "is not an ARN"),
        ("no-default-version", "no default policy version"),
        ("bad-inline", "Statement must be"),
        ("bad-tag", "Key must be"),
    ],
)
def test_malformed_snapshots_fail_with_the_location(edit: str, message: str) -> None:
    with pytest.raises(SnapshotError, match=message):
        parse_snapshot(_broken(edit))


def test_top_level_and_empty_documents() -> None:
    with pytest.raises(SnapshotError, match="snapshot must be an object"):
        parse_snapshot([])
    empty = parse_snapshot({})
    assert empty.principals == {}
    assert empty.account_id == ""


def test_load_rejects_missing_invalid_and_oversized_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(SnapshotError, match="cannot read"):
        load_snapshot(tmp_path / "nope.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    with pytest.raises(SnapshotError, match="not valid UTF-8 JSON"):
        load_snapshot(bad)
    monkeypatch.setattr(snapshot_mod, "MAX_SNAPSHOT_BYTES", 10)
    with pytest.raises(SnapshotError, match="larger than"):
        load_snapshot(LAB)


def test_synthetic_account_parses_and_is_deterministic() -> None:
    a, b = account(50, 20, seed=3), account(50, 20, seed=3)
    assert a == b
    assert len(parse_snapshot(a).principals) == 70
    assert account(50, 20, seed=4) != a
    with pytest.raises(ValueError, match="groups"):
        account(1, 1, groups=0)
