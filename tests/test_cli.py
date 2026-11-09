"""The iamgraph command line."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from helpers import LAB

from iam_attack_path_graph import cli, collect


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    """Run the CLI and capture its output."""
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_perms_text_lists_every_principal(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "perms", str(LAB))
    assert code == 0
    assert "user alice                admin=allowed       escalation=all" in out
    assert (
        "user bob                  admin=implicit-deny escalation=iam:PassRole,lambda:CreateFunction,lambda:InvokeFunction"
        in out
    )
    assert "10 principals, 2 admins, 0 conditional admins, 9 hold escalation actions" in out


def test_perms_json_for_one_principal_and_custom_actions(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = run(
        capsys,
        "perms",
        str(LAB),
        "--principal",
        "dave",
        "--actions",
        "s3:PutObject,iam:CreateUser",
        "--json",
    )
    data = json.loads(out)
    assert code == 0
    (dave,) = data["principals"]
    assert dave["actions"]["s3:PutObject"]["decision"] == "allowed"
    assert dave["actions"]["iam:CreateUser"]["decision"] == "implicit-deny"
    assert data["account"] == "123456789012"


def test_check_with_context(capsys: pytest.CaptureFixture[str]) -> None:
    args = ("check", str(LAB), "--principal", "carol", "--action", "iam:AttachUserPolicy")
    _, out, _ = run(capsys, *args)
    assert ": conditional" in out
    assert (
        "because: user/carol:inline/iam-with-mfa#IamWithMfa: Bool on aws:MultiFactorAuthPresent depends on the request"
        in out
    )
    _, out, _ = run(capsys, *args, "--context", "aws:MultiFactorAuthPresent=true")
    assert ": allowed" in out
    _, out, _ = run(capsys, *args, "--complete-context")
    assert ": implicit-deny" in out


def test_trust_lists_role_grants(capsys: pytest.CaptureFixture[str]) -> None:
    _, out, _ = run(capsys, "trust", str(LAB))
    assert out.splitlines() == [
        "ci-deploy: AWS arn:aws:iam::123456789012:root",
        "iamgraph-readonly: AWS arn:aws:iam::123456789012:user/auditor (with conditions)",
        "lambda-admin: Service lambda.amazonaws.com",
    ]


def test_bench_reports_counts(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "bench", "--users", "20", "--roles", "10")
    data = json.loads(out)
    assert code == 0
    assert data["principals"] == 30
    assert data["evaluations"] == 30 * (data["catalog_actions"] + 1)


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["perms", "missing.json"], "cannot read"),
        (["perms", str(LAB), "--principal", "mallory"], "no principal named"),
        (
            ["check", str(LAB), "--principal", "bob", "--action", "not-an-action"],
            "action must look like",
        ),
    ],
)
def test_errors_exit_2_with_one_line(
    capsys: pytest.CaptureFixture[str], argv: list[str], message: str
) -> None:
    code, _, err = run(capsys, *argv)
    assert code == 2
    assert message in err
    assert err.count("\n") == 1


def test_bad_arguments_exit_2(capsys: pytest.CaptureFixture[str]) -> None:
    for argv in (
        ["bench", "--users", "0"],
        [
            "check",
            str(LAB),
            "--principal",
            "bob",
            "--action",
            "s3:GetObject",
            "--context",
            "novalue",
        ],
    ):
        with pytest.raises(SystemExit) as info:
            cli.main(argv)
        assert info.value.code == 2
    assert "key=value" in capsys.readouterr().err


def test_collect_writes_a_snapshot_with_a_fake_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    lab: dict[str, Any] = json.loads(LAB.read_text(encoding="utf-8"))
    lab.pop("Metadata")

    class Client:
        """One page: the lab account."""

        def get_paginator(self, name: str) -> Any:
            """A paginator over one page."""

            class P:
                def paginate(self) -> Any:
                    """The page."""
                    return iter([lab])

            return P()

    monkeypatch.setattr(collect, "iam_client", lambda role, ext: Client())
    out_file = tmp_path / "snap.json"
    code, out, _ = run(
        capsys, "collect", "--role-arn", "arn:aws:iam::123456789012:role/x", "--out", str(out_file)
    )
    assert code == 0
    assert "10 principals, 4 managed policies" in out
    code, out, _ = run(capsys, "perms", str(out_file))
    assert "2 admins" in out


def test_collect_does_not_write_when_the_snapshot_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(role: str | None, ext: str | None) -> Any:
        """A client whose page has an invalid user."""

        class C:
            def get_paginator(self, name: str) -> Any:
                """Paginator."""

                class P:
                    def paginate(self) -> Any:
                        """One bad page."""
                        return iter([{"UserDetailList": [{"UserName": "x"}]}])

                return P()

        return C()

    monkeypatch.setattr(collect, "iam_client", broken)
    out_file = tmp_path / "snap.json"
    code, _, err = run(capsys, "collect", "--out", str(out_file))
    assert code == 2
    assert "Arn must be a non-empty string" in err
    assert not out_file.exists()
