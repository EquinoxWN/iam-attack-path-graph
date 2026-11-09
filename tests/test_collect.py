"""Live collection with a fake boto3: role assumption, timeouts, pagination and atomic writes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from iam_attack_path_graph.collect import CollectError, fetch, iam_client, write_atomic
from iam_attack_path_graph.snapshot import parse_snapshot

ROLE = "arn:aws:iam::123456789012:role/iamgraph-readonly"


class FakeConfig:
    """Records the botocore Config arguments."""

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


class FakePaginator:
    """Yields canned pages, or raises."""

    def __init__(self, pages: list[Any], error: Exception | None = None) -> None:
        self.pages, self.error = pages, error

    def paginate(self) -> Any:
        """Iterate the pages."""
        yield from self.pages
        if self.error is not None:
            raise self.error


class FakeClient:
    """An IAM or STS client."""

    def __init__(
        self, service: str, pages: list[Any] | None = None, error: Exception | None = None
    ) -> None:
        self.service, self.pages, self.error = service, pages or [], error
        self.assumed: dict[str, Any] = {}

    def assume_role(self, **params: Any) -> dict[str, Any]:
        """Return fake credentials, or raise."""
        if self.error is not None:
            raise self.error
        self.assumed = params
        return {
            "Credentials": {
                "AccessKeyId": "ASIAEXAMPLE",
                "SecretAccessKey": "EXAMPLE-NOT-A-SECRET",
                "SessionToken": "EXAMPLE-NOT-A-SECRET",
            }
        }

    def get_paginator(self, name: str) -> FakePaginator:
        """The only paginator collection uses."""
        assert name == "get_account_authorization_details"
        return FakePaginator(self.pages, self.error)


class FakeBoto3:
    """Records client() calls."""

    def __init__(self, sts_error: Exception | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.sts = FakeClient("sts", error=sts_error)

    def client(self, service: str, **kwargs: Any) -> FakeClient:
        """A fake client."""
        self.calls.append((service, kwargs))
        return self.sts if service == "sts" else FakeClient(service)


def test_assumes_the_read_only_role_with_timeouts_and_bounded_retries() -> None:
    boto = FakeBoto3()
    iam_client(ROLE, "EXAMPLE-NOT-A-SECRET", boto3_module=boto, config_class=FakeConfig)
    assert boto.sts.assumed == {
        "RoleArn": ROLE,
        "RoleSessionName": "iam-attack-path-graph",
        "DurationSeconds": 900,
        "ExternalId": "EXAMPLE-NOT-A-SECRET",
    }
    (sts_name, sts_kwargs), (iam_name, iam_kwargs) = boto.calls
    assert (sts_name, iam_name) == ("sts", "iam")
    assert iam_kwargs["aws_session_token"] == "EXAMPLE-NOT-A-SECRET"  # noqa: S105
    config = iam_kwargs["config"].kwargs
    assert config == {
        "connect_timeout": 5,
        "read_timeout": 30,
        "retries": {"max_attempts": 5, "mode": "standard"},
    }
    assert sts_kwargs["config"].kwargs == config


def test_without_a_role_uses_current_credentials() -> None:
    boto = FakeBoto3()
    iam_client(None, boto3_module=boto, config_class=FakeConfig)
    assert [c[0] for c in boto.calls] == ["iam"]
    assert boto.sts.assumed == {}


@pytest.mark.parametrize(
    ("role", "external_id", "message"),
    [
        ("arn:aws:iam::123456789012:user/alice", None, "not an IAM role ARN"),
        ("role/x", None, "not an IAM role ARN"),
        (ROLE, "x", "external ID"),
        (ROLE, "bad id with spaces", "external ID"),
    ],
)
def test_invalid_role_or_external_id_is_rejected_before_any_call(
    role: str, external_id: str | None, message: str
) -> None:
    boto = FakeBoto3()
    with pytest.raises(CollectError, match=message):
        iam_client(role, external_id, boto3_module=boto, config_class=FakeConfig)
    assert boto.calls == []


def test_assume_role_failure_is_raised_with_its_cause() -> None:
    cause = PermissionError("AccessDenied")
    with pytest.raises(CollectError, match=r"assume role .* failed: PermissionError") as info:
        iam_client(ROLE, boto3_module=FakeBoto3(sts_error=cause), config_class=FakeConfig)
    assert info.value.__cause__ is cause


def test_missing_boto3_gives_an_install_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(name: str) -> Any:
        """Pretend boto3 is not installed."""
        raise ImportError(name)

    monkeypatch.setattr("iam_attack_path_graph.collect.importlib.import_module", fail)
    with pytest.raises(CollectError, match="needs boto3"):
        iam_client(None)


def _page(n: int) -> dict[str, Any]:
    """A page with one user."""
    return {
        "UserDetailList": [
            {
                "UserName": f"u{n}",
                "UserId": f"AIDA{n}",
                "Arn": f"arn:aws:iam::123456789012:user/u{n}",
            }
        ],
        "IsTruncated": True,
    }


def test_pages_are_merged_and_stamped_in_utc() -> None:
    doc = fetch(FakeClient("iam", [_page(1), _page(2), {"Policies": []}]))
    assert [u["UserName"] for u in doc["UserDetailList"]] == ["u1", "u2"]
    assert doc["Metadata"]["Pages"] == 3
    assert doc["Metadata"]["CollectedAt"].endswith("Z")
    assert len(parse_snapshot(doc).principals) == 2


@pytest.mark.parametrize(
    ("pages", "message"),
    [
        ([], "no pages"),
        (["x"], "not an object"),
        ([{"UserDetailList": {}}], "UserDetailList is not a list"),
    ],
)
def test_bad_pages_fail(pages: list[Any], message: str) -> None:
    with pytest.raises(CollectError, match=message):
        fetch(FakeClient("iam", pages))


def test_page_limit_is_enforced() -> None:
    with pytest.raises(CollectError, match="more than 2 pages"):
        fetch(FakeClient("iam", [_page(i) for i in range(5)]), max_pages=2)


def test_api_errors_mid_pagination_are_raised_with_their_cause() -> None:
    cause = TimeoutError("read timeout")
    with pytest.raises(
        CollectError, match="GetAccountAuthorizationDetails failed: TimeoutError"
    ) as info:
        fetch(FakeClient("iam", [_page(1)], error=cause))
    assert info.value.__cause__ is cause


def test_write_atomic_replaces_whole_file_and_leaves_no_temp(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "snap.json"
    write_atomic(target, {"a": 1})
    write_atomic(target, {"b": 2})
    assert json.loads(target.read_text(encoding="utf-8")) == {"b": 2}
    assert [p.name for p in target.parent.iterdir()] == ["snap.json"]


def test_write_atomic_failure_keeps_the_old_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "snap.json"
    write_atomic(target, {"old": True})

    def crash(src: str, dst: Path) -> None:
        """Simulate a crash at the rename."""
        raise OSError("disk full")

    monkeypatch.setattr("iam_attack_path_graph.collect.os.replace", crash)
    with pytest.raises(OSError, match="disk full"):
        write_atomic(target, {"new": True})
    assert json.loads(target.read_text(encoding="utf-8")) == {"old": True}
    assert [p.name for p in tmp_path.iterdir()] == ["snap.json"]
