"""Read an account's IAM through a read-only role and save it as a snapshot file.

Only two API calls are made: `sts:AssumeRole` into the read-only role (when a role ARN is given)
and the paginated, read-only `iam:GetAccountAuthorizationDetails`. Every call has connect and
read timeouts and botocore's bounded "standard" retries; pagination has a hard page limit.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_PAGES = 500
SESSION_SECONDS = 900
_ROLE_ARN = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$")
_EXTERNAL_ID = re.compile(r"^[\w+=,.@:/-]{2,1224}$")
_LIST_KEYS = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")


class CollectError(RuntimeError):
    """Collection failed; the snapshot file is left untouched."""


def client_config(botocore_config: Any) -> Any:
    """Timeouts and bounded retries for every AWS call."""
    return botocore_config(
        connect_timeout=5,
        read_timeout=30,
        retries={"max_attempts": 5, "mode": "standard"},
    )


def iam_client(
    role_arn: str | None,
    external_id: str | None = None,
    *,
    boto3_module: Any = None,
    config_class: Any = None,
) -> Any:
    """An IAM client, optionally using credentials from assuming the read-only role."""
    if role_arn is not None and not _ROLE_ARN.match(role_arn):
        raise CollectError(f"not an IAM role ARN: {role_arn!r}")
    if external_id is not None and not _EXTERNAL_ID.match(external_id):
        raise CollectError("external ID must be 2 to 1224 characters of [A-Za-z0-9+=,.@:/_-]")
    if boto3_module is None or config_class is None:
        try:
            boto3_module = importlib.import_module("boto3")
            config_class = importlib.import_module("botocore.config").Config
        except ImportError as exc:
            raise CollectError('live collection needs boto3: pip install ".[aws]"') from exc
    config = client_config(config_class)
    if role_arn is None:
        return boto3_module.client("iam", config=config)
    sts = boto3_module.client("sts", config=config)
    params: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": "iam-attack-path-graph",
        "DurationSeconds": SESSION_SECONDS,
    }
    if external_id is not None:
        params["ExternalId"] = external_id
    try:
        creds = sts.assume_role(**params)["Credentials"]
    except Exception as exc:  # botocore raises many types; keep the cause chained
        raise CollectError(f"assume role {role_arn} failed: {type(exc).__name__}: {exc}") from exc
    return boto3_module.client(
        "iam",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        config=config,
    )


def _pages(client: Any) -> Iterator[Any]:
    """Pages of GetAccountAuthorizationDetails, with AWS errors raised as CollectError."""
    try:
        yield from client.get_paginator("get_account_authorization_details").paginate()
    except Exception as exc:  # botocore raises many types; keep the cause chained
        raise CollectError(
            f"GetAccountAuthorizationDetails failed: {type(exc).__name__}: {exc}"
        ) from exc


def fetch(client: Any, max_pages: int = MAX_PAGES) -> dict[str, Any]:
    """Merge every page of GetAccountAuthorizationDetails into one document."""
    merged: dict[str, Any] = {k: [] for k in _LIST_KEYS}
    count = 0
    for page in _pages(client):
        count += 1
        if count > max_pages:
            raise CollectError(f"more than {max_pages} pages; refusing to continue")
        if not isinstance(page, dict):
            raise CollectError(f"page {count} is not an object")
        for key in _LIST_KEYS:
            items = page.get(key, [])
            if not isinstance(items, list):
                raise CollectError(f"page {count}: {key} is not a list")
            merged[key].extend(items)
    if count == 0:
        raise CollectError("the API returned no pages")
    merged["Metadata"] = {
        "CollectedAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Pages": count,
        "Source": "iam:GetAccountAuthorizationDetails",
    }
    return merged


def write_atomic(path: Path, document: dict[str, Any]) -> None:
    """Write JSON to a sibling temp file, fsync it, then rename over the target."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(document, fh, indent=1, sort_keys=True, default=str)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
