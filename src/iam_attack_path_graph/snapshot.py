"""An account's IAM state, parsed from `GetAccountAuthorizationDetails` output.

The input is the API response (merged pages) as written by `iamgraph collect` or by
`aws iam get-account-authorization-details`. Parsing is strict: a malformed element raises
`SnapshotError` naming where it is. A managed policy that is attached but missing from the
snapshot is recorded in `warnings` (the principal is then analysed without it).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .context import Context
from .evaluator import PolicySet
from .policy import PolicyDocument, PolicyError, parse_policy

MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_ENTITIES = 50_000

Kind = Literal["user", "role"]


class SnapshotError(ValueError):
    """A snapshot file that cannot be used."""


@dataclass(frozen=True)
class Principal:
    """A user or role with every policy that applies to it."""

    kind: Kind
    name: str
    arn: str
    user_id: str
    policies: PolicySet
    groups: tuple[str, ...] = ()
    tags: Mapping[str, str] = field(default_factory=dict)
    trust_policy: PolicyDocument | None = None

    def context(self) -> Context:
        """Condition keys that are known for every request this principal makes."""
        values: dict[str, tuple[str, ...]] = {
            "aws:PrincipalArn": (self.arn,),
            "aws:PrincipalAccount": (self.arn.split(":")[4],),
            "aws:PrincipalType": ("User" if self.kind == "user" else "AssumedRole",),
        }
        if self.kind == "user":
            values["aws:username"] = (self.name,)
            values["aws:userid"] = (self.user_id,)
        for k, v in self.tags.items():
            values[f"aws:PrincipalTag/{k}"] = (v,)
        return Context(values)


@dataclass(frozen=True)
class Snapshot:
    """All principals, groups and managed policies of one account."""

    account_id: str
    collected_at: str
    principals: Mapping[str, Principal]
    groups: Mapping[str, tuple[PolicyDocument, ...]]
    managed_policies: Mapping[str, PolicyDocument]
    warnings: tuple[str, ...] = ()

    def find(self, name_or_arn: str) -> Principal:
        """A principal by ARN, or by name when the name is unique."""
        if name_or_arn in self.principals:
            return self.principals[name_or_arn]
        hits = [p for p in self.principals.values() if p.name == name_or_arn]
        if len(hits) != 1:
            raise SnapshotError(
                f"no principal named {name_or_arn!r}"
                if not hits
                else f"{name_or_arn!r} is ambiguous; use the ARN"
            )
        return hits[0]


def _obj(value: object, where: str) -> dict[str, Any]:
    """Require a JSON object."""
    if not isinstance(value, dict):
        raise SnapshotError(f"{where} must be an object")
    return value


def _list(value: object, where: str) -> list[Any]:
    """Require a JSON array (missing means empty)."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise SnapshotError(f"{where} must be a list")
    if len(value) > MAX_ENTITIES:
        raise SnapshotError(f"{where} has more than {MAX_ENTITIES} entries")
    return value


def _str(obj: Mapping[str, Any], key: str, where: str) -> str:
    """Require a non-empty string field."""
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise SnapshotError(f"{where}.{key} must be a non-empty string")
    return value


def _arn(value: str, where: str) -> str:
    """Require something shaped like an IAM ARN."""
    parts = value.split(":")
    if len(parts) < 6 or parts[0] != "arn":
        raise SnapshotError(f"{where} is not an ARN: {value!r}")
    return value


def _policy(raw: object, name: str) -> PolicyDocument:
    """Parse a policy, turning PolicyError into SnapshotError."""
    try:
        return parse_policy(raw, name)
    except PolicyError as exc:
        raise SnapshotError(str(exc)) from exc


def _managed(raw: list[Any]) -> dict[str, PolicyDocument]:
    """Managed policies by ARN, using each one's default version."""
    out: dict[str, PolicyDocument] = {}
    for i, item in enumerate(raw):
        where = f"Policies[{i}]"
        pol = _obj(item, where)
        arn = _arn(_str(pol, "Arn", where), f"{where}.Arn")
        default = pol.get("DefaultVersionId")
        versions = _list(pol.get("PolicyVersionList"), f"{where}.PolicyVersionList")
        chosen = [
            _obj(v, f"{where}.PolicyVersionList[{j}]")
            for j, v in enumerate(versions)
            if isinstance(v, dict)
            and (v.get("IsDefaultVersion") is True or v.get("VersionId") == default)
        ]
        if not chosen:
            raise SnapshotError(f"{where} ({arn}) has no default policy version")
        out[arn] = _policy(chosen[0].get("Document"), arn)
    return out


def _inline(raw: object, owner: str, key: str, where: str) -> list[PolicyDocument]:
    """Inline policies of a user, group or role."""
    docs = []
    for i, item in enumerate(_list(raw, f"{where}.{key}")):
        pol = _obj(item, f"{where}.{key}[{i}]")
        name = _str(pol, "PolicyName", f"{where}.{key}[{i}]")
        docs.append(_policy(pol.get("PolicyDocument"), f"{owner}:inline/{name}"))
    return docs


def _attached(
    raw: object, managed: Mapping[str, PolicyDocument], where: str, warnings: list[str]
) -> list[PolicyDocument]:
    """Attached managed policies, warning about any not in the snapshot."""
    docs = []
    for i, item in enumerate(_list(raw, f"{where}.AttachedManagedPolicies")):
        arn = _str(_obj(item, f"{where}.AttachedManagedPolicies[{i}]"), "PolicyArn", where)
        if arn in managed:
            docs.append(managed[arn])
        else:
            warnings.append(
                f"{where}: attached policy {arn} is not in the snapshot; analysed without it"
            )
    return docs


def _boundary(
    entity: Mapping[str, Any],
    managed: Mapping[str, PolicyDocument],
    where: str,
    warnings: list[str],
) -> PolicyDocument | None:
    """The permissions boundary, if one is set."""
    raw = entity.get("PermissionsBoundary")
    if raw is None:
        return None
    arn = _str(_obj(raw, f"{where}.PermissionsBoundary"), "PermissionsBoundaryArn", where)
    if arn not in managed:
        warnings.append(
            f"{where}: permissions boundary {arn} is not in the snapshot; every action is treated as conditional"
        )
        return PolicyDocument(
            name=f"missing-boundary:{arn}",
            statements=(
                parse_policy(
                    {
                        "Version": "2012-10-17",
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                            "Condition": {"Bool": {"iamgraph:UnknownBoundary": "true"}},
                        },
                    },
                    "missing",
                ).statements
            ),
        )
    return managed[arn]


def _tags(raw: object, where: str) -> dict[str, str]:
    """Tags as a dict."""
    out: dict[str, str] = {}
    for i, item in enumerate(_list(raw, f"{where}.Tags")):
        tag = _obj(item, f"{where}.Tags[{i}]")
        out[_str(tag, "Key", f"{where}.Tags[{i}]")] = str(tag.get("Value", ""))
    return out


def parse_snapshot(raw: object) -> Snapshot:
    """Build a Snapshot from the decoded JSON document."""
    doc = _obj(raw, "snapshot")
    warnings: list[str] = []
    managed = _managed(_list(doc.get("Policies"), "Policies"))
    groups: dict[str, tuple[PolicyDocument, ...]] = {}
    for i, item in enumerate(_list(doc.get("GroupDetailList"), "GroupDetailList")):
        where = f"GroupDetailList[{i}]"
        g = _obj(item, where)
        name = _str(g, "GroupName", where)
        groups[name] = tuple(
            _inline(g.get("GroupPolicyList"), f"group/{name}", "GroupPolicyList", where)
            + _attached(g.get("AttachedManagedPolicies"), managed, where, warnings)
        )
    principals: dict[str, Principal] = {}
    for i, item in enumerate(_list(doc.get("UserDetailList"), "UserDetailList")):
        where = f"UserDetailList[{i}]"
        u = _obj(item, where)
        name = _str(u, "UserName", where)
        arn = _arn(_str(u, "Arn", where), f"{where}.Arn")
        member_of = tuple(str(g) for g in _list(u.get("GroupList"), f"{where}.GroupList"))
        docs = _inline(u.get("UserPolicyList"), f"user/{name}", "UserPolicyList", where)
        docs += _attached(u.get("AttachedManagedPolicies"), managed, where, warnings)
        for gname in member_of:
            if gname not in groups:
                warnings.append(
                    f"{where}: group {gname} is not in the snapshot; analysed without it"
                )
            docs += groups.get(gname, ())
        principals[arn] = Principal(
            kind="user",
            name=name,
            arn=arn,
            user_id=str(u.get("UserId", "")),
            policies=PolicySet(tuple(docs), _boundary(u, managed, where, warnings)),
            groups=member_of,
            tags=_tags(u.get("Tags"), where),
        )
    for i, item in enumerate(_list(doc.get("RoleDetailList"), "RoleDetailList")):
        where = f"RoleDetailList[{i}]"
        r = _obj(item, where)
        name = _str(r, "RoleName", where)
        arn = _arn(_str(r, "Arn", where), f"{where}.Arn")
        docs = _inline(r.get("RolePolicyList"), f"role/{name}", "RolePolicyList", where)
        docs += _attached(r.get("AttachedManagedPolicies"), managed, where, warnings)
        trust_raw = r.get("AssumeRolePolicyDocument")
        principals[arn] = Principal(
            kind="role",
            name=name,
            arn=arn,
            user_id=str(r.get("RoleId", "")),
            policies=PolicySet(tuple(docs), _boundary(r, managed, where, warnings)),
            tags=_tags(r.get("Tags"), where),
            trust_policy=_policy(trust_raw, f"role/{name}:trust")
            if trust_raw is not None
            else None,
        )
    arns = list(principals) + list(managed)
    account = next((a.split(":")[4] for a in arns if a.split(":")[4].isdigit()), "")
    meta = doc.get("Metadata", {})
    collected_at = str(meta.get("CollectedAt", "")) if isinstance(meta, dict) else ""
    return Snapshot(account, collected_at, principals, groups, managed, tuple(warnings))


def load_snapshot(path: Path) -> Snapshot:
    """Read and parse a snapshot file, bounded in size."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SnapshotError(f"cannot read {path}: {exc.strerror}") from exc
    if size > MAX_SNAPSHOT_BYTES:
        raise SnapshotError(f"{path} is larger than {MAX_SNAPSHOT_BYTES} bytes")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SnapshotError(f"{path} is not valid UTF-8 JSON: {exc}") from exc
    return parse_snapshot(raw)
