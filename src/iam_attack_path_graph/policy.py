"""Parsed, validated IAM policy documents.

A policy document is untrusted input (it comes from a snapshot file), so parsing is strict:
unknown top-level shapes raise `PolicyError` instead of being ignored, and sizes are bounded.
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Literal

MAX_DOCUMENT_CHARS = 131_072
MAX_STATEMENTS = 1_000
MAX_VALUES_PER_ELEMENT = 1_000
MAX_VALUE_CHARS = 2_048

Effect = Literal["Allow", "Deny"]


class PolicyError(ValueError):
    """A policy document that is malformed or too large."""


@dataclass(frozen=True)
class Statement:
    """One statement; exactly one of each Action/NotAction and Resource/NotResource pair is set."""

    effect: Effect
    sid: str = ""
    actions: tuple[str, ...] = ()
    not_actions: tuple[str, ...] | None = None
    resources: tuple[str, ...] = ()
    not_resources: tuple[str, ...] | None = None
    principals: dict[str, tuple[str, ...]] | None = None
    not_principals: dict[str, tuple[str, ...]] | None = None
    conditions: dict[str, dict[str, tuple[str, ...]]] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDocument:
    """A named policy document and its statements."""

    name: str
    statements: tuple[Statement, ...]
    version: str = "2012-10-17"


def decode_document(raw: object) -> dict[str, Any]:
    """Turn a dict, JSON string or URL-encoded JSON string (raw IAM API form) into a dict."""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        raise PolicyError(
            f"policy document must be an object or a string, got {type(raw).__name__}"
        )
    if len(raw) > MAX_DOCUMENT_CHARS * 3:
        raise PolicyError("policy document is too large")
    text = raw.strip()
    if text.startswith(("%7B", "%7b")):
        text = urllib.parse.unquote(text)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy document is not valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise PolicyError("policy document must be a JSON object")
    return value


def _strings(value: object, where: str) -> tuple[str, ...]:
    """A string or list of strings as a non-empty tuple."""
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or not items:
        raise PolicyError(f"{where} must be a string or a non-empty list of strings")
    if len(items) > MAX_VALUES_PER_ELEMENT:
        raise PolicyError(f"{where} has more than {MAX_VALUES_PER_ELEMENT} values")
    out: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item or len(item) > MAX_VALUE_CHARS:
            raise PolicyError(
                f"{where} values must be non-empty strings up to {MAX_VALUE_CHARS} chars"
            )
        out.append(item)
    return tuple(out)


def _condition_values(value: object, where: str) -> tuple[str, ...]:
    """Condition values: strings, numbers and booleans, normalised to strings."""
    items = value if isinstance(value, list) else [value]
    if not items or len(items) > MAX_VALUES_PER_ELEMENT:
        raise PolicyError(f"{where} must have 1 to {MAX_VALUES_PER_ELEMENT} values")
    out: list[str] = []
    for item in items:
        if isinstance(item, bool):
            out.append("true" if item else "false")
        elif isinstance(item, (str, int, float)):
            out.append(str(item))
        else:
            raise PolicyError(f"{where} values must be strings, numbers or booleans")
    return tuple(out)


def _principals(value: object, where: str) -> dict[str, tuple[str, ...]]:
    """A Principal element: `"*"` or a map of principal type to identifiers."""
    if value == "*":
        return {"AWS": ("*",)}
    if not isinstance(value, dict) or not value:
        raise PolicyError(f'{where} must be "*" or a non-empty object')
    return {str(kind): _strings(ids, f"{where}.{kind}") for kind, ids in value.items()}


def _conditions(value: object, where: str) -> dict[str, dict[str, tuple[str, ...]]]:
    """A Condition element: operator to key to values."""
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be an object")
    out: dict[str, dict[str, tuple[str, ...]]] = {}
    for operator, block in value.items():
        if not isinstance(block, dict) or not block:
            raise PolicyError(f"{where}.{operator} must be a non-empty object")
        out[str(operator)] = {
            str(key): _condition_values(vals, f"{where}.{operator}.{key}")
            for key, vals in block.items()
        }
    return out


def parse_statement(raw: object, where: str) -> Statement:
    """Validate one statement object."""
    if not isinstance(raw, dict):
        raise PolicyError(f"{where} must be an object")
    allowed = {
        "Sid",
        "Effect",
        "Action",
        "NotAction",
        "Resource",
        "NotResource",
        "Principal",
        "NotPrincipal",
        "Condition",
    }
    unknown = set(raw) - allowed
    if unknown:
        raise PolicyError(f"{where} has unknown elements: {sorted(unknown)}")
    effect = raw.get("Effect")
    if effect not in ("Allow", "Deny"):
        raise PolicyError(f"{where}.Effect must be Allow or Deny")
    if ("Action" in raw) == ("NotAction" in raw):
        raise PolicyError(f"{where} needs exactly one of Action or NotAction")
    if "Resource" in raw and "NotResource" in raw:
        raise PolicyError(f"{where} cannot have both Resource and NotResource")
    if "Principal" in raw and "NotPrincipal" in raw:
        raise PolicyError(f"{where} cannot have both Principal and NotPrincipal")
    sid = raw.get("Sid", "")
    if not isinstance(sid, str):
        raise PolicyError(f"{where}.Sid must be a string")
    has_principal = "Principal" in raw or "NotPrincipal" in raw
    if not has_principal and "Resource" not in raw and "NotResource" not in raw:
        raise PolicyError(f"{where} needs Resource or NotResource")
    return Statement(
        effect=effect,
        sid=sid,
        actions=_strings(raw["Action"], f"{where}.Action") if "Action" in raw else (),
        not_actions=_strings(raw["NotAction"], f"{where}.NotAction")
        if "NotAction" in raw
        else None,
        resources=_strings(raw["Resource"], f"{where}.Resource") if "Resource" in raw else (),
        not_resources=(
            _strings(raw["NotResource"], f"{where}.NotResource") if "NotResource" in raw else None
        ),
        principals=_principals(raw["Principal"], f"{where}.Principal")
        if "Principal" in raw
        else None,
        not_principals=(
            _principals(raw["NotPrincipal"], f"{where}.NotPrincipal")
            if "NotPrincipal" in raw
            else None
        ),
        conditions=_conditions(raw["Condition"], f"{where}.Condition")
        if "Condition" in raw
        else {},
    )


def parse_policy(raw: object, name: str) -> PolicyDocument:
    """Validate a whole policy document (identity, boundary or trust policy)."""
    doc = decode_document(raw)
    if len(json.dumps(doc)) > MAX_DOCUMENT_CHARS:
        raise PolicyError(f"{name}: policy document is larger than {MAX_DOCUMENT_CHARS} chars")
    version = doc.get("Version", "2008-10-17")
    if version not in ("2012-10-17", "2008-10-17"):
        raise PolicyError(f"{name}: unsupported Version {version!r}")
    statements = doc.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise PolicyError(f"{name}: Statement must be an object or a non-empty list")
    if len(statements) > MAX_STATEMENTS:
        raise PolicyError(f"{name}: more than {MAX_STATEMENTS} statements")
    parsed = tuple(parse_statement(s, f"{name}.Statement[{i}]") for i, s in enumerate(statements))
    return PolicyDocument(name=name, statements=parsed, version=str(version))
