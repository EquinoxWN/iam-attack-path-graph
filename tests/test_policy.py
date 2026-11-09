"""Policy parsing: accepted shapes, normalisation and rejected input."""

from __future__ import annotations

import json
import urllib.parse
from typing import Any

import pytest

from iam_attack_path_graph.policy import (
    MAX_STATEMENTS,
    PolicyError,
    decode_document,
    parse_policy,
)


def test_single_statement_object_and_string_values_are_normalised() -> None:
    p = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        },
        "x",
    )
    assert p.statements[0].actions == ("s3:GetObject",)
    assert p.statements[0].resources == ("*",)


def test_url_encoded_and_plain_json_strings_decode_to_the_same_document() -> None:
    raw = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }
    text = json.dumps(raw)
    assert decode_document(text) == raw
    assert decode_document(urllib.parse.quote(text)) == raw


def test_condition_values_of_any_scalar_type_become_strings() -> None:
    p = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "Bool": {"aws:SecureTransport": True},
                        "NumericLessThan": {"k": [3, 4.5]},
                    },
                }
            ],
        },
        "x",
    )
    assert p.statements[0].conditions == {
        "Bool": {"aws:SecureTransport": ("true",)},
        "NumericLessThan": {"k": ("3", "4.5")},
    }


def test_trust_policy_principal_star_and_no_resource_is_valid() -> None:
    p = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}],
        },
        "t",
    )
    assert p.statements[0].principals == {"AWS": ("*",)}


def test_missing_version_defaults_to_2008() -> None:
    p = parse_policy({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}, "x")
    assert p.version == "2008-10-17"


def _stmt(**kw: Any) -> dict[str, Any]:
    """A statement with the given elements."""
    return {"Version": "2012-10-17", "Statement": [kw]}


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (42, "object or a string"),
        ("not json", "not valid JSON"),
        ("[1]", "JSON object"),
        ({"Version": "2099-01-01", "Statement": []}, "unsupported Version"),
        ({"Version": "2012-10-17", "Statement": []}, "non-empty list"),
        (_stmt(Effect="Maybe", Action="*", Resource="*"), "Allow or Deny"),
        (_stmt(Effect="Allow", Resource="*"), "exactly one of Action or NotAction"),
        (_stmt(Effect="Allow", Action="*", NotAction="x", Resource="*"), "exactly one"),
        (_stmt(Effect="Allow", Action="*", Resource="*", NotResource="*"), "both Resource"),
        (_stmt(Effect="Allow", Action="*"), "needs Resource"),
        (_stmt(Effect="Allow", Action=[], Resource="*"), "non-empty list"),
        (_stmt(Effect="Allow", Action=[""], Resource="*"), "non-empty strings"),
        (_stmt(Effect="Allow", Action=[1], Resource="*"), "non-empty strings"),
        (_stmt(Effect="Allow", Action="*", Resource="*", Sid=5), "Sid must be a string"),
        (_stmt(Effect="Allow", Action="*", Resource="*", Extra=1), "unknown elements"),
        (_stmt(Effect="Allow", Action="*", Resource="*", Condition=[]), "must be an object"),
        (
            _stmt(Effect="Allow", Action="*", Resource="*", Condition={"Bool": {}}),
            "non-empty object",
        ),
        (
            _stmt(Effect="Allow", Action="*", Resource="*", Condition={"Bool": {"k": {"x": 1}}}),
            "strings, numbers",
        ),
        (_stmt(Effect="Allow", Action="*", Principal=5), "non-empty object"),
        ({"Version": "2012-10-17", "Statement": ["x"]}, "must be an object"),
    ],
)
def test_malformed_documents_are_rejected(raw: object, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        parse_policy(raw, "bad")


def test_statement_and_size_limits() -> None:
    too_many = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "a:b", "Resource": "*"}] * (MAX_STATEMENTS + 1),
    }
    with pytest.raises(PolicyError, match="more than"):
        parse_policy(too_many, "big")
    huge = _stmt(Effect="Allow", Action=["a:" + "b" * 2000] * 100, Resource="*")
    with pytest.raises(PolicyError, match="larger than"):
        parse_policy(huge, "big")
    with pytest.raises(PolicyError, match="too large"):
        decode_document("x" * 500_000)
