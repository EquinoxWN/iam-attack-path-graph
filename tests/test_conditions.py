"""Condition operators in three-valued logic, against AWS's documented semantics."""

from __future__ import annotations

import pytest

from iam_attack_path_graph.conditions import Operator, evaluate, supported
from iam_attack_path_graph.context import Context
from iam_attack_path_graph.tristate import Tri

T, F, U = Tri.TRUE, Tri.FALSE, Tri.UNKNOWN


def run(op: str, key: str, values: tuple[str, ...], ctx: Context) -> Tri:
    """Evaluate a one-operator, one-key condition."""
    return evaluate({op: {key: values}}, ctx)[0]


def known(**kv: str | tuple[str, ...]) -> Context:
    """A complete context from keyword values."""
    return Context(
        {k.replace("__", ":"): (v if isinstance(v, tuple) else (v,)) for k, v in kv.items()},
        complete=True,
    )


@pytest.mark.parametrize(
    ("op", "policy", "request_value", "expected"),
    [
        ("StringEquals", ("prod",), "prod", T),
        ("StringEquals", ("prod",), "Prod", F),
        ("StringEquals", ("dev", "prod"), "prod", T),
        ("StringNotEquals", ("dev", "prod"), "prod", F),
        ("StringNotEquals", ("dev", "prod"), "test", T),
        ("StringEqualsIgnoreCase", ("PROD",), "prod", T),
        ("StringNotEqualsIgnoreCase", ("PROD",), "prod", F),
        ("StringLike", ("home/*",), "home/alice/x", T),
        ("StringNotLike", ("home/*",), "tmp/x", T),
        ("NumericLessThan", ("10",), "9", T),
        ("NumericLessThan", ("10",), "10", F),
        ("NumericLessThanEquals", ("10",), "10", T),
        ("NumericGreaterThan", ("10",), "10.5", T),
        ("NumericGreaterThanEquals", ("10",), "9", F),
        ("NumericEquals", ("10",), "10.0", T),
        ("NumericNotEquals", ("10",), "11", T),
        ("NumericEquals", ("10",), "ten", F),
        ("DateLessThan", ("2026-12-01T00:00:00Z",), "2026-11-09T12:00:00Z", T),
        ("DateGreaterThan", ("2026-12-01T00:00:00Z",), "2026-11-09T12:00:00Z", F),
        ("DateEquals", ("1700000000",), "2023-11-14T22:13:20Z", T),
        ("DateNotEquals", ("2026-01-01",), "2026-01-01T00:00:00Z", F),
        ("DateLessThanEquals", ("2026-01-01T00:00:00Z",), "2026-01-01T00:00:00Z", T),
        ("DateGreaterThanEquals", ("2026-01-01T00:00:00Z",), "not a date", F),
        ("Bool", ("true",), "TRUE", T),
        ("Bool", ("true",), "false", F),
        ("BinaryEquals", ("QmluYXJ5",), "QmluYXJ5", T),
        ("IpAddress", ("203.0.113.0/24",), "203.0.113.7", T),
        ("IpAddress", ("203.0.113.0/24",), "198.51.100.7", F),
        ("NotIpAddress", ("203.0.113.0/24",), "198.51.100.7", T),
        ("IpAddress", ("203.0.113.0/24",), "not-an-ip", F),
        ("ArnLike", ("arn:aws:iam::*:role/app-*",), "arn:aws:iam::123456789012:role/app-1", T),
        ("ArnEquals", ("arn:aws:iam::123456789012:role/x",), "arn:aws:iam::123456789012:role/y", F),
        ("ArnNotLike", ("arn:aws:iam::*:role/app-*",), "arn:aws:iam::123456789012:role/db", T),
        ("ArnNotEquals", ("arn:aws:iam::*:role/x",), "arn:aws:iam::123456789012:role/x", F),
    ],
)
def test_operators_with_known_values(
    op: str, policy: tuple[str, ...], request_value: str, expected: Tri
) -> None:
    assert run(op, "k", policy, known(k=request_value)) is expected


def test_unknown_key_gives_unknown_and_a_reason() -> None:
    result, reasons = evaluate({"Bool": {"aws:MultiFactorAuthPresent": ("true",)}}, Context())
    assert result is U
    assert reasons == ["Bool on aws:MultiFactorAuthPresent depends on the request"]


def test_a_false_part_beats_an_unknown_part() -> None:
    ctx = Context({"aws:RequestedRegion": ("us-east-1",)})
    block = {"StringEquals": {"aws:RequestedRegion": ("eu-west-1",), "aws:SourceVpc": ("vpc-1",)}}
    assert evaluate(block, ctx)[0] is F


def test_operators_and_keys_are_and_ed() -> None:
    ctx = known(a="1", b="2")
    assert evaluate({"StringEquals": {"a": ("1",), "b": ("2",)}}, ctx)[0] is T
    assert evaluate({"StringEquals": {"a": ("1",)}, "NumericEquals": {"b": ("3",)}}, ctx)[0] is F


@pytest.mark.parametrize(
    ("op", "expected"),
    [
        ("StringEquals", F),
        ("StringNotEquals", T),
        ("StringEqualsIfExists", T),
        ("ForAnyValue:StringEquals", F),
        ("ForAllValues:StringEquals", T),
    ],
)
def test_absent_key_semantics(op: str, expected: Tri) -> None:
    assert run(op, "k", ("x",), Context(complete=True)) is expected


def test_if_exists_still_checks_a_present_key() -> None:
    assert run("StringEqualsIfExists", "k", ("x",), known(k="y")) is F


def test_null_operator() -> None:
    assert run("Null", "k", ("true",), Context(complete=True)) is T
    assert run("Null", "k", ("true",), known(k="v")) is F
    assert run("Null", "k", ("false",), known(k="v")) is T
    assert run("Null", "k", ("true",), Context()) is U


def test_set_operators_on_multivalued_keys() -> None:
    ctx = known(tags=("env", "team"))
    assert run("ForAllValues:StringEquals", "tags", ("env", "team", "cost"), ctx) is T
    assert run("ForAllValues:StringEquals", "tags", ("env",), ctx) is F
    assert run("ForAnyValue:StringEquals", "tags", ("team",), ctx) is T
    assert run("ForAnyValue:StringEquals", "tags", ("cost",), ctx) is F
    assert run("ForAllValues:StringNotEquals", "tags", ("cost",), ctx) is T
    assert run("ForAnyValue:StringNotEquals", "tags", ("env",), ctx) is T


def test_policy_variables_in_condition_values() -> None:
    ctx = known(aws__username="alice", s3__prefix="home/alice/")
    assert run("StringLike", "s3:prefix", ("home/${aws:username}/*",), ctx) is T
    assert (
        run(
            "StringLike",
            "s3:prefix",
            ("home/${aws:username}/*",),
            known(s3__prefix="home/bob/", aws__username="alice"),
        )
        is F
    )
    partial = Context({"s3:prefix": ("home/alice/",)})
    assert run("StringLike", "s3:prefix", ("home/${aws:username}/*",), partial) is U


def test_unsupported_operator_is_unknown_not_true() -> None:
    result, reasons = evaluate({"StringMagic": {"k": ("x",)}}, known(k="x"))
    assert result is U
    assert "unsupported condition operator StringMagic" in reasons[0]
    assert not supported("StringMagic")
    assert supported("ForAnyValue:StringLikeIfExists")
    assert supported("Null")


def test_operator_parsing() -> None:
    assert Operator.parse("ForAnyValue:StringLikeIfExists") == Operator(
        "stringlike", "foranyvalue", True
    )
    assert Operator.parse("Bool") == Operator("bool", "", False)
