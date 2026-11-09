"""IAM wildcard matching, including a randomized comparison with a regex reference."""

from __future__ import annotations

import random
import re

import pytest

from iam_attack_path_graph.wildcard import has_wildcard, match


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        ("*", "", True),
        ("*", "arn:aws:s3:::bucket/key", True),
        ("", "", True),
        ("", "a", False),
        ("a", "", False),
        ("iam:Get*", "iam:GetUser", True),
        ("iam:Get*", "iam:ListUsers", False),
        ("iam:Get?ser", "iam:GetUser", True),
        ("iam:Get?ser", "iam:GetUUser", False),
        ("arn:aws:s3:::b/*", "arn:aws:s3:::b/", True),
        ("arn:aws:s3:::b/*", "arn:aws:s3:::b", False),
        ("*:Get*", "s3:GetObject", True),
        ("a*b*c", "aXXbYYc", True),
        ("a*b*c", "aXXcYYb", False),
        ("a**", "a", True),
        ("?", "", False),
    ],
)
def test_known_cases(pattern: str, text: str, expected: bool) -> None:
    assert match(pattern, text) is expected


def test_resources_are_case_sensitive_actions_need_not_be() -> None:
    assert not match("arn:aws:s3:::Bucket", "arn:aws:s3:::bucket")
    assert match("IAM:getuser", "iam:GetUser", case_sensitive=False)


def test_has_wildcard() -> None:
    assert has_wildcard("a*")
    assert has_wildcard("a?")
    assert not has_wildcard("arn:aws:iam::123456789012:user/x")


def _reference(pattern: str, text: str) -> bool:
    """Regex translation of the same semantics."""
    regex = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(regex, text, flags=re.DOTALL) is not None


def test_matches_a_regex_reference_on_5000_random_pairs() -> None:
    rng = random.Random(20261109)
    alphabet = "ab:/*?"
    for _ in range(5000):
        pattern = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))
        text = "".join(rng.choice("ab:/") for _ in range(rng.randint(0, 10)))
        assert match(pattern, text) == _reference(pattern, text), (pattern, text)


def test_hostile_pattern_stays_fast() -> None:
    pattern = "*a" * 50 + "b"
    text = "a" * 5000
    assert match(pattern, text) is False
