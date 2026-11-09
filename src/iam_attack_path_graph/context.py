"""Request context (condition keys) and IAM policy variable substitution."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

_VARIABLE = re.compile(r"\$\{([^}]{1,256})\}")
_ESCAPES = {"*": "*", "?": "?", "$": "$"}


@dataclass(frozen=True)
class Context:
    """Condition key values for one request.

    Keys are case-insensitive. When `complete` is false, a key that is not listed is *unknown*
    (it may or may not be in the real request); when true, a missing key is *absent*.
    """

    values: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    complete: bool = False

    def __post_init__(self) -> None:
        """Normalise keys to lower case."""
        object.__setattr__(self, "values", {k.lower(): tuple(v) for k, v in self.values.items()})

    def lookup(self, key: str) -> tuple[str, ...] | None:
        """The key's values, or None when the key is absent or unknown."""
        return self.values.get(key.lower())

    def is_unknown(self, key: str) -> bool:
        """Whether nothing can be said about the key."""
        return key.lower() not in self.values and not self.complete

    def merged(self, extra: Mapping[str, tuple[str, ...]]) -> Context:
        """A copy with `extra` keys added where not already set."""
        values = {k.lower(): tuple(v) for k, v in extra.items()}
        values.update(self.values)
        return Context(values=values, complete=self.complete)


class UnresolvedError(Exception):
    """A policy variable refers to a key with an unknown value."""


class AbsentError(Exception):
    """A policy variable refers to a key that is not in the request and has no default."""


def substitute(text: str, ctx: Context) -> str:
    """Replace `${key}` and `${key, 'default'}` variables; raise UnresolvedError or AbsentError."""

    def repl(m: re.Match[str]) -> str:
        """One variable's value."""
        body = m.group(1).strip()
        if body in _ESCAPES:
            return _ESCAPES[body]
        key, _, default = body.partition(",")
        key = key.strip()
        values = ctx.lookup(key)
        if values is not None and len(values) == 1:
            return values[0]
        if values is None and ctx.is_unknown(key):
            raise UnresolvedError(key)
        default = default.strip()
        if len(default) >= 2 and default[0] == default[-1] == "'":
            return default[1:-1]
        raise AbsentError(key)

    return _VARIABLE.sub(repl, text)


def widen(text: str) -> str:
    """Replace every policy variable by `*`, the widest thing it could stand for."""
    return _VARIABLE.sub(
        lambda m: _ESCAPES.get(m.group(1).strip(), "*"),
        text,
    )


def has_variable(text: str) -> bool:
    """Whether the text contains a policy variable."""
    return "${" in text
