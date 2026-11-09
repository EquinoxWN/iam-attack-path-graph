"""Three-valued logic: a check is true, false, or unknown because the request context is unknown."""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum


class Tri(Enum):
    """True, false or unknown."""

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"

    @staticmethod
    def of(value: bool) -> Tri:
        """A known boolean as a Tri."""
        return Tri.TRUE if value else Tri.FALSE

    def negate(self) -> Tri:
        """Logical not; unknown stays unknown."""
        if self is Tri.UNKNOWN:
            return self
        return Tri.FALSE if self is Tri.TRUE else Tri.TRUE


def all_of(values: Iterable[Tri]) -> Tri:
    """Kleene AND: false wins, then unknown."""
    result = Tri.TRUE
    for v in values:
        if v is Tri.FALSE:
            return Tri.FALSE
        if v is Tri.UNKNOWN:
            result = Tri.UNKNOWN
    return result


def any_of(values: Iterable[Tri]) -> Tri:
    """Kleene OR: true wins, then unknown."""
    result = Tri.FALSE
    for v in values:
        if v is Tri.TRUE:
            return Tri.TRUE
        if v is Tri.UNKNOWN:
            result = Tri.UNKNOWN
    return result
