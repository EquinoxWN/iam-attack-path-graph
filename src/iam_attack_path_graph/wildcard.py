"""IAM wildcard matching (`*` and `?`) without regular expressions.

IAM patterns use `*` for any run of characters (including none, and including `:` and `/`) and
`?` for exactly one character. A greedy two-pointer match with one backtrack point runs in
O(len(pattern) * len(text)) worst case, so hostile patterns cannot cause catastrophic
backtracking the way a naive regular expression can.
"""

from __future__ import annotations


def match(pattern: str, text: str, *, case_sensitive: bool = True) -> bool:
    """Whether `text` matches the IAM wildcard `pattern`."""
    if not case_sensitive:
        pattern, text = pattern.casefold(), text.casefold()
    p = t = 0
    star = -1
    star_t = 0
    while t < len(text):
        if p < len(pattern) and (pattern[p] == "?" or pattern[p] == text[t]):
            p += 1
            t += 1
        elif p < len(pattern) and pattern[p] == "*":
            star = p
            star_t = t
            p += 1
        elif star != -1:
            p = star + 1
            star_t += 1
            t = star_t
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def has_wildcard(pattern: str) -> bool:
    """Whether the pattern contains `*` or `?`."""
    return "*" in pattern or "?" in pattern
