"""Canonical integer literals, shared by every human-signed envelope (steer, grant).

A nonce, an expiry, a ceiling: each must serialise ONE way in both Python and the browser
JS port, or a signature made on one side fails on the other. This is the single definition.
"""
import re

_CANON_INT = re.compile(r"0|[1-9][0-9]{0,18}")


def canon_int(x, label="value"):
    """Return the canonical decimal string for x (int or decimal string). Rejects bools,
    floats, signs, leading zeros, trailing whitespace/newline, and anything over 19 digits.
    Raises ValueError so a non-canonical value can never be signed or checked two ways."""
    if isinstance(x, bool):
        raise ValueError("%s must be an integer, not a bool" % label)
    if isinstance(x, int):
        s = str(x)
    elif isinstance(x, str):
        s = x
    else:
        raise ValueError("%s must be an int or a decimal string, got %s"
                         % (label, type(x).__name__))
    if not _CANON_INT.fullmatch(s):
        raise ValueError("%s is not a canonical non-negative integer literal: %r"
                         % (label, s))
    return s
