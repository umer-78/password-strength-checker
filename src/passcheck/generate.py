"""Generate strong random passwords with the `secrets` module (CSPRNG)."""

from __future__ import annotations

import secrets
import string

# Characters that are easy to confuse when read aloud or copied by hand.
AMBIGUOUS = set("Il1O0o")
SYMBOLS = "!#$%&*+-=?@^_~"


def generate_password(length: int = 16, *, symbols: bool = True, avoid_ambiguous: bool = True) -> str:
    """Return a random password of `length` characters.

    It always contains at least one lower-case letter, upper-case letter and digit
    (and one symbol when `symbols` is true), so it passes typical site rules.
    """
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        classes.append(SYMBOLS)
    if avoid_ambiguous:
        classes = ["".join(c for c in cls if c not in AMBIGUOUS) for cls in classes]
    if length < max(8, len(classes)):
        raise ValueError("length must be at least 8")
    if length > 256:
        raise ValueError("length must be at most 256")

    pool = "".join(classes)
    chars = [secrets.choice(cls) for cls in classes]
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    # Fisher-Yates with the CSPRNG so the guaranteed characters are not always first
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)
