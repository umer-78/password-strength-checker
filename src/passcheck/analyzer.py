"""Password scoring.

The score starts from the brute-force entropy of the character pool and then
subtracts entropy for the patterns attackers try first: dictionary words,
keyboard walks, sequences, repeats and dates. Nothing leaves the machine.
"""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field

from .wordlist import COMMON, KEYBOARD_ROWS, LEET

# Guesses per second for an offline attack on a fast, unsalted hash.
OFFLINE_GUESSES_PER_SECOND = 1e10

LABELS = ["very weak", "weak", "fair", "strong", "very strong"]

# Bits per word for a passphrase, assuming words from a Diceware-sized list.
BITS_PER_WORD = math.log2(7776)


@dataclass
class Report:
    password_length: int
    entropy_bits: float
    score: int  # 0..4
    label: str
    crack_time_seconds: float
    crack_time_display: str
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def pool_size(password: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation or c == " " for c in password):
        size += 33
    if any(ord(c) > 127 for c in password):
        size += 100
    return size


def _sequence_runs(password: str, min_len: int = 3) -> list[str]:
    """Runs like 'abcd', '4321' or 'qwer' (alphabet, digits or keyboard rows)."""
    runs: list[str] = []
    lower = password.lower()
    sources = [string.ascii_lowercase, string.digits, *KEYBOARD_ROWS]
    i = 0
    while i < len(lower):
        best = 1
        for src in sources:
            for direction in (src, src[::-1]):
                pos = direction.find(lower[i])
                if pos < 0:
                    continue
                length = 1
                while (
                    i + length < len(lower)
                    and pos + length < len(direction)
                    and lower[i + length] == direction[pos + length]
                ):
                    length += 1
                best = max(best, length)
        if best >= min_len:
            runs.append(password[i : i + best])
            i += best
        else:
            i += 1
    return runs


def _repeats(password: str) -> list[str]:
    return [m.group(0) for m in re.finditer(r"(.+?)\1{2,}", password)]


def _dictionary_hits(password: str) -> list[str]:
    lower = password.lower()
    unleet = lower.translate(LEET)
    hits = set()
    for word in COMMON:
        if len(word) >= 4 and (word in lower or word in unleet):
            hits.add(word)
    stripped = re.sub(r"[\d\W_]+$", "", unleet)
    if stripped in COMMON or unleet in COMMON:
        hits.add(stripped or unleet)
    return sorted(hits, key=len, reverse=True)


def _dates(password: str) -> list[str]:
    pattern = r"(19\d{2}|20\d{2})|(\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})"
    return [m.group(0) for m in re.finditer(pattern, password)]


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        ("century", 100 * 365.25 * 86400),
        ("year", 365.25 * 86400),
        ("month", 30.44 * 86400),
        ("day", 86400),
        ("hour", 3600),
        ("minute", 60),
        ("second", 1),
    ]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if name == "century" and value >= 1000:
                return "centuries"
            n = int(value)
            plural = "centuries" if name == "century" else name + "s"
            return f"{n} {name if n == 1 else plural}"
    return "instantly"


def analyze(password: str) -> Report:
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    length = len(password)
    pool = pool_size(password)
    entropy = length * math.log2(pool) if pool else 0.0
    warnings: list[str] = []
    suggestions: list[str] = []

    lower = password.lower()
    whole_common = lower in COMMON or lower.translate(LEET) in COMMON
    if whole_common:
        warnings.append("This is one of the most common passwords.")
        entropy = min(entropy, 5.0)

    # A passphrase is guessed word by word, not letter by letter, so letter-level
    # entropy hugely overstates it ("correct horse battery staple" is 4 words).
    words = password.split()
    if len(words) >= 2 and all(w.isalpha() for w in words):
        entropy = min(entropy, len(words) * BITS_PER_WORD)

    for word in ([] if whole_common else _dictionary_hits(password)):
        warnings.append(f"Contains the common word '{word}'.")
        # a known word costs about as much as picking it from a short list
        entropy -= max(0.0, len(word) * math.log2(pool or 1) - math.log2(len(COMMON)))

    for run in _sequence_runs(password):
        warnings.append(f"Contains the sequence '{run}'.")
        entropy -= max(0.0, (len(run) - 1) * math.log2(pool or 1) - 3)

    for rep in _repeats(password):
        warnings.append(f"Contains the repeated pattern '{rep}'.")
        entropy -= max(0.0, (len(rep) - 2) * math.log2(pool or 1))

    for date in _dates(password):
        warnings.append(f"Contains what looks like a year or date ('{date}').")
        entropy -= max(0.0, len(date) * math.log2(pool or 1) - 15)

    entropy = max(0.0, entropy)

    if length < 12:
        suggestions.append("Use at least 12 characters; length matters more than symbols.")
    if pool <= 26:
        suggestions.append("Mix in upper-case letters, digits or symbols.")
    if warnings:
        suggestions.append("Avoid words, dates, keyboard patterns and repeats.")
    if entropy < 60:
        suggestions.append(
            "A passphrase of 5 or more randomly chosen words is easy to remember and hard to guess."
        )

    if entropy < 28:
        score = 0
    elif entropy < 36:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 80:
        score = 3
    else:
        score = 4

    seconds = (2 ** entropy) / 2 / OFFLINE_GUESSES_PER_SECOND
    return Report(
        password_length=length,
        entropy_bits=round(entropy, 1),
        score=score,
        label=LABELS[score],
        crack_time_seconds=seconds,
        crack_time_display=format_duration(seconds),
        warnings=list(dict.fromkeys(warnings)),
        suggestions=suggestions,
    )
