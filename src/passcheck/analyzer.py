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

from .wordlist import COMMON, KEYBOARD_ROWS, LEET, LEET_ALT

# Guesses per second for an offline attack on a fast, unsalted hash.
OFFLINE_GUESSES_PER_SECOND = 1e10

# The same estimate under the attacks that matter in practice (zxcvbn's
# reference rates). A site that rate-limits logins is far harder to attack
# than a leaked database of fast hashes, so one number alone misleads.
ATTACK_SCENARIOS = {
    "online_throttled": 100 / 3600,  # a login form that locks out or slows down
    "online_unthrottled": 10.0,  # a login form with no limit
    "offline_slow_hash": 1e4,  # leaked bcrypt / scrypt / Argon2 hashes
    "offline_fast_hash": OFFLINE_GUESSES_PER_SECOND,  # leaked MD5 / SHA-1 hashes, many GPUs
}

# Longer input is refused rather than slowly analysed; no real password is near it.
MAX_LENGTH = 1024

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
    # Estimated time to guess under each attack in ATTACK_SCENARIOS (display text).
    crack_times: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["warnings"] = list(self.warnings)
        d["suggestions"] = list(self.suggestions)
        d["crack_times"] = dict(self.crack_times)
        return d


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


def _repeats(password: str) -> list[tuple[str, str]]:
    """Repeated chunks as (whole run, repeated unit): 'aaaa' -> ('aaaa', 'a'),
    'abcabc' -> ('abcabc', 'abc'). One character must repeat 3+ times; a longer
    chunk counts from its second copy, since attackers try doubled words."""
    out = []
    for m in re.finditer(r"(.)\1{2,}|(.{2,}?)\2+", password):
        out.append((m.group(0), m.group(1) or m.group(2)))
    return out


def _readings(text: str) -> list[str]:
    """The ways an attacker would read the text: as typed, both leetspeak
    readings, and each of those reversed ('drowssap')."""
    lower = text.lower()
    forms = dict.fromkeys([lower, lower.translate(LEET), lower.translate(LEET_ALT)])
    return list(dict.fromkeys([*forms, *(f[::-1] for f in forms)]))


def _decorated_common(password: str) -> tuple[str, str] | None:
    """A common password with digits or symbols bolted on ('Password123!',
    '!!qwerty'): returns (the common word, the decoration) or None."""
    m = re.fullmatch(r"([\d\W_]*)(.*?)([\d\W_]*)", password)
    if not m or not m.group(2) or not (m.group(1) or m.group(3)):
        return None
    if any(r in COMMON for r in _readings(m.group(2))):
        return m.group(2), m.group(1) + m.group(3)
    return None


def _dictionary_hits(password: str) -> list[str]:
    readings = _readings(password)
    hits = set()
    for word in COMMON:
        if len(word) >= 4 and any(word in r for r in readings):
            hits.add(word)
    for r in readings:
        stripped = re.sub(r"[\d\W_]+$", "", r)
        if stripped in COMMON or r in COMMON:
            hits.add(stripped or r)
    return sorted(hits, key=len, reverse=True)


# Years 1900-2099, separated dates (12/05/1998, 1998-05-12) and run-together
# day-month-year or month-day-year (12051998, 051298).
_DATE = re.compile(
    r"(?<!\d)(?:"
    r"\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}"
    r"|(?:19|20)\d{2}[-/.]\d{1,2}[-/.]\d{1,2}"
    r"|(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])(?:19|20)?\d{2}"
    r"|(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:19|20)?\d{2}"
    r"|(?:19|20)\d{2}"
    r")(?!\d)"
)


def _dates(password: str) -> list[str]:
    return [m.group(0) for m in _DATE.finditer(password)]


def format_duration(seconds: float) -> str:
    if not math.isfinite(seconds) or seconds >= 1e6 * 365.25 * 86400 * 100:
        return "centuries"
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
    if len(password) > MAX_LENGTH:
        raise ValueError(f"password is longer than {MAX_LENGTH} characters")

    length = len(password)
    pool = pool_size(password)
    entropy = length * math.log2(pool) if pool else 0.0
    warnings: list[str] = []
    suggestions: list[str] = []

    whole_common = any(r in COMMON for r in _readings(password))
    decorated = None if whole_common else _decorated_common(password)
    if whole_common:
        warnings.append("This is one of the most common passwords.")
        entropy = min(entropy, 5.0)
    elif decorated:
        # Attackers try every common password with digits and symbols added
        # before they try anything random, so it is worth little more than the
        # decoration itself.
        word, extra = decorated
        warnings.append(f"This is the common password '{word}' with characters added; that is among the first things attackers try.")
        # popular endings (123, !, 2024) are tried first, so each added character
        # is charged at half its brute-force cost
        entropy = min(entropy, math.log2(len(COMMON)) + len(extra) * math.log2(pool_size(extra) or 1) / 2 + 2)

    # A passphrase is guessed word by word, not letter by letter, so letter-level
    # entropy hugely overstates it ("correct horse battery staple" is 4 words).
    words = password.split()
    if len(words) >= 2 and all(w.isalpha() for w in words):
        entropy = min(entropy, len(words) * BITS_PER_WORD)

    for word in ([] if whole_common or decorated else _dictionary_hits(password)):
        warnings.append(f"Contains the common word '{word}'.")
        # a known word costs about as much as picking it from a short list
        entropy -= max(0.0, len(word) * math.log2(pool or 1) - math.log2(len(COMMON)))

    # A common password already has its estimate capped above; the patterns
    # inside it are reported but not charged twice.
    capped = whole_common or decorated is not None

    for run in _sequence_runs(password):
        warnings.append(f"Contains the sequence '{run}'.")
        if not capped:
            entropy -= max(0.0, (len(run) - 1) * math.log2(pool or 1) - 3)

    for rep, unit in _repeats(password):
        warnings.append(f"Contains the repeated pattern '{rep}'.")
        # every copy after the first adds almost nothing
        if not capped:
            entropy -= max(0.0, (len(rep) - len(unit)) * math.log2(pool or 1) - math.log2(len(rep) // len(unit)))

    for date in _dates(password):
        warnings.append(f"Contains what looks like a year or date ('{date}').")
        if not capped:
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

    # on average an attacker finds it halfway through the search
    guesses = (2 ** entropy) / 2 if length else 0.0
    seconds = guesses / OFFLINE_GUESSES_PER_SECOND
    crack_times = {name: format_duration(guesses / rate) for name, rate in ATTACK_SCENARIOS.items()}
    return Report(
        password_length=length,
        entropy_bits=round(entropy, 1),
        score=score,
        label=LABELS[score],
        crack_time_seconds=seconds,
        crack_time_display=format_duration(seconds),
        warnings=list(dict.fromkeys(warnings)),
        suggestions=suggestions,
        crack_times=crack_times,
    )
