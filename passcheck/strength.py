"""Password strength analysis: entropy estimate, common-password check, pattern checks."""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field
from pathlib import Path

COMMON_FILE = Path(__file__).resolve().parent.parent / "data" / "common_passwords.txt"

RATINGS = ["very weak", "weak", "fair", "strong", "very strong"]

# Keyboard rows and alphabet/digit runs. Checked forwards and backwards.
SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "0123456789",
]

# Common "leetspeak" substitutions, so P@ssw0rd is treated like password.
LEET_MAP = str.maketrans(
    {"@": "a", "4": "a", "0": "o", "1": "i", "!": "i", "3": "e", "$": "s", "5": "s", "7": "t"}
)

SEQUENCE_PENALTY_BITS = 10
COMMON_PASSWORD_MAX_SCORE = 0


@dataclass
class StrengthResult:
    length: int
    entropy_bits: float
    score: int  # 0 (very weak) .. 4 (very strong)
    rating: str
    is_common: bool
    feedback: list[str] = field(default_factory=list)


def load_common(path: Path = COMMON_FILE) -> set[str]:
    """Load the common-password list. Returns an empty set if the file is missing."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return set()
    return {line.strip().lower() for line in text.splitlines() if line.strip()}


def charset_size(password: str) -> int:
    """Estimate the size of the character pool the password draws from."""
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation or c == " " for c in password):
        size += len(string.punctuation) + 1
    if any(ord(c) > 127 for c in password):
        size += 64  # rough allowance for non-ASCII characters
    return size


def collapse_repeats(password: str) -> str:
    """'aaaa' -> 'a'. Repeated characters add almost no real entropy."""
    return re.sub(r"(.)\1+", r"\1", password)


def has_sequence(password: str, run: int = 4) -> bool:
    """True if the password contains `run` consecutive chars of a keyboard/alphabet sequence."""
    lowered = password.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - run + 1):
                if s[i : i + run] in lowered:
                    return True
    return False


def has_repeats(password: str, run: int = 3) -> bool:
    return re.search(r"(.)\1{%d,}" % (run - 1), password) is not None


def estimate_entropy(password: str) -> float:
    """Entropy in bits: effective length x log2(character pool size)."""
    if not password:
        return 0.0
    pool = charset_size(password)
    effective_len = len(collapse_repeats(password))
    return effective_len * math.log2(pool)


def _score_from_entropy(bits: float) -> int:
    if bits < 28:
        return 0
    if bits < 36:
        return 1
    if bits < 60:
        return 2
    if bits < 80:
        return 3
    return 4


def _is_common(password: str, common: set[str]) -> bool:
    lowered = password.lower()
    return lowered in common or lowered.translate(LEET_MAP) in common


def check_strength(password: str, common: set[str] | None = None) -> StrengthResult:
    """Analyze a password and return a score, rating and human-readable feedback."""
    if common is None:
        common = load_common()

    feedback: list[str] = []
    if not password:
        return StrengthResult(0, 0.0, 0, RATINGS[0], False, ["Password is empty."])

    bits = estimate_entropy(password)
    is_common = _is_common(password, common)

    if is_common:
        feedback.append("This is a very common password (or a trivial variation of one).")
    if has_sequence(password):
        bits = max(0.0, bits - SEQUENCE_PENALTY_BITS)
        feedback.append("Avoid keyboard or alphabet sequences like 'qwer', 'abcd' or '1234'.")
    if has_repeats(password):
        feedback.append("Avoid repeating the same character 3+ times in a row.")
    if len(password) < 12:
        feedback.append("Use at least 12 characters; length matters most.")
    if charset_size(password) < 62:
        feedback.append("Mix lowercase, uppercase, digits and symbols.")

    score = _score_from_entropy(bits)
    if is_common:
        score = min(score, COMMON_PASSWORD_MAX_SCORE)

    if score >= 3 and not feedback:
        feedback.append("Looks good. A passphrase of 4+ random words is also easy to remember.")

    return StrengthResult(
        length=len(password),
        entropy_bits=round(bits, 1),
        score=score,
        rating=RATINGS[score],
        is_common=is_common,
        feedback=feedback,
    )