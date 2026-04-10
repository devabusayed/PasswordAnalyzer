from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PatternFindings:
    has_repeated_chars: bool
    has_sequential: bool
    has_keyboard_pattern: bool
    has_dictionary_word: bool
    dictionary_hits: tuple[str, ...]


_RE_REPEAT_4 = re.compile(r"(.)\1{3,}")  # aaaa, 1111, !!!!

_KEYBOARD_PATTERNS = (
    "qwerty",
    "asdf",
    "zxcv",
    "12345",
    "09876",
    "1q2w3e",
    "qazwsx",
    "password",
    "admin",
)

# Lightweight built-in dictionary (keeps project dependency-free).
# This is intended to catch obvious words; the common-password list catches the rest.
_BASIC_DICTIONARY_WORDS = {
    "love",
    "welcome",
    "monkey",
    "dragon",
    "football",
    "iloveyou",
    "princess",
    "letmein",
    "sunshine",
    "shadow",
    "master",
    "hello",
    "secret",
}


def _has_sequential_run(s: str, min_len: int = 4) -> bool:
    if len(s) < min_len:
        return False

    def is_seq(a: str, b: str) -> bool:
        # Only consider alnum sequences, case-insensitive for letters.
        if a.isdigit() and b.isdigit():
            return ord(b) - ord(a) == 1
        if a.isalpha() and b.isalpha():
            return ord(b.lower()) - ord(a.lower()) == 1
        return False

    run = 1
    for i in range(1, len(s)):
        if is_seq(s[i - 1], s[i]):
            run += 1
            if run >= min_len:
                return True
        else:
            run = 1
    return False


def detect_patterns(password: str) -> PatternFindings:
    pwd = password or ""
    low = pwd.lower()

    has_repeated = _RE_REPEAT_4.search(pwd) is not None
    has_seq = _has_sequential_run(pwd, min_len=4)
    has_keyboard = any(pat in low for pat in _KEYBOARD_PATTERNS)

    hits = []
    for w in _BASIC_DICTIONARY_WORDS:
        if len(w) >= 4 and w in low:
            hits.append(w)
    hits.sort()

    return PatternFindings(
        has_repeated_chars=has_repeated,
        has_sequential=has_seq,
        has_keyboard_pattern=has_keyboard,
        has_dictionary_word=len(hits) > 0,
        dictionary_hits=tuple(hits),
    )


def compute_penalty_points(
    *,
    is_common_password: bool,
    patterns: PatternFindings,
) -> int:
    penalty = 0
    if is_common_password:
        penalty += 35
    if patterns.has_repeated_chars:
        penalty += 15
    if patterns.has_sequential:
        penalty += 15
    if patterns.has_keyboard_pattern:
        penalty += 15
    if patterns.has_dictionary_word:
        penalty += 10
    return penalty
