from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ScoreBreakdown:
    score_0_100: int
    strength_label: str  # Weak / Moderate / Strong
    length_points: int
    variety_points: int
    penalty_points: int
    estimated_entropy_bits: float


_RE_LOWER = re.compile(r"[a-z]")
_RE_UPPER = re.compile(r"[A-Z]")
_RE_DIGIT = re.compile(r"\d")
_RE_SPECIAL = re.compile(r"[^A-Za-z0-9]")


def estimate_entropy_bits(password: str) -> float:
    # Lightweight estimate: pool size based on character classes used.
    # Not a replacement for a real cracking model; used only for user-facing guidance.
    if not password:
        return 0.0

    pool = 0
    if _RE_LOWER.search(password):
        pool += 26
    if _RE_UPPER.search(password):
        pool += 26
    if _RE_DIGIT.search(password):
        pool += 10
    if _RE_SPECIAL.search(password):
        pool += 33  # rough printable special characters count

    pool = max(pool, 1)
    return len(password) * math.log2(pool)


def classify_strength(score_0_100: int) -> str:
    if score_0_100 < 40:
        return "Weak"
    if score_0_100 < 70:
        return "Moderate"
    return "Strong"


def score_password(
    password: str,
    *,
    penalty_points: int = 0,
) -> ScoreBreakdown:
    pwd = password or ""
    n = len(pwd)

    # Length points (0..45)
    if n <= 4:
        length_points = 0
    elif n <= 7:
        length_points = 10
    elif n <= 11:
        length_points = 25
    elif n <= 15:
        length_points = 35
    else:
        length_points = 45

    # Variety points (0..45)
    variety_points = 0
    classes = 0
    classes += 1 if _RE_LOWER.search(pwd) else 0
    classes += 1 if _RE_UPPER.search(pwd) else 0
    classes += 1 if _RE_DIGIT.search(pwd) else 0
    classes += 1 if _RE_SPECIAL.search(pwd) else 0

    # Reward combining classes, and mildly reward having at least 3 unique characters.
    variety_points += classes * 10  # 0..40
    if len(set(pwd)) >= 6:
        variety_points += 5

    variety_points = min(variety_points, 45)

    raw = length_points + variety_points - max(penalty_points, 0)
    score_0_100 = int(max(0, min(100, raw)))

    entropy = estimate_entropy_bits(pwd)
    label = classify_strength(score_0_100)

    return ScoreBreakdown(
        score_0_100=score_0_100,
        strength_label=label,
        length_points=length_points,
        variety_points=variety_points,
        penalty_points=max(penalty_points, 0),
        estimated_entropy_bits=entropy,
    )
