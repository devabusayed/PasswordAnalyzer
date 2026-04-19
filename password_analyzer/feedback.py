from __future__ import annotations

from dataclasses import dataclass

from .analysis import PatternFindings
from .policy import MIN_PASSWORD_LENGTH
from .scoring import ScoreBreakdown


@dataclass(frozen=True)
class Feedback:
    results_title: str
    results: tuple[str, ...]
    recommendations: tuple[str, ...]


def generate_feedback(
    *,
    password: str,
    score: ScoreBreakdown,
    patterns: PatternFindings,
    is_common_password: bool,
    common_list_loaded_count: int,
) -> Feedback:
    results: list[str] = []
    recs: list[str] = []

    if not password:
        return Feedback(
            results_title="No password entered",
            results=("Nothing to analyze yet.",),
            recommendations=(
                "Type a password in the input field.",
                "Click “Check Password” to see the score and suggestions.",
            ),
        )

    results.append(f"Strength label: {score.strength_label}")
    results.append(f"Numeric score: {score.score_0_100} / 100")
    results.append(f"Estimated entropy: {score.estimated_entropy_bits:.1f} bits (rough estimate)")
    results.append(f"Length: {len(password)} characters (minimum recommended: {MIN_PASSWORD_LENGTH})")

    if is_common_password:
        results.append("Common-password list: MATCH (exact hit — high risk).")
    else:
        if common_list_loaded_count == 0:
            results.append("Common-password list: not loaded (optional file).")
        else:
            results.append("Common-password list: no exact match.")

    if patterns.has_repeated_chars:
        results.append("Pattern check: repeated characters (e.g. aaaa, 1111).")
    if patterns.has_sequential:
        results.append("Pattern check: sequential run (e.g. 1234, abcd).")
    if patterns.has_keyboard_pattern:
        results.append("Pattern check: keyboard-style substring (e.g. qwerty, asdf).")
    if patterns.has_dictionary_word:
        words = ", ".join(patterns.dictionary_hits[:5])
        results.append(f"Dictionary check: contains common word(s): {words}.")

    if len(password) < MIN_PASSWORD_LENGTH:
        recs.append(f"Use at least {MIN_PASSWORD_LENGTH} characters (policy requirement).")
    if is_common_password:
        recs.append("Choose a password that is not on common-password lists.")
    if patterns.has_repeated_chars:
        recs.append("Avoid long runs of the same character.")
    if patterns.has_sequential:
        recs.append("Avoid obvious ascending/descending sequences.")
    if patterns.has_keyboard_pattern:
        recs.append("Avoid keyboard walks and predictable layout patterns.")
    if patterns.has_dictionary_word:
        recs.append("Avoid common dictionary words and predictable phrases.")

    if not any(c.islower() for c in password):
        recs.append("Add lowercase letters (a–z).")
    if not any(c.isupper() for c in password):
        recs.append("Add uppercase letters (A–Z).")
    if not any(c.isdigit() for c in password):
        recs.append("Add digits (0–9).")
    if password.isalnum():
        recs.append("Add special characters (e.g. !@#$%).")

    if not recs and score.strength_label == "Strong":
        recs.append("This password meets the main checks; rotate it periodically for important accounts.")

    results_title = "Analysis results"
    if score.strength_label == "Strong":
        results_title = "Analysis results — strong"
    elif score.strength_label == "Moderate":
        results_title = "Analysis results — moderate"
    else:
        results_title = "Analysis results — weak"

    return Feedback(results_title=results_title, results=tuple(results), recommendations=tuple(recs))
