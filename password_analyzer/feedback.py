from __future__ import annotations

from dataclasses import dataclass

from .analysis import PatternFindings
from .scoring import ScoreBreakdown


@dataclass(frozen=True)
class Feedback:
    title: str
    bullets: tuple[str, ...]


def generate_feedback(
    *,
    password: str,
    score: ScoreBreakdown,
    patterns: PatternFindings,
    is_common_password: bool,
    common_list_loaded_count: int,
) -> Feedback:
    bullets: list[str] = []

    if not password:
        return Feedback(
            title="Enter a password to analyze.",
            bullets=(
                "Type a password in the input field.",
                "Click “Check Password” to see score, patterns, and suggestions.",
            ),
        )

    bullets.append(f"Score: {score.score_0_100}/100 ({score.strength_label})")
    bullets.append(f"Estimated entropy: {score.estimated_entropy_bits:.1f} bits (rough estimate)")

    if is_common_password:
        bullets.append("This password is found in the common-password list (high risk).")
    else:
        if common_list_loaded_count == 0:
            bullets.append("Common-password list is not loaded (optional file).")

    if patterns.has_repeated_chars:
        bullets.append("Detected repeated characters (e.g., aaaa, 1111). Avoid repeats.")
    if patterns.has_sequential:
        bullets.append("Detected sequential characters (e.g., 1234, abcd). Avoid sequences.")
    if patterns.has_keyboard_pattern:
        bullets.append("Detected keyboard pattern (e.g., qwerty/asdf). Avoid predictable patterns.")
    if patterns.has_dictionary_word:
        words = ", ".join(patterns.dictionary_hits[:5])
        bullets.append(f"Contains common word(s): {words}. Avoid dictionary words.")

    # Actionable improvements
    if len(password) < 12:
        bullets.append("Use at least 12 characters (longer is better).")
    if not any(c.islower() for c in password):
        bullets.append("Add lowercase letters (a-z).")
    if not any(c.isupper() for c in password):
        bullets.append("Add uppercase letters (A-Z).")
    if not any(c.isdigit() for c in password):
        bullets.append("Add digits (0-9).")
    if password.isalnum():
        bullets.append("Add special characters (e.g., !@#$%).")

    title = "Password analysis complete."
    if score.strength_label == "Strong":
        title = "Strong password."
    elif score.strength_label == "Moderate":
        title = "Moderate password."
    else:
        title = "Weak password."

    return Feedback(title=title, bullets=tuple(bullets))

