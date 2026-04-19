from __future__ import annotations

import secrets
import string

from .policy import MIN_PASSWORD_LENGTH


def generate_random_password(length: int = MIN_PASSWORD_LENGTH) -> str:
    length = max(MIN_PASSWORD_LENGTH, int(length))
    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()-_=+[]{};:,.?/|"

    # Ensure at least one from each major class for a “strong default”.
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+[]{};:,.?/|"),
    ]
    remaining = [secrets.choice(alphabet) for _ in range(max(0, length - len(required)))]
    chars = required + remaining
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
