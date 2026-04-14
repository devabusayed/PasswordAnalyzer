from __future__ import annotations

from pathlib import Path
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


_PASSPHRASE_WORDS = [
    "River",
    "Cloud",
    "Moon",
    "Forest",
    "Echo",
    "Cedar",
    "Quartz",
    "Falcon",
    "Comet",
    "Harbor",
    "Maple",
    "Nova",
    "Canyon",
    "Orchid",
    "Voyage",
    "Sunset",
]

def _default_wordlist_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "wordlist.txt"


def _load_wordlist(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    words: list[str] = []
    for line in text.splitlines():
        w = line.strip()
        if not w or w.startswith("#"):
            continue
        words.append(w)
    return words


def generate_passphrase(num_words: int = 3) -> str:
    num_words = max(3, int(num_words))
    wordlist_path = _default_wordlist_path()
    large_words = _load_wordlist(wordlist_path) if wordlist_path.exists() else []
    source = large_words if len(large_words) >= 1000 else _PASSPHRASE_WORDS

    words = [secrets.choice(source) for _ in range(num_words)]
    digits = f"{secrets.randbelow(90) + 10}"
    punct = secrets.choice("!@#$%&?")
    return "-".join(words) + f"-{digits}{punct}"

