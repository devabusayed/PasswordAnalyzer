from __future__ import annotations

import math
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class LinguisticFindings:
    normalized: str
    tokens: tuple[str, ...]
    has_meaningful_tokens: bool
    language_likeness: float  # 0..1 (higher => more “natural-language-like”)


_LEET_MAP = str.maketrans(
    {
        "@": "a",
        "4": "a",
        "8": "b",
        "(": "c",
        "{": "c",
        "[": "c",
        "3": "e",
        "6": "g",
        "1": "i",
        "!": "i",
        "0": "o",
        "$": "s",
        "5": "s",
        "7": "t",
        "+": "t",
        "2": "z",
    }
)


def normalize_leetspeak(s: str) -> str:
    return (s or "").lower().translate(_LEET_MAP)


def _default_wordlist_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "wordlist.txt"


def load_word_lexicon(*, path: Path | None = None, max_words: int = 120_000) -> set[str]:
    """
    Load a word lexicon for NLP tokenization.

    Uses data/wordlist.txt when available (downloaded by scripts/download_passphrase_wordlist.py).
    Falls back to a small built-in set if the wordlist is missing.
    """
    p = path or _default_wordlist_path()
    words: set[str] = set()
    if p.exists():
        try:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                w = line.strip().lower()
                if not w or w.startswith("#"):
                    continue
                if len(w) < 3 or len(w) > 24:
                    continue
                words.add(w)
                if len(words) >= max_words:
                    break
        except OSError:
            words = set()

    if words:
        # Always include some high-signal security/common terms even if the wordlist
        # is an EFF passphrase list (which intentionally avoids some weak words).
        words |= {
            "love",
            "welcome",
            "monkey",
            "dragon",
            "football",
            "princess",
            "sunshine",
            "shadow",
            "master",
            "hello",
            "secret",
            "admin",
            "password",
            "letmein",
        }
        return words

    return {
        "love",
        "welcome",
        "monkey",
        "dragon",
        "football",
        "princess",
        "sunshine",
        "shadow",
        "master",
        "hello",
        "secret",
        "admin",
        "password",
    }


def segment_tokens(s: str, lexicon: set[str]) -> tuple[str, ...]:
    """
    Segment a normalized string into likely words using a simple DP tokenizer.
    Returns a best-effort list of tokens (may be empty).
    """
    text = "".join(ch for ch in (s or "").lower() if ch.isalpha())
    if len(text) < 6:
        return ()

    max_word_len = 20
    n = len(text)

    @lru_cache(maxsize=None)
    def best(i: int) -> tuple[int, tuple[str, ...]]:
        if i >= n:
            return (0, ())

        # Option 1: skip a char (no penalty; we only maximize total token chars).
        best_chars, best_tokens = best(i + 1)

        # Option 2: take a lexicon word.
        for j in range(i + 3, min(n, i + max_word_len) + 1):
            w = text[i:j]
            if w not in lexicon:
                continue
            chars_rest, toks_rest = best(j)
            chars_here = chars_rest + len(w)
            toks_here = (w,) + toks_rest
            if chars_here > best_chars:
                best_chars, best_tokens = chars_here, toks_here

        return best_chars, best_tokens

    token_chars, toks = best(0)
    if token_chars < 8:
        return ()
    return toks


class CharNgramLanguageModel:
    """
    Tiny “ML” component: a smoothed character trigram language model.

    Trained on a word lexicon (and optionally other lists). Used to estimate whether a
    password resembles natural language. This helps penalize meaningful-word passwords.
    """

    def __init__(self) -> None:
        self._counts: dict[str, dict[str, int]] = {}
        self._totals: dict[str, int] = {}
        self._trained = False

    def train(self, words: set[str]) -> None:
        counts: dict[str, dict[str, int]] = {}
        totals: dict[str, int] = {}

        for w in words:
            t = f"^^{w.lower()}$$"
            for i in range(len(t) - 2):
                ctx = t[i : i + 2]
                nxt = t[i + 2]
                bucket = counts.setdefault(ctx, {})
                bucket[nxt] = bucket.get(nxt, 0) + 1
                totals[ctx] = totals.get(ctx, 0) + 1

        self._counts = counts
        self._totals = totals
        self._trained = True

    def avg_neg_log2_prob(self, text: str) -> float:
        """
        Average negative log2 probability per character.
        Lower => more “language-like”.
        """
        if not self._trained:
            return 10.0

        s = "".join(ch for ch in (text or "").lower() if ch.isalpha())
        if len(s) < 6:
            return 10.0

        t = f"^^{s}$$"
        vocab = 28  # rough: 26 letters + start/end markers
        total_bits = 0.0
        steps = 0
        for i in range(len(t) - 2):
            ctx = t[i : i + 2]
            nxt = t[i + 2]
            bucket = self._counts.get(ctx)
            ctx_total = self._totals.get(ctx, 0)
            nxt_count = (bucket.get(nxt, 0) if bucket else 0)
            # Add-1 smoothing
            p = (nxt_count + 1) / (ctx_total + vocab)
            total_bits += -math.log2(p)
            steps += 1

        return total_bits / max(1, steps)


_LEXICON: set[str] | None = None
_LM: CharNgramLanguageModel | None = None


def analyze_linguistic(password: str) -> LinguisticFindings:
    global _LEXICON, _LM

    if _LEXICON is None:
        _LEXICON = load_word_lexicon()
    if _LM is None:
        _LM = CharNgramLanguageModel()
        _LM.train(_LEXICON)

    normalized = normalize_leetspeak(password)
    tokens = segment_tokens(normalized, _LEXICON)

    # Convert bits-per-char to a 0..1 “likeness” where higher is more language-like.
    bits = _LM.avg_neg_log2_prob(normalized)
    likeness = 1.0 / (1.0 + math.exp((bits - 3.5) * 1.25))  # ~sigmoid threshold around 3.5 bits/char

    meaningful = len(tokens) > 0
    return LinguisticFindings(
        normalized=normalized,
        tokens=tokens,
        has_meaningful_tokens=meaningful,
        language_likeness=float(max(0.0, min(1.0, likeness))),
    )

