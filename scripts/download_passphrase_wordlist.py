from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path


# EFF large wordlist (public, commonly used for passphrases).
# We download the plain text variant and extract the word column.
DEFAULT_EFF_RAW_URL = (
    "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt"
)


def download_text(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "PasswordAnalyzer/1.0 (educational)"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="ignore")


def parse_eff_wordlist(text: str) -> list[str]:
    # EFF format: "11111 word"
    words: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        parts = s.split()
        if len(parts) >= 2 and parts[0].isdigit():
            w = parts[1].strip()
            if w:
                words.append(w)
    return words


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Download a large wordlist for passphrase generation into ./data/wordlist.txt"
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_EFF_RAW_URL,
        help="URL to a wordlist (default: EFF large wordlist).",
    )
    parser.add_argument(
        "--out",
        default=str(Path(__file__).resolve().parents[1] / "data" / "wordlist.txt"),
        help="Output path for the wordlist.",
    )
    args = parser.parse_args(argv)

    out_path = Path(args.out).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        text = download_text(args.url)
    except Exception as e:  # noqa: BLE001 - keep script beginner-friendly
        print(f"Download failed: {e}", file=sys.stderr)
        return 2

    words = parse_eff_wordlist(text)
    if not words:
        # If user passes a different URL that is already "one word per line",
        # fall back to that format.
        words = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]

    # Normalize: keep alphabetic-ish words, remove duplicates while preserving order.
    seen = set()
    cleaned: list[str] = []
    for w in words:
        w2 = w.strip()
        if not w2:
            continue
        if w2 in seen:
            continue
        seen.add(w2)
        cleaned.append(w2)

    if not cleaned:
        print("Downloaded wordlist had no usable words.", file=sys.stderr)
        return 3

    out_path.write_text("\n".join(cleaned) + "\n", encoding="utf-8")
    print(f"Saved {len(cleaned)} words to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

