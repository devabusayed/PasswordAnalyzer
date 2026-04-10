from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path


DEFAULT_SECLISTS_RAW_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Passwords/Common-Credentials/10k-most-common.txt"
)


def download_text(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={
            # Some networks/CDNs behave better with a UA.
            "User-Agent": "PasswordAnalyzer/1.0 (educational)",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="ignore")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Download a SecLists common-passwords file into ./data/common_passwords.txt"
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_SECLISTS_RAW_URL,
        help="Raw GitHub URL to a SecLists password list (default: 10k-most-common.txt).",
    )
    parser.add_argument(
        "--out",
        default=str(Path(__file__).resolve().parents[1] / "data" / "common_passwords.txt"),
        help="Output path for the common passwords file.",
    )
    args = parser.parse_args(argv)

    out_path = Path(args.out).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        text = download_text(args.url)
    except Exception as e:  # noqa: BLE001 - keep script beginner-friendly
        print(f"Download failed: {e}", file=sys.stderr)
        return 2

    # Normalize: keep non-empty lines, strip whitespace, drop comments.
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)

    if not lines:
        print("Downloaded file had no usable passwords.", file=sys.stderr)
        return 3

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Saved {len(lines)} passwords to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

