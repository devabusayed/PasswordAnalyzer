from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path


def iter_passwords(path: Path):
    # Stream passwords from a text file (one per line).
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            yield s


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build an on-disk SQLite index for millions of common passwords."
    )
    parser.add_argument(
        "--in",
        dest="in_path",
        default=str(Path(__file__).resolve().parents[1] / "data" / "common_passwords.txt"),
        help="Input text file path (one password per line).",
    )
    parser.add_argument(
        "--out",
        dest="out_path",
        default=str(Path(__file__).resolve().parents[1] / "data" / "common_passwords.sqlite"),
        help="Output SQLite DB path.",
    )
    args = parser.parse_args(argv)

    in_path = Path(args.in_path).expanduser().resolve()
    out_path = Path(args.out_path).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not in_path.exists():
        print(f"Input file not found: {in_path}", file=sys.stderr)
        return 2

    # Rebuild DB each run (simple + deterministic).
    if out_path.exists():
        out_path.unlink()

    conn = sqlite3.connect(str(out_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=OFF;")
    conn.execute("PRAGMA temp_store=MEMORY;")

    conn.execute("CREATE TABLE passwords (password TEXT PRIMARY KEY)")

    total = 0
    batch = []
    batch_size = 50_000

    try:
        for pwd in iter_passwords(in_path):
            batch.append((pwd,))
            if len(batch) >= batch_size:
                conn.executemany("INSERT OR IGNORE INTO passwords(password) VALUES (?)", batch)
                conn.commit()
                total += len(batch)
                batch.clear()
                print(f"Inserted ~{total:,} ...")

        if batch:
            conn.executemany("INSERT OR IGNORE INTO passwords(password) VALUES (?)", batch)
            conn.commit()
            total += len(batch)

        # Count unique rows.
        cur = conn.execute("SELECT COUNT(1) FROM passwords")
        unique_count = int(cur.fetchone()[0])
    finally:
        conn.close()

    print(f"Done. Saved {unique_count:,} unique passwords to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

