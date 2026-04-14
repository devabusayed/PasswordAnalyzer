from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Iterable


@dataclass(frozen=True)
class StoredHash:
    id: int
    label: str
    hash_string: str
    created_at: str


def default_hash_db_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "password_hashes.sqlite"


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_hash_db(db_path: Path | None = None) -> None:
    p = db_path or default_hash_db_path()
    conn = _connect(p)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS password_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                hash_string TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def save_password_hash(*, label: str, hash_string: str, db_path: Path | None = None) -> int:
    p = db_path or default_hash_db_path()
    init_hash_db(p)
    conn = _connect(p)
    try:
        cur = conn.execute(
            "INSERT INTO password_hashes (label, hash_string) VALUES (?, ?)",
            (label.strip() or "password", hash_string),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_password_hashes(*, limit: int = 25, db_path: Path | None = None) -> tuple[StoredHash, ...]:
    p = db_path or default_hash_db_path()
    if not p.exists():
        return ()
    conn = _connect(p)
    try:
        cur = conn.execute(
            "SELECT id, label, hash_string, created_at FROM password_hashes ORDER BY id DESC LIMIT ?",
            (int(limit),),
        )
        rows = cur.fetchall()
        return tuple(StoredHash(id=int(r[0]), label=str(r[1]), hash_string=str(r[2]), created_at=str(r[3])) for r in rows)
    finally:
        conn.close()

