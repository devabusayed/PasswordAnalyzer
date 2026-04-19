from __future__ import annotations

from dataclasses import dataclass
import sqlite3
from pathlib import Path


@dataclass(frozen=True)
class StoredVaultEntry:
    id: int
    label: str
    hash_string: str
    enc_payload: str | None
    created_at: str


def default_hash_db_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "password_hashes.sqlite"


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    cur = conn.execute("PRAGMA table_info(password_hashes)")
    cols = {str(row[1]) for row in cur.fetchall()}
    if "enc_payload" not in cols:
        conn.execute("ALTER TABLE password_hashes ADD COLUMN enc_payload TEXT")


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
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                enc_payload TEXT
            )
            """
        )
        _migrate(conn)
        conn.commit()
    finally:
        conn.close()


def save_password_hash(
    *,
    label: str,
    hash_string: str,
    enc_payload: str | None = None,
    db_path: Path | None = None,
) -> int:
    p = db_path or default_hash_db_path()
    init_hash_db(p)
    conn = _connect(p)
    try:
        cur = conn.execute(
            "INSERT INTO password_hashes (label, hash_string, enc_payload) VALUES (?, ?, ?)",
            (label.strip() or "password", hash_string, enc_payload),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_password_hashes(*, limit: int = 50, db_path: Path | None = None) -> tuple[StoredVaultEntry, ...]:
    p = db_path or default_hash_db_path()
    if not p.exists():
        return ()
    init_hash_db(p)
    conn = _connect(p)
    try:
        cur = conn.execute(
            """
            SELECT id, label, hash_string, enc_payload, created_at
            FROM password_hashes
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        )
        rows = cur.fetchall()
        return tuple(
            StoredVaultEntry(
                id=int(r[0]),
                label=str(r[1]),
                hash_string=str(r[2]),
                enc_payload=str(r[3]) if r[3] is not None else None,
                created_at=str(r[4]),
            )
            for r in rows
        )
    finally:
        conn.close()


def clear_vault_entries(*, db_path: Path | None = None) -> int:
    """Delete all saved vault rows. Returns number of rows removed."""
    p = db_path or default_hash_db_path()
    if not p.exists():
        return 0
    init_hash_db(p)
    conn = _connect(p)
    try:
        cur = conn.execute("DELETE FROM password_hashes")
        conn.commit()
        return int(cur.rowcount or 0)
    finally:
        conn.close()


def get_vault_entry(*, row_id: int, db_path: Path | None = None) -> StoredVaultEntry | None:
    p = db_path or default_hash_db_path()
    if not p.exists():
        return None
    init_hash_db(p)
    conn = _connect(p)
    try:
        cur = conn.execute(
            """
            SELECT id, label, hash_string, enc_payload, created_at
            FROM password_hashes
            WHERE id = ?
            """,
            (int(row_id),),
        )
        r = cur.fetchone()
        if not r:
            return None
        return StoredVaultEntry(
            id=int(r[0]),
            label=str(r[1]),
            hash_string=str(r[2]),
            enc_payload=str(r[3]) if r[3] is not None else None,
            created_at=str(r[4]),
        )
    finally:
        conn.close()
