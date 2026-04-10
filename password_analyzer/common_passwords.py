from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Protocol


@dataclass(frozen=True)
class CommonPasswordResult:
    is_common: bool
    source_path: str | None
    loaded_count: int


def default_common_passwords_path() -> Path:
    # Stored under V1.0/data/ so it's easy to locate for the client.
    return Path(__file__).resolve().parents[1] / "data" / "common_passwords.txt"


def default_common_passwords_sqlite_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "common_passwords.sqlite"


class CommonPasswordChecker(Protocol):
    def contains(self, password: str) -> bool: ...

    @property
    def loaded_count(self) -> int: ...

    @property
    def source_path(self) -> str | None: ...


class SetCommonPasswordChecker:
    def __init__(self, items: set[str], source_path: str | None) -> None:
        self._items = items
        self._source_path = source_path

    def contains(self, password: str) -> bool:
        return password.strip() in self._items

    @property
    def loaded_count(self) -> int:
        return len(self._items)

    @property
    def source_path(self) -> str | None:
        return self._source_path


class SqliteCommonPasswordChecker:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")

    def contains(self, password: str) -> bool:
        # Exact match; stripping only.
        p = password.strip()
        if not p:
            return False
        cur = self._conn.execute("SELECT 1 FROM passwords WHERE password=? LIMIT 1", (p,))
        return cur.fetchone() is not None

    @property
    def loaded_count(self) -> int:
        try:
            cur = self._conn.execute("SELECT COUNT(1) FROM passwords")
            row = cur.fetchone()
            return int(row[0]) if row else 0
        except sqlite3.Error:
            return 0

    @property
    def source_path(self) -> str | None:
        return str(self._db_path)


def load_common_passwords_checker(
    *,
    txt_path: str | Path | None = None,
    sqlite_path: str | Path | None = None,
) -> tuple[CommonPasswordChecker, CommonPasswordResult]:
    # Prefer SQLite (supports millions without loading into RAM).
    sqlite_p = Path(sqlite_path) if sqlite_path is not None else default_common_passwords_sqlite_path()
    if sqlite_p.exists():
        checker = SqliteCommonPasswordChecker(sqlite_p)
        return checker, CommonPasswordResult(is_common=False, source_path=str(sqlite_p), loaded_count=checker.loaded_count)

    p = Path(txt_path) if txt_path is not None else default_common_passwords_path()
    if not p.exists():
        checker = SetCommonPasswordChecker(set(), str(p))
        return checker, CommonPasswordResult(is_common=False, source_path=str(p), loaded_count=0)

    items: set[str] = set()
    try:
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            items.add(s)
    except OSError:
        checker = SetCommonPasswordChecker(set(), str(p))
        return checker, CommonPasswordResult(is_common=False, source_path=str(p), loaded_count=0)

    checker = SetCommonPasswordChecker(items, str(p))
    return checker, CommonPasswordResult(is_common=False, source_path=str(p), loaded_count=len(items))


def is_common_password(password: str, checker: CommonPasswordChecker) -> bool:
    # Kept for backward compatibility with earlier code.
    return checker.contains(password)
