from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from .policy import (
    PBKDF2_DKLEN_BYTES,
    PBKDF2_HASH_NAME,
    PBKDF2_ITERATIONS,
    PBKDF2_SALT_BYTES,
)


@dataclass(frozen=True)
class PasswordHash:
    algorithm: str  # e.g. "pbkdf2_sha256"
    iterations: int
    salt_b64: str
    hash_b64: str

    def to_compact_string(self) -> str:
        return f"{self.algorithm}${self.iterations}${self.salt_b64}${self.hash_b64}"


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def hash_password_pbkdf2(password: str) -> PasswordHash:
    pwd = (password or "").encode("utf-8")
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_NAME,
        pwd,
        salt,
        PBKDF2_ITERATIONS,
        dklen=PBKDF2_DKLEN_BYTES,
    )
    return PasswordHash(
        algorithm=f"pbkdf2_{PBKDF2_HASH_NAME}",
        iterations=PBKDF2_ITERATIONS,
        salt_b64=_b64e(salt),
        hash_b64=_b64e(dk),
    )


def verify_password(password: str, stored: str) -> bool:
    """
    Verify a password against a compact hash string:
    pbkdf2_sha256$200000$saltB64$hashB64
    """
    try:
        algorithm, iters_s, salt_b64, hash_b64 = stored.split("$", 3)
        if not algorithm.startswith("pbkdf2_"):
            return False
        hash_name = algorithm.split("_", 1)[1]
        iterations = int(iters_s)
        salt = _b64d(salt_b64)
        expected = _b64d(hash_b64)
    except Exception:
        return False

    pwd = (password or "").encode("utf-8")
    got = hashlib.pbkdf2_hmac(hash_name, pwd, salt, iterations, dklen=len(expected))
    return hmac.compare_digest(got, expected)

