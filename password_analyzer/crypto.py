from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .policy import (
    PBKDF2_DKLEN_BYTES,
    PBKDF2_HASH_NAME,
    PBKDF2_ITERATIONS,
    PBKDF2_SALT_BYTES,
)

# Key derivation for AES-256-GCM (separate from PBKDF2 password hashing parameters).
_VAULT_PBKDF2_ITERS = 200_000
_VAULT_SALT_BYTES = 16
_VAULT_NONCE_BYTES = 12


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


def encrypt_password_aes_gcm(plaintext: str, master_password: str) -> str:
    """
    Encrypt a password for storage so it can be restored with the same master password.
    Format (base64): salt | nonce | ciphertext (AES-GCM includes auth tag).
    """
    pwd = master_password or ""
    if not pwd:
        raise ValueError("Master password is required for encryption.")

    salt = secrets.token_bytes(_VAULT_SALT_BYTES)
    key = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_NAME,
        pwd.encode("utf-8"),
        salt,
        _VAULT_PBKDF2_ITERS,
        dklen=32,
    )
    aes = AESGCM(key)
    nonce = secrets.token_bytes(_VAULT_NONCE_BYTES)
    ct = aes.encrypt(nonce, (plaintext or "").encode("utf-8"), None)
    blob = salt + nonce + ct
    return base64.b64encode(blob).decode("ascii")


def default_vault_key_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / ".vault_key"


def get_or_create_vault_key() -> bytes:
    """
    Local-only 256-bit key for AES-GCM vault storage (no master password in UI).
    Stored under data/.vault_key — anyone with this file and the DB can decrypt.
    """
    path = default_vault_key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        k = path.read_bytes()
        if len(k) == 32:
            return k
    key = secrets.token_bytes(32)
    path.write_bytes(key)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


def encrypt_password_vault_local(plaintext: str) -> str:
    """AES-256-GCM using device-local key file (nonce | ciphertext)."""
    key = get_or_create_vault_key()
    aes = AESGCM(key)
    nonce = secrets.token_bytes(_VAULT_NONCE_BYTES)
    ct = aes.encrypt(nonce, (plaintext or "").encode("utf-8"), None)
    blob = nonce + ct
    return base64.b64encode(blob).decode("ascii")


def decrypt_password_vault_local(blob_b64: str) -> str:
    key = get_or_create_vault_key()
    raw = base64.b64decode(blob_b64.encode("ascii"))
    if len(raw) < _VAULT_NONCE_BYTES + 16:
        raise ValueError("Invalid encrypted payload.")
    nonce = raw[:_VAULT_NONCE_BYTES]
    ct = raw[_VAULT_NONCE_BYTES:]
    aes = AESGCM(key)
    pt = aes.decrypt(nonce, ct, None)
    return pt.decode("utf-8")


def delete_vault_key_file() -> None:
    """Remove local vault key (e.g. after clearing DB for testing). Next save creates a new key."""
    path = default_vault_key_path()
    if path.exists():
        path.unlink()


def decrypt_password_aes_gcm(blob_b64: str, master_password: str) -> str:
    pwd = master_password or ""
    if not pwd:
        raise ValueError("Master password is required to decrypt.")

    raw = base64.b64decode(blob_b64.encode("ascii"))
    if len(raw) < _VAULT_SALT_BYTES + _VAULT_NONCE_BYTES + 16:
        raise ValueError("Invalid encrypted payload.")

    salt = raw[:_VAULT_SALT_BYTES]
    nonce = raw[_VAULT_SALT_BYTES : _VAULT_SALT_BYTES + _VAULT_NONCE_BYTES]
    ct = raw[_VAULT_SALT_BYTES + _VAULT_NONCE_BYTES :]
    key = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_NAME,
        pwd.encode("utf-8"),
        salt,
        _VAULT_PBKDF2_ITERS,
        dklen=32,
    )
    aes = AESGCM(key)
    pt = aes.decrypt(nonce, ct, None)
    return pt.decode("utf-8")


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

