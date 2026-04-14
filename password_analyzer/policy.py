from __future__ import annotations

MIN_PASSWORD_LENGTH = 16

# PBKDF2 settings (standard-library, intentionally dependency-free).
PBKDF2_HASH_NAME = "sha256"
PBKDF2_ITERATIONS = 200_000
PBKDF2_SALT_BYTES = 16
PBKDF2_DKLEN_BYTES = 32

