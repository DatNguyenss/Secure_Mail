"""HMAC-SHA256 + password hashing (PBKDF2-like via HKDF+salt)."""
import hmac
import hashlib
import os


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def hmac_verify(key: bytes, msg: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(hmac_sha256(key, msg), tag)


def password_hash(password: str, salt: bytes | None = None, iterations: int = 200_000) -> tuple[bytes, bytes]:
    """Return (salt, hash). Uses PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return salt, h


def password_verify(password: str, salt: bytes, expected: bytes, iterations: int = 200_000) -> bool:
    _, h = password_hash(password, salt, iterations)
    return hmac.compare_digest(h, expected)
