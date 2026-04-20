"""HKDF-SHA256 for hierarchical / subsession key derivation (B7)."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf_derive(master: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    kdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return kdf.derive(master)


def kerberos_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive Kc (32 bytes) for AS from user password. Mirror of hmac_utils.password_hash."""
    from .hmac_utils import password_hash
    _, h = password_hash(password, salt)
    return h
