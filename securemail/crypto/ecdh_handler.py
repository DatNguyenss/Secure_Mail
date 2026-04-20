"""X25519 ECDH ephemeral (A8 — forward secrecy, bonus)."""
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization


def generate_ephemeral() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def public_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_public(raw: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(raw)


def derive_shared(priv: X25519PrivateKey, peer_pub: X25519PublicKey) -> bytes:
    return priv.exchange(peer_pub)
