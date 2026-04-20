"""AES-128-CBC (S/MIME body) + AES-256-GCM (ticket / STARTTLS / subsession)."""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def aes_cbc_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Return (iv, ciphertext). key must be 16 bytes (AES-128)."""
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv, ct


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Return (nonce, ciphertext||tag). key must be 32 bytes (AES-256)."""
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    enc = cipher.encryptor()
    if aad:
        enc.authenticate_additional_data(aad)
    ct = enc.update(plaintext) + enc.finalize()
    return nonce, ct + enc.tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, ct_and_tag: bytes, aad: bytes = b"") -> bytes:
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    dec = cipher.decryptor()
    if aad:
        dec.authenticate_additional_data(aad)
    return dec.update(ct) + dec.finalize()


def random_key(nbytes: int) -> bytes:
    return os.urandom(nbytes)
