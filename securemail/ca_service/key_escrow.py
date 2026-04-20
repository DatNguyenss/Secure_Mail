"""A9 — Shamir 2-of-3 key recovery cho encryption key (không phải signing key).

Cài Shamir thủ công trên GF(256) để không cần thêm dependency.
"""
import os
import secrets
from pathlib import Path

ESCROW_DIR = Path("data/ca/escrow")


# --- Shamir Secret Sharing on GF(256) ---
_GF_EXP = [0] * 512
_GF_LOG = [0] * 256


def _init_gf():
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x ^= (x << 1) & 0xFF
        if x == 0:
            x = 1
        # standard AES-like generator
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


# Proper init using generator 3
def _init_gf_proper():
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        # multiply x by 3 in GF(256) with poly 0x11b
        x = _gf_mul_raw(x, 3)
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


def _gf_mul_raw(a: int, b: int) -> int:
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1b
        b >>= 1
    return r


_init_gf_proper()


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def gf_div(a: int, b: int) -> int:
    if a == 0:
        return 0
    if b == 0:
        raise ZeroDivisionError
    return _GF_EXP[(_GF_LOG[a] - _GF_LOG[b]) % 255]


def _eval_poly(coeffs: list[int], x: int) -> int:
    r = 0
    for c in reversed(coeffs):
        r = gf_mul(r, x) ^ c
    return r


def split_secret(secret: bytes, threshold: int = 2, shares: int = 3) -> list[tuple[int, bytes]]:
    """Split mỗi byte độc lập bằng Shamir. Trả list (idx, share_bytes)."""
    result = [bytearray() for _ in range(shares)]
    for byte in secret:
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for i in range(shares):
            result[i].append(_eval_poly(coeffs, i + 1))
    return [(i + 1, bytes(result[i])) for i in range(shares)]


def combine_shares(shares: list[tuple[int, bytes]]) -> bytes:
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares")
    size = len(shares[0][1])
    out = bytearray(size)
    for pos in range(size):
        # Lagrange interpolation at x=0
        total = 0
        for j, (xj, yj) in enumerate(shares):
            num = 1
            den = 1
            for m, (xm, _) in enumerate(shares):
                if m == j:
                    continue
                num = gf_mul(num, xm)
                den = gf_mul(den, xj ^ xm)
            total ^= gf_mul(yj[pos], gf_div(num, den))
        out[pos] = total
    return bytes(out)


# --- Escrow API ---
def escrow_key(user_email: str, encryption_priv_pem: bytes):
    """Split + lưu 3 share vào 3 file riêng."""
    ESCROW_DIR.mkdir(parents=True, exist_ok=True)
    shares = split_secret(encryption_priv_pem, threshold=2, shares=3)
    for idx, data in shares:
        path = ESCROW_DIR / f"{user_email.replace('@','_at_')}.share{idx}.bin"
        path.write_bytes(data)
    print(f"[Escrow] Split key for {user_email} into 3 shares (threshold 2)")


def recover_key(user_email: str, share_indices: list[int]) -> bytes:
    if len(share_indices) < 2:
        raise ValueError("Cần ít nhất 2 share")
    shares = []
    for i in share_indices:
        path = ESCROW_DIR / f"{user_email.replace('@','_at_')}.share{i}.bin"
        shares.append((i, path.read_bytes()))
    return combine_shares(shares)
