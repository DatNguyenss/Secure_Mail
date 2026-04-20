"""DKIM-lite: MTA ký selected headers + body với domain key.

Giản lược: canonicalization `relaxed/relaxed` only.
Thay cho DNS TXT lookup → dùng KDS với email đặc biệt `_dkim.<domain>`.
"""
import base64
import hashlib

from cryptography import x509

from securemail.crypto import rsa_handler
from .mime_lite import canonicalize_relaxed


SIGNED_HEADERS = ["From", "To", "Subject", "Date", "Message-ID"]


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def sign(headers: dict, body: bytes, domain: str, selector: str, domain_privkey) -> str:
    """Return DKIM-Signature header value (without `DKIM-Signature:` prefix)."""
    body_hash = hashlib.sha256(body).digest()
    bh = _b64(body_hash)

    header_names = " : ".join(SIGNED_HEADERS)
    dkim_sig_template = (
        f"v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s={selector}; "
        f"h={header_names}; bh={bh}; b="
    )
    # include DKIM-Signature header in canonicalization (without b= value)
    headers_plus = dict(headers)
    headers_plus["DKIM-Signature"] = dkim_sig_template

    to_sign = canonicalize_relaxed(headers_plus, SIGNED_HEADERS + ["DKIM-Signature"], body)
    sig = rsa_handler.pss_sign(domain_privkey, to_sign)
    return dkim_sig_template + _b64(sig)


def verify(headers: dict, body: bytes, dkim_sig_value: str, domain_cert_pem: bytes) -> bool:
    # Parse the DKIM-Signature
    parts = {}
    for seg in dkim_sig_value.split(";"):
        seg = seg.strip()
        if not seg or "=" not in seg:
            continue
        k, v = seg.split("=", 1)
        parts[k.strip()] = v.strip()
    if "b" not in parts:
        return False
    sig_b64 = parts["b"]
    try:
        sig = base64.b64decode(sig_b64.encode("ascii"))
    except Exception:
        return False

    # Reconstruct the string that was signed: DKIM-Signature with b= emptied
    template = dkim_sig_value[: dkim_sig_value.rfind("b=") + 2]
    headers_plus = dict(headers)
    headers_plus["DKIM-Signature"] = template
    signed_blob = canonicalize_relaxed(headers_plus, SIGNED_HEADERS + ["DKIM-Signature"], body)

    cert = x509.load_pem_x509_certificate(domain_cert_pem)
    return rsa_handler.pss_verify(cert.public_key(), sig, signed_blob)


def verify_body_hash(body: bytes, dkim_sig_value: str) -> bool:
    parts = dict(x.strip().split("=", 1) for x in dkim_sig_value.split(";") if "=" in x)
    expected = parts.get("bh", "")
    actual = _b64(hashlib.sha256(body).digest())
    return expected == actual
