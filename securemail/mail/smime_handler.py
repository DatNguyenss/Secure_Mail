"""S/MIME-lite: EnvelopedData + SignedData.

JSON-based envelope (thay cho PKCS#7 BER để đơn giản hóa):
  envelope = {
    "version": "smime-lite/1",
    "recipients": [
        {"email": "bob@...", "serial": "0x...", "cek_oaep_b64": "..."}
    ],
    "content": {
        "iv_b64": "...", "ct_b64": "...", "algo": "AES-128-CBC"
    },
    "signature": {
        "signer_cert_pem_b64": "...",
        "sig_b64": "...",
        "algo": "RSA-PSS/SHA-256"
    }
  }
"""
import base64
import hashlib
import json

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from securemail.crypto import rsa_handler
from securemail.crypto.aes_handler import aes_cbc_encrypt, aes_cbc_decrypt, random_key


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _ub(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def build_envelope(
    plaintext: bytes,
    recipient_certs: list[tuple[str, bytes]],   # [(email, cert_pem)]
    signer_cert_pem: bytes,
    signer_privkey,
) -> bytes:
    """Sign-then-encrypt (S/MIME recommended order: sign first).

    Trả về JSON bytes của envelope.
    """
    # 1. Sign plaintext
    sig = rsa_handler.pss_sign(signer_privkey, plaintext)

    # 2. Generate CEK, encrypt (plaintext || signature) with AES-CBC
    cek = random_key(16)
    inner = json.dumps({
        "body_b64": _b64(plaintext),
        "sig_b64": _b64(sig),
        "signer_cert_b64": _b64(signer_cert_pem),
    }).encode("utf-8")
    iv, ct = aes_cbc_encrypt(cek, inner)

    # 3. For each recipient, RSA-OAEP encrypt CEK
    recipients = []
    for email, cert_pem in recipient_certs:
        cert = x509.load_pem_x509_certificate(cert_pem)
        pub = cert.public_key()
        enc_cek = rsa_handler.oaep_encrypt(pub, cek)
        recipients.append({
            "email": email,
            "serial": hex(cert.serial_number),
            "cek_oaep_b64": _b64(enc_cek),
        })

    envelope = {
        "version": "smime-lite/1",
        "recipients": recipients,
        "content": {"iv_b64": _b64(iv), "ct_b64": _b64(ct), "algo": "AES-128-CBC"},
    }
    return json.dumps(envelope).encode("utf-8")


def open_envelope(envelope_json: bytes, recipient_email: str, recipient_privkey) -> dict:
    """Decrypt + verify signature. Raise ValueError if verify fails.

    Return dict {body: bytes, signer_cert_pem: bytes, signer_subject: str}.
    """
    env = json.loads(envelope_json.decode("utf-8"))

    # 1. Find recipient block, decrypt CEK
    rec = next((r for r in env["recipients"] if r["email"] == recipient_email), None)
    if rec is None:
        raise ValueError(f"email {recipient_email} not in recipients list")
    cek = rsa_handler.oaep_decrypt(recipient_privkey, _ub(rec["cek_oaep_b64"]))

    # 2. Decrypt content
    iv = _ub(env["content"]["iv_b64"])
    ct = _ub(env["content"]["ct_b64"])
    inner_bytes = aes_cbc_decrypt(cek, iv, ct)
    inner = json.loads(inner_bytes.decode("utf-8"))

    body = _ub(inner["body_b64"])
    sig = _ub(inner["sig_b64"])
    signer_cert_pem = _ub(inner["signer_cert_b64"])

    # 3. Verify signature
    signer_cert = x509.load_pem_x509_certificate(signer_cert_pem)
    ok = rsa_handler.pss_verify(signer_cert.public_key(), sig, body)
    if not ok:
        raise ValueError("signature verification FAILED")

    return {
        "body": body,
        "signer_cert_pem": signer_cert_pem,
        "signer_subject": signer_cert.subject.rfc4514_string(),
        "signer_serial": hex(signer_cert.serial_number),
    }


def fingerprint(envelope_json: bytes) -> str:
    return hashlib.sha256(envelope_json).hexdigest()[:16]
