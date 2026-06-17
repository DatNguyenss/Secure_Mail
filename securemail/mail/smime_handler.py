"""S/MIME-lite: EnvelopedData + SignedData — Dual Key Pair architecture.

Signing key  → RSA-PSS digital signature (sender's sign_privkey)
Encryption   → RSA-OAEP encrypt CEK using recipient's ENCRYPTION cert public key

JSON envelope format:
  {
    "version": "smime-lite/2",
    "recipients": [
        {"email": "bob@...", "enc_serial": "0x...", "cek_oaep_b64": "..."}
    ],
    "content": {
        "iv_b64": "...", "ct_b64": "...", "algo": "AES-128-CBC"
    },
    "signature": {
        "signer_sign_cert_b64": "...",   ← signing cert (not enc cert)
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
    recipient_enc_certs: list[tuple[str, bytes]],  # [(email, enc_cert_pem)]
    signer_sign_cert_pem: bytes,                   # sender's SIGNING certificate
    signer_sign_privkey,                           # sender's SIGNING private key
) -> bytes:
    """Sign-then-encrypt using DUAL KEY PAIR architecture.

    - Signing  : sender's SIGNING private key (RSA-PSS)
    - Encryption: each recipient's ENCRYPTION public key (RSA-OAEP on CEK)

    Returns JSON bytes of the envelope.
    """
    # 1. Sign plaintext with sender's SIGNING key
    sig = rsa_handler.pss_sign(signer_sign_privkey, plaintext)

    # 2. Generate CEK, encrypt (plaintext || signature) with AES-CBC
    cek = random_key(16)
    inner = json.dumps({
        "body_b64": _b64(plaintext),
        "sig_b64": _b64(sig),
        # Embed the SIGNING cert so recipient can verify signature
        "signer_sign_cert_b64": _b64(signer_sign_cert_pem),
    }).encode("utf-8")
    iv, ct = aes_cbc_encrypt(cek, inner)

    # 3. For each recipient, RSA-OAEP encrypt CEK with their ENCRYPTION public key
    recipients = []
    for email, enc_cert_pem in recipient_enc_certs:
        enc_cert = x509.load_pem_x509_certificate(enc_cert_pem)
        enc_pub = enc_cert.public_key()
        encrypted_cek = rsa_handler.oaep_encrypt(enc_pub, cek)
        recipients.append({
            "email": email,
            "enc_serial": hex(enc_cert.serial_number),
            "cek_oaep_b64": _b64(encrypted_cek),
        })

    envelope = {
        "version": "smime-lite/2",
        "recipients": recipients,
        "content": {"iv_b64": _b64(iv), "ct_b64": _b64(ct), "algo": "AES-128-CBC"},
    }
    return json.dumps(envelope).encode("utf-8")


def open_envelope(envelope_json: bytes, recipient_email: str, recipient_enc_privkey) -> dict:
    """Decrypt + verify signature using DUAL KEY PAIR architecture.

    Args:
        recipient_enc_privkey: The recipient's ENCRYPTION private key for CEK decryption.

    Returns dict {body: bytes, signer_cert_pem: bytes, signer_subject: str}.
    """
    env = json.loads(envelope_json.decode("utf-8"))

    # 1. Find recipient block, decrypt CEK using ENCRYPTION private key
    rec = next((r for r in env["recipients"] if r["email"] == recipient_email), None)
    if rec is None:
        raise ValueError(f"email {recipient_email} not in recipients list")
    cek = rsa_handler.oaep_decrypt(recipient_enc_privkey, _ub(rec["cek_oaep_b64"]))

    # 2. Decrypt content
    iv = _ub(env["content"]["iv_b64"])
    ct = _ub(env["content"]["ct_b64"])
    inner_bytes = aes_cbc_decrypt(cek, iv, ct)
    inner = json.loads(inner_bytes.decode("utf-8"))

    body = _ub(inner["body_b64"])
    sig = _ub(inner["sig_b64"])

    # Support both old format (signer_cert_b64) and new format (signer_sign_cert_b64)
    signer_cert_key = "signer_sign_cert_b64" if "signer_sign_cert_b64" in inner else "signer_cert_b64"
    signer_cert_pem = _ub(inner[signer_cert_key])

    # 3. Verify signature using sender's SIGNING cert public key
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
