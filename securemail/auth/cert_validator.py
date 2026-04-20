"""Verify certificate chain User → CA + CRL check (M3)."""
import datetime as dt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def verify_chain(user_cert_pem: bytes, ca_cert_pem: bytes, crl_pem: bytes | None = None) -> tuple[bool, str]:
    try:
        user = x509.load_pem_x509_certificate(user_cert_pem)
        ca = x509.load_pem_x509_certificate(ca_cert_pem)
    except Exception as e:
        return False, f"parse error: {e}"

    now = dt.datetime.now(dt.timezone.utc)
    if user.not_valid_before_utc > now:
        return False, "cert not yet valid"
    if user.not_valid_after_utc < now:
        return False, "cert expired"

    # Verify CA signature on user cert
    try:
        ca_pub = ca.public_key()
        if isinstance(ca_pub, rsa.RSAPublicKey):
            ca_pub.verify(
                user.signature,
                user.tbs_certificate_bytes,
                padding.PKCS1v15(),
                user.signature_hash_algorithm,
            )
        else:
            return False, "CA key must be RSA"
    except Exception as e:
        return False, f"CA signature invalid: {e}"

    # CRL check
    if crl_pem:
        try:
            crl = x509.load_pem_x509_crl(crl_pem)
            for entry in crl:
                if entry.serial_number == user.serial_number:
                    return False, "cert revoked (CRL)"
        except Exception:
            pass

    return True, "ok"
