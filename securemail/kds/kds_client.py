"""Client library cho KDS."""
from securemail.network.json_framing import request, b64, unb64
from .kds_server import KDS_HOST, KDS_PORT


def put_cert(email: str, serial_hex: str, cert_pem: bytes, cert_type: str = "sign"):
    return request(KDS_HOST, KDS_PORT, {
        "op": "kds.put_cert", "email": email, "cert_type": cert_type,
        "serial_hex": serial_hex, "cert_pem_b64": b64(cert_pem),
    })


def get_cert(email: str) -> bytes | None:
    """Backward-compatible alias: returns the signing certificate PEM."""
    return get_sign_cert(email)


def get_sign_cert(email: str) -> bytes | None:
    """Return signing certificate PEM bytes, or None if not found."""
    r = request(KDS_HOST, KDS_PORT, {"op": "kds.get_sign_cert", "email": email})
    if not r.get("ok"):
        return None
    return unb64(r["cert_pem_b64"])


def get_enc_cert(email: str) -> bytes | None:
    """Return encryption certificate PEM bytes, or None if not found."""
    r = request(KDS_HOST, KDS_PORT, {"op": "kds.get_enc_cert", "email": email})
    if not r.get("ok"):
        return None
    return unb64(r["cert_pem_b64"])


def bulk_get(emails: list[str]) -> dict[str, dict[str, bytes]]:
    """Return {email: {"sign": cert_pem_bytes, "enc": cert_pem_bytes}} for each email.

    For backward compatibility, also supports callers that just need the signing cert
    via bulk_get(emails)[email]["sign"].
    """
    r = request(KDS_HOST, KDS_PORT, {"op": "kds.bulk", "emails": emails})
    result = {}
    for e, certs in r.get("certs", {}).items():
        entry = {}
        if "sign" in certs:
            entry["sign"] = unb64(certs["sign"])
        if "enc" in certs:
            entry["enc"] = unb64(certs["enc"])
        result[e] = entry
    return result


def sync_crl(crl_pem: bytes):
    return request(KDS_HOST, KDS_PORT, {"op": "kds.sync_crl", "crl_pem_b64": b64(crl_pem)})


def get_crl() -> bytes | None:
    r = request(KDS_HOST, KDS_PORT, {"op": "kds.get_crl"})
    if not r.get("ok"):
        return None
    return unb64(r["crl_pem_b64"])


def list_emails() -> list[str]:
    r = request(KDS_HOST, KDS_PORT, {"op": "kds.list_emails"})
    return r.get("emails", [])
