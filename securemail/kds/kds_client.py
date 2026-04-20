"""Client library cho KDS."""
from securemail.network.json_framing import request, b64, unb64
from .kds_server import KDS_HOST, KDS_PORT


def put_cert(email: str, serial_hex: str, cert_pem: bytes):
    return request(KDS_HOST, KDS_PORT, {
        "op": "kds.put_cert", "email": email,
        "serial_hex": serial_hex, "cert_pem_b64": b64(cert_pem),
    })


def get_cert(email: str) -> bytes | None:
    r = request(KDS_HOST, KDS_PORT, {"op": "kds.get_cert", "email": email})
    if not r.get("ok"):
        return None
    return unb64(r["cert_pem_b64"])


def bulk_get(emails: list[str]) -> dict[str, bytes]:
    r = request(KDS_HOST, KDS_PORT, {"op": "kds.bulk", "emails": emails})
    return {e: unb64(c) for e, c in r.get("certs", {}).items()}


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
