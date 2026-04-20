"""Client library cho Ticket Service."""
import base64
import json
import time

from securemail.network.json_framing import request, b64, unb64
from securemail.crypto.aes_handler import aes_gcm_decrypt
from securemail.crypto.hmac_utils import password_hash
from . import authenticator as auth_mod
from .as_tgs_server import TS_HOST, TS_PORT, TGS_NAME


def register(id_c: str, salt: bytes, kc: bytes, role: str = "user"):
    return request(TS_HOST, TS_PORT, {
        "op": "ts.register_principal", "id_c": id_c,
        "salt_b64": b64(salt), "kc_b64": b64(kc), "role": role,
    })


def as_request(id_c: str, password: str) -> dict:
    """Return {k_c_tgs, tgt, lifetime} after successful AS exchange."""
    ts1 = int(time.time())
    resp = request(TS_HOST, TS_PORT, {
        "op": "ts.as_req", "id_c": id_c, "id_tgs": TGS_NAME, "ts1": ts1,
    })
    if not resp.get("ok"):
        raise RuntimeError(f"AS-REQ failed: {resp.get('error')}")

    salt = unb64(resp["salt_b64"])
    _, kc = password_hash(password, salt)

    blob = unb64(resp["as_rep_b64"])
    nonce, ct = blob[:12], blob[12:]
    try:
        pt = aes_gcm_decrypt(kc, nonce, ct, aad=b"as-rep-v1")
    except Exception:
        raise RuntimeError("wrong password (AS-REP decrypt failed)")
    payload = json.loads(pt.decode("utf-8"))

    return {
        "k_c_tgs": unb64(payload["k_c_tgs_b64"]),
        "tgt": payload["tgt"],
        "lifetime": payload["lifetime"],
    }


def tgs_request(k_c_tgs: bytes, tgt: str, id_c: str, id_v: str, ad_c: str = "127.0.0.1") -> dict:
    """Return {k_c_v, ticket_v, lifetime}."""
    authn = auth_mod.build(k_c_tgs, id_c, ad_c)
    resp = request(TS_HOST, TS_PORT, {
        "op": "ts.tgs_req", "id_v": id_v, "tgt": tgt, "authenticator": authn,
    })
    if not resp.get("ok"):
        raise RuntimeError(f"TGS-REQ failed: {resp.get('error')}")

    blob = unb64(resp["tgs_rep_b64"])
    nonce, ct = blob[:12], blob[12:]
    pt = aes_gcm_decrypt(k_c_tgs, nonce, ct, aad=b"tgs-rep-v1")
    payload = json.loads(pt.decode("utf-8"))
    return {
        "k_c_v": unb64(payload["k_c_v_b64"]),
        "ticket_v": payload["ticket_v"],
        "lifetime": payload["lifetime"],
    }


def get_service_key(id_v: str) -> bytes:
    r = request(TS_HOST, TS_PORT, {"op": "ts.get_service_key", "id_v": id_v})
    return unb64(r["kv_b64"])
