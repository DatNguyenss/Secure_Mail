"""Ticket structs — đóng gói bằng AES-256-GCM thay cho DES của giáo trình.

Cấu trúc theo Stallings Ch.15 Table 15.1:
  Tickettgs = E(Ktgs, [Kc,tgs || IDc || ADc || IDtgs || TS2 || Lifetime2])
  Ticketv   = E(Kv,   [Kc,v   || IDc || ADc || IDv   || TS4 || Lifetime4])
"""
import json
import time
from securemail.crypto.aes_handler import aes_gcm_encrypt, aes_gcm_decrypt


def seal_ticket(service_key: bytes, payload: dict) -> str:
    """payload = {session_key_b64, id_c, ad_c, id_srv, ts, lifetime, permissions}"""
    import base64
    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    nonce, ct = aes_gcm_encrypt(service_key, data, aad=b"ticket-v1")
    return base64.b64encode(nonce + ct).decode("ascii")


def open_ticket(service_key: bytes, blob: str) -> dict:
    import base64
    raw = base64.b64decode(blob.encode("ascii"))
    nonce, ct = raw[:12], raw[12:]
    pt = aes_gcm_decrypt(service_key, nonce, ct, aad=b"ticket-v1")
    return json.loads(pt.decode("utf-8"))


def is_expired(payload: dict) -> bool:
    return (payload["ts"] + payload["lifetime"]) < time.time()
