"""Authenticator — chống replay ticket trong lifetime.

Authenticator = E(K_c,x, [IDc || ADc || TSn])
Server giữ replay cache (IDc, TSn) trong cửa sổ chống replay.
"""
import json
import time
import threading
from securemail.crypto.aes_handler import aes_gcm_encrypt, aes_gcm_decrypt


class ReplayCache:
    """In-memory TTL cache — dữ (IDc, nonce) trong `window` giây.

    Nonce đảm bảo 2 authenticator trong cùng giây vẫn phân biệt.
    TS dùng riêng cho window check.
    """

    def __init__(self, window_seconds: int = 300):
        self.window = window_seconds
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, idc: str, nonce_hex: str, ts: float) -> bool:
        now = time.time()
        with self._lock:
            expired = [k for k, t in self._seen.items() if now - t > self.window]
            for k in expired:
                del self._seen[k]
            if abs(now - ts) > self.window:
                return False
            key = (idc, nonce_hex)
            if key in self._seen:
                return False
            self._seen[key] = now
            return True


def build(key: bytes, idc: str, ad_c: str, subkey: bytes | None = None) -> str:
    import base64
    import os
    payload = {
        "id_c": idc,
        "ad_c": ad_c,
        "ts": time.time(),
        "nonce": os.urandom(16).hex(),
    }
    if subkey:
        payload["subkey_b64"] = base64.b64encode(subkey).decode("ascii")
    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    nonce, ct = aes_gcm_encrypt(key, data, aad=b"authenticator-v1")
    return base64.b64encode(nonce + ct).decode("ascii")


def open_auth(key: bytes, blob: str) -> dict:
    import base64
    raw = base64.b64decode(blob.encode("ascii"))
    nonce, ct = raw[:12], raw[12:]
    pt = aes_gcm_decrypt(key, nonce, ct, aad=b"authenticator-v1")
    return json.loads(pt.decode("utf-8"))
