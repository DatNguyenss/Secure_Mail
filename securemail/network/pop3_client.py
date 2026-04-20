"""POP3-lite client."""
import base64
import json
import socket

from securemail.network.json_framing import send_json, recv_json, b64, unb64
from securemail.network import tls_lite
from securemail.crypto.aes_handler import aes_gcm_decrypt
from securemail.ticket_service import authenticator as auth_mod


class Pop3Client:
    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port), timeout=20)
        self.framer = None

    def _s(self, obj):
        if self.framer:
            self.framer.send(obj)
        else:
            send_json(self.sock, obj)

    def _r(self):
        if self.framer:
            return self.framer.recv()
        return recv_json(self.sock)

    def helo_starttls(self):
        send_json(self.sock, {"op": "HELO"})
        r = recv_json(self.sock)
        if r.get("starttls"):
            send_json(self.sock, {"op": "STARTTLS"})
            key, _ = tls_lite.client_handshake(self.sock)
            self.framer = tls_lite.SecureFramer(self.sock, key)

    def auth(self, id_c: str, ticket_v: str, k_c_v: bytes):
        authn = auth_mod.build(k_c_v, id_c, "127.0.0.1")
        self._s({"op": "AUTH", "ticket_v": ticket_v, "authenticator": authn})
        r = self._r()
        if not r.get("ok"):
            raise RuntimeError(f"AUTH: {r.get('error')}")
        # Verify mutual
        blob = unb64(r["mutual_b64"])
        nonce, ct = blob[:12], blob[12:]
        aes_gcm_decrypt(k_c_v, nonce, ct, aad=b"mutual-v1")

    def list(self) -> list[dict]:
        self._s({"op": "LIST"})
        r = self._r()
        return r.get("messages", [])

    def retr(self, mid: int) -> dict | None:
        self._s({"op": "RETR", "id": mid})
        r = self._r()
        if not r.get("ok"):
            return None
        return {
            "sender": r["sender"],
            "envelope": unb64(r["envelope_b64"]),
            "headers": r["headers"],
            "dmarc_action": r["dmarc_action"],
            "spf_result": r["spf_result"],
            "dkim_result": r["dkim_result"],
        }

    def dele(self, mid: int):
        self._s({"op": "DELE", "id": mid})
        self._r()

    def quit(self):
        try:
            self._s({"op": "QUIT"})
            self._r()
        except Exception:
            pass
        self.sock.close()
